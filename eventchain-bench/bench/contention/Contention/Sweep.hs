{- | The sweep driver both benchmarks share: parse the flags over a set of
defaults, calibrate the signature and the delays on this machine, run every
cell, print the table, and write the rows as JSON Lines if asked.

The benchmarks differ only in their defaults — the contention sweep holds
the batch at one and crosses load, Producers and delay; the batching sweep
holds load at saturating and crosses batch size instead; the hub-append
sweep crosses the Hub model, with the checks proven live before anything is
timed — so the driver is one module and each @main-is@ is the defaults and a
call.
-}
module Contention.Sweep
    ( Settings (..)
    , runSweep
    , parseArgs
    ) where

import Control.Monad (forM, forM_, unless, when)
import Data.List (sort)
import GHC.Clock (getMonotonicTimeNSec)
import GHC.Conc (numCapabilities)
import System.IO (IOMode (..), hPutStrLn, withFile)
import Text.Printf (printf)

import Contention.Cell (Cell (..), Front (..), HubModel (..), Window (..), hubFromName, hubName, runCell)
import Contention.Hub (Checks (..))
import Contention.Predict (Prediction (..), predict)
import Contention.Producer (Committed (..), Load (..), inFlight, timeCheck, timeSignature)
import Contention.Refusals (proveChecks)

data Settings = Settings
    { wallSeconds :: Double
    , runCount :: Int
    , jsonPath :: Maybe FilePath
    , producerCounts :: [Int]
    , delays :: [Int]
    , loads :: [Load]
    , batches :: [Int]
    , hubs :: [HubModel]
    }

-- | Run every cell the settings describe and print the table.
runSweep :: Settings -> IO ()
runSweep settings = do
    forM_ settings.batches $ \b -> when (b < 1) (fail ("a batch of " <> show b <> " events signs nothing"))
    let threaded = any (\h -> h.front == Thread) settings.hubs
        checked = any (\h -> h.checks == Checked) settings.hubs
        needed = maximum settings.producerCounts + 1 + fromEnum threaded
    unless (numCapabilities >= needed) $
        fail ("needs " <> show needed <> " capabilities for " <> show (maximum settings.producerCounts) <> " Producers, the clock" <> (if threaded then " and the Hub thread" else "") <> "; has " <> show numCapabilities <> ". Pass +RTS -N" <> show needed)
    when checked proveChecks
    signMicros <- timeSignature 3000
    checkMicros <- if checked then timeCheck 3000 else pure 0
    calibrated <- forM settings.delays $ \d -> (,) d <$> calibrate d
    let cells = [Cell{hub = h, producers = p, load = l, delayMicros = d, batch = b} | h <- settings.hubs, l <- settings.loads, b <- settings.batches, d <- settings.delays, p <- settings.producerCounts]
    printf "%d capabilities; one produce %.1f µs on one thread; %d cells × %d runs × %.1f s\n" numCapabilities signMicros (length cells) settings.runCount settings.wallSeconds
    when checked $ printf "a checked Hub refused a stale, a forged and a malformed line and wrote nothing for them; one checked append %.1f µs on one thread\n" checkMicros
    forM_ calibrated $ \(d, actual) -> when (d > 0) (printf "an in-flight delay of %d µs delivers %.0f µs\n" d actual)
    putStrLn ""
    printf "%-9s %-12s %5s %3s %8s | %21s %9s | %13s %6s | %11s | %19s | %5s\n" "hub" "load" "batch" "P" "delay" "commits/s" "pred" "sig/entry" "pred" "retry p50/99" "latency p50/99 µs" "fair"
    rows <- forM cells $ \cell -> do
        windows <- forM [1 .. settings.runCount] $ \run -> runCell settings.wallSeconds run cell
        let actualDelay = maybe 0 id (lookup cell.delayMicros calibrated)
            service = case cell.hub.checks of
                HeadOnly -> 0
                Checked -> checkMicros
            prediction = predict signMicros actualDelay service cell.producers cell.batch cell.load
            row = summarise cell prediction windows
        putStrLn (tableRow row)
        pure row
    forM_ settings.jsonPath $ \path -> withFile path WriteMode $ \h -> mapM_ (hPutStrLn h . jsonRow) rows

-- | Mean microseconds 'inFlight' actually takes for a requested @d@.
calibrate :: Int -> IO Double
calibrate 0 = pure 0
calibrate d = do
    let samples = max 20 (min 200 (400000 `div` d))
    t0 <- getMonotonicTimeNSec
    forM_ [1 .. samples] $ \_ -> inFlight d
    t1 <- getMonotonicTimeNSec
    pure (fromIntegral (t1 - t0) / 1e3 / fromIntegral samples)

data Row = Row
    { cell :: Cell
    , prediction :: Prediction
    , commitRate :: (Double, Double)
    , signaturesPerEntry :: (Double, Double)
    , retryP50 :: Int
    , retryP99 :: Int
    , latencyP50 :: Int
    , latencyP99 :: Int
    , fairness :: Double
    -- ^ Smallest per-Producer commit count over the mean, worst run. One is perfect.
    }

summarise :: Cell -> Prediction -> [Window] -> Row
summarise cell prediction windows =
    Row
        { cell
        , prediction
        , commitRate = range [fromIntegral (count w) / w.seconds | w <- windows]
        , signaturesPerEntry = range [fromIntegral w.signatures / fromIntegral (count w) | w <- windows]
        , retryP50 = percentile 0.5 retries
        , retryP99 = percentile 0.99 retries
        , latencyP50 = percentile 0.5 latencies
        , latencyP99 = percentile 0.99 latencies
        , fairness = minimum (map fair windows)
        }
  where
    count w = length (concat w.perProducer)
    pooled = concatMap (concat . (.perProducer)) windows
    retries = sort [c.signatures - 1 | c <- pooled]
    latencies = sort [fromIntegral (c.latencyNanos `div` 1000) | c <- pooled]
    range xs = (minimum xs, maximum xs)
    fair w =
        let counts = map length w.perProducer
         in fromIntegral (minimum counts) * fromIntegral (length counts) / fromIntegral (sum counts)

-- | The @p@th percentile of a sorted list, nearest rank.
percentile :: Double -> [Int] -> Int
percentile _ [] = 0
percentile p xs = xs !! max 0 (min (length xs - 1) (ceiling (p * fromIntegral (length xs)) - 1))

tableRow :: Row -> String
tableRow r =
    printf
        "%-9s %-12s %5d %3d %8s | %21s %9.0f | %13s %6.2f | %5d/%-5d | %9d/%-9d | %5.2f"
        (hubName r.cell.hub)
        (loadName r.cell.load)
        r.cell.batch
        r.cell.producers
        (delayName r.cell.delayMicros)
        (rangeText "%.0f" r.commitRate)
        r.prediction.commitsPerSecond
        (rangeText "%.2f" r.signaturesPerEntry)
        r.prediction.signaturesPerEntry
        r.retryP50
        r.retryP99
        r.latencyP50
        r.latencyP99
        r.fairness

rangeText :: String -> (Double, Double) -> String
rangeText fmt (lo, hi) = printf fmt lo <> "-" <> printf fmt hi

loadName :: Load -> String
loadName = \case
    Saturating -> "saturating"
    Poisson r -> printf "poisson %.0f" r

delayName :: Int -> String
delayName d
    | d == 0 = "0"
    | d < 1000 = show d <> " µs"
    | otherwise = show (d `div` 1000) <> " ms"

-- | One minified object per cell, for the figure script.
jsonRow :: Row -> String
jsonRow r =
    printf
        "{\"hub\":\"%s\",\"load\":\"%s\",\"rate\":%s,\"batch\":%d,\"producers\":%d,\"delay_us\":%d,\"commits_per_s\":[%.1f,%.1f],\"pred_commits_per_s\":%.1f,\"sig_per_entry\":[%.4f,%.4f],\"pred_sig_per_entry\":%.4f,\"retry_p50\":%d,\"retry_p99\":%d,\"latency_p50_us\":%d,\"latency_p99_us\":%d,\"fairness\":%.4f}"
        (hubName r.cell.hub)
        (case r.cell.load of Saturating -> "saturating"; Poisson _ -> "poisson" :: String)
        (case r.cell.load of Saturating -> "null"; Poisson x -> printf "%.0f" x :: String)
        r.cell.batch
        r.cell.producers
        r.cell.delayMicros
        (fst r.commitRate)
        (snd r.commitRate)
        r.prediction.commitsPerSecond
        (fst r.signaturesPerEntry)
        (snd r.signaturesPerEntry)
        r.prediction.signaturesPerEntry
        r.retryP50
        r.retryP99
        r.latencyP50
        r.latencyP99
        r.fairness

-- | The flags over a benchmark's defaults; each one named narrows or replaces its axis.
parseArgs :: Settings -> [String] -> Settings
parseArgs = go
  where
    go s = \case
        [] -> s
        "--seconds" : v : rest -> go s{wallSeconds = read v} rest
        "--runs" : v : rest -> go s{runCount = read v} rest
        "--json" : v : rest -> go s{jsonPath = Just v} rest
        "--producers" : v : rest -> go s{producerCounts = commaList read v} rest
        "--delays" : v : rest -> go s{delays = commaList read v} rest
        "--loads" : v : rest -> go s{loads = commaList loadOf v} rest
        "--batches" : v : rest -> go s{batches = commaList read v} rest
        "--hubs" : v : rest -> go s{hubs = commaList hubFromName v} rest
        other -> error ("unknown arguments: " <> unwords other <> "; expected --seconds N, --runs N, --json PATH, --producers 1,2, --delays 0,200, --loads saturating,300, --batches 1,100, --hubs lock,head-only,checked")
    loadOf "saturating" = Saturating
    loadOf v = Poisson (read v)

commaList :: (String -> a) -> String -> [a]
commaList parse = map parse . words . map (\c -> if c == ',' then ' ' else c)
