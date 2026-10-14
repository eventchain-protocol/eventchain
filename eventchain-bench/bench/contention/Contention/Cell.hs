{- | One cell of the sweep: a Hub model, a Producer count, a load, a delay
and a batch size, run for a fixed wall time, then the file it wrote checked
by the Verifier.

Rates are taken over the window between start and the stop flag, on the
events that committed inside it. The drain after the flag is outside the
window but inside the file, and the file check counts everything: every line
Sound, as many lines as events committed, and each Producer's key on exactly
as many lines as it reports committing. A file this harness wrote that does
not verify is a broken harness, not a finding.
-}
module Contention.Cell
    ( Cell (..)
    , HubModel (..)
    , Front (..)
    , hubName
    , hubFromName
    , Window (..)
    , runCell
    ) where

import Control.Concurrent (forkFinally, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (throwIO)
import Control.Monad (forM, unless, (>=>))
import Data.ByteString.Lazy qualified as LBS
import Data.IORef (atomicWriteIORef, newIORef)
import Data.Map.Strict qualified as Map
import EventChain.Crypto (privateKeyPublic)
import EventChain.Crypto.Types (ClaimedKey)
import EventChain.Verify (Verdict (..), verifiedEntry, verify)
import EventChain.Verify.Types (Entry (..), ProducedProof (..))
import GHC.Clock (getMonotonicTimeNSec)
import System.Directory (getTemporaryDirectory, removeFile)
import System.FilePath ((</>))

import Contention.Hub (Checks (..), Endpoint, direct, withHub)
import Contention.Processor (withProcessor)
import Contention.Producer (Committed (..), Load (..), Producer (..), Tally (..), producerKey, runProducer)

-- | How submissions reach the Hub.
data Front
    = -- | Appended on the submitting Producer's thread, under the Hub's lock.
      Lock
    | -- | Handed to one Hub thread through a queue, and the reply awaited.
      Thread
    deriving stock (Eq, Show)

-- | What sits between a Producer and the file.
data HubModel = HubModel
    { front :: Front
    , checks :: Checks
    }
    deriving stock (Eq, Show)

-- | The name a table row and the @--hubs@ flag use.
hubName :: HubModel -> String
hubName = \case
    HubModel Lock HeadOnly -> "lock"
    HubModel Lock Checked -> "lock-checked"
    HubModel Thread HeadOnly -> "head-only"
    HubModel Thread Checked -> "checked"

hubFromName :: String -> HubModel
hubFromName = \case
    "lock" -> HubModel Lock HeadOnly
    "lock-checked" -> HubModel Lock Checked
    "head-only" -> HubModel Thread HeadOnly
    "checked" -> HubModel Thread Checked
    other -> error ("unknown hub model " <> show other <> "; expected lock, lock-checked, head-only or checked")

data Cell = Cell
    { hub :: HubModel
    , producers :: Int
    , load :: Load
    -- ^ A Poisson rate here is the aggregate; each Producer gets its share.
    , delayMicros :: Int
    , batch :: Int
    -- ^ Events each Producer signs and submits together.
    }

-- | What one run of a cell yields: the measured window and every Producer's commits.
data Window = Window
    { seconds :: Double
    , perProducer :: [[Committed]]
    -- ^ Only the events that committed inside the window, one list per Producer.
    , signatures :: Int
    -- ^ Every signature made inside the window, whether or not its event committed in it.
    }

-- | Run the cell for @seconds@ of wall time, as run number @run@ (seeds the arrivals).
runCell :: Double -> Int -> Cell -> IO Window
runCell seconds run cell = do
    tmp <- getTemporaryDirectory
    let path = tmp </> ("eventchain-contention-" <> show run <> ".jsonl")
    stop <- newIORef False
    (t0, tStop, tallies) <- withEndpoint cell.hub path $ \ep -> do
        t0 <- getMonotonicTimeNSec
        dones <- forM ps $ \p -> do
            done <- newEmptyMVar
            _ <- forkFinally (runProducer ep stop p) (putMVar done)
            pure done
        threadDelay (round (seconds * 1e6))
        atomicWriteIORef stop True
        tStop <- getMonotonicTimeNSec
        tallies <- mapM (takeMVar >=> either throwIO pure) dones
        pure (t0, tStop, tallies)
    checkFile path (zip ps (map (.committed) tallies))
    removeFile path
    pure
        Window
            { seconds = fromIntegral (tStop - t0) / 1e9
            , perProducer = map (filter (\c -> c.doneAt <= tStop) . (.committed)) tallies
            , signatures = sum [length (filter (<= tStop) t.signedAt) | t <- tallies]
            }
  where
    ps =
        [ Producer
            { index = i
            , key = producerKey i
            , load = share cell.load
            , delayMicros = cell.delayMicros
            , batch = cell.batch
            , seed = 0x9E3779B97F4A7C15 * fromIntegral (i + 1) + fromIntegral run
            }
        | i <- [0 .. cell.producers - 1]
        ]
    share = \case
        Saturating -> Saturating
        Poisson aggregate -> Poisson (aggregate / fromIntegral cell.producers)

-- | An empty AOF at @path@ behind the model's Hub, reached the model's way.
withEndpoint :: HubModel -> FilePath -> (Endpoint -> IO a) -> IO a
withEndpoint model path act = case model.front of
    Lock -> withHub model.checks path (act . direct)
    Thread -> withProcessor model.checks path act

-- | The Verifier's verdict on what the Hub wrote, against what the Producers report.
checkFile :: FilePath -> [(Producer, [Committed])] -> IO ()
checkFile path tallies = do
    file <- LBS.readFile path
    verdicts <- either (fail . ("the harness's own file did not frame: " <>) . show) pure (verify file)
    let lineCount = LBS.count 0x0a file
        committed = sum (map (length . snd) tallies)
        claimed = Map.fromListWith (+) [(privateKeyPublic p.key, 1 :: Int) | (p, cs) <- tallies, _ <- cs]
    signed <- foldr tallyVerdict (pure Map.empty) verdicts
    unless (fromIntegral lineCount == committed) $
        fail ("the file has " <> show lineCount <> " lines for " <> show committed <> " commits")
    unless (signed == claimed) $
        fail ("per-key line counts " <> show (Map.elems signed) <> " do not match per-Producer commits " <> show (Map.elems claimed))
  where
    tallyVerdict :: Verdict -> IO (Map.Map ClaimedKey Int) -> IO (Map.Map ClaimedKey Int)
    tallyVerdict v rest = case v of
        Sound ve -> Map.insertWith (+) (verifiedEntry ve).producedProof.publicKey 1 <$> rest
        other -> fail ("the harness's own file did not verify: " <> show other)
