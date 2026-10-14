{- | One Producer under contention: read the head, sign against it, submit,
and sign again for as long as the Hub says the head moved.

The loop is the critique's mechanism made literal. An event is one business
occurrence with one entry id; a rejection does not make a new event, it makes
a new signature for the same one against a newer head. So what each committed
event records is how many signatures it cost and how long it waited, and
every signature is also stamped on its own, because a Producer that never
wins a race has signatures and no committed event to hang them on.

The injected delay sits between signing and submitting: the time a signed
line spends in flight to the Hub. In process that time is zero and the race
window is the signature alone; the delay stands in for a network hop so the
window can be widened without pretending the laptop is slower than it is.
It is jittered by ±10%, because a constant delay phase-locks the Producers
and the same one wins every round, which no network does.

A Producer with a batch above one signs that many events in a row, each
chained to the one before and the first to the head it read, and submits them
together; the Hub takes all of them or none. A rejection costs the whole batch
a new signature each, against the head the rejection returned. Every event in
a committed batch is recorded on its own, with the batch's attempt count and
the batch's latency, so the rates stay in events and the signature count per
Entry stays comparable with a batch of one. Under Poisson load the batch is
the next that many arrivals, and signing starts when the last of them is
due; the wait for a batch to fill is a cost of batching and is outside what
latency measures here, which runs from the first signature.
-}
module Contention.Producer
    ( Load (..)
    , Producer (..)
    , Committed (..)
    , Tally (..)
    , runProducer
    , inFlight
    , producerKey
    , payloadDigest
    , timeSignature
    , timeCheck
    ) where

import Control.Concurrent (threadDelay)
import Control.Exception (evaluate, throwIO)
import Control.Monad (forM_, when)
import Data.Bits (shiftL, shiftR, xor)
import Data.ByteString qualified as BS
import Data.IORef (IORef, readIORef)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.List.NonEmpty qualified as NE
import Data.Text qualified as T
import Data.Word (Word64)
import EventChain (ChainedEvent (..), EventKind (..), ProducedLine (..), entryId, genesisHash, payloadRef, produce)
import EventChain.Crypto (PrivateKey, privateKey)
import EventChain.Crypto.Types (PayloadHash, payloadHashFromBytes)
import GHC.Clock (getMonotonicTimeNSec)
import System.Directory (getTemporaryDirectory, removeFile)
import System.FilePath ((</>))

import Contention.Hub (Checks (..), Endpoint (..), Outcome (..), Submission (..), direct, withHub)

-- | How often this Producer has an event to commit.
data Load
    = -- | The next event is ready the moment the last one committed.
      Saturating
    | -- | Events arrive as a Poisson process at this many per second, whether or not the last one has committed.
      Poisson Double

data Producer = Producer
    { index :: Int
    , key :: PrivateKey
    , load :: Load
    , delayMicros :: Int
    , batch :: Int
    -- ^ Events signed and submitted together. One is the protocol as written.
    , seed :: Word64
    }

-- | One event that reached the file.
data Committed = Committed
    { signatures :: Int
    -- ^ How many times it was signed. One means it never lost a race.
    , latencyNanos :: Word64
    -- ^ From the first signature to acceptance.
    , doneAt :: Word64
    -- ^ Monotonic clock at acceptance, for windowing.
    }

-- | What one Producer did, most recent first in both lists.
data Tally = Tally
    { committed :: [Committed]
    , signedAt :: [Word64]
    -- ^ The clock at every signature, committed or not.
    }

{- | Run until the stop flag is set, then finish the event in hand. The
reporter windows both lists on the clock, so the drain after the flag costs
nothing in the rates, and every signature counted inside the window belongs
to an attempt made inside it.
-}
runProducer :: Endpoint -> IORef Bool -> Producer -> IO Tally
runProducer ep stop p = do
    start <- getMonotonicTimeNSec
    loop p.seed start (0 :: Int) Tally{committed = [], signedAt = []}
  where
    loop rng due ordinal tally = do
        halt <- readIORef stop
        if halt
            then pure tally
            else do
                (rng', due') <- arrivals p.batch rng due
                t0 <- getMonotonicTimeNSec
                against <- ep.readHead
                (rng'', sigs, stamps) <- attempt rng' ordinal against 1 tally.signedAt
                t1 <- getMonotonicTimeNSec
                let done = Committed{signatures = sigs, latencyNanos = t1 - t0, doneAt = t1}
                loop rng'' due' (ordinal + p.batch) Tally{committed = replicate p.batch done <> tally.committed, signedAt = stamps}

    attempt rng ordinal against n stamps = do
        (lns, stamps') <- signBatch ordinal against stamps
        rng' <- jittered rng
        outcome <- ep.submit Submission{against, lines = lns}
        case outcome of
            Accepted _ -> pure (rng', n, stamps')
            Rejected moved -> attempt rng' ordinal moved (n + 1) stamps'
            Refused why -> throwIO (userError ("the Hub refused a line this Producer signed against the head it stated: " <> show why))

    -- The batch's lines in chain order, and every signature stamped at its own time.
    signBatch ordinal against stamps = go ordinal against p.batch [] stamps
      where
        go i prev k acc stamped
            | k <= 0 = case reverse acc of
                [] -> throwIO (userError "Contention.Producer: a batch of zero events")
                l : ls -> pure (l :| ls, stamped)
            | otherwise = do
                now <- getMonotonicTimeNSec
                produced <- either (throwIO . userError . ("produce refused a key libcrypto accepted: " <>) . show) pure (produce p.key (event i prev))
                _ <- evaluate produced.lineHash
                go (i + 1) produced.lineHash (k - 1) (produced.line : acc) (now : stamped)

    jittered rng
        | p.delayMicros == 0 = pure rng
        | otherwise = do
            let (u, rng') = uniform rng
            inFlight (round (fromIntegral p.delayMicros * (0.9 + 0.2 * u)))
            pure rng'

    arrivals k rng due
        | k <= 0 = pure (rng, due)
        | otherwise = do
            (rng', due') <- arrival rng due
            arrivals (k - 1) rng' due'

    arrival rng due = case p.load of
        Saturating -> pure (rng, due)
        Poisson perSecond -> do
            let (u, rng') = uniform rng
                due' = due + round (negate (log u) / perSecond * 1e9)
            now <- getMonotonicTimeNSec
            when (due' > now) (threadDelay (fromIntegral ((due' - now) `div` 1000)))
            pure (rng', due')

    event ordinal against =
        ChainedEvent
            { entryId = entryId (T.pack ("evt-p" <> show p.index <> "-" <> show ordinal))
            , payloadHash = payloadDigest p.index ordinal
            , payloadRef = payloadRef (T.pack ("ref-p" <> show p.index <> "-" <> show ordinal))
            , prevHash = against
            , kind = Lifecycle
            }

{- | Hold a signed line for this many microseconds.

Below a millisecond this spins on the clock, because 'threadDelay' on this
runtime lands a 200 µs request two milliseconds late and the sub-millisecond
rows would all be the same row. Above it, the timer is accurate enough and
spinning would heat twelve cores to wait.
-}
inFlight :: Int -> IO ()
inFlight micros
    | micros <= 0 = pure ()
    | micros < 1000 = do
        t0 <- getMonotonicTimeNSec
        let until' = t0 + fromIntegral micros * 1000
            spin = do
                now <- getMonotonicTimeNSec
                when (now < until') spin
        spin
    | otherwise = threadDelay micros

-- | Any 32 bytes are a payload hash claim; nothing here resolves them.
payloadDigest :: Int -> Int -> PayloadHash
payloadDigest i ordinal = case payloadHashFromBytes (BS.pack (take 32 (cycle (bytesOf i <> bytesOf ordinal)))) of
    Right h -> h
    Left err -> error ("32 bytes refused as a digest: " <> show err)
  where
    bytesOf n = map fromIntegral [n, n `div` 256, n `div` 65536, n `div` 16777216]

{- | The @i@th Producer's key: RFC 6979 §A.2.5's scalar with its last byte
replaced by @i@. Distinct per Producer, every one inside the group order
because the leading bytes are unchanged, and nothing about which key signs
is what this measures.
-}
producerKey :: Int -> PrivateKey
producerKey i
    | i < 0 || i > 255 = error ("producerKey: " <> show i <> " is not a byte")
    | otherwise = case privateKey (BS.pack (init rfcScalar <> [fromIntegral i])) of
        Right k -> k
        Left err -> error ("a scalar below the group order was rejected: " <> show err)
  where
    rfcScalar = [0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21]

-- | Microseconds one 'produce' costs on one thread, over @n@ chained events.
timeSignature :: Int -> IO Double
timeSignature n = do
    t0 <- getMonotonicTimeNSec
    _ <- evaluate (go genesisHash 0)
    t1 <- getMonotonicTimeNSec
    pure (fromIntegral (t1 - t0) / 1e3 / fromIntegral n)
  where
    key = producerKey 0
    go prev ordinal
        | ordinal >= n = prev
        | otherwise = case produce key ChainedEvent{entryId = entryId (T.pack ("warm-" <> show ordinal)), payloadHash = payloadDigest 0 ordinal, payloadRef = payloadRef (T.pack "warm"), prevHash = prev, kind = Lifecycle} of
            Right produced -> go produced.lineHash (ordinal + 1)
            Left err -> error ("produce failed on a key libcrypto accepted: " <> show err)

{- | Microseconds one 'Checked' append costs on one thread, over @n@ chained
events: the Hub's fold per line, judged and written, with no thread in front
of it. Measured on lines produced beforehand, so no signature is inside it.
-}
timeCheck :: Int -> IO Double
timeCheck n = do
    tmp <- getTemporaryDirectory
    let path = tmp </> "eventchain-hub-append-calibration.jsonl"
        key = producerKey 0
        chain prev ordinal
            | ordinal >= n = []
            | otherwise = case produce key ChainedEvent{entryId = entryId (T.pack ("calibrate-" <> show ordinal)), payloadHash = payloadDigest 0 ordinal, payloadRef = payloadRef (T.pack "calibrate"), prevHash = prev, kind = Lifecycle} of
                Right produced -> (prev, produced.line) : chain produced.lineHash (ordinal + 1)
                Left err -> error ("produce failed on a key libcrypto accepted: " <> show err)
    produced <- evaluate (chain genesisHash 0)
    _ <- evaluate (length produced)
    micros <- withHub Checked path $ \hub -> do
        let ep = direct hub
        t0 <- getMonotonicTimeNSec
        forM_ produced $ \(against, ln) -> do
            outcome <- ep.submit Submission{against, lines = NE.singleton ln}
            case outcome of
                Accepted _ -> pure ()
                other -> throwIO (userError ("calibration: a chained line was not accepted: " <> show other))
        t1 <- getMonotonicTimeNSec
        pure (fromIntegral (t1 - t0) / 1e3 / fromIntegral n)
    removeFile path
    pure micros

-- | xorshift64*: deterministic per Producer, so a run is repeatable.
uniform :: Word64 -> (Double, Word64)
uniform x0 = (u, x3)
  where
    x1 = x0 `xor` (x0 `shiftR` 12)
    x2 = x1 `xor` (x1 `shiftL` 25)
    x3 = x2 `xor` (x2 `shiftR` 27)
    -- 53 bits of the scrambled state, mapped into (0, 1] so log never sees zero.
    u = (fromIntegral ((x3 * 2685821657736338717) `shiftR` 11) + 1) / 9007199254740992
