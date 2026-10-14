{- | The Hub, modelled: the single-threaded event processor the upstream
protocol's ordering rule names, reduced to what appending needs from it.

A Producer signs against the head it read. By the time the signed line
arrives, the head may have moved, and a line whose @prev_hash@ is not the
head cannot be appended: it would chain to a line that is no longer last. So
the Hub's append is a compare-and-swap on the head. It accepts a line signed
against the current head and advances; it rejects any other and reports the
head it has, so the Producer can sign again. Nothing else the real Hub does
(payload storage, role gating, distribution) is modelled, because none of it
is in the race.

Two models of what the Hub does before it writes, chosen per Hub:

* 'HeadOnly': the Hub learns the head a line was signed against from the
  submission rather than by parsing the line, compares it, writes, and
  advances its head by hashing the bytes it wrote rather than trusting a
  digest the Producer sends. The contention and batching notes were measured
  against this model: what it measures is the comparison and its outcome.
* 'Checked': the Hub judges the line before it writes. The stated head is
  still compared first — a stale submission is refused without being read,
  the way an append API refuses a failed precondition — and every submission
  that passes goes through the Verifier's fold from the Hub's own checkpoint,
  which checks that the line is well formed under the exact-bytes rules,
  that its @prev_hash@ is the head, and that its signature verifies under
  the key it carries. The Hub writes only if every line in the submission is
  Sound, and advances to the digest the fold computed from the bytes it
  judged. A line failing any check is 'Refused' and writes nothing. The
  stated head is a hint; the fold is the judge, so a Producer that lies
  about the head it signed against is caught by the chain check.

A submission may carry more than one line. The Producer chains them among
themselves and signs the first against the head it read; the Hub compares
that one head and takes the submission whole or not at all. 'HeadOnly'
hashes the lines in one batched call and does not check the chain inside
the batch — that is the Verifier's job, and "Contention.Cell" has it verify
every file afterwards. 'Checked' judges the chain inside the batch as part
of judging the batch.

The lock serialises appends on whichever thread holds it. Called directly
from Producer threads that is the single-threaded processor without a thread
hop in front of it; "Contention.Processor" puts one thread and a queue in
front of the same Hub for the measurement that wants the hop inside. A stale
submission is rejected from a read of the head before the lock is taken, and
checked again inside it: the answer is the same either way, and keeping the
losers out of the lock keeps the runtime's lock handoff out of the numbers.
Writes go through a block-buffered handle with no fsync: durability policy
belongs to the Hub's implementation and is not what either measurement asked
about.
-}
module Contention.Hub
    ( Hub
    , Checks (..)
    , checksName
    , Submission (..)
    , Outcome (..)
    , Refusal (..)
    , Endpoint (..)
    , withHub
    , direct
    , currentHead
    , append
    ) where

import Control.Concurrent.MVar (MVar, modifyMVar, newMVar, readMVar)
import Control.Monad (forM_)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Foldable (toList)
import Data.List.NonEmpty (NonEmpty)
import Data.List.NonEmpty qualified as NE
import EventChain (genesisHash)
import EventChain.Crypto (hashLines)
import EventChain.Crypto.Types (LineBytes, LineHash, lineBytesRaw)
import EventChain.Verify (Verdict (..), checkpointFrom, verifiedLineHash, verify, verifyFrom)
import EventChain.Verify.Wire (FramingError)
import System.IO (BufferMode (..), Handle, IOMode (..), hSetBuffering, withBinaryFile)

data Hub = Hub
    { checks :: Checks
    , state :: MVar HubState
    , file :: Handle
    }

data HubState = HubState
    { headHash :: LineHash
    , commits :: Int
    }

-- | What the Hub does to a submission before it writes.
data Checks
    = -- | Compare the stated head, write, hash what was written.
      HeadOnly
    | -- | Compare the stated head, then the Verifier's fold judges every line before anything is written.
      Checked
    deriving stock (Eq, Show)

checksName :: Checks -> String
checksName = \case
    HeadOnly -> "head-only"
    Checked -> "checked"

-- | Signed lines chained in order, and the head the first was signed against.
data Submission = Submission
    { against :: LineHash
    , lines :: NonEmpty LineBytes
    }

data Outcome
    = -- | Written. The ordinal is how many lines the file now holds.
      Accepted Int
    | -- | Not written: the head had moved. This is the head to sign against now.
      Rejected LineHash
    | -- | Not written: the stated head was current and a check said no. Only a 'Checked' Hub answers this.
      Refused Refusal
    deriving stock (Show)

-- | Why a 'Checked' Hub would not write a submission whose stated head was current.
data Refusal
    = -- | The bytes did not frame as a first line: the Verifier's file-level complaint.
      Unframed FramingError
    | -- | The fold's verdicts, at least one of them not Sound, or fewer of them than lines.
      Judged [Verdict]
    deriving stock (Show)

-- | How a Producer reaches a Hub: read the head, submit, wait for the outcome.
data Endpoint = Endpoint
    { readHead :: IO LineHash
    , submit :: Submission -> IO Outcome
    }

-- | An empty AOF at @path@, closed when the action returns.
withHub :: Checks -> FilePath -> (Hub -> IO a) -> IO a
withHub checks path act = withBinaryFile path WriteMode $ \h -> do
    hSetBuffering h (BlockBuffering (Just (1024 * 1024)))
    st <- newMVar HubState{headHash = genesisHash, commits = 0}
    act Hub{checks, state = st, file = h}

-- | The Hub reached from the calling thread, with nothing in front of it.
direct :: Hub -> Endpoint
direct hub = Endpoint{readHead = currentHead hub, submit = append hub}

-- | What a Producer reads before it signs.
currentHead :: Hub -> IO LineHash
currentHead hub = (.headHash) <$> readMVar hub.state

-- | Compare-and-swap append: nothing on rejection; on acceptance one write, and one batched hash or one judged fold.
append :: Hub -> Submission -> IO Outcome
append hub s = do
    seen <- readMVar hub.state
    if s.against /= seen.headHash
        then pure (Rejected seen.headHash)
        else modifyMVar hub.state $ \st ->
            if s.against /= st.headHash
                then pure (st, Rejected st.headHash)
                else case hub.checks of
                    HeadOnly -> commit st (lastDigest s.lines)
                    Checked -> case judge st s.lines of
                        Right newHead -> commit st newHead
                        Left refusal -> pure (st, Refused refusal)
  where
    commit st newHead = do
        forM_ s.lines $ \ln -> BS.hPut hub.file (lineBytesRaw ln) >> BS.hPut hub.file (BS.singleton 0x0a)
        let n = st.commits + NE.length s.lines
        pure (HubState{headHash = newHead, commits = n}, Accepted n)

    lastDigest lns = case hashLines (toList lns) of
        hs | length hs == NE.length lns -> last hs
        hs -> error ("Contention.Hub.append: " <> show (length hs) <> " digests for " <> show (NE.length lns) <> " lines")

{- | The Verifier's verdict on the submission as the next lines of this file.

The Hub holds what a resuming holder holds — the ordinal and digest of its
last line — and the fold continues from there; before the first line there
is no checkpoint, and the submission is judged as a file's opening bytes,
which is also where the byte order mark rule applies. The new head is the
digest the fold computed from the last line's bytes: the Hub does not hash
again, and does not take a digest from the Producer.
-}
judge :: HubState -> NonEmpty LineBytes -> Either Refusal LineHash
judge st lns = case verdicts of
    Left framing -> Left (Unframed framing)
    Right vs
        | length vs == NE.length lns
        , Just sound <- traverse soundHash vs ->
            Right (last sound)
        | otherwise -> Left (Judged vs)
  where
    bytes = LBS.fromChunks (concatMap (\ln -> [lineBytesRaw ln, BS.singleton 0x0a]) (toList lns))
    verdicts
        | st.commits == 0 = verify bytes
        | otherwise = Right (verifyFrom (checkpointFrom (fromIntegral st.commits - 1) st.headHash) bytes)
    soundHash = \case
        Sound ve -> Just (verifiedLineHash ve)
        _ -> Nothing
