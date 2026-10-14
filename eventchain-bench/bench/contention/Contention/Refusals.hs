{- | Evidence that a 'Checked' Hub's checks are live, taken before any cell
is timed.

A Hub that checked nothing would post the same commit rate as one that
checked everything cheaply, and the files it wrote would still verify,
because the Producers only ever submit good lines. So before the sweep, one
checked Hub is handed one good line and three bad ones — a line signed
against a head that is not the one it states, a line altered after it was
signed, and a line that is not JSON — and each bad one must be refused with
the fault that names what was wrong, leave the head where it was, and write
nothing. The run does not start if any of that fails.
-}
module Contention.Refusals
    ( proveChecks
    ) where

import Control.Exception (throwIO)
import Control.Monad (unless)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.List.NonEmpty qualified as NE
import Data.Text qualified as T
import EventChain (ChainedEvent (..), EventKind (..), ProducedLine (..), entryId, payloadRef, produce)
import EventChain.Crypto (PrivateKey)
import EventChain.Crypto.Types (LineBytes, LineHash, lineBytes, lineBytesRaw)
import EventChain.Verify (Fault (..), Verdict (..), verify)
import System.Directory (getTemporaryDirectory, removeFile)
import System.FilePath ((</>))

import Contention.Hub (Checks (..), Endpoint (..), Outcome (..), Refusal (..), Submission (..))
import Contention.Processor (withProcessor)
import Contention.Producer (payloadDigest, producerKey)

-- | Refuse three bad lines and accept two good ones, or fail.
proveChecks :: IO ()
proveChecks = do
    tmp <- getTemporaryDirectory
    let path = tmp </> "eventchain-hub-append-refusals.jsonl"
    withProcessor Checked path $ \ep -> do
        head0 <- ep.readHead
        accepted "the first good line" 1 =<< ep.submit (one head0 (sign "good" head0))
        head1 <- ep.readHead
        unless (head1 /= head0) (throwIO (userError "the head did not move on an accepted line"))

        -- Signed against the genesis head, stated as signed against the current one.
        refused "a stale line stating the current head" isChainMismatch =<< ep.submit (one head1 (sign "stale" head0))
        -- Signed against the current head, then one byte of its entry id changed.
        let forged = sign "forged" head1
        refused "a line altered after signing" isSignatureInvalid =<< ep.submit (one head1 (tamper forged))
        -- The same good line with its closing brace missing.
        refused "a line that is not JSON" isMalformed =<< ep.submit (one head1 (truncated forged))

        head1' <- ep.readHead
        unless (head1' == head1) (throwIO (userError "the head moved on a refused line"))
        accepted "a good line after the refusals" 2 =<< ep.submit (one head1 (sign "after" head1))

    file <- LBS.readFile path
    removeFile path
    verdicts <- either (throwIO . userError . ("the refusal proof's file did not frame: " <>) . show) pure (verify file)
    unless (length verdicts == 2 && all sound verdicts && LBS.count 0x0a file == 2) $
        throwIO (userError ("the refusal proof's file should hold two Sound lines; the Verifier says " <> show verdicts))
  where
    key :: PrivateKey
    key = producerKey 0

    sign name against = case produce key ChainedEvent{entryId = entryId (T.pack ("proof-" <> name)), payloadHash = payloadDigest 0 0, payloadRef = payloadRef (T.pack "proof"), prevHash = against, kind = Lifecycle} of
        Right produced -> produced.line
        Left err -> error ("produce refused a key libcrypto accepted: " <> show err)

    one :: LineHash -> LineBytes -> Submission
    one against ln = Submission{against, lines = NE.singleton ln}

    accepted what n = \case
        Accepted m | m == n -> pure ()
        other -> throwIO (userError (what <> " should have been accepted as line " <> show n <> "; got " <> show other))

    refused what expected = \case
        Refused (Judged [v]) | expected v -> pure ()
        other -> throwIO (userError (what <> " should have been refused with the named fault; got " <> show other))

    isChainMismatch = \case
        Unsound _ faults -> any (\case ChainMismatch{} -> True; _ -> False) faults
        _ -> False
    isSignatureInvalid = \case
        Unsound _ faults -> SignatureInvalid `elem` faults
        _ -> False
    isMalformed = \case
        Malformed _ -> True
        _ -> False
    sound = \case
        Sound _ -> True
        _ -> False

    -- The entry id "proof-forged" becomes "proof-forgeD": still a string of the same length, no longer what was signed.
    tamper ln =
        let raw = lineBytesRaw ln
            (before, rest) = BS.breakSubstring (BS.pack (map (fromIntegral . fromEnum) "proof-forged")) raw
         in if BS.null rest
                then error "the forged line does not contain its own entry id"
                else relined (before <> BS.pack (map (fromIntegral . fromEnum) "proof-forgeD") <> BS.drop 12 rest)

    truncated ln = relined (BS.init (lineBytesRaw ln))

    relined raw = case lineBytes raw of
        Right ln -> ln
        Left err -> error ("tampered bytes refused as a line's content: " <> show err)
