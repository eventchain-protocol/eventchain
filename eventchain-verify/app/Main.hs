{-# LANGUAGE OverloadedStrings #-}

{- | The Verifier's command line: an AOF's bytes in, one minified JSON line per
AOF line out.

The output contract is the TypeScript verifier's @aof@ command, field for field
— @{"line":1,"outcome":"valid","event_id":"..."}@ — so that two verifiers that
share no code can be compared by diffing what they print. The outcome is the
specification's fault name; a line with several faults reports the first in the
specification's order (chain, key, signature, attestation), as the TypeScript
verifier does.

Exit status: 0 when every line is valid, 1 when any line is not, 2 for a usage
or IO error. A line libcrypto did not answer is also 2: that is this machine
failing, and reporting it as a verdict on the file would pronounce the file
forged because the installation was broken.
-}
module Main (main) where

import Control.Exception (IOException, catch)
import Data.Base64.Types (extractBase64)
import Data.ByteString.Base64.URL qualified as Base64Url
import Data.ByteString.Builder (Builder)
import Data.ByteString.Builder qualified as Builder
import Data.ByteString.Lazy qualified as LBS
import Data.List.NonEmpty (NonEmpty)
import Data.List.NonEmpty qualified as NE
import Data.Word (Word64)
import EventChain.Crypto.Types (LineHash, lineHashRaw)
import EventChain.Verify (Fault (..), Verdict (..), verifiedLineHash, verifiedPosition, verify)
import EventChain.Verify.Types (ChainPosition, chainPositionIndex)
import EventChain.Verify.Wire (DecodeError (..), FramingError (..))
import System.Environment (getArgs)
import System.Exit (ExitCode (..), exitWith)
import System.IO (BufferMode (..), hPutStrLn, hSetBinaryMode, hSetBuffering, stderr, stdout)

usage :: String
usage =
    unlines
        [ "usage:"
        , "  eventchain-verify aof <aof-file>"
        , "      one JSON line per AOF line: {\"line\":1,\"outcome\":\"valid\",\"event_id\":\"...\"}"
        , "      exit 0 when every line is valid, 1 when any is not, 2 for a usage or IO error"
        ]

main :: IO ()
main = do
    hSetBinaryMode stdout True
    hSetBuffering stdout (BlockBuffering Nothing)
    args <- getArgs
    code <- case args of
        ["aof", path] -> aof path `catch` ioFailure
        ["--help"] -> putStr usage >> pure ExitSuccess
        _ -> hPutStrLn stderr ("eventchain-verify: unknown command or wrong number of arguments\n" <> usage) >> pure (ExitFailure 2)
    exitWith code

-- | The file is read lazily, so a read error can surface mid-fold; it is IO either way.
ioFailure :: IOException -> IO ExitCode
ioFailure err = hPutStrLn stderr ("eventchain-verify: " <> show err) >> pure (ExitFailure 2)

aof :: FilePath -> IO ExitCode
aof path = do
    bytes <- LBS.readFile path
    case verify bytes of
        Left FileHasBom -> do
            hPutStrLn stderr "eventchain-verify: line 1: the file opens with a byte order mark, which JSON Lines forbids"
            emit (malformedLine 1)
            pure (ExitFailure 1)
        Right verdicts -> report True verdicts

-- | Print each verdict as the fold produces it, so a large file streams.
report :: Bool -> [Verdict] -> IO ExitCode
report allValid [] = pure (if allValid then ExitSuccess else ExitFailure 1)
report allValid (verdict : rest) = case verdict of
    Sound v -> emit (line (verifiedPosition v) "valid" (Just (verifiedLineHash v))) >> report allValid rest
    Unsound pos faults -> emit (line pos (faultName (firstFault faults)) Nothing) >> report False rest
    Malformed err -> do
        hPutStrLn stderr ("eventchain-verify: line " <> show (lineNumber err.position) <> ": " <> show err.reason)
        emit (malformedLine (lineNumber err.position))
        report False rest
    Undecided pos err -> do
        hPutStrLn stderr ("eventchain-verify: line " <> show (lineNumber pos) <> ": libcrypto did not answer, so no verdict was reached: " <> show err)
        pure (ExitFailure 2)

emit :: Builder -> IO ()
emit b = Builder.hPutBuilder stdout (b <> Builder.char7 '\n')

{- | A well-formed line's report. The event ID is present only on a valid line:
the library's 'Unsound' verdict carries the faults and not the line's digest,
so the TypeScript verifier's @event_id@ on a faulted line has no source here.
-}
line :: ChainPosition -> Builder -> Maybe LineHash -> Builder
line pos outcome eventId =
    "{\"line\":"
        <> Builder.word64Dec (lineNumber pos)
        <> ",\"outcome\":\""
        <> outcome
        <> "\""
        <> maybe "" (\h -> ",\"event_id\":\"" <> Builder.byteString (extractBase64 (Base64Url.encodeBase64Unpadded' (lineHashRaw h))) <> "\"") eventId
        <> "}"

malformedLine :: Word64 -> Builder
malformedLine n = "{\"line\":" <> Builder.word64Dec n <> ",\"outcome\":\"malformed\"}"

-- | 1-based, as an editor and the TypeScript verifier count lines.
lineNumber :: ChainPosition -> Word64
lineNumber pos = chainPositionIndex pos + 1

-- | The specification's order of faults; the first present is the line's outcome.
firstFault :: NonEmpty Fault -> Fault
firstFault = NE.head . NE.sortWith rank
  where
    rank :: Fault -> Int
    rank = \case
        ChainMismatch{} -> 0
        KeyOffCurve -> 1
        SignatureInvalid -> 2
        AttestationFault _ -> 3

-- | The specification's refusal reasons.
faultName :: Fault -> Builder
faultName = \case
    ChainMismatch{} -> "chain_mismatch"
    KeyOffCurve -> "key_off_curve"
    SignatureInvalid -> "signature_invalid"
    AttestationFault _ -> "attestation_fault"
