{-# LANGUAGE OverloadedStrings #-}

{- | M3's gate: an AOF written by a Producer this package has never seen
verifies, and a corrupted one fails at the line that was corrupted.

The file at @vectors/v0-lifecycle.jsonl@ is the whole of what crosses the wall.
@eventchain-verify@ may not depend on @eventchain@ — @gates:verifier-independence@
walks the resolved install plan and seeds on every unit of this package, this
test suite included — so nothing here can ask the Producer for an AOF, import
its canonicalizer, or name its member vocabulary. What is available is bytes and
a published document, which is exactly the position a stranger is in, and the
reason a pass here means anything at all.

What a pass establishes, and it is more than it looks: the two member
vocabularies name the same members, the two RFC 8785 implementations derive the
same bytes for the same entry, and the two readings of ADR-0002 agree about
which bytes are chained. None of that is checked by a shared function, because
there is no shared function. If any of it were wrong, this file would not
verify — and that is what makes the agreement evidence rather than a tautology.
-}
module Test.EventChain.Verify.Fold (tests) where

import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.ByteString.Lazy.Char8 qualified as LC8
import Data.List.NonEmpty qualified as NE
import EventChain.Verify
    ( Fault (..)
    , Verdict (..)
    , VerifiedEntry
    , genesisHash
    , verifiedEntry
    , verifiedLineHash
    , verifiedPosition
    , verify
    )
import EventChain.Verify.Types (Entry (..), chainPositionIndex)
import System.Directory (doesFileExist, getCurrentDirectory)
import System.FilePath (takeDirectory, (</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertFailure, testCase, (@?=))

tests :: TestTree
tests =
    testGroup
        "EventChain.Verify"
        [ testCase "the committed AOF verifies, every line" vectorVerifies
        , testCase "the first line chains to the genesis sentinel" chainsToGenesis
        , testCase "each line's prev_hash is the previous line's digest" chainsForward
        , testCase "a corrupted line fails, and so does the link that follows it" corruptionFound
        , testCase "a truncated file verifies: it is a shorter chain, not a broken one" truncation
        ]

{- | Every line of the vector is Sound.

The negative control is 'corruptionFound' — a verification that cannot fail
establishes nothing, and this one would pass just as happily on a fold that
returned 'Sound' without looking.
-}
vectorVerifies :: Assertion
vectorVerifies = do
    verdicts <- vectorVerdicts
    length verdicts @?= 4
    mapM_ expectSound verdicts
    map (chainPositionIndex . verifiedPosition) (sounds verdicts) @?= [0, 1, 2, 3]

{- | The first entry's @prev_hash@ is the genesis sentinel: 32 zero bytes.

Asserted from the outside rather than trusted to the fold: 'verify' checks the
first link against 'genesisHash' itself, so a fold that used the wrong sentinel
would agree with itself and report Sound. This reads the entry's own claim and
compares it to the value the format fixes.
-}
chainsToGenesis :: Assertion
chainsToGenesis = do
    verdicts <- vectorVerdicts
    case sounds verdicts of
        (first : _) -> (verifiedEntry first).prevHash @?= genesisHash
        [] -> assertFailure "the vector produced no sound entries"

{- | Each entry links to the digest of the line before it.

The fold already checks this, so what is added here is independence from the
fold's own arithmetic: the claimed @prev_hash@ of entry @n+1@ is compared to the
t'EventChain.Crypto.Types.LineHash' the fold reported for entry @n@ — two values
that only agree if the chain rule reads line /bytes/ (ADR-0002 §1).
-}
chainsForward :: Assertion
chainsForward = do
    verdicts <- vectorVerdicts
    let entries = sounds verdicts
        claimed = map ((.prevHash) . verifiedEntry) (drop 1 entries)
        actual = map verifiedLineHash (init entries)
    claimed @?= actual

{- | One byte changed inside a line, and the fold says so twice.

The mutation is inside @entry_id@, so the line stays valid JSON and stays a
well-formed entry — what breaks is only what the signature covers, which is the
failure this test is for. A parse error would exercise @aeson@ instead.

Two faults follow, and both are the point. Line 1's signature no longer covers
its own canonical bytes. And line 2's @prev_hash@ no longer matches, because the
digest is of line bytes: change any byte of a line and every later link is
broken. A verifier that canonicalized before hashing would report only the first
and call the chain intact.
-}
corruptionFound :: Assertion
corruptionFound = do
    aof <- vectorBytes
    let corrupted = flipByteIn 1 aof
    verdicts <- either (assertFailure . show) pure (verify corrupted)
    faultsAt verdicts 1 @?= [SignatureInvalid]
    case faultsAt verdicts 2 of
        [ChainMismatch{}] -> pure ()
        other -> assertFailure ("line 2's link should have broken; got " <> show other)
    -- Lines the corruption is not about are untouched.
    map (chainPositionIndex . verifiedPosition) (sounds verdicts) @?= [0, 3]

{- | A file cut short at a line boundary verifies.

Truncation is not corruption: an AOF is append-only, so every prefix of one is
an AOF. A reader holding the first two lines of a four-line file has a chain of
two, and a verifier that reported a fault because a later entry was missing
would be inventing a rule the format does not have — the file carries no length
and nothing commits to what comes after.
-}
truncation :: Assertion
truncation = do
    aof <- vectorBytes
    let firstTwo = LC8.unlines (take 2 (LC8.lines aof))
    verdicts <- either (assertFailure . show) pure (verify firstTwo)
    length verdicts @?= 2
    mapM_ expectSound verdicts

-- Fixtures -------------------------------------------------------------------

-- | The committed vector's bytes.
vectorBytes :: IO LBS.ByteString
vectorBytes = do
    root <- findRepoRoot
    let path = root </> "vectors" </> "v0-lifecycle.jsonl"
    exists <- doesFileExist path
    if exists
        then LBS.readFile path
        else
            assertFailure . unlines $
                [ "No vector at " <> path <> "."
                , ""
                , "It is committed rather than generated here: this package cannot build one,"
                , "because building one means the Producer, and the Producer is the thing this"
                , "file is evidence about."
                ]

-- | The vector's verdicts.
vectorVerdicts :: IO [Verdict]
vectorVerdicts = vectorBytes >>= either (assertFailure . show) pure . verify

-- | Flip one bit inside the given line's @entry_id@ text.
flipByteIn :: Int -> LBS.ByteString -> LBS.ByteString
flipByteIn n aof = LC8.unlines (zipWith bump [0 ..] (LC8.lines aof))
  where
    bump i ln
        | i /= (n :: Int) = ln
        | otherwise = LBS.fromStrict (mutate (LBS.toStrict ln))

    -- The label's first character, whatever it is: the line stays JSON and stays
    -- an entry, and only the bytes under the signature have moved.
    mutate ln
        | BS.null after = error "the fixture has no entry_id to corrupt"
        | otherwise = case BS.indexMaybe ln at of
            Nothing -> error "the fixture's entry_id has no first character"
            Just w -> BS.take at ln <> BS.singleton (w + 1) <> BS.drop (at + 1) ln
      where
        marker = "\"entry_id\":\""
        (before, after) = BS.breakSubstring marker ln
        at = BS.length before + BS.length marker

-- | The entries a run reported as Sound.
sounds :: [Verdict] -> [VerifiedEntry]
sounds verdicts = [v | Sound v <- verdicts]

-- | The faults reported at one position, or a failure if that line was Sound.
faultsAt :: [Verdict] -> Word -> [Fault]
faultsAt verdicts n =
    case [fs | Unsound pos fs <- verdicts, chainPositionIndex pos == fromIntegral n] of
        (fs : _) -> NE.toList fs
        [] -> []

-- | A verdict that is not Sound is a failure, and the verdict says which line.
expectSound :: Verdict -> Assertion
expectSound = \case
    Sound _ -> pure ()
    Malformed err -> assertFailure ("the vector has a line that is not an entry: " <> show err)
    Unsound pos faults ->
        assertFailure
            ("line " <> show (chainPositionIndex pos) <> " of the vector failed: " <> show (NE.toList faults))
    Undecided pos err ->
        assertFailure
            ("libcrypto did not answer for line " <> show (chainPositionIndex pos) <> ": " <> show err)

{- | The directory holding @cabal.project@, found by walking up.

Cabal runs a test suite from its own package directory, and the vector is a
project-level artifact. Six lines the Producer's suite also has: a test helper is
not format logic, and sharing them would need a package one of these two is not
allowed to import.
-}
findRepoRoot :: IO FilePath
findRepoRoot = getCurrentDirectory >>= go
  where
    go dir = do
        found <- doesFileExist (dir </> "cabal.project")
        if found
            then pure dir
            else
                let up = takeDirectory dir
                 in if up == dir
                        then error "No cabal.project above the working directory."
                        else go up
