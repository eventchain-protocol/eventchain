{-# LANGUAGE OverloadedStrings #-}

{- | M4's gate: the committed Mint vectors, adjudicated blind.

Each file under @vectors/mint/@ is a two-line AOF a fabricator this package
has never seen built — a lifecycle target, then a Mint exercising one rule
from ADR-0007's list — and each case here states the verdict the rules
require. The wall holds as it did at M3: nothing here can name the
fabricator, so the expected verdicts are re-derived from ADR-0006 and
ADR-0007, and agreement is evidence about the format.

The sound case is the control that makes the ten rejections mean something,
and the rejections are the control that makes the sound case mean something:
a Verifier that waved every envelope through would pass @sound.jsonl@, and
one that rejected every envelope would pass the other ten.
-}
module Test.EventChain.Verify.Mint (tests) where

import Data.ByteString.Lazy qualified as LBS
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Map.Strict qualified as Map
import EventChain.Verify
    ( Fault (..)
    , Verdict (..)
    , verifiedPosition
    , verify
    )
import EventChain.Verify.EntryObject (Member (..))
import EventChain.Verify.Minted (MintedReport (..), OrphanMint (..), mintedStatus)
import EventChain.Verify.Types (chainPositionIndex)
import EventChain.Verify.WebAuthn (EnvelopeFault (..))
import EventChain.Verify.Wire (DecodeError (..), LineError (..))
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.EventChain.Verify.Fold (findRepoRoot)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertBool, assertFailure, testCase, (@?=))

tests :: TestTree
tests =
    testGroup
        "EventChain.Verify.Mint"
        [ testCase "sound.jsonl: both lines Sound, the target minted by its Mint" soundCase
        , testCase "up-unset.jsonl: rejected, user presence unset" (rejectedWith "up-unset.jsonl" (== AttestationFault UserPresenceUnset))
        , testCase "bs-without-be.jsonl: rejected, backup state inconsistent" (rejectedWith "bs-without-be.jsonl" (== AttestationFault BackupStateInconsistent))
        , testCase "wrong-challenge.jsonl: rejected, challenge does not name the target" (rejectedWith "wrong-challenge.jsonl" challengeMismatch)
        , testCase "tampered-authdata.jsonl: rejected, assertion invalid" (rejectedWith "tampered-authdata.jsonl" (== AttestationFault AssertionInvalid))
        , testCase "tampered-clientdata.jsonl: rejected, assertion invalid" (rejectedWith "tampered-clientdata.jsonl" (== AttestationFault AssertionInvalid))
        , testCase "duplicate-clientdata-member.jsonl: rejected, an ambiguous read" (rejectedWith "duplicate-clientdata-member.jsonl" duplicateChallenge)
        , testCase "orphan.jsonl: Sound, and reported an orphan by the join" orphanCase
        , testCase "mismatched-target.jsonl: rejected, envelope bound elsewhere" (rejectedWith "mismatched-target.jsonl" challengeMismatch)
        , testCase "missing-v.jsonl: malformed, kind outside the base vocabulary" (malformedWith "missing-v.jsonl" (MemberOutsideRevision Kind))
        , testCase "unknown-v.jsonl: malformed, a revision nobody here can read" (malformedWith "unknown-v.jsonl" (UnknownRevision "2"))
        , testCase "cross-soft-webauthn.jsonl: a foreign authenticator's envelope is Sound" crossCase
        ]
  where
    challengeMismatch = \case
        AttestationFault (ChallengeMismatch _ _) -> True
        _ -> False

    duplicateChallenge = \case
        AttestationFault (ClientDataDuplicate name) -> name == "challenge"
        _ -> False

{- | The control: a sound Mint is Sound, and the join credits its target.

Also the one place minted status is asserted positively — an Entry attested
by position 1, at position 0, found by hash and not by adjacency.
-}
soundCase :: Assertion
soundCase = do
    verdicts <- adjudicate "sound.jsonl"
    case verdicts of
        [Sound _, Sound _] -> pure ()
        other -> assertFailure ("expected two Sound lines, got " <> show other)
    let report = mintedStatus verdicts
    report.orphans @?= []
    case Map.toList report.minted of
        [(targetPos, mintPos :| [])] -> do
            chainPositionIndex targetPos @?= 0
            chainPositionIndex mintPos @?= 1
        other -> assertFailure ("expected one minted target, got " <> show other)

{- | An orphan is not a fault: the envelope is sound and the fold says so.
What the file fails to establish is the join's finding, and the claimed hash
travels with it so a holder of more files knows what to look for.
-}
orphanCase :: Assertion
orphanCase = do
    verdicts <- adjudicate "orphan.jsonl"
    case verdicts of
        [Sound _, Sound mint] -> do
            let report = mintedStatus verdicts
            report.minted @?= Map.empty
            case report.orphans of
                [orphan] -> chainPositionIndex orphan.position @?= chainPositionIndex (verifiedPosition mint)
                other -> assertFailure ("expected one orphan, got " <> show other)
        other -> assertFailure ("expected two Sound lines, got " <> show other)

{- | ADR-0007's cross-ecosystem claim, landing: the envelope in this vector
was produced by soft-webauthn's software authenticator — python, the
@cryptography@ library, an implementation this Verifier's authors never read —
and the checks hand-written here from §6.1 and §7.2 find it Sound and credit
its target.

Two readings of the WebAuthn signing construction agreeing across languages
is the same kind of evidence the golden vectors carry across the ADR-0005
wall, extended past the ecosystem's edge.
-}
crossCase :: Assertion
crossCase = do
    verdicts <- adjudicate "cross-soft-webauthn.jsonl"
    case verdicts of
        [Sound _, Sound _] -> do
            let report = mintedStatus verdicts
            report.orphans @?= []
            Map.size report.minted @?= 1
        other -> assertFailure ("expected two Sound lines, got " <> show other)

{- | The shape every envelope rejection shares: the target stands, the Mint is
Unsound at position 1, and among its faults is the one the case fabricated.

Membership rather than equality on purpose: some fabrications trip one rule,
and pinning "exactly one fault" would make every case brittle against a
second finding the rules are entitled to report.
-}
rejectedWith :: FilePath -> (Fault -> Bool) -> Assertion
rejectedWith name matches = do
    verdicts <- adjudicate name
    case verdicts of
        [Sound _, Unsound pos faults] -> do
            chainPositionIndex pos @?= 1
            assertBool
                ("no matching fault among " <> show faults)
                (any matches faults)
        other -> assertFailure ("expected Sound then Unsound, got " <> show other)

{- | The decode-level cases: the fold halts, and the last verdict names the
vocabulary rule the line broke, at the line's own position.
-}
malformedWith :: FilePath -> LineError -> Assertion
malformedWith name expected = do
    verdicts <- adjudicate name
    case verdicts of
        [Sound _, Malformed (DecodeError pos reason)] -> do
            chainPositionIndex pos @?= 1
            reason @?= expected
        other -> assertFailure ("expected Sound then Malformed, got " <> show other)

-- | Read a committed Mint vector and fold it.
adjudicate :: FilePath -> IO [Verdict]
adjudicate name = do
    root <- findRepoRoot
    let path = root </> "vectors" </> "mint" </> name
    exists <- doesFileExist path
    if not exists
        then assertFailure ("No vector at " <> path <> ". The fabricator's suite commits these; this one only reads them.")
        else do
            file <- LBS.readFile path
            either (assertFailure . show) pure (verify file)
