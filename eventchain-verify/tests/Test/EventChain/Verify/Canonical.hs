{-# LANGUAGE OverloadedStrings #-}

{- | The Verifier's RFC 8785 implementation, graded by one that shares no code
with it.

@Data.Aeson.RFC8785@ is the oracle for the same reason it is the Producer's:
it was written by someone else, from the RFC, and agreement between two
independent readings of a specification is evidence where a round-trip through
our own code is not. The library may never import it
(@gates:no-jcs-oracle-import@) — the grader is not the graded — and a test is
where a grader belongs.

Note what this does /not/ establish. That the Verifier's canonicalizer agrees
with the Producer's is a different claim, and no test in either package can make
it: neither can name the other. The vector is what carries it, and
"Test.EventChain.Verify.Fold" is where it is settled — a signature the Producer
made over its canonical bytes verifies here only if both readings of RFC 8785
produced the same bytes.

The member /sort/ became checkable at M4 and the generator spends the Mint
members on it. Before them it could not be: the six sort into their own
declaration order, so a canonicalizer that never sorted at all would have
agreed with the oracle on every object it could be handed. @kind@ is the first
name that distinguishes the orders — RFC 8785 puts it second where the
declaration order puts it seventh — so an object carrying the Mint group only
canonicalizes to the oracle's bytes if the sort ran. M5's hand-written
non-canonical-order vector still checks the same point from outside.
-}
module Test.EventChain.Verify.Canonical (tests) where

import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Aeson.RFC8785 (encodeCanonical)
import Data.ByteString.Lazy qualified as LBS
import Data.Text (Text)
import EventChain.Verify.Canonical (canonicalBytesRaw, canonicalize)
import EventChain.Verify.EntryObject (EntryObject (..), Member (..), MintMembers (..), entryObjectMembers, memberName)
import Hedgehog (Gen, Property, forAll, property, withTests, (===))
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, (@?=))
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "EventChain.Verify.Canonical"
        [ testProperty "matches the oracle, signature dropped and names sorted" matchesOracle
        , testCase "escapes \\b and \\f as the RFC's table does, not as aeson does" rfcEscapes
        ]

{- | The oracle agrees with us on any object we can hand it.

The oracle derives the expected bytes from an @aeson@ 'Aeson.Object' built out
of the same members with @signature@ removed — so what is compared is two
canonicalizations of one object, and nothing of ours contributes to the
expectation.
-}
matchesOracle :: Property
matchesOracle = property $ do
    object <- forAll genObject
    let ours = canonicalBytesRaw (canonicalize object)
        theirs = LBS.toStrict (encodeCanonical (Aeson.Object (oracleObject object)))
    ours === theirs

{- | The object as the oracle sees it: every member but @signature@.

Dropping it here rather than asking the oracle to is the honest comparison —
"remove the signature member" is ADR-0002 §2's rule and ours to get right, and a
test that let the oracle do it would be grading the oracle.
-}
oracleObject :: EntryObject -> Aeson.Object
oracleObject o =
    KeyMap.fromList
        [ (Key.fromText (memberName m), Aeson.String v)
        | (m, v) <- entryObjectMembers o
        , m /= Signature
        ]

{- | Objects the oracle can be asked about without disagreeing for a reason that
is not ours.

@aeson@'s canonicalizer emits @\\u0008@ and @\\u000c@ where RFC 8785 §3.2.2.2
requires @\\b@ and @\\f@. We follow the RFC, so text carrying either would have
the oracle derive different bytes and this property would fail on correct code —
it would be measuring the oracle's known defect. 'rfcEscapes' pins those two
against the RFC's own table instead, which is the only honest way to grade a
point the oracle is wrong about.

Everything else hostile stays in and belongs in: a line's members are text
someone else wrote, and the escaping that reaches the canonicalizer is exactly
what is under test.
-}
genObject :: Gen EntryObject
genObject = do
    entryIdText <- genText
    payloadHashText <- genText
    payloadRefText <- genText
    prevHashText <- genText
    publicKeyText <- genText
    signatureText <- genText
    vLabel <- Gen.maybe genText
    mintGroup <-
        Gen.maybe
            ( MintMembers
                <$> genText
                <*> genText
                <*> genText
                <*> genText
                <*> genText
                <*> genText
            )
    pure
        EntryObject
            { entryId = entryIdText
            , payloadHash = payloadHashText
            , payloadRef = payloadRefText
            , prevHash = prevHashText
            , publicKey = publicKeyText
            , signature = signatureText
            , v = vLabel
            , mint = mintGroup
            }

genText :: Gen Text
genText = Gen.text (Range.linear 0 24) (Gen.filter oracleSafe genChar)
  where
    oracleSafe c = c /= '\b' && c /= '\f'

    genChar =
        Gen.frequency
            [ (5, Gen.unicode)
            , (2, Gen.element ['"', '\\', '/', ' ', '\t', '\n', '\r'])
            , (1, Gen.enum '\x00' '\x1f')
            ]

{- | The two escapes the oracle is wrong about, against RFC 8785's table.

The RFC's §3.2.2.2 requires the two-character forms. Both encodings are valid
JSON and they are different /bytes/, which is the only thing a signature has an
opinion about: a producer following the RFC and a verifier following @aeson@
would derive different messages and every line carrying a backspace would fail
to attribute.
-}
rfcEscapes :: IO ()
rfcEscapes =
    canonicalOf blank{entryId = "\b\f"}
        @?= "{\"entry_id\":\"\\b\\f\",\"payload_hash\":\"\",\"payload_ref\":\"\",\"prev_hash\":\"\",\"public_key\":\"\"}"

-- | An object of empty members, for tests about one member at a time.
blank :: EntryObject
blank =
    EntryObject
        { entryId = ""
        , payloadHash = ""
        , payloadRef = ""
        , prevHash = ""
        , publicKey = ""
        , signature = ""
        , v = Nothing
        , mint = Nothing
        }

-- | Ours, as bytes.
canonicalOf :: EntryObject -> LBS.ByteString
canonicalOf = LBS.fromStrict . canonicalBytesRaw . canonicalize
