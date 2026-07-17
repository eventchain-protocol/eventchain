{-# LANGUAGE OverloadedStrings #-}

{- | The JCS conformance gate for "EventChain.Canonical".

Signatures are only as portable as the bytes they cover, so "our
canonicalizer agrees with itself" proves nothing. The gate is @aeson@'s
independent RFC 8785 implementation: it shares no code with ours, so
agreement across generated objects is evidence rather than a tautology.

Two things the oracle cannot settle, and what stands in for it:

* @aeson@ serializes U+0008 and U+000C as @\\u0008@ and @\\u000c@; RFC 8785
  §3.2.2.2 requires @\\b@ and @\\f@. The oracle is wrong there, so generated
  values exclude those two code points and 'escapes' pins them against the
  RFC's own table instead.
* 'Member' names are ASCII, so the RFC's UTF-16 ordering examples cannot be
  expressed here. What the oracle checks is the ordering of the names we
  actually emit — the only ordering claim this library makes.
-}
module Test.EventChain.Canonical (tests) where

import Data.Aeson ((.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.RFC8785 (encodeCanonical)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy qualified as LBS
import Data.Text (Text)
import EventChain.Canonical (canonicalBytesRaw, signingMessage)
import EventChain.EntryObject
    ( Member (..)
    , MemberValue
    , entryObject
    , memberName
    , memberValue
    , memberValueText
    )
import Hedgehog (Gen, Property, forAll, property, withTests, (===))
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "EventChain.Canonical"
        [ testProperty "matches the RFC 8785 oracle" matchesOracle
        , testProperty "the signature member is not signed over" excludesSignature
        , testProperty "escapes per RFC 8785 3.2.2.2" escapes
        , testProperty "non-ASCII travels as literal UTF-8" literalUtf8
        ]

-- | Canonicalize, or fail the test with whatever the object was rejected for.
canonical :: [(Member, MemberValue)] -> ByteString
canonical = either (error . show) (canonicalBytesRaw . signingMessage) . entryObject

{- | The same members through @aeson@'s canonicalizer.

Independent of ours all the way down: its own object model, its own sort,
its own escaping.
-}
oracle :: [(Member, MemberValue)] -> ByteString
oracle ms =
    LBS.toStrict . encodeCanonical . Aeson.object $
        [Key.fromText (memberName m) .= memberValueText v | (m, v) <- ms]

{- | An arbitrary subset of the vocabulary, in arbitrary order, with
arbitrary string values. Shuffled because input order must not survive
canonicalization.
-}
genMembers :: [Member] -> Gen [(Member, MemberValue)]
genMembers vocabulary = do
    ms <- Gen.shuffle =<< Gen.subsequence vocabulary
    traverse (\m -> (,) m . memberValue <$> genValue) ms

{- | Text weighted toward what breaks canonicalizers: the escapes, the C0
range, and the astral planes — @entry_id@ and @payload_ref@ are
producer-chosen, so any of it can reach the signing message.

U+0008 and U+000C are excluded: the oracle is non-conformant there (see the
module header), and 'escapes' covers them directly.
-}
genValue :: Gen Text
genValue = Gen.text (Range.linear 0 24) (Gen.filter oracleAgrees genChar)
  where
    oracleAgrees c = c /= '\b' && c /= '\f'

    genChar =
        Gen.frequency
            [ (5, Gen.unicode)
            , (2, Gen.element ['"', '\\', '/', ' ', '\t', '\n', '\r'])
            , (1, Gen.enum '\x00' '\x1f')
            ]

-- | Byte-identical to the oracle across the vocabulary and arbitrary values.
matchesOracle :: Property
matchesOracle = property $ do
    ms <- forAll (genMembers (filter (/= Signature) [minBound .. maxBound]))
    canonical ms === oracle ms

{- | A Produced Proof cannot sign the bytes it is: whatever else the object
carries, the signing message is the object without @signature@.
-}
excludesSignature :: Property
excludesSignature = property $ do
    ms <- forAll (genMembers (filter (/= Signature) [minBound .. maxBound]))
    sig <- forAll (memberValue <$> genValue)
    signed <- forAll (Gen.shuffle ((Signature, sig) : ms))
    canonical signed === oracle ms

{- | The RFC's escape table, verbatim: the five control characters with a
JSON shorthand take it, the rest of C0 takes @\\u00hh@ with lowercase hex,
and above U+001F only @"@ and @\\@ are escaped — not @/@, and not DEL.

This is where @\\b@ and @\\f@ are pinned, since the oracle emits @\\u0008@
and @\\u000c@ for them.
-}
escapes :: Property
escapes = withTests 1 . property $ do
    canonical [(EntryId, memberValue "\b\t\n\f\r\"\\")]
        === "{\"entry_id\":\"\\b\\t\\n\\f\\r\\\"\\\\\"}"
    canonical [(EntryId, memberValue "\x00\x01\x1f")]
        === "{\"entry_id\":\"\\u0000\\u0001\\u001f\"}"
    canonical [(EntryId, memberValue "/\x7f")]
        === "{\"entry_id\":\"/\x7f\"}"

{- | Anything above U+001F that is not @"@ or @\\@ is emitted as the UTF-8 it
already is — no @\\u@ escapes, no surrogate pairs, including astral code
points.
-}
literalUtf8 :: Property
literalUtf8 = withTests 1 . property $ do
    canonical [(EntryId, memberValue "é€𝄞")]
        === "{\"entry_id\":\"\xc3\xa9\xe2\x82\xac\xf0\x9d\x84\x9e\"}"
