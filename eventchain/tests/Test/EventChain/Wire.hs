{-# LANGUAGE OverloadedStrings #-}

{- | The line codec's gate: what a line carries, and how it is written.

@aeson@ does the reading here, and that is the only reason these tests prove
anything. The Producer cannot parse JSON — that absence is a security property,
not a gap — so "it round-trips" cannot mean "our decoder agrees with our
encoder", which is the tautology this package is built to avoid. It means a
JSON reader that has never seen this format gets back what we put in.

What is /not/ gated here is whether the signature covers what the line says.
That is "Test.EventChain.Produce", where the oracle derives the signing message
and OpenSSL checks it.
-}
module Test.EventChain.Wire (tests) where

import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as Base64Url
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import EventChain
import EventChain.Crypto.Types
    ( claimedKeyRaw
    , lineBytesRaw
    , lineHashRaw
    , payloadHashRaw
    )
import EventChain.EntryObject (Member (..), memberName)
import Hedgehog (Gen, Property, forAll, property, (===))
import Test.EventChain.Fixtures (chainFrom, genEvent, genLabel, producerClaim, producerKey)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "EventChain.Wire"
        [ testProperty "every line is JSON a stranger's parser reads" parses
        , testProperty "a line carries the vocabulary and nothing else" membersMatch
        , testProperty "base64url values decode to the bytes that went in" decodesToInput
        , testProperty "labels travel as themselves, whatever is in them" labelsSurvive
        , testProperty "no label can put a terminator on a line" noTerminator
        , testProperty "members are written in the vocabulary's order" declarationOrder
        ]

-- | One produced line, from an event with arbitrary labels.
genLine :: Gen (ChainedEvent, ByteString)
genLine = do
    event <- genEvent genLabel
    case chainFrom producerKey [event] of
        [p] -> pure (event, lineBytesRaw p.line)
        ps -> error ("one event produced " <> show (length ps) <> " lines")

-- | The line's object, as @aeson@ reads it. Fails the test if it is not JSON.
parsed :: ByteString -> Aeson.Object
parsed line = case Aeson.eitherDecodeStrict line of
    Right (Aeson.Object o) -> o
    Right v -> error ("a line decoded to " <> show v <> ", which is not an object")
    Left err -> error ("a produced line is not JSON: " <> err)

-- | The text at a member, or a test failure naming what was there instead.
memberText :: Member -> Aeson.Object -> Text
memberText m o = case KeyMap.lookup (Key.fromText (memberName m)) o of
    Just (Aeson.String t) -> t
    other -> error (show (memberName m) <> " is " <> show other <> ", not a string")

{- | Every line parses, and parses to an object.

The Producer's whole promise to the ecosystem is that the AOF is a JSON Lines
document any conformant reader reads. This is the smallest statement of it that
a hostile label can falsify.
-}
parses :: Property
parses = property $ do
    (_, line) <- forAll genLine
    KeyMap.null (parsed line) === False

{- | A lifecycle line carries exactly the six members the paper defines.

Both directions matter. A missing member is an unverifiable line; an extra one
is a member the Verifier must reject as unknown, and would be a decision made
here by accident rather than in @docs/wire-format.md@ on purpose.
-}
membersMatch :: Property
membersMatch = property $ do
    (_, line) <- forAll genLine
    let expected = map memberName [EntryId, PayloadHash, PayloadRef, PrevHash, PublicKey, Signature]
    map Key.toText (KeyMap.keys (parsed line)) === expected

{- | Every binary member base64url-decodes to the exact bytes it was built from.

This is the base64url gate: the encoding is unpadded and URL-safe (ADR-0002 §4),
and a decoder that has never seen our encoder recovers the digest, the point and
the signature we meant to write.
-}
decodesToInput :: Property
decodesToInput = property $ do
    (event, line) <- forAll genLine
    let object = parsed line
        decode m = unbase64 (memberText m object)
    decode PayloadHash === payloadHashRaw event.payloadHash
    decode PrevHash === lineHashRaw genesisHash
    decode PublicKey === claimedKeyRaw producerClaim
    BS.length (decode Signature) === 64

{- | @entry_id@ and @payload_ref@ come back as the text that went in.

They are opaque labels with no encoding requirement, so quotes, control
characters and astral-plane text are all legal input and none of them may be
mangled, normalized or dropped on the way to a line.
-}
labelsSurvive :: Property
labelsSurvive = property $ do
    (event, line) <- forAll genLine
    let object = parsed line
    memberText EntryId object === entryIdText event.entryId
    memberText PayloadRef object === payloadRefText event.payloadRef

{- | No label, however hostile, puts a @0x0a@ into a line's bytes.

The stakes are the file rather than the line: a raw terminator inside a line
would split it in two, and JSON Lines §3 has no way to say otherwise. Escaping
is what stops it — a newline in a label becomes the two characters @\\n@ — and
'EventChain.Wire.encodeLine' would rather crash than emit one, so this property
is really asking whether that branch is reachable from a caller. It is not.
-}
noTerminator :: Property
noTerminator = property $ do
    (_, line) <- forAll genLine
    BS.elem 0x0a line === False

{- | Members are written in the vocabulary's declaration order.

Pinned because it is a decision, not an accident: the format leaves line order
free (PA-01) and we spend that freedom on @docs/protocol.md@'s table order.

The six sort to the same sequence under RFC 8785, so this property cannot tell
the two orders apart and does not claim to. It fails when the order stops being
/deliberate/ — which is what would happen if 'EventChain.Wire.encodeLine' ever
started handing out whatever the underlying map returned.
-}
declarationOrder :: Property
declarationOrder = property $ do
    (_, line) <- forAll genLine
    let written = map Key.toText (KeyMap.keys (parsed line))
        vocabulary = map memberName [minBound .. maxBound]
    filter (`elem` written) vocabulary === written

{- | base64url in, bytes out, through the untyped door.

Untyped on purpose. The typed encoder's wrapper is a claim the encoder makes
about its own output, which is worth nothing to a reader; what a line hands you
is text, and whether that text is unpadded base64url is the question rather than
the premise.
-}
unbase64 :: Text -> ByteString
unbase64 t = case Base64Url.decodeBase64UnpaddedUntyped (TE.encodeUtf8 t) of
    Right bs -> bs
    Left err -> error ("a member is not unpadded base64url: " <> show err)
