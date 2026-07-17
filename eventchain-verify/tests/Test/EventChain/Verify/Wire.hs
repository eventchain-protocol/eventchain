{-# LANGUAGE OverloadedStrings #-}

{- | The codec's strictness, and the framing rules JSON Lines fixes.

Every line here is written by hand. That is not a shortcut around a generator —
it is the only honest shape for these tests. What is under test is what the
Verifier does with bytes /someone else/ wrote, and a line built by our own
encoder could never carry a duplicate member, a number where a hash belongs, or
a byte order mark. The malformed input is the fixture.
-}
module Test.EventChain.Verify.Wire (tests) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import EventChain.Crypto.Types (ShapeError (..))
import EventChain.Verify.EntryObject (EntryObject (..), Member (..))
import EventChain.Verify.Types (chainPositionIndex)
import EventChain.Verify.Wire
    ( DecodeError (..)
    , DecodedEntry
    , FramingError (..)
    , LineError (..)
    , decodeLine
    , decodedObject
    , frameFile
    )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertBool, assertFailure, testCase, (@?=))

tests :: TestTree
tests =
    testGroup
        "EventChain.Verify.Wire"
        [ testGroup
            "framing"
            [ testCase "a byte order mark is refused, as a BOM and not as bad JSON" bomRefused
            , testCase "the terminator is 0x0a and a trailing one is optional" terminator
            , testCase "0x0d before the terminator is content, not framing" crIsContent
            , testCase "an empty file has no lines and is not an error" emptyFile
            ]
        , testGroup
            "strictness"
            [ testCase "a well-formed line decodes" wellFormed
            , testCase "an unknown member is refused" unknownMember
            , testCase "a duplicate member is refused" duplicateMember
            , testCase "a non-string value is refused" nonStringValue
            , testCase "a missing member is refused" missingMember
            , testCase "padded base64 is refused" paddedBase64
            , testCase "a 31-byte hash is refused" shortHash
            , testCase "a lone surrogate escape is refused" loneSurrogate
            , testCase "a line that is not an object is refused" notAnObject
            , testCase "trailing content is refused, trailing whitespace is not" trailing
            ]
        ]

-- Framing --------------------------------------------------------------------

{- | JSON Lines requires UTF-8 "without a BOM" of the /document/, so this is a
file-level rule and the framer owns it.

Rejected for being a byte order mark rather than for being unparseable — @aeson@
would refuse it too, but "line 0 is not JSON" would send a reader hunting for a
syntax error in a line that has none.
-}
bomRefused :: Assertion
bomRefused = frameFile (LBS.fromStrict ("\xef\xbb\xbf" <> validLine <> "\n")) @?= Left FileHasBom

{- | Lines end at @0x0a@, and the last one need not.

[JSON Lines](https://jsonlines.org/) §3: "the last character in the file may be a
line separator, and it will be treated the same as if there was no line
separator present". So the empty remainder after a final terminator is not a
line — a verifier that made one out of it would report a phantom malformed entry
on every well-formed file.
-}
terminator :: Assertion
terminator = do
    framed "a\nb\n" @?= ["a", "b"]
    framed "a\nb" @?= ["a", "b"]

{- | A @0x0d@ sitting before the terminator is one of the line's content bytes.

ADR-0002 §1, and JSON Lines is what settles it: the terminator is @0x0a@, so a
line's content is every byte before it. A CRLF-terminated file is valid JSON
Lines whose lines each end in @0x0d@, and it chains to different hashes than the
LF-terminated original — the middlebox consequence, working as specified. The
framer must not look for @0x0d@ at all, and this is what says it does not.
-}
crIsContent :: Assertion
crIsContent = framed "a\r\nb\r\n" @?= ["a\r", "b\r"]

-- | A chain of zero entries is intact, vacuously.
emptyFile :: Assertion
emptyFile = framed "" @?= []

-- Strictness -----------------------------------------------------------------

-- | The control: without this, every rejection below could be a broken fixture.
wellFormed :: Assertion
wellFormed = case decodeOnly validLine of
    Left err -> assertFailure ("a well-formed line was refused: " <> show err)
    Right d -> (decodedObject d).entryId @?= "evt-001"

-- | A line saying something we cannot account for might mean something we did not read.
unknownMember :: Assertion
unknownMember = refuses (withMember "\"kind\":\"mint\"") (UnknownMember "kind")

{- | The reason the codec folds tokens instead of calling @decode@.

@Data.Aeson.Decoding.Conversion@: "the first duplicate key in objects wins". So
@decode@ would read this line as having one @prev_hash@ — chosen for us,
silently — and verify the chain against whichever it picked. The token stream
keeps both, which is what makes the duplicate fatal.
-}
duplicateMember :: Assertion
duplicateMember = refuses (withMember ("\"prev_hash\":\"" <> genesisText <> "\"")) (DuplicateMember PrevHash)

-- | Every value on an AOF line is a string (ADR-0002 §4).
nonStringValue :: Assertion
nonStringValue = refuses (replace ("\"" <> genesisText <> "\"") "42") (NonStringValue PrevHash)

-- | The format's members are required, not defaulted.
missingMember :: Assertion
missingMember = refuses (replace "\"payload_ref\":\"aof/2026-07/001\"," "") (MissingMember PayloadRef)

{- | Unpadded, and the decoder's strictness is why this package chose @base64@.

@decodeBase64UnpaddedUntyped@ validates before decoding: padding is refused, and
so are non-canonical trailing bits, so two different texts cannot decode to the
same bytes. An encoder has no invalid input to reject, which is why the
Producer's dependency on the same package buys it nothing and this one's buys
the format.
-}
paddedBase64 :: Assertion
paddedBase64 = refusesWith (replace genesisText (genesisText <> "=")) $ \case
    NotBase64Url PrevHash _ -> True
    _ -> False

-- | A hash is 32 bytes; 31 well-formed base64url bytes are not a hash.
shortHash :: Assertion
shortHash =
    refuses
        (replace genesisText "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        (MemberWrongShape PrevHash (HashWrongLength 31))

{- | @\\ud800@ with no low surrogate after it is RFC 8259-legal /syntax/ that
names no Unicode scalar value — RFC 8259 §8.2 calls the behaviour of software
receiving one "unpredictable". RFC 8785 canonicalizes strings over UTF-16 code
units, so a canonical form of the lone surrogate exists — and cannot be
represented by an implementation whose text type holds scalar values only,
which is this one and most others; a parser that substituted U+FFFD instead
would canonicalize a string the producer never wrote and verify a signature
against it. So the behaviour is pinned rather than inherited: the line is
refused outright, before anything is hashed or checked against it.
@docs/paper-amendments.md@ PA-10 carries the correction proposed upstream.
-}
loneSurrogate :: Assertion
loneSurrogate = refusesWith (replace "evt-001" "\\ud800") $ \case
    LineNotJson _ -> True
    _ -> False

-- | An AOF line is one entry, so a line that is valid JSON but not an object is not one.
notAnObject :: Assertion
notAnObject = refuses "[]" LineNotAnObject

{- | Whitespace after the object is legal JSON and legal JSON Lines; anything
else is not.

The trailing space changes what the line hashes to, which is ADR-0002 §1's
business and not the codec's. Accepting it is not laxness — rejecting it would
mean rejecting a legal file.
-}
trailing :: Assertion
trailing = do
    case decodeOnly (validLine <> "  ") of
        Left err -> assertFailure ("a legal trailing space was refused: " <> show err)
        Right _ -> pure ()
    refuses (validLine <> "{}") LineTrailingContent

-- Fixtures -------------------------------------------------------------------

{- | The vector's first line, inlined.

Inlined rather than read from @vectors/@ on purpose: these tests are about
mutations of a line, and a fixture that moved when the vector was regenerated
would make every one of them fail for a reason that has nothing to do with what
it asks.
-}
validLine :: ByteString
validLine =
    "{\"entry_id\":\"evt-001\",\"payload_hash\":\"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\",\"payload_ref\":\"aof/2026-07/001\",\"prev_hash\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"public_key\":\"A2D-1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p-2\",\"signature\":\"T_9WW8SIsZPs7rJ62LYejBikXWfPxXdHuGmaqpDwHUuY3vnxJ4AEE2793phDRW6ZE9CU0wixPegBq3lGw-YdHg\"}"

-- | The genesis sentinel as a line carries it: 32 zero bytes, base64url.
genesisText :: ByteString
genesisText = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

-- | The valid line with one more member spliced in after the opening brace.
withMember :: ByteString -> ByteString
withMember member = "{" <> member <> "," <> LBS.toStrict (LBS.drop 1 (LBS.fromStrict validLine))

-- | The valid line with the first occurrence of some bytes replaced.
replace :: ByteString -> ByteString -> ByteString
replace needle new
    | BS.null after = error ("the fixture does not contain " <> show needle)
    | otherwise = before <> new <> BS.drop (BS.length needle) after
  where
    (before, after) = BS.breakSubstring needle validLine

{- | Decode a line through the door a caller has.

'frameFile' is what mints a position, and this suite reaches 'decodeLine' the
same way anything else must: a t'EventChain.Verify.Types.ChainPosition' comes
from the framer or it does not exist. That the tests cannot fabricate one is the
type discipline holding at the package edge, not an inconvenience to work
around.
-}
decodeOnly :: ByteString -> Either DecodeError DecodedEntry
decodeOnly line = case frameFile (LBS.fromStrict line) of
    Left err -> error ("framing refused the fixture: " <> show err)
    Right [(pos, raw)] -> decodeLine pos raw
    Right lns -> error ("the fixture framed into " <> show (length lns) <> " lines, not one")

-- | The line is refused, with exactly this complaint, at the line's own position.
refuses :: ByteString -> LineError -> Assertion
refuses line expected = refusesWith line (== expected)

-- | The line is refused, with a complaint of this shape.
refusesWith :: ByteString -> (LineError -> Bool) -> Assertion
refusesWith line matches = case decodeOnly line of
    Right _ -> assertFailure ("a malformed line decoded: " <> show line)
    Left (DecodeError pos reason) -> do
        chainPositionIndex pos @?= 0
        assertBool ("wrong complaint: " <> show reason) (matches reason)

-- | The lines a file frames into.
framed :: LBS.ByteString -> [ByteString]
framed file = case frameFile file of
    Left err -> error ("framing refused a file it should not have: " <> show err)
    Right lns -> map snd lns
