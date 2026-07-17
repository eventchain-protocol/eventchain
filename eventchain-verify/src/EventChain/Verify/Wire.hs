{- | The JSON Lines codec, decode direction: file bytes to lines, and a line to
the Entry it claims.

Two jobs, and the boundary between them is what JSON Lines draws. /Framing/ is a
file-level question — where a line ends, whether the file may open with a byte
order mark — and it builds no JSON value: splitting on @0x0a@ is not parsing.
/Decoding/ is a line-level question, and it is where the only JSON parser in the
system runs.

This module is also the only place a t'DecodedEntry' is made, which is the
exact-bytes invariant's home. The chain commits to line bytes (ADR-0002 §1), so
verification must hash the bytes an Entry was actually read from; a pair whose
halves disagree would let a line say one thing while the parsed view says
another. Nothing can take a pair apart and put a different one back together,
and nothing outside this module can build one — which is why the parse cannot be
lifted out into a caller. A caller handing us a parsed structure would leave
nothing to hash; one handing us both bytes and a structure would supply an
unverified pairing, which is the forgery the type exists to refuse.

/Strict on purpose./ Unknown member, duplicate member, non-string value, missing
member, bad base64url, wrong length: all hard errors carrying the position of
the line that caused them. A Verifier that repaired or ignored any of these
would be verifying a line other than the one in the file.
-}
module EventChain.Verify.Wire
    ( -- * The pairing
      DecodedEntry
    , decodedLine
    , decodedObject
    , decodedEntry

      -- * Framing
    , FramingError (..)
    , frameFile

      -- * Decoding
    , LineError (..)
    , DecodeError (..)
    , decodeLine
    ) where

import Data.Aeson.Decoding.ByteString (bsToTokens)
import Data.Aeson.Decoding.Tokens (Lit (..), TkRecord (..), Tokens (..))
import Data.Aeson.Key qualified as Key
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as Base64Url
import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import EventChain.Crypto.Types
    ( LineBytes
    , ShapeError
    , claimedKey
    , lineBytes
    , lineHashFromBytes
    , payloadHashFromBytes
    , sigFromRaw
    )
import EventChain.Verify.EntryObject (EntryObject (..), Member (..), memberFromName)
import EventChain.Verify.Types.Internal.Entry
    ( ChainPosition
    , Entry (..)
    , EntryKind (..)
    , ProducedProof (..)
    , chainPosition
    , entryId
    , payloadRef
    )

{- | A line's bytes, what it said, and what that means.

Three views of one line, and each has a consumer that must not be handed a
different one. The bytes are what the chain covers. The object is what the line
said, which is what "EventChain.Verify.Canonical" derives the signing message
from — /not/ a re-encoding of the Entry, because the message must be a function
of the line rather than of our reading of it. The Entry is that reading: base64
resolved, lengths checked, ready for the fold.

Opaque, and the accessors are the only way in. Keeping the object alongside the
Entry is not redundancy: re-deriving it would mean re-encoding a t'LineHash'
back to base64url with a second encoder, and two encoders that quietly disagree
is the whole failure this package's architecture is built to make impossible.
-}
data DecodedEntry = DecodedEntry
    { line :: LineBytes
    , object :: EntryObject
    , entry :: Entry
    }
    deriving stock (Eq, Show)

-- | The bytes this Entry was read from — what the chain commits to.
decodedLine :: DecodedEntry -> LineBytes
decodedLine d = d.line

-- | What the line said: members and their text, before any of it meant anything.
decodedObject :: DecodedEntry -> EntryObject
decodedObject d = d.object

-- | The Entry the line claims.
decodedEntry :: DecodedEntry -> Entry
decodedEntry d = d.entry

{- | The only way framing can fail.

One constructor, because JSON Lines leaves framing almost nothing to get wrong:
the terminator is fixed, a line's content is what precedes it, and everything
else about a line is the decoder's problem.
-}
data FramingError
    = -- | The file opens with a UTF-8 byte order mark, which JSON Lines forbids.
      FileHasBom
    deriving stock (Eq, Show)

{- | Split a file into its lines, per [JSON Lines](https://jsonlines.org/) §3.

The terminator is @0x0a@ and a line's content is every byte before it, so a
@0x0d@ sitting there is content and will be hashed with the rest — a
CRLF-terminated file is valid JSON Lines whose lines each end in @0x0d@, and it
chains to different hashes than the LF-terminated original. That is ADR-0002's
middlebox consequence working as specified, not a case to normalize away. This
function does not look for @0x0d@ at all, which is the point.

A trailing terminator on the last line is optional ("the last character in the
file may be a line separator, and it will be treated the same as if there was no
line separator present"), so the empty remainder after a final @0x0a@ is not a
line. An empty file has no lines and is not an error: a chain of zero entries is
intact, vacuously.

The byte order mark is checked here rather than in
'EventChain.Crypto.Types.lineBytes' because it is a /file/-level rule — JSON
Lines requires "UTF-8 encoded ... without a BOM" of the document — and a
function handed one line cannot know whether it is the first. Note that a BOM is
not rejected for being unparseable: @aeson@ would refuse it anyway. It is
rejected for being a BOM, so the error says so.

Returns lines lazily against a lazy file, so a fold over a large AOF holds one
line rather than all of them. The 'Either' resolves after three bytes.
-}
frameFile :: LBS.ByteString -> Either FramingError [(ChainPosition, ByteString)]
frameFile file
    | LBS.isPrefixOf bom file = Left FileHasBom
    | otherwise = Right (zip (map chainPosition [0 ..]) (split file))
  where
    bom = LBS.pack [0xef, 0xbb, 0xbf]

    split bs
        | LBS.null bs = []
        | otherwise = case LBS.elemIndex 0x0a bs of
            Nothing -> [LBS.toStrict bs]
            Just i -> LBS.toStrict (LBS.take i bs) : split (LBS.drop (i + 1) bs)

{- | Every way one line can fail to be an Entry.

Data, not text: rendering belongs at the edge. Each constructor names the member
it is about wherever there is one, because "this line is malformed" sends a
reader back to the bytes with nothing to look for.
-}
data LineError
    = -- | The bytes are not an AOF line's content at all: empty, or not UTF-8.
      LineNotWellFormed ShapeError
    | -- | The line is not JSON. Carries @aeson@'s complaint.
      LineNotJson String
    | -- | The line is JSON, but not an object. An AOF line is one entry.
      LineNotAnObject
    | -- | Bytes follow the object that are not whitespace.
      LineTrailingContent
    | -- | A member this Verifier has no account of. Carries the name as written.
      UnknownMember Text
    | {- | A member appears twice. Fatal: the line means two things, and a
      signature would cover one of them arbitrarily.
      -}
      DuplicateMember Member
    | -- | A member's value is not a string. Every value on an AOF line is one.
      NonStringValue Member
    | -- | The line omits a member the format requires.
      MissingMember Member
    | -- | A member's text is not unpadded base64url. Carries the decoder's complaint.
      NotBase64Url Member Text
    | {- | A member's bytes are the wrong shape — a hash that is not 32 bytes, a
      key that is not a compressed point.
      -}
      MemberWrongShape Member ShapeError
    deriving stock (Eq, Show)

-- | A line's failure, and which line it was.
data DecodeError = DecodeError
    { position :: ChainPosition
    , reason :: LineError
    }
    deriving stock (Eq, Show)

{- | Read one line: its bytes, what it says, and what it claims.

The parse runs over @aeson@'s token stream rather than @decode@, and that is a
correctness decision rather than a performance one.
@Data.Aeson.Decoding.Conversion@ documents @decode@'s rule — "the first
duplicate key in objects wins" — so a line carrying two @prev_hash@ members
would verify against one of them arbitrarily, which is precisely the ambiguity
this format must reject. The token stream preserves both, so the duplicate is
detectable, and 'DuplicateMember' is what it becomes. That the fold is also
/less/ work than @decode@ — which is this same tokenizer plus a @KeyMap@ build
we would immediately discard — is a bonus and not the reason.
-}
decodeLine :: ChainPosition -> ByteString -> Either DecodeError DecodedEntry
decodeLine pos raw = case build of
    Left err -> Left (DecodeError pos err)
    Right d -> Right d
  where
    build = do
        ln <- first LineNotWellFormed (lineBytes raw)
        members <- foldTokens (bsToTokens raw)
        object <- completeObject members
        e <- readEntry object
        pure DecodedEntry{line = ln, object = object, entry = e}

{- | Fold the token stream straight into the member vocabulary. No @Value@ is
ever built.

A top-level literal, number or array is 'LineNotAnObject' rather than a parse
error: those lines are valid JSON and simply are not entries, and saying so is
more use to whoever wrote them.
-}
foldTokens :: Tokens ByteString String -> Either LineError (Map Member Text)
foldTokens = \case
    TkRecordOpen record -> pairs Map.empty record
    TkErr err -> Left (LineNotJson err)
    TkLit _ rest -> notObject rest
    TkText _ rest -> notObject rest
    TkNumber _ rest -> notObject rest
    TkArrayOpen _ -> Left LineNotAnObject
  where
    -- The value parsed, so the line is JSON; it is the wrong kind of JSON. A
    -- trailing-content complaint would be a lie about which problem it has.
    notObject _ = Left LineNotAnObject

    pairs acc = \case
        TkPair key value -> do
            member <- known (Key.toText key)
            (text, rest) <- stringValue member value
            acc' <- insertOnce member text acc
            pairs acc' rest
        TkRecordEnd rest -> trailing rest >> pure acc
        TkRecordErr err -> Left (LineNotJson err)

    known name = maybe (Left (UnknownMember name)) Right (memberFromName name)

    insertOnce member text acc
        | Map.member member acc = Left (DuplicateMember member)
        | otherwise = Right (Map.insert member text acc)

{- | A member's value must be a string, and the rest of the record follows it.

Every value on an AOF line is a string: @docs/protocol.md@'s fields are an
identifier and five base64url quantities, and ADR-0002 §4 puts every binary
field in base64url so a line stays plain text. A number where a hash belongs is
a malformed line, not a shape to coerce.
-}
stringValue :: Member -> Tokens (TkRecord ByteString String) String -> Either LineError (Text, TkRecord ByteString String)
stringValue member = \case
    TkText text rest -> Right (text, rest)
    TkErr err -> Left (LineNotJson err)
    TkLit LitNull _ -> wrong
    TkLit LitTrue _ -> wrong
    TkLit LitFalse _ -> wrong
    TkNumber _ _ -> wrong
    TkArrayOpen _ -> wrong
    TkRecordOpen _ -> wrong
  where
    wrong = Left (NonStringValue member)

{- | Whatever follows the object must be whitespace and nothing else.

Whitespace is accepted rather than rejected because JSON allows it around a
value and JSON Lines does not take it away: a line with a trailing space is a
legal line. It hashes differently from the same line without one, which is
ADR-0002 §1 and not this function's business.
-}
trailing :: ByteString -> Either LineError ()
trailing rest
    | BS.all isJsonSpace rest = Right ()
    | otherwise = Left LineTrailingContent
  where
    isJsonSpace w = w == 0x20 || w == 0x09 || w == 0x0a || w == 0x0d

{- | Every member present, or the first one that is not.

Ordered by the vocabulary so the complaint about a line missing several is
stable rather than dependent on a 'Map''s internals.
-}
completeObject :: Map Member Text -> Either LineError EntryObject
completeObject members = do
    entryIdText <- need EntryId
    payloadHashText <- need PayloadHash
    payloadRefText <- need PayloadRef
    prevHashText <- need PrevHash
    publicKeyText <- need PublicKey
    signatureText <- need Signature
    pure
        EntryObject
            { entryId = entryIdText
            , payloadHash = payloadHashText
            , payloadRef = payloadRefText
            , prevHash = prevHashText
            , publicKey = publicKeyText
            , signature = signatureText
            }
  where
    need m = maybe (Left (MissingMember m)) Right (Map.lookup m members)

{- | What the line's text means: base64url resolved, lengths and encodings
checked.

Everything built here is a /claim/. A t'LineHash' from this function is 32
well-formed bytes that the line asserts are its predecessor's digest; whether
they are is "EventChain.Verify"'s question and cannot be settled by
construction. That 'EventChain.Crypto.Types.lineHashFromBytes' accepts any 32
bytes is the claim tier working as designed — the chain rule is enforced one
tier up, where "EventChain.Crypto" is the only thing that can compute a digest
and takes 'EventChain.Crypto.Types.LineBytes' to do it.
-}
readEntry :: EntryObject -> Either LineError Entry
readEntry o = do
    prev <- member PrevHash lineHashFromBytes o.prevHash
    payload <- member PayloadHash payloadHashFromBytes o.payloadHash
    key <- member PublicKey claimedKey o.publicKey
    sig <- member Signature sigFromRaw o.signature
    pure
        Entry
            { entryId = entryId o.entryId
            , payloadHash = payload
            , payloadRef = payloadRef o.payloadRef
            , prevHash = prev
            , producedProof = ProducedProof{publicKey = key, signature = sig}
            , -- Every v0 line is a lifecycle event. `kind` is an unknown member
              -- until M4 adds it, so a Mint does not decode here rather than
              -- decoding as the wrong thing.
              kind = LifecycleEntry
            }
  where
    member :: Member -> (ByteString -> Either ShapeError a) -> Text -> Either LineError a
    member m f text = first (MemberWrongShape m) . f =<< unbase64 m text

{- | A member's text as the bytes it encodes.

Unpadded base64url, and the decoder's strictness is why this package chose
@base64@: @decodeBase64UnpaddedUntyped@ validates before decoding and rejects
padding as well as non-canonical trailing bits, so two different texts cannot
decode to the same bytes. That matters here and nowhere else — an encoder has
no invalid input to reject, which is why @eventchain@'s dependency on the same
package buys it nothing.

Through the untyped door on purpose. The typed API's wrapper is a claim an
/encoder/ makes about its own output; what a line hands us is text someone else
wrote, and whether it is unpadded base64url is the question rather than the
premise.
-}
unbase64 :: Member -> Text -> Either LineError ByteString
unbase64 m text = first (NotBase64Url m) (Base64Url.decodeBase64UnpaddedUntyped (TE.encodeUtf8 text))
