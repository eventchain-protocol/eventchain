{-# LANGUAGE OverloadedStrings #-}

{- | The signing message: an entry object minus its @signature@ member,
serialized per RFC 8785 (JSON Canonicalization Scheme).

A Produced Proof signs the Entry it travels in, so the signed bytes cannot
include the signature. ADR-0002 fixes what remains: the entry with its
@signature@ member removed, re-serialized per RFC 8785 — members sorted,
minified, no whitespace. A producer's field order on the line therefore
stays free without weakening the chain rule, which covers
t'EventChain.Crypto.Types.LineBytes' exactly as written.

Canonicalization exists /only/ here. Producer and verifier must derive the
same bytes from the same Entry or every signature drifts apart, so the
type t'CanonicalBytes' is defined in this module with its constructor
unexported: holding one is proof this module made it, and the compiler is
what says so rather than a comment asking nicely.

== The subset

RFC 8785's two hard parts are number serialization (ECMA-262
@NumberToString@) and UTF-16 member ordering. An "EventChain.EntryObject"
has neither: every value is a string, and every 'Member' name is ASCII, so
'Data.List.sortOn' over the names /is/ UTF-16 order. Both of those are
properties of the input type rather than promises this module keeps — if
'Member' ever admits a non-ASCII name, the sort below is wrong and needs
UTF-16 code units, as @aeson@'s canonicalizer does for arbitrary keys.

What is left is escaping and a sort, which is why this is an encoder rather
than a dependency.

== Divergence from @Data.Aeson.RFC8785@

The conformance gate compares against @aeson@'s canonicalizer, which
serializes U+0008 and U+000C as @\\u0008@ and @\\u000c@. RFC 8785 §3.2.2.2
requires @\\b@ and @\\f@. We follow the RFC; the tests pin those two code
points against the RFC's table rather than against the oracle.
-}
module EventChain.Canonical
    ( CanonicalBytes
    , canonicalBytesRaw
    , signingMessage
    ) where

import Data.ByteString (ByteString)
import Data.ByteString.Builder qualified as BB
import Data.ByteString.Lazy qualified as LBS
import Data.Char (ord)
import Data.List (sortOn)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import EventChain.EntryObject
    ( EntryObject
    , Member (Signature)
    , MemberValue
    , entryObjectMembers
    , memberName
    , memberValueText
    )

{- | The RFC 8785 serialization of an entry minus its @signature@ member:
the exact message a Produced Proof signs.

Canonicalization lives only inside signing, so a producer's field order stays
free without weakening the chain rule that covers
t'EventChain.Crypto.Types.LineBytes'.

The constructor is unexported and 'signingMessage' is the only thing in
scope to build one, so a value of this type cannot be anything but what this
module produced. That matters for the verifier: fabricating these bytes is
checking a signature against a message of your choosing.
-}
newtype CanonicalBytes = CanonicalBytes ByteString
    deriving stock (Eq, Show)

-- | The signing message's bytes, for the crypto edge.
canonicalBytesRaw :: CanonicalBytes -> ByteString
canonicalBytesRaw (CanonicalBytes bs) = bs

{- | The bytes a Produced Proof signs — the paper's @entry.data()@.

The paper names @entry.data()@ in its @VerifyAttribution@ pseudocode and
defines it nowhere; @docs/paper-amendments.md@ PA-01 carries the definition
this function implements, for submission upstream. Every member except
@signature@ is covered, including any this vocabulary gains later: removal is
by exclusion, so a new member is signed by default rather than by remembering
to add it.

That @prev_hash@ is among them is load-bearing, not incidental. The producer
signs its own chain position, so no Hub can relocate an entry or move it to
another chain without invalidating a signature it cannot forge — ordering
rests on the producer's key rather than on the Hub behaving. Filtering more
than @Signature@ here would hand that guarantee back to the Hub silently, and
every test would still pass (ADR-0002 §2, PA-08).

Total in both directions of use. A producer canonicalizes an object with no
signature in it yet; a verifier canonicalizes one read off a line, where the
signature is present and must come out. Dropping a member that isn't there
is not an error — it is the producer's case.

Uniform across Kinds. A Mint's WebAuthn envelope (@assertion_sig@,
@authenticator_data@, @client_data_json@, @attester_key@) are ordinary
members, so the Producer's signature covers them and the attestation is bound
to its chain position. The envelope's own signature is a WebAuthn assertion
over @authenticatorData || SHA-256(clientDataJSON)@ and is checked elsewhere —
it never covers these bytes, which is why the paper's single @VerifyAttribution@
cannot verify a passkey (PA-07).
-}
signingMessage :: EntryObject -> CanonicalBytes
signingMessage =
    CanonicalBytes
        . LBS.toStrict
        . BB.toLazyByteString
        . renderObject
        . sortOn (memberName . fst)
        . filter ((/= Signature) . fst)
        . entryObjectMembers

-- | @{"a":"b","c":"d"}@ — no whitespace, members already in RFC 8785 order.
renderObject :: [(Member, MemberValue)] -> BB.Builder
renderObject ms = BB.char8 '{' <> commaSep (map renderMember ms) <> BB.char8 '}'
  where
    renderMember (m, v) = renderString (memberName m) <> BB.char8 ':' <> renderString (memberValueText v)

    commaSep [] = mempty
    commaSep (b : bs) = b <> foldMap (BB.char8 ',' <>) bs

{- | A JSON string per RFC 8785 §3.2.2.2: escape @"@, @\\@ and the control
characters; emit everything else as the UTF-8 it already is.

The escaped case is rare — base64url values and ASCII names never enter it —
so the common path stays a single copy rather than a fold over characters.
-}
renderString :: Text -> BB.Builder
renderString t = BB.char8 '"' <> body <> BB.char8 '"'
  where
    body
        | T.any needsEscape t = T.foldr (\c acc -> escapeChar c <> acc) mempty t
        | otherwise = TE.encodeUtf8Builder t

    needsEscape c = c == '"' || c == '\\' || c < '\x20'

{- | One character, escaped by the RFC's table.

The five control characters with a JSON shorthand take it; the rest of the
C0 range takes @\\u00hh@ with lowercase hex. Nothing above U+001F is escaped
but @"@ and @\\@ — not @\/@, and not any non-ASCII character, which travels
as UTF-8 rather than as a surrogate escape.
-}
escapeChar :: Char -> BB.Builder
escapeChar = \case
    '"' -> BB.string8 "\\\""
    '\\' -> BB.string8 "\\\\"
    '\b' -> BB.string8 "\\b"
    '\t' -> BB.string8 "\\t"
    '\n' -> BB.string8 "\\n"
    '\f' -> BB.string8 "\\f"
    '\r' -> BB.string8 "\\r"
    c
        | c < '\x20' -> BB.string8 "\\u00" <> BB.word8HexFixed (fromIntegral (ord c))
        | otherwise -> BB.charUtf8 c
