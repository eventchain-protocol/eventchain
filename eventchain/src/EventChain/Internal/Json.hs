{- | JSON syntax for a flat, string-valued object: braces, commas, and RFC 8785
§3.2.2.2 escaping.

Syntax, and deliberately nothing else. /Which/ members an object carries is
"EventChain.EntryObject"'s; which of them are dropped and how they are ordered
is the caller's decision and the reason the caller exists —
"EventChain.Canonical" drops @signature@ and sorts by name because RFC 8785 says
so, "EventChain.Wire" keeps everything in the vocabulary's own order because the
format lets a producer choose. This module is handed a list already in the order
it will be written and renders it.

== Why both of them come here

The Producer and the Verifier share no format logic (ADR-0005), and this is not
a breach of that: the rule runs across /packages/, where two independently
written encoders that agree are evidence. Inside one package the same
duplication is graded by nothing at all. Two copies of this escaper in
@eventchain@ would manufacture no evidence and buy a divergence — one where the
line says something the signed bytes do not, which is the exact failure the
split exists to catch and could not catch here.

It stays graded all the same. "EventChain.Canonical" is built on this, and the
@aeson@ oracle grades "EventChain.Canonical" over generated objects, so an
escaping bug fails that property before it can reach a line.

== Only strings

Every value on an AOF line is a JSON string — every binary field is base64url
and every label is text (ADR-0002) — so there is no number serialization here.
That is the hard half of RFC 8785 (ECMA-262 @NumberToString@) and this format
does not reach it. What is left is escaping.
-}
module EventChain.Internal.Json
    ( renderObject
    ) where

import Data.ByteString (ByteString)
import Data.ByteString.Builder qualified as BB
import Data.ByteString.Lazy qualified as LBS
import Data.Char (ord)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import EventChain.EntryObject (Member, MemberValue, memberName, memberValueText)

{- | @{"a":"b","c":"d"}@ — no whitespace, members written in the order given.

The order is the caller's claim, not this function's: nothing here sorts, and
nothing here checks that a name appears once. An t'EventChain.EntryObject.EntryObject'
has already refused a duplicate by the time its members reach here.
-}
renderObject :: [(Member, MemberValue)] -> ByteString
renderObject = LBS.toStrict . BB.toLazyByteString . object
  where
    object ms = BB.char8 '{' <> commaSep (map member ms) <> BB.char8 '}'

    member (m, v) = renderString (memberName m) <> BB.char8 ':' <> renderString (memberValueText v)

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
