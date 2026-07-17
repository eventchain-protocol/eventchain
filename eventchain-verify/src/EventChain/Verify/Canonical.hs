{-# LANGUAGE OverloadedStrings #-}

{- | RFC 8785 (JCS) serialization of an Entry minus its @signature@ member —
the bytes a Produced Proof covers — and t'CanonicalBytes' itself.

This is the /second/ implementation of RFC 8785 in this repository, and that is
the design rather than an accident (ADR-0005). @eventchain@ has its own, written
separately; two canonicalizers that agree are evidence about the format, where
one shared canonicalizer is an assumption about our own code. If they ever
diverge, one of them is wrong about the RFC and the vectors are what say so.

Fabricating the signing message is signing a message of your choosing, so the
constructor is unexported and this module is the only door — rule 8 of
@docs/plan.md@: the type whose meaning is "the canonicalizer ran" is defined
where the canonicalizer is.

Why canonicalization exists here at all, given that ADR-0002 §1 chains raw line
bytes and refuses to canonicalize: the paper puts @signature@ inside the object
it signs, and bytes containing a signature cannot be the bytes that signature
covers. Something has to define "the entry without its signature", and RFC 8785
is that definition (ADR-0002 §2). The chain has no such problem — the previous
line's bytes are already complete — which is why the two rules answer the
same-sounding question differently.
-}
module EventChain.Verify.Canonical
    ( CanonicalBytes
    , canonicalBytesRaw
    , canonicalize
    , signingMessage
    ) where

import Data.ByteString (ByteString)
import Data.ByteString.Builder qualified as B
import Data.ByteString.Lazy qualified as LBS
import Data.Char (ord)
import Data.List (sortOn)
import Data.Text (Text)
import Data.Text qualified as T
import EventChain.Crypto.Types (SignedBytes, signedBytes)
import EventChain.Verify.EntryObject (EntryObject, Member (..), entryObjectMembers, memberName)
import Numeric (showHex)

{- | The RFC 8785 serialization of an Entry minus its @signature@: the exact
bytes a Produced Proof is over.

Holding one proves this module built it. That is the whole of the guarantee —
whether the signature over these bytes verifies is "EventChain.Verify"'s
question, and this type has no opinion about it.
-}
newtype CanonicalBytes = CanonicalBytes ByteString
    deriving stock (Eq, Show)

-- | The canonical bytes, for hashing or display.
canonicalBytesRaw :: CanonicalBytes -> ByteString
canonicalBytesRaw (CanonicalBytes bs) = bs

{- | The signing message these bytes are: what the crypto seam verifies against.

A separate step from 'canonicalize' on purpose. 'EventChain.Crypto.Types.SignedBytes'
is a label with no shape to check — it would accept any bytes at all — so the
claim "these are the entry's canonical bytes" is made exactly once, here, by a
function that can only be handed something this module built.
-}
signingMessage :: CanonicalBytes -> SignedBytes
signingMessage = signedBytes . canonicalBytesRaw

{- | The entry's members minus @signature@, RFC 8785: sorted by name, minified,
no whitespace anywhere.

The @signature@ member is dropped rather than emptied or zeroed. ADR-0002 §2
says /removed/, and the distinction is not cosmetic: an entry with an empty
signature member is a different object with a different canonical form, so a
verifier that blanked instead of dropping would derive bytes no producer ever
signed.

Note what is /not/ dropped: @prev_hash@ stays, so the Producer signs its own
chain position and no Hub can relocate an entry without invalidating a
signature it cannot forge (ADR-0002 §2, @docs/paper-amendments.md@ PA-08).
Removing only @signature@ is the rule; every other member is in.
-}
canonicalize :: EntryObject -> CanonicalBytes
canonicalize o =
    CanonicalBytes
        . LBS.toStrict
        . B.toLazyByteString
        $ "{" <> commas (map member sorted) <> "}"
  where
    -- Sorted by name, which for this vocabulary is arithmetic rather than a rule
    -- we implement. RFC 8785 §3.2.3 orders members by the UTF-16 code units of
    -- their names; every name in the vocabulary is ASCII, where UTF-16 code unit
    -- order, code point order and Text's own Ord all coincide -- and an unknown
    -- member is a hard error, so no other name can reach here. A vocabulary that
    -- ever admits a non-ASCII member name needs the real comparison, and this
    -- comment is where to start.
    sorted = sortOn (memberName . fst) [p | p@(m, _) <- entryObjectMembers o, m /= Signature]

    member (m, v) = jsonString (memberName m) <> ":" <> jsonString v

    commas = mconcat . intersperseB ","

    intersperseB _ [] = []
    intersperseB sep (x : xs) = x : concatMap (\y -> [sep, y]) xs

{- | A JSON string, escaped per RFC 8785 §3.2.2.2.

The RFC's own table, not @aeson@'s: the two-character escapes @\\b@ and @\\f@
are required where a general JSON encoder is free to emit @\\u0008@ and
@\\u000c@ instead. Both are valid JSON and they are different /bytes/, which is
the only thing that matters to a signature. @Test.EventChain.Verify.Canonical@
pins those two against the RFC's table for exactly that reason — the oracle we
grade against is wrong about them.

Everything at or above @0x20@ other than @"@ and @\\@ passes through as UTF-8.
Non-ASCII text is /not/ escaped: RFC 8785 emits it literally, and a
canonicalizer that reached for @\\u@ would derive different bytes for a label
that is legal opaque text (@docs/paper-amendments.md@ PA-03).
-}
jsonString :: Text -> B.Builder
jsonString t = "\"" <> T.foldr (\c acc -> escape c <> acc) mempty t <> "\""
  where
    escape c = case c of
        '"' -> "\\\""
        '\\' -> "\\\\"
        '\b' -> "\\b"
        '\f' -> "\\f"
        '\n' -> "\\n"
        '\r' -> "\\r"
        '\t' -> "\\t"
        _
            | ord c < 0x20 -> B.string7 ("\\u" <> pad (showHex (ord c) ""))
            | otherwise -> B.charUtf8 c

    -- Four hex digits, lowercase, which is what the RFC's table shows. Only
    -- reachable for c < 0x20, so two leading zeros are always right.
    pad h = replicate (4 - length h) '0' <> h
