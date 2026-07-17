{- | Bytes typed by provenance.

Three byte strings flow through the system and mixing them up is the bug
class this library exists to prevent: the bytes a line /is/, the bytes a
signature covers, and the bytes a payload commitment covers. They are
distinct types, so a wrong pairing is a compile error rather than a
silently valid-looking proof.

All three live here, but the third arrives stripped of the one thing that
matters about it, and that is the point. @CanonicalBytes@ is a /format/
judgment: holding one is the claim that RFC 8785 ran, and this package — which
owns no format logic — is in no position to make it. So each side canonicalizes
for itself and each side's own @Canonical@ defines that type, as ADR-0005
requires.

t'SignedBytes' is what is left once that claim is spent: bytes a signature
covers, asserting nothing about where they came from. The kernels need /a/ name
for their message, because a domain quantity may not cross a module edge as a
bare 'ByteString' (ADR-0003), and they cannot name either side's
@CanonicalBytes@. Converting one into the other is a deliberate step at the
crypto edge — the guarantee stays upstream, where only a @Canonical@ can produce
the @CanonicalBytes@ that step consumes.

Sharing these costs nothing: a length, an encoding, and "these are the bytes"
are not decisions two implementations could reach differently.
-}
module EventChain.Crypto.Types.Internal.Bytes
    ( LineBytes (..)
    , lineBytes
    , lineBytesRaw
    , PayloadBytes (..)
    , payloadBytes
    , payloadBytesRaw
    , SignedBytes (..)
    , signedBytes
    , signedBytesRaw
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import EventChain.Crypto.Types.Internal.Error (ShapeError (..))

{- | One AOF line's content, exactly as read from or written to the file:
UTF-8, terminator excluded — the @0x0a@ lives in the file, never in these
bytes.

These bytes are load-bearing (ADR-0002): @prev_hash@ covers them and a Mint
references its target by their hash. The chain therefore commits to the
line as it was written, not to any re-serialization of the parsed view —
which is why a decoded entry carries its line bytes rather than
reconstructing them.
-}
newtype LineBytes = LineBytes ByteString
    deriving stock (Eq, Show)

{- | Accept bytes as an AOF line's content: non-empty, free of the @0x0a@
terminator, valid UTF-8 (the encoding JSON text is defined over).

JSON Lines §3 fixes the terminator at @0x0a@ ("Line Terminator is @'\n'@"), so
a line's content is every byte before it — a @0x0d@ among them is content like
any other and is hashed with the rest. A CRLF-terminated file is valid JSON
Lines whose lines each end in @0x0d@; it chains to different hashes than the
LF-terminated original, which is ADR-0002's middlebox consequence working as
specified.
-}
lineBytes :: ByteString -> Either ShapeError LineBytes
lineBytes bs
    | BS.null bs = Left LineEmpty
    | BS.elem 0x0a bs = Left LineHasTerminator
    | not (BS.isValidUtf8 bs) = Left LineNotUtf8
    | otherwise = Right (LineBytes bs)

-- | The line's bytes, for hashing or writing.
lineBytesRaw :: LineBytes -> ByteString
lineBytesRaw (LineBytes bs) = bs

{- | Payload content, obtained through the caller's lookup.

Payloads never live in the AOF — an entry commits to one by hash only.
Deliberately has no 'Show' instance: payload content is the RBAC-gated
material, and this type exists at the boundary where it would otherwise
leak into logs.
-}
newtype PayloadBytes = PayloadBytes ByteString
    deriving stock (Eq)

-- | Any bytes are payload content; there is no shape to violate.
payloadBytes :: ByteString -> PayloadBytes
payloadBytes = PayloadBytes

-- | The payload's bytes, for hashing.
payloadBytesRaw :: PayloadBytes -> ByteString
payloadBytesRaw (PayloadBytes bs) = bs

{- | The exact bytes a signature covers.

A label, and deliberately nothing more. Whether these bytes are the RFC 8785
serialization of an entry minus its @signature@ member is a claim each side's own
@Canonical@ makes and this package cannot check — so this type does not pretend
to. What it buys is that "the message" is a domain quantity with a name, rather
than a 'ByteString' that could be any of the three byte strings above.

Both Kinds of signed message pass through here: the Producer's canonical bytes,
and a Mint's @authenticatorData || SHA-256(clientDataJSON)@, which is a different
construction the kernels have no opinion about either.
-}
newtype SignedBytes = SignedBytes ByteString
    deriving stock (Eq, Show)

{- | Name some bytes as a signing message; there is no shape to violate.

Fabricating these is not a hole this type could plug: signing bytes of your
choosing is possible with any signature API, and what stops it mattering is that
a verifier derives its message from the line rather than accepting one.
-}
signedBytes :: ByteString -> SignedBytes
signedBytes = SignedBytes

-- | The message's bytes, for the crypto edge.
signedBytesRaw :: SignedBytes -> ByteString
signedBytesRaw (SignedBytes bs) = bs
