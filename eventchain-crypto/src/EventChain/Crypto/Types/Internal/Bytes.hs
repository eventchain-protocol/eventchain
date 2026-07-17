{- | Bytes typed by provenance.

Three byte strings flow through the system and mixing them up is the bug
class this library exists to prevent: the bytes a line /is/, the bytes a
signature covers, and the bytes a payload commitment covers. They are
distinct types, so a wrong pairing is a compile error rather than a
silently valid-looking proof.

Two of the three live here, and the third deliberately does not. Canonical
bytes are a /format/ judgment, so each side canonicalizes for itself and each
side's own @Canonical@ defines the type — the constructor is the claim that
RFC 8785 ran, and this package is in no position to make it. Sharing a
canonicalizer is what ADR-0005 forbids; sharing these two costs nothing,
because a length and an encoding are not a decision two implementations could
reach differently.
-}
module EventChain.Crypto.Types.Internal.Bytes
    ( LineBytes (..)
    , lineBytes
    , lineBytesRaw
    , PayloadBytes (..)
    , payloadBytes
    , payloadBytesRaw
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
