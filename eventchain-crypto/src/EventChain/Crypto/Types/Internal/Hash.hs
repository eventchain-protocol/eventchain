{- | SHA-256 digests, named by what was hashed.

The AOF hashes two unrelated things — entry lines and payload content —
and comparing one to the other would be a proof that proves nothing. Two
distinct types make that comparison a type error. Distinctness is the
whole mechanism; neither type carries a parameter, so neither leaks a
'Data.Coerce.coerce' hole for a @type role@ annotation to plug.

t'LineHash' is the protocol's /entry hash/ — an entry is identified by the
digest of its line bytes (ADR-0002), never of a re-serialization, so the
bytes are what the name says.
-}
module EventChain.Crypto.Types.Internal.Hash
    ( LineHash (..)
    , PayloadHash (..)
    , lineHashFromBytes
    , payloadHashFromBytes
    , lineHashRaw
    , payloadHashRaw
    , sha256Length
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import EventChain.Crypto.Types.Internal.Error (ShapeError (..))

{- | A SHA-256 digest of an Entry's line bytes: 32 bytes.

'Ord' is here for the minted-status join, which indexes entry hashes.
-}
newtype LineHash = LineHash ByteString
    deriving stock (Eq, Ord, Show)

{- | A SHA-256 digest of a Payload's content: 32 bytes.

The Payload itself lives outside the AOF; an Entry commits to it by this
digest and never embeds it.
-}
newtype PayloadHash = PayloadHash ByteString
    deriving stock (Eq, Ord, Show)

-- | Bytes in a SHA-256 digest.
sha256Length :: Int
sha256Length = 32

{- | Accept 32 bytes as a digest of an Entry's line bytes.

This is the claim tier: the caller asserts what these bytes are a digest
of, and nothing here can check that. The Verifier's codec uses it to read a
claimed @prev_hash@ or @target_hash@ off a line; "EventChain.Crypto" is what
computes a digest that actually covers the bytes it names.
-}
lineHashFromBytes :: ByteString -> Either ShapeError LineHash
lineHashFromBytes = fmap LineHash . digestBytes

{- | Accept 32 bytes as a digest of a Payload's content.

The claim tier, on the same terms as 'lineHashFromBytes': the Verifier's
codec reads a claimed @payload_hash@ off a line and cannot check it.
-}
payloadHashFromBytes :: ByteString -> Either ShapeError PayloadHash
payloadHashFromBytes = fmap PayloadHash . digestBytes

-- | The length check both digests share.
digestBytes :: ByteString -> Either ShapeError ByteString
digestBytes bs
    | BS.length bs == sha256Length = Right bs
    | otherwise = Left (HashWrongLength (BS.length bs))

-- | The digest's bytes, for encoding or the crypto edge.
lineHashRaw :: LineHash -> ByteString
lineHashRaw (LineHash bs) = bs

-- | The digest's bytes, for encoding or the crypto edge.
payloadHashRaw :: PayloadHash -> ByteString
payloadHashRaw (PayloadHash bs) = bs
