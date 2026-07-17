{- | P-256 keys and signatures, split by what has actually been proven
about them.

A key read off a line is 33 bytes of the right shape — a t'ClaimedKey'.
Whether those bytes decode to a point on P-256 is curve arithmetic, and
curve arithmetic lives behind the FFI seam, so only "EventChain.Crypto"
promotes a claim to a t'PublicKey'. Keeping the tiers apart is what lets
the codec stay free of crypto: decoding a line must not cost a key load
per line, which ADR-0004 forbids anyway (every FFI call is batched).
-}
module EventChain.Crypto.Types.Internal.Key
    ( ClaimedKey (..)
    , claimedKey
    , claimedKeyRaw
    , PublicKey (..)
    , publicKeyClaim
    , publicKeyRaw
    , Sig (..)
    , sigFromRaw
    , sigRaw
    , compressedPointLength
    , rawSigLength
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import EventChain.Crypto.Types.Internal.Error (ShapeError (..))

-- | Bytes in a SEC1 compressed P-256 point.
compressedPointLength :: Int
compressedPointLength = 33

-- | Bytes in a raw @r‖s@ P-256 signature.
rawSigLength :: Int
rawSigLength = 64

{- | A claimed public key: 33 bytes shaped like a SEC1 compressed P-256
point, as carried on the wire.

Shape only. The point may not be on the curve; holding this proves
nothing about attribution.
-}
newtype ClaimedKey = ClaimedKey ByteString
    deriving stock (Eq, Ord, Show)

-- | Accept 33 bytes leading with @0x02@ or @0x03@ as a compressed point encoding.
claimedKey :: ByteString -> Either ShapeError ClaimedKey
claimedKey bs = case BS.uncons bs of
    Just (prefix, _)
        | BS.length bs /= compressedPointLength -> Left (KeyWrongLength (BS.length bs))
        | prefix /= 0x02 && prefix /= 0x03 -> Left (KeyBadPrefix prefix)
        | otherwise -> Right (ClaimedKey bs)
    Nothing -> Left (KeyWrongLength 0)

-- | The claimed point's bytes, for encoding or the crypto edge.
claimedKeyRaw :: ClaimedKey -> ByteString
claimedKeyRaw (ClaimedKey bs) = bs

{- | A public key that is a point on P-256, proven so by
"EventChain.Crypto", which is the only module that can build one.

Wraps the claim it was promoted from: the fact is the claim plus the
check that discharged it.
-}
newtype PublicKey = PublicKey ClaimedKey
    deriving stock (Eq, Ord, Show)

-- | The claim this key was promoted from.
publicKeyClaim :: PublicKey -> ClaimedKey
publicKeyClaim (PublicKey k) = k

-- | The key's compressed point bytes.
publicKeyRaw :: PublicKey -> ByteString
publicKeyRaw = claimedKeyRaw . publicKeyClaim

{- | An ECDSA P-256 signature as raw @r‖s@: 64 bytes.

DER is normalized away at the boundaries that produce it (OpenSSL when
signing, WebAuthn assertions when minting); it never reaches the core.
Shape only — a well-formed t'Sig' is not a valid one. Validity is a
relation between signature, message and key, discharged by
"EventChain.Crypto" at verification time, and @r@/@s@ range checks belong
to that same check rather than to construction.
-}
newtype Sig = Sig ByteString
    deriving stock (Eq, Show)

-- | Accept 64 bytes as a raw @r‖s@ signature.
sigFromRaw :: ByteString -> Either ShapeError Sig
sigFromRaw bs
    | BS.length bs == rawSigLength = Right (Sig bs)
    | otherwise = Left (SigWrongLength (BS.length bs))

-- | The signature's bytes, for encoding or the crypto edge.
sigRaw :: Sig -> ByteString
sigRaw (Sig bs) = bs
