{- | The types the crypto kernels operate on, and the smart constructors that
admit values into them.

Both the Producer and the Verifier depend on this package, and that is a
decision rather than a convenience (ADR-0005). Format logic is gated by
/disagreement/ — two independently written canonicalizers that agree are
evidence, where one shared canonicalizer is an assumption — but nothing here
encodes a format judgment. A digest is 32 bytes, a compressed point is 33, a
raw signature is 64, and a line's bytes are the bytes of a line. No two
implementations could reach those differently, so writing them twice would
manufacture no evidence while splitting the FFI's memory-safety obligation in
two.

Two rules shape this module.

/Values are typed by what they are, not by what they hold./ Bytes are typed by
provenance and hashes by subject, so a payload hash and a line hash do not
compare. Where a type has a shape to enforce — a hash's length, a key's point
encoding — the constructor is unexported and a validating function is the only
door, so holding one of those proves the shape was checked. Where there is
nothing to check — t'PayloadBytes' — the newtype buys labelling and no more,
and says so.

/A constructor proves shape, not truth./ At the boundary we take a supplier's
word that a field is a hash and not an arbitrary string; validation makes it a
well-formed /claim/. Whether a claimed hash equals SHA-256 of its line bytes,
or a claimed key is a point on P-256, is a relation between values —
discharged by "EventChain.Crypto", never by construction. Claims flow in from
the wire; facts flow out of verification; nothing else converts between them.

Note what this module therefore does /not/ give you. 'lineHashFromBytes' will
build a t'LineHash' from any 32 bytes, including a re-serialization of a
parsed entry — that is the claim tier working as designed, and it is why the
chain rule cannot rest on this module alone. Only "EventChain.Crypto" can
compute a digest, and only from the byte type that matches the subject; the
guarantee lives in that API's shape, not in t'LineHash' itself.

Note the omission: these types deliberately carry no @ToJSON@ or @FromJSON@
instances. A derived instance would be a second serialization path silently
bypassing the exact-bytes invariant that the chain rests on. Each side's own
explicit codec is the only door (ADR-0003).
-}
module EventChain.Crypto.Types
    ( -- * Errors
      ShapeError (..)

      -- * Bytes, by provenance
    , LineBytes
    , lineBytes
    , lineBytesRaw
    , PayloadBytes
    , payloadBytes
    , payloadBytesRaw

      -- * Hashes, by subject
    , LineHash
    , lineHashFromBytes
    , lineHashRaw
    , PayloadHash
    , payloadHashFromBytes
    , payloadHashRaw
    , sha256Length

      -- * Keys and signatures
    , ClaimedKey
    , claimedKey
    , claimedKeyRaw
    , PublicKey
    , publicKeyClaim
    , publicKeyRaw
    , Sig
    , sigFromRaw
    , sigRaw
    , compressedPointLength
    , rawSigLength
    ) where

import EventChain.Crypto.Types.Internal.Bytes
import EventChain.Crypto.Types.Internal.Error
import EventChain.Crypto.Types.Internal.Hash
import EventChain.Crypto.Types.Internal.Key
