{- | The crypto kernels: the only module that can compute a digest, prove a key,
or make and check a signature.

Both the Producer and the Verifier call these, and that sharing is a decision
rather than a convenience (ADR-0005). Format logic is gated by /disagreement/ —
two independently written canonicalizers that agree are evidence — but agreement
here is the requirement rather than the question, and a known-answer test against
published vectors grades it without needing a dissenter. Writing this twice would
manufacture no evidence while doubling the one memory-safety obligation in the
system.

== What this module is for

"EventChain.Crypto.Types" is the claim tier: a t'EventChain.Crypto.Types.LineHash'
built there is 32 bytes /asserted/ to be a digest, and a
t'EventChain.Crypto.Types.ClaimedKey' is 33 bytes /asserted/ to be a point. Those
constructors prove shape and nothing else, which is all a boundary can prove
about bytes someone else wrote.

This module is where claims become facts, and it is the only one that can do it:

* 'hashLines' is the only way to /compute/ a t'EventChain.Crypto.Types.LineHash',
  and it takes t'EventChain.Crypto.Types.LineBytes'. The chain rule rests on that
  API's shape — not on the hash type, which cannot tell what it is a digest of.
* 'publicKey' is the only way to obtain a 'PublicKey', and obtaining one /is/ the
  on-curve proof.
* 'verifyBatch' is the only thing that can answer whether a signature is a
  signer's.

== The API is pure, and honestly so

SHA-256 is a function. ECDSA verification is a function. Signing is a function
too, because the nonce is deterministic (RFC 6979, ADR-0004) — so nothing here
takes 'IO' except key generation, which needs randomness and says so by its type.

That is not a stylistic preference: @docs/plan.md@ requires the reference
verifier be pure — file bytes in, verdict out — and an 'IO' kernel would make
that impossible to state in a type.

== Everything is batched

'hashLines', 'hashPayloads' and 'verifyBatch' take chunks and never single values
(ADR-0004). For hashing this is worth 2.3× — one context and one fetched
algorithm reused down the chunk, measured at 2.97 GB/s against 1.32 for the
obvious per-line call. For verification the win is elsewhere: the key is loaded
once and reused, which is the difference between 29.5k and 21.5k verify/s/core.
-}
module EventChain.Crypto
    ( -- * Hashing
      hashLines
    , hashPayloads

      -- * Keys
    , PublicKey
    , publicKey
    , publicKeyClaim
    , publicKeyRaw
    , PrivateKey
    , privateKey
    , privateKeyPublic

      -- * Signing and verification
    , SigCheck (..)
    , sign
    , verifyBatch

      -- * Errors
    , CryptoError (..)
    ) where

import EventChain.Crypto.Internal.Digest (hashLines, hashPayloads)
import EventChain.Crypto.Internal.Ecdsa
    ( PrivateKey
    , PublicKey
    , SigCheck (..)
    , privateKey
    , privateKeyPublic
    , publicKey
    , publicKeyClaim
    , publicKeyRaw
    , sign
    , verifyBatch
    )
import EventChain.Crypto.Internal.Error (CryptoError (..))
