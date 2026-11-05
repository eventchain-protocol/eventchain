{- | ECDSA-P256 verification from a precomputed key, on an architecture that
has no table kernel.

s2n-bignum is vendored for arm64 only. On every other architecture the
Verifier verifies on libcrypto, the same general verify it uses on arm64 for a
key that signs too few lines to pay for a table (ADR-0004 as amended on
2026-11-05). x86-64 waits on a measurement: its s2n-bignum kernel needs BMI2
and ADX, and OpenSSL's own x86-64 P-256 code is already hand-written assembly,
so a table there has to show it is faster before it is vendored.

This module has the arm64 module's exports so that nothing above it changes
shape by architecture. 'PrecomputedKey' has no values here, so 'precomputeKey'
can only answer 'Nothing', and 'verifyBatchPrecomputed' can only be handed an
empty list: the type, not a runtime check, is what keeps a table out of reach.
-}
module EventChain.Crypto.Internal.Precomputed
    ( PrecomputedKey
    , precomputeKey
    , precomputedKeyPublic
    , verifyBatchPrecomputed
    ) where

import EventChain.Crypto.Internal.Ecdsa (PublicKey, SigCheck)
import EventChain.Crypto.Types.Internal.Bytes (SignedBytes)
import EventChain.Crypto.Types.Internal.Key (Sig)

-- | A public key and the table of its multiples. None exist in this build.
data PrecomputedKey
    deriving stock (Eq, Ord, Show)

-- | No table kernel in this build, so no key has a table.
precomputeKey :: PublicKey -> Maybe PrecomputedKey
precomputeKey _ = Nothing

-- | The key a table was built for. Unreachable: there are no tables.
precomputedKeyPublic :: PrecomputedKey -> PublicKey
precomputedKeyPublic key = case key of {}

-- | Verify against tables. Only the empty batch can be built in this build.
verifyBatchPrecomputed :: [(PrecomputedKey, SignedBytes, Sig)] -> [SigCheck]
verifyBatchPrecomputed [] = []
verifyBatchPrecomputed ((key, _, _) : _) = case key of {}
