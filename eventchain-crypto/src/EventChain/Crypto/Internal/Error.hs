{- | Every way the crypto kernels can refuse.

Distinct from t'EventChain.Crypto.Types.ShapeError', and the split is the claims
tier showing through. A t'EventChain.Crypto.Types.ClaimedKey' is 33 bytes of the
right shape — that is all a smart constructor can prove, and 'ShapeError' is what
it says when even that fails. Whether those 33 bytes name a point on P-256 is
curve arithmetic, and the answer lives here.

Note what is /not/ an error: a signature that does not verify. That is a fact
about the world, reported as 'EventChain.Crypto.SigInvalid'. Only a malfunction —
libcrypto failing to answer at all — is an error. Collapsing the two would mean a
broken installation reads as a forged entry, and an AOF would be pronounced bad
because our library was.
-}
module EventChain.Crypto.Internal.Error
    ( CryptoError (..)
    ) where

import Data.Word (Word64)

{- | A crypto operation's refusal.

Errors are data. Rendering to human text happens at the edge, in whichever
package hit the boundary.
-}
data CryptoError
    = {- | 33 well-formed bytes that name no point on P-256. There is no @y@ for
      this @x@, so decompression failed — which is the on-curve check, not a
      step before it. Roughly half of all 33-byte strings land here.
      -}
      KeyNotOnCurve
    | -- | A private scalar is not 32 bytes. Carries the length supplied.
      ScalarWrongLength Int
    | {- | 32 bytes that are not a usable P-256 private scalar: zero, or at or
      beyond the group order.
      -}
      ScalarRejected
    | {- | A signature's @r@ or @s@ does not fit in 32 bytes, so it is not a
      P-256 signature whatever else it is.
      -}
      SigOutOfRange
    | {- | libcrypto malfunctioned, carrying the code from its error queue.

      Not a verdict about anyone's bytes — the library failed to answer.
      Decode with @openssl errstr \<code\>@. The code is carried rather than a
      message because rendering one means a @Text@ dependency, and this
      package is a seam.
      -}
      OpenSslFailed Word64
    deriving stock (Eq, Show)
