-- | Every way a smart constructor in "EventChain.Crypto.Types" can reject its input.
module EventChain.Crypto.Types.Internal.Error
    ( ShapeError (..)
    ) where

import Data.Word (Word8)

{- | Rejections from the claim tier: a value's /shape/ is wrong.

Shape is all a smart constructor can prove — that a field is the right
length, the right encoding, a well-formed point encoding. Whether a
claimed hash actually equals SHA-256 of some bytes, or a signature
actually verifies, is a relation between values that only the
verification machinery discharges; those failures are not modelled here.

Errors are data. Rendering to human text happens at the edge, in whichever
package hit the boundary: the Verifier's codec wraps these with the line
number that produced them.
-}
data ShapeError
    = -- | An AOF line carries no bytes.
      LineEmpty
    | -- | An AOF line contains @0x0a@, the byte that delimits lines (JSON Lines §3).
      LineHasTerminator
    | -- | An AOF line is not valid UTF-8, so it is not JSON text.
      LineNotUtf8
    | -- | A hash is not 32 bytes. Carries the length supplied.
      HashWrongLength Int
    | -- | A raw @r‖s@ signature is not 64 bytes. Carries the length supplied.
      SigWrongLength Int
    | -- | A compressed P-256 point is not 33 bytes. Carries the length supplied.
      KeyWrongLength Int
    | -- | A compressed P-256 point does not lead with @0x02@ or @0x03@. Carries the byte supplied.
      KeyBadPrefix Word8
    deriving stock (Eq, Show)
