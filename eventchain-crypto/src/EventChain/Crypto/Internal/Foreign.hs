{-# LANGUAGE CApiFFI #-}

{- | The language seam: every line of libcrypto we speak to, and nothing else.

This is the only module in the system that names a foreign function, and the only
one that can get memory wrong. Everything above it is Haskell that cannot.

Four rules hold here, and each is the answer to a specific way this goes wrong.

/Imports are @capi@, not @ccall@./ GHC's own guidance is to use @capi@ for
libraries we do not ship, because it makes the C compiler check each call against
the real header instead of trusting a signature we typed. The bug it prevents is
not hypothetical or portable-in-theory: a wrong-shaped @ccall@ crashed GHCi on
AArch64/Darwin, which is this project's development platform. HsOpenSSL imports
its entire OpenSSL surface this way.

/Every C object is a t'ForeignPtr' finalized by libcrypto's own free./ Never
@bracket@: the base docs single it out as the thing that cannot be used safely
under a duplicated or aborted computation, and a raw pointer whose release never
runs is a leak — or, if something else frees it, worse. A finalizer turns that
case into "the handle was dropped", which the garbage collector already knows how
to finish. Acquisition is wrapped in 'mask_' so an abort cannot land between the
@_new@ and the finalizer being attached, stranding a pointer with no owner.

/Access is 'withForeignPtr', never @unsafeWithForeignPtr@./ The unsafe variant
lets GHC drop the liveness requirement when it can prove the continuation
diverges (GHC #17760), freeing memory C still holds. The failure is silent.

/@safe@ or @unsafe@ is decided by how long the call takes and by who chooses the
size, not by taste./ An @unsafe@ call cannot be preempted and blocks its
capability for its whole duration, stalling garbage collection; a @safe@ call
costs about 89ns to release and reacquire. Measured on this project's kernels: a
verify is ~34µs and a key load ~15µs, so 89ns is 0.26% and there is nothing to
discuss. Hashing is the interesting one — see "EventChain.Crypto.Internal.Digest".
-}
module EventChain.Crypto.Internal.Foreign
    ( -- * Opaque libcrypto types
      EVP_MD
    , EVP_MD_CTX
    , EVP_PKEY
    , EVP_PKEY_CTX
    , OSSL_PARAM
    , OSSL_PARAM_BLD

      -- * Message digests
    , c_EVP_MD_fetch
    , c_EVP_MD_free
    , c_EVP_MD_CTX_new
    , p_EVP_MD_CTX_free
    , c_EVP_DigestInit_ex2
    , c_EVP_DigestUpdate
    , c_EVP_DigestUpdate_safe
    , c_EVP_DigestFinal_ex

      -- * Keys
    , c_EVP_PKEY_CTX_new_from_name
    , c_EVP_PKEY_CTX_new_from_pkey
    , p_EVP_PKEY_CTX_free
    , c_EVP_PKEY_fromdata_init
    , c_EVP_PKEY_fromdata
    , p_EVP_PKEY_free
    , c_EVP_PKEY_get_octet_string_param
    , c_EVP_PKEY_set_utf8_string_param

      -- * Parameter building
    , c_OSSL_PARAM_BLD_new
    , p_OSSL_PARAM_BLD_free
    , c_OSSL_PARAM_BLD_push_utf8_string
    , c_OSSL_PARAM_BLD_push_octet_string
    , c_OSSL_PARAM_BLD_push_BN
    , c_OSSL_PARAM_BLD_push_uint
    , c_OSSL_PARAM_BLD_to_param
    , p_OSSL_PARAM_free

      -- * Bignums
    , BIGNUM
    , ConstBignum
    , c_BN_bin2bn
    , c_BN_bn2binpad
    , p_BN_free

      -- * Signing and verification
    , c_EVP_DigestSignInit_ex
    , c_EVP_DigestSign
    , c_EVP_PKEY_verify_init_ex
    , c_EVP_PKEY_verify

      -- * DER signatures
    , ECDSA_SIG
    , ConstBytes (..)
    , p_ECDSA_SIG_free
    , c_ECDSA_SIG_get0_r
    , c_ECDSA_SIG_get0_s
    , c_d2i_ECDSA_SIG

      -- * Deriving a public point
    , EC_GROUP
    , EC_POINT
    , BN_CTX
    , c_EC_GROUP_new_by_curve_name
    , p_EC_GROUP_free
    , c_EC_POINT_new
    , p_EC_POINT_free
    , c_EC_POINT_mul
    , c_EC_POINT_point2oct
    , nidP256
    , pointConversionCompressed

      -- * The error queue
    , c_ERR_get_error
    , c_ERR_clear_error

      -- * Selection constants
    , evpPkeyPublicKey
    , evpPkeyKeypair
    ) where

import Data.Word (Word8)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (..), CLong (..), CSize (..), CUInt (..), CULong (..))
import Foreign.ForeignPtr (FinalizerPtr)
import Foreign.Ptr (Ptr)
import Foreign.Storable (Storable)

-- | @EVP_MD@ — a fetched digest algorithm. Immutable, and shareable once fetched.
data {-# CTYPE "openssl/evp.h" "EVP_MD" #-} EVP_MD

-- | @EVP_MD_CTX@ — digest state. Mutated by every update; never share one.
data {-# CTYPE "openssl/evp.h" "EVP_MD_CTX" #-} EVP_MD_CTX

-- | @EVP_PKEY@ — a key. Refcounted, and safe to share read-only across threads.
data {-# CTYPE "openssl/evp.h" "EVP_PKEY" #-} EVP_PKEY

-- | @EVP_PKEY_CTX@ — a key operation's state. \"Contexts MUST NOT be shared between threads.\"
data {-# CTYPE "openssl/evp.h" "EVP_PKEY_CTX" #-} EVP_PKEY_CTX

-- | @OSSL_PARAM@ — a built parameter array. Opaque here on purpose: see 'OSSL_PARAM_BLD'.
data {-# CTYPE "openssl/params.h" "OSSL_PARAM" #-} OSSL_PARAM

{- | @OSSL_PARAM_BLD@ — the builder.

Why the builder rather than an @OSSL_PARAM@ array: @OSSL_PARAM_construct_*@
return a struct /by value/ and the array's layout is a struct, so building one
from Haskell would mean knowing @sizeof(OSSL_PARAM)@ and its field offsets —
which is what @hsc2hs@ or a C shim exists for. Every @OSSL_PARAM_BLD_*@ function
is an ordinary function returning an opaque pointer, so the layout never has to
leave C. This is the whole reason this package ships no C.
-}
data {-# CTYPE "openssl/param_build.h" "OSSL_PARAM_BLD" #-} OSSL_PARAM_BLD

-- | @BIGNUM@ — an arbitrary-precision integer. Only ECDSA's @r@ and @s@ reach it.
data {-# CTYPE "openssl/bn.h" "BIGNUM" #-} BIGNUM

{- | @const BIGNUM@ — a bignum owned by something else, reachable only as @Ptr ConstBignum@.

'c_ECDSA_SIG_get0_r' and 'c_ECDSA_SIG_get0_s' return /borrowed/ pointers into the
signature, which is why the header makes them @const@: they must not be freed,
and they die with the t'ECDSA_SIG'. A distinct type carries that, so the borrow is
visible on this side and the C compiler agrees on the other.

It is a phantom @data@ rather than a @newtype@ over @Ptr BIGNUM@ because GHC
unwraps a newtype in /result/ position and renders the type underneath, ignoring
this pragma — the @const@ silently came back. In @Ptr@ position the pragma is
honoured, which is why 'ConstBytes' can be a newtype and this cannot.
-}
data {-# CTYPE "openssl/bn.h" "const BIGNUM" #-} ConstBignum

-- | @ECDSA_SIG@ — a DER signature's two halves. The only reason DER exists here.
data {-# CTYPE "openssl/ecdsa.h" "ECDSA_SIG" #-} ECDSA_SIG

-- | @EC_GROUP@ — a curve. Only P-256 is ever named.
data {-# CTYPE "openssl/ec.h" "EC_GROUP" #-} EC_GROUP

-- | @EC_POINT@ — a point on a curve.
data {-# CTYPE "openssl/ec.h" "EC_POINT" #-} EC_POINT

-- | @BN_CTX@ — bignum scratch space. We always pass NULL and let libcrypto make its own.
data {-# CTYPE "openssl/bn.h" "BN_CTX" #-} BN_CTX

{- | @const unsigned char *@ — the cursor @d2i_ECDSA_SIG@ advances as it reads.

This newtype exists to carry the @const@. @d2i_ECDSA_SIG@ takes
@const unsigned char **@, and C does not let @unsigned char **@ convert to it
implicitly — the qualifier would be discarded in a nested pointer, which is a
real rule and not pedantry. Without this, @capi@'s generated wrapper draws a
warning from the C compiler on every build.

That warning is @capi@ working. A @ccall@ import would have taken the signature I
typed at face value and said nothing, which is the class of bug @capi@ exists to
find: GHC's own guidance for it cites a wrong-shaped @ccall@ crashing GHCi on
AArch64/Darwin, this project's platform.
-}
newtype {-# CTYPE "const unsigned char *" #-} ConstBytes = ConstBytes (Ptr Word8)
    deriving newtype (Storable)

{- | @EVP_PKEY_PUBLIC_KEY@, the @fromdata@ selection for a public key alone.

Imported from the header rather than written down. Both of these are /computed/
macros — @EVP_PKEY_PUBLIC_KEY@ is @EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY@,
itself a union of four more — so a literal here would be a transcription of
arithmetic done in someone else's header, and would keep compiling after they
changed it. @capi@'s @value@ import is what makes that a compile-time fact
instead. (They are 0x86 and 0x87 on OpenSSL 3.6.2, which is precisely the kind of
thing not to rely on.)
-}
foreign import capi "openssl/evp.h value EVP_PKEY_PUBLIC_KEY"
    evpPkeyPublicKey :: CInt

-- | @EVP_PKEY_KEYPAIR@, the @fromdata@ selection for a private key and its point.
foreign import capi "openssl/evp.h value EVP_PKEY_KEYPAIR"
    evpPkeyKeypair :: CInt

-- Digests -------------------------------------------------------------------

-- | Fetch a digest by name. Costly enough to do once and share; see 'EVP_MD'.
foreign import capi safe "openssl/evp.h EVP_MD_fetch"
    c_EVP_MD_fetch :: Ptr () -> CString -> CString -> IO (Ptr EVP_MD)

foreign import capi "openssl/evp.h &EVP_MD_free"
    c_EVP_MD_free :: FinalizerPtr EVP_MD

foreign import capi unsafe "openssl/evp.h EVP_MD_CTX_new"
    c_EVP_MD_CTX_new :: IO (Ptr EVP_MD_CTX)

foreign import capi "openssl/evp.h &EVP_MD_CTX_free"
    p_EVP_MD_CTX_free :: FinalizerPtr EVP_MD_CTX

foreign import capi unsafe "openssl/evp.h EVP_DigestInit_ex2"
    c_EVP_DigestInit_ex2 :: Ptr EVP_MD_CTX -> Ptr EVP_MD -> Ptr OSSL_PARAM -> IO CInt

{- | Feed bytes to a digest. Bounded caller — @unsafe@.

Paired with 'c_EVP_DigestUpdate_safe', which is the identical function imported
@safe@. Which one a call site uses depends on the length of the buffer, because
the length is chosen by whoever wrote the file.
-}
foreign import capi unsafe "openssl/evp.h EVP_DigestUpdate"
    c_EVP_DigestUpdate :: Ptr EVP_MD_CTX -> Ptr Word8 -> CSize -> IO CInt

-- | 'c_EVP_DigestUpdate' for buffers big enough that blocking a capability matters.
foreign import capi safe "openssl/evp.h EVP_DigestUpdate"
    c_EVP_DigestUpdate_safe :: Ptr EVP_MD_CTX -> Ptr Word8 -> CSize -> IO CInt

foreign import capi unsafe "openssl/evp.h EVP_DigestFinal_ex"
    c_EVP_DigestFinal_ex :: Ptr EVP_MD_CTX -> Ptr Word8 -> Ptr CUInt -> IO CInt

-- Keys ----------------------------------------------------------------------

foreign import capi safe "openssl/evp.h EVP_PKEY_CTX_new_from_name"
    c_EVP_PKEY_CTX_new_from_name :: Ptr () -> CString -> CString -> IO (Ptr EVP_PKEY_CTX)

foreign import capi safe "openssl/evp.h EVP_PKEY_CTX_new_from_pkey"
    c_EVP_PKEY_CTX_new_from_pkey :: Ptr () -> Ptr EVP_PKEY -> CString -> IO (Ptr EVP_PKEY_CTX)

foreign import capi "openssl/evp.h &EVP_PKEY_CTX_free"
    p_EVP_PKEY_CTX_free :: FinalizerPtr EVP_PKEY_CTX

foreign import capi safe "openssl/evp.h EVP_PKEY_fromdata_init"
    c_EVP_PKEY_fromdata_init :: Ptr EVP_PKEY_CTX -> IO CInt

-- | ~15µs, and it decompresses the point — which is what makes it the on-curve check.
foreign import capi safe "openssl/evp.h EVP_PKEY_fromdata"
    c_EVP_PKEY_fromdata :: Ptr EVP_PKEY_CTX -> Ptr (Ptr EVP_PKEY) -> CInt -> Ptr OSSL_PARAM -> IO CInt

foreign import capi "openssl/evp.h &EVP_PKEY_free"
    p_EVP_PKEY_free :: FinalizerPtr EVP_PKEY

{- | Read a key parameter as bytes.

This, and not @EVP_PKEY_get1_encoded_public_key@, is how a compressed point comes
back out: measured on OpenSSL 3.6.2, @get1_encoded_public_key@ ignores the
conversion-format parameter and returns 65 uncompressed bytes even when the
parameter reads back as @\"compressed\"@. This function honours it.
-}
foreign import capi safe "openssl/evp.h EVP_PKEY_get_octet_string_param"
    c_EVP_PKEY_get_octet_string_param :: Ptr EVP_PKEY -> CString -> Ptr Word8 -> CSize -> Ptr CSize -> IO CInt

foreign import capi safe "openssl/evp.h EVP_PKEY_set_utf8_string_param"
    c_EVP_PKEY_set_utf8_string_param :: Ptr EVP_PKEY -> CString -> CString -> IO CInt

-- Parameter building --------------------------------------------------------

foreign import capi unsafe "openssl/param_build.h OSSL_PARAM_BLD_new"
    c_OSSL_PARAM_BLD_new :: IO (Ptr OSSL_PARAM_BLD)

foreign import capi "openssl/param_build.h &OSSL_PARAM_BLD_free"
    p_OSSL_PARAM_BLD_free :: FinalizerPtr OSSL_PARAM_BLD

foreign import capi unsafe "openssl/param_build.h OSSL_PARAM_BLD_push_utf8_string"
    c_OSSL_PARAM_BLD_push_utf8_string :: Ptr OSSL_PARAM_BLD -> CString -> CString -> CSize -> IO CInt

foreign import capi unsafe "openssl/param_build.h OSSL_PARAM_BLD_push_octet_string"
    c_OSSL_PARAM_BLD_push_octet_string :: Ptr OSSL_PARAM_BLD -> CString -> Ptr Word8 -> CSize -> IO CInt

foreign import capi unsafe "openssl/param_build.h OSSL_PARAM_BLD_push_BN"
    c_OSSL_PARAM_BLD_push_BN :: Ptr OSSL_PARAM_BLD -> CString -> Ptr BIGNUM -> IO CInt

foreign import capi unsafe "openssl/param_build.h OSSL_PARAM_BLD_push_uint"
    c_OSSL_PARAM_BLD_push_uint :: Ptr OSSL_PARAM_BLD -> CString -> CUInt -> IO CInt

foreign import capi unsafe "openssl/param_build.h OSSL_PARAM_BLD_to_param"
    c_OSSL_PARAM_BLD_to_param :: Ptr OSSL_PARAM_BLD -> IO (Ptr OSSL_PARAM)

foreign import capi "openssl/params.h &OSSL_PARAM_free"
    p_OSSL_PARAM_free :: FinalizerPtr OSSL_PARAM

-- Bignums -------------------------------------------------------------------

foreign import capi unsafe "openssl/bn.h BN_bin2bn"
    c_BN_bin2bn :: Ptr Word8 -> CInt -> Ptr BIGNUM -> IO (Ptr BIGNUM)

{- | Write a bignum big-endian into exactly @len@ bytes, left-padding with zeroes.

Returns -1 if the number will not fit, which is the range check: a @BIGNUM@ that
needs more than 32 bytes is not a P-256 @r@ or @s@, and the caller finds out
here rather than by silently truncating.

Takes t'ConstBignum' because the only bignums this is ever handed are the ones
borrowed from a t'ECDSA_SIG'.
-}
foreign import capi unsafe "openssl/bn.h BN_bn2binpad"
    c_BN_bn2binpad :: Ptr ConstBignum -> Ptr Word8 -> CInt -> IO CInt

foreign import capi "openssl/bn.h &BN_free"
    p_BN_free :: FinalizerPtr BIGNUM

-- Signing and verification --------------------------------------------------

{- | Begin a signature.

The @OSSL_PARAM@ argument is where @nonce-type@ = 1 selects RFC 6979. The
provider docs are explicit that @digest@ must be set alongside it or
"deterministic nonce generation will fail"; a reproduction of exactly that failure
is what put the sentence in the docs.
-}
foreign import capi safe "openssl/evp.h EVP_DigestSignInit_ex"
    c_EVP_DigestSignInit_ex
        :: Ptr EVP_MD_CTX
        -> Ptr (Ptr EVP_PKEY_CTX)
        -> CString
        -> Ptr ()
        -> CString
        -> Ptr EVP_PKEY
        -> Ptr OSSL_PARAM
        -> IO CInt

-- | ~35µs. Emits DER, which is why @eventchain-crypto@ normalizes it away here.
foreign import capi safe "openssl/evp.h EVP_DigestSign"
    c_EVP_DigestSign :: Ptr EVP_MD_CTX -> Ptr Word8 -> Ptr CSize -> Ptr Word8 -> CSize -> IO CInt

{- | Prepare an @EVP_PKEY_CTX@ for repeated one-shot verifies.

The reuse is contractual, not observed: "When initialized using
EVP_PKEY_verify_init_ex() ... EVP_PKEY_verify() can be called more than once on
the same context to have several one-shot operations performed using the same
parameters" (@EVP_PKEY_verify(3ssl)@, shipped with 3.6.2; the function is 3.0+,
inside our 3.2 floor). That sentence is what lets a chunk pay for initialization
once per signer run instead of once per line — @EVP_DigestVerify@, the
alternative, is one-shot per init and re-fetches its digest by name every time.
-}
foreign import capi safe "openssl/evp.h EVP_PKEY_verify_init_ex"
    c_EVP_PKEY_verify_init_ex :: Ptr EVP_PKEY_CTX -> Ptr OSSL_PARAM -> IO CInt

{- | ~34µs — the hot kernel, and the reason a key is loaded once and reused.

Takes the /digest/ of the message, not the message: the EC provider treats @tbs@
as the value ECDSA signs, so the caller hashes first — through the same batched
SHA-256 kernel the chain walk uses.

Returns 1 for a valid signature, 0 for an invalid one — including "the
signature was of invalid form" (@EVP_PKEY_verify(3ssl)@) — and negative for a
malfunction. Those are three outcomes, not two.
-}
foreign import capi safe "openssl/evp.h EVP_PKEY_verify"
    c_EVP_PKEY_verify :: Ptr EVP_PKEY_CTX -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> IO CInt

-- DER signatures ------------------------------------------------------------

foreign import capi "openssl/ecdsa.h &ECDSA_SIG_free"
    p_ECDSA_SIG_free :: FinalizerPtr ECDSA_SIG

foreign import capi unsafe "openssl/ecdsa.h ECDSA_SIG_get0_r"
    c_ECDSA_SIG_get0_r :: Ptr ECDSA_SIG -> IO (Ptr ConstBignum)

foreign import capi unsafe "openssl/ecdsa.h ECDSA_SIG_get0_s"
    c_ECDSA_SIG_get0_s :: Ptr ECDSA_SIG -> IO (Ptr ConstBignum)

foreign import capi unsafe "openssl/ecdsa.h d2i_ECDSA_SIG"
    c_d2i_ECDSA_SIG :: Ptr (Ptr ECDSA_SIG) -> Ptr ConstBytes -> CLong -> IO (Ptr ECDSA_SIG)

-- Deriving a public point ---------------------------------------------------

{- | Multiply the generator by a scalar: the public key of a private one.

Measured on OpenSSL 3.6.2: @EVP_PKEY_fromdata@ given only a private scalar
/succeeds/, and the key /signs correctly/ — but @OSSL_PKEY_PARAM_PUB_KEY@ then
reads back as absent, because nothing derived it. A Producer restoring a key from
a stored scalar could therefore sign entries and be unable to say which key
signed them, or publish a key that does not match. So the point is derived here
and handed to @fromdata@ alongside the scalar, and a t'EventChain.Crypto.PrivateKey'
always knows its own point.

These are the low-level EC calls, and they are here for that one reason. Note
what is /not/ imported: @EC_KEY_set_public_key@ and @EVP_PKEY_set1_EC_KEY@, which
are deprecated in 3.0. @EC_POINT_*@ are not.
-}
foreign import capi safe "openssl/ec.h EC_GROUP_new_by_curve_name"
    c_EC_GROUP_new_by_curve_name :: CInt -> IO (Ptr EC_GROUP)

foreign import capi "openssl/ec.h &EC_GROUP_free"
    p_EC_GROUP_free :: FinalizerPtr EC_GROUP

foreign import capi unsafe "openssl/ec.h EC_POINT_new"
    c_EC_POINT_new :: Ptr EC_GROUP -> IO (Ptr EC_POINT)

foreign import capi "openssl/ec.h &EC_POINT_free"
    p_EC_POINT_free :: FinalizerPtr EC_POINT

-- | @r = generator * n@ when @q@ and @m@ are NULL. ~50µs of curve arithmetic.
foreign import capi safe "openssl/ec.h EC_POINT_mul"
    c_EC_POINT_mul
        :: Ptr EC_GROUP
        -> Ptr EC_POINT
        -> Ptr BIGNUM
        -> Ptr EC_POINT
        -> Ptr BIGNUM
        -> Ptr BN_CTX
        -> IO CInt

-- | Encode a point. With a NULL buffer, returns the length it would need.
foreign import capi safe "openssl/ec.h EC_POINT_point2oct"
    c_EC_POINT_point2oct
        :: Ptr EC_GROUP
        -> Ptr EC_POINT
        -> CInt
        -> Ptr Word8
        -> CSize
        -> Ptr BN_CTX
        -> IO CSize

-- | @NID_X9_62_prime256v1@ — P-256. From the header; NIDs are not ours to memorise.
foreign import capi "openssl/obj_mac.h value NID_X9_62_prime256v1"
    nidP256 :: CInt

-- | @POINT_CONVERSION_COMPRESSED@ — the 33-byte @0x02@\/@0x03@ encoding the AOF carries.
foreign import capi "openssl/ec.h value POINT_CONVERSION_COMPRESSED"
    pointConversionCompressed :: CInt

-- The error queue -----------------------------------------------------------

{- | The most recent error code, or 0.

libcrypto's error queue is thread-local and /accumulates/. A code left behind by
a failed call is read by the next thing to look, so every failure path drains it
and every success path clears it — otherwise an error reported here belongs to
some earlier call and names the wrong problem.
-}
foreign import capi unsafe "openssl/err.h ERR_get_error"
    c_ERR_get_error :: IO CULong

foreign import capi unsafe "openssl/err.h ERR_clear_error"
    c_ERR_clear_error :: IO ()
