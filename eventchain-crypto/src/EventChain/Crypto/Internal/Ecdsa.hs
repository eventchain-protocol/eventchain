{-# LANGUAGE OverloadedStrings #-}

{- | ECDSA over P-256: keys that have been proven, signatures that are
deterministic, and the verification that discharges a claim.

== Why a key is a handle

@EVP_PKEY_fromdata@ costs __14.95 µs__ against a __34 µs__ verify on this
project's dev machine. Loading per verify runs at 21.5k verify/s against
ADR-0004's 30.6k baseline — a 30% miss, outside M1's own ±20% bar. The cheaper
trick, re-pointing a scratch key with @EVP_PKEY_set1_encoded_public_key@ (7.63 µs),
still misses at 23.5k/s. Only a key loaded once and reused makes the bar, at
29.5k/s.

So a t'PublicKey' /is/ the loaded @EVP_PKEY@. That is forced by measurement, and
it is also what the type wanted to be: the fact is the claim plus the check that
discharged it, and here the check leaves an artifact worth keeping.

Sharing one across threads is measured at 7.8× on 8 threads with no contention,
and libcrypto's own contract says why: "A given object may be used concurrently on
multiple threads by non-mutating functions", and @EVP_DigestVerifyInit@ "does not
mutate pkey". The @EVP_MD_CTX@ is the mutable part, so each verify makes its own —
which costs 1.8%, measured, and is the price of a rule that reads "Contexts MUST
NOT be shared between threads".

== Why DER never leaves

The AOF carries raw 64-byte @r‖s@ (ADR-0002). libcrypto speaks DER at both ends:
it emits DER when signing and demands DER when verifying. Both conversions happen
here, which is what "@eventchain-crypto@ normalizes it away at those two sources"
means. The cost is 0.46 µs, 1.4% of a verify.
-}
module EventChain.Crypto.Internal.Ecdsa
    ( -- * Keys
      PublicKey
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
    ) where

import Control.Exception (mask_)
import Control.Monad (when)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe qualified as BSU
import EventChain.Crypto.Internal.Error (CryptoError (..))
import EventChain.Crypto.Internal.Foreign
import EventChain.Crypto.Types.Internal.Bytes (SignedBytes, signedBytesRaw)
import EventChain.Crypto.Types.Internal.Key
    ( ClaimedKey
    , Sig
    , claimedKey
    , claimedKeyRaw
    , rawSigLength
    , sigFromRaw
    , sigRaw
    )
import Foreign.C.String (CString, withCString)
import Foreign.C.Types (CInt)
import Foreign.ForeignPtr (FinalizerPtr, ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (with)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (peek, poke)
import System.IO.Unsafe (unsafePerformIO)

-- Types ----------------------------------------------------------------------

{- | A public key proven to be a point on P-256.

Only this module can build one, and building one /is/ the proof: the 33 bytes
were decompressed, which cannot succeed for an @x@ with no @y@ on the curve.

Carries the t'ClaimedKey' it was promoted from — the fact is the claim plus the
check — and compares on that. Two 'PublicKey's are equal when they name the same
point, not when they are the same allocation.
-}
data PublicKey = PublicKey (ForeignPtr EVP_PKEY) ClaimedKey

instance Eq PublicKey where
    a == b = publicKeyClaim a == publicKeyClaim b

instance Ord PublicKey where
    compare a b = compare (publicKeyClaim a) (publicKeyClaim b)

instance Show PublicKey where
    show k = "PublicKey " <> show (publicKeyClaim k)

{- | A P-256 private key, and the public point that belongs to it.

No 'Show': this is the one secret in the system, and a type that prints itself
ends up in a log.

The point is carried because libcrypto will not derive it. Measured on 3.6.2:
@EVP_PKEY_fromdata@ given a scalar alone succeeds and signs correctly, but the
public-key parameter then reads back /absent/. A Producer restoring a key from a
stored scalar would be able to sign entries and unable to say which key signed
them. So 'privateKey' derives the point itself and 'privateKeyPublic' is total.
-}
data PrivateKey = PrivateKey (ForeignPtr EVP_PKEY) ClaimedKey

{- | Did a signature verify?

Not a t'Bool' (ADR-0003 rule 5). The difference that matters is not true/false —
it is that neither of these is an error. A signature that does not verify is a
fact about the entry; libcrypto failing to answer is a 'CryptoError'. Collapsing
them would report a broken installation as a forged AOF.
-}
data SigCheck
    = -- | The signature is the signer's, over exactly these bytes.
      SigValid
    | -- | It is not. Nothing is wrong except the claim.
      SigInvalid
    deriving stock (Eq, Show)

{- | The order of P-256's group, big-endian.

A private scalar must be in @[1, n-1]@. Because both this and a scalar are 32
big-endian bytes, the numeric comparison /is/ the lexicographic one, so the check
is a 'ByteString' comparison and needs no bignum and no FFI call.

Checked against @openssl ecparam -name prime256v1@ rather than recalled.
-}
p256Order :: ByteString
p256Order =
    BS.pack
        [ 0xFF
        , 0xFF
        , 0xFF
        , 0xFF
        , 0x00
        , 0x00
        , 0x00
        , 0x00
        , 0xFF
        , 0xFF
        , 0xFF
        , 0xFF
        , 0xFF
        , 0xFF
        , 0xFF
        , 0xFF
        , 0xBC
        , 0xE6
        , 0xFA
        , 0xAD
        , 0xA7
        , 0x17
        , 0x9E
        , 0x84
        , 0xF3
        , 0xB9
        , 0xCA
        , 0xC2
        , 0xFC
        , 0x63
        , 0x25
        , 0x51
        ]

-- | Bytes in a P-256 private scalar.
scalarLength :: Int
scalarLength = 32

-- Keys -----------------------------------------------------------------------

{- | Promote a claimed key to one proven on the curve.

The promotion is the decompression. A compressed point supplies only @x@; @y@ is
solved for, and roughly half of all @x@ have no solution — so a claim that
survives is on the curve by construction, not by a check bolted alongside.
@EVP_PKEY_public_check@ afterwards measures free and adds nothing here: P-256 has
cofactor 1, so its "full" check reduces to not-infinity, in-range and on-curve,
and a 33-byte encoding cannot be the point at infinity.
-}
publicKey :: ClaimedKey -> Either CryptoError PublicKey
publicKey claimed = unsafePerformIO $ do
    c_ERR_clear_error
    built <- buildParams $ \bld ->
        withNamed "group" $ \g ->
            withCString "prime256v1" $ \curve -> do
                okG <- c_OSSL_PARAM_BLD_push_utf8_string bld g curve 0
                okP <- withNamed "pub" $ \pubName ->
                    BSU.unsafeUseAsCStringLen (claimedKeyRaw claimed) $ \(p, n) ->
                        c_OSSL_PARAM_BLD_push_octet_string bld pubName (castPtr p) (fromIntegral n)
                pure (okG == 1 && okP == 1)
    case built of
        Nothing -> Left <$> openSslFailed
        Just params ->
            fromdata evpPkeyPublicKey params >>= \case
                -- fromdata's only plausible failure on 33 well-formed bytes is
                -- that they name no point. Any other cause would be a
                -- malfunction, and the error code is carried either way.
                Nothing -> pure (Left KeyNotOnCurve)
                Just k -> pure (Right (PublicKey k claimed))
{-# NOINLINE publicKey #-}

-- | The claim this key was promoted from.
publicKeyClaim :: PublicKey -> ClaimedKey
publicKeyClaim (PublicKey _ c) = c

-- | The key's compressed point bytes.
publicKeyRaw :: PublicKey -> ByteString
publicKeyRaw = claimedKeyRaw . publicKeyClaim

{- | Take 32 bytes as a private scalar, deriving the point that belongs to it.

Rejects zero and anything at or beyond the group order before touching libcrypto:
those are not private keys, and @EC_POINT_mul@ would reduce them modulo the order
rather than complain, silently signing as some other key.
-}
privateKey :: ByteString -> Either CryptoError PrivateKey
privateKey scalar
    | BS.length scalar /= scalarLength = Left (ScalarWrongLength (BS.length scalar))
    | BS.all (== 0) scalar = Left ScalarRejected
    | scalar >= p256Order = Left ScalarRejected
    | otherwise = unsafePerformIO $ do
        c_ERR_clear_error
        withBignum scalar $ \bn -> do
            derived <- derivePoint bn
            case derived of
                Left err -> pure (Left err)
                Right pt -> case claimedKey pt of
                    -- A 33-byte compressed point is what point2oct was asked
                    -- for; anything else means the scalar produced infinity.
                    Left _ -> pure (Left ScalarRejected)
                    Right claimed -> do
                        built <- buildParams $ \bld ->
                            withNamed "group" $ \g ->
                                withCString "prime256v1" $ \curve -> do
                                    okG <- c_OSSL_PARAM_BLD_push_utf8_string bld g curve 0
                                    okD <- withNamed "priv" $ \privName -> c_OSSL_PARAM_BLD_push_BN bld privName bn
                                    okP <- withNamed "pub" $ \pubName ->
                                        BSU.unsafeUseAsCStringLen pt $ \(p, n) ->
                                            c_OSSL_PARAM_BLD_push_octet_string bld pubName (castPtr p) (fromIntegral n)
                                    pure (okG == 1 && okD == 1 && okP == 1)
                        case built of
                            Nothing -> Left <$> openSslFailed
                            Just params ->
                                fromdata evpPkeyKeypair params >>= \case
                                    Nothing -> pure (Left ScalarRejected)
                                    Just k -> pure (Right (PrivateKey k claimed))
{-# NOINLINE privateKey #-}

-- | The public key that belongs to this private one. Total: it was derived at construction.
privateKeyPublic :: PrivateKey -> ClaimedKey
privateKeyPublic (PrivateKey _ pt) = pt

-- Signing --------------------------------------------------------------------

{- | Sign with a deterministic nonce, per RFC 6979.

Deterministic is the decision (ADR-0004), and it is also what makes this function
honest as a pure one: the same key and message give the same signature, always.
Verified against RFC 6979 §A.2.5, whose @r@ and @s@ this reproduces exactly.

@nonce-type@ = 1 selects it, and @digest@ must be set alongside or, in the
provider docs' words, "deterministic nonce generation will fail" — a failure mode
discovered by someone hitting it, not theorised.

Not batched: a Producer signs once per append, and the chain makes appends
sequential anyway. The batching rule is about the Verifier's hot path.
-}
sign :: PrivateKey -> SignedBytes -> Either CryptoError Sig
sign (PrivateKey pkey _) message = unsafePerformIO $ do
    c_ERR_clear_error
    built <- buildParams $ \bld -> do
        okN <- withNamed "nonce-type" $ \n -> c_OSSL_PARAM_BLD_push_uint bld n 1
        okD <- withNamed "digest" $ \d -> withCString "SHA256" $ \sha -> c_OSSL_PARAM_BLD_push_utf8_string bld d sha 0
        pure (okN == 1 && okD == 1)
    case built of
        Nothing -> Left <$> openSslFailed
        Just params -> withForeignPtr params $ \ps -> do
            ctx <- newMdCtx
            withForeignPtr ctx $ \c -> withForeignPtr pkey $ \k -> do
                ok <- withCString "SHA256" $ \md -> c_EVP_DigestSignInit_ex c nullPtr md nullPtr nullPtr k ps
                if ok /= 1
                    then Left <$> openSslFailed
                    else BSU.unsafeUseAsCStringLen (signedBytesRaw message) $ \(m, mlen) ->
                        alloca $ \lenPtr -> do
                            -- NULL output asks for the length; DER's is variable.
                            okLen <- c_EVP_DigestSign c nullPtr lenPtr (castPtr m) (fromIntegral mlen)
                            if okLen /= 1
                                then Left <$> openSslFailed
                                else do
                                    maxLen <- peek lenPtr
                                    der <- BSI.create (fromIntegral maxLen) $ \out -> do
                                        okS <- c_EVP_DigestSign c out lenPtr (castPtr m) (fromIntegral mlen)
                                        when (okS /= 1) $ error "EventChain.Crypto: EVP_DigestSign failed after sizing."
                                    actual <- peek lenPtr
                                    derToRaw (BS.take (fromIntegral actual) der)
{-# NOINLINE sign #-}

-- Verification ---------------------------------------------------------------

{- | Verify a chunk of (key, message, signature) triples.

Takes a chunk because ADR-0004 says the kernel API does. The chunk buys less here
than it does for hashing — an @EVP_MD_CTX@ per verify measures at 1.8%, and the
key, which is what actually costs, is already loaded. What a chunk does buy is a
shape the caller can parallelise over: signature checks dominate wall-clock at
scale, and one shared t'PublicKey' across a worker pool is measured at 7.8× on 8
threads.

Fails wholesale on a malfunction rather than per entry. libcrypto failing to
answer is not a fact about any one line, and reporting it as 'SigInvalid' would
be a fail-quiet: the AOF would be pronounced forged because our library broke.
-}
verifyBatch :: [(PublicKey, SignedBytes, Sig)] -> Either CryptoError [SigCheck]
verifyBatch [] = Right []
verifyBatch triples = unsafePerformIO $ do
    c_ERR_clear_error
    ctx <- newMdCtx
    withForeignPtr ctx $ \c -> traverseEither (verifyOne c) triples
{-# NOINLINE verifyBatch #-}

verifyOne :: Ptr EVP_MD_CTX -> (PublicKey, SignedBytes, Sig) -> IO (Either CryptoError SigCheck)
verifyOne ctx (PublicKey pkey _, message, signature) = do
    converted <- rawToDer (sigRaw signature)
    case converted of
        Left err -> pure (Left err)
        Right der -> withForeignPtr pkey $ \k -> do
            ok <- withCString "SHA256" $ \md -> c_EVP_DigestVerifyInit_ex ctx nullPtr md nullPtr nullPtr k nullPtr
            if ok /= 1
                then Left <$> openSslFailed
                else BSU.unsafeUseAsCStringLen der $ \(d, dlen) ->
                    BSU.unsafeUseAsCStringLen (signedBytesRaw message) $ \(m, mlen) -> do
                        r <- c_EVP_DigestVerify ctx (castPtr d) (fromIntegral dlen) (castPtr m) (fromIntegral mlen)
                        -- 1 valid, 0 invalid, negative a malfunction. Three outcomes.
                        case r of
                            1 -> pure (Right SigValid)
                            0 -> c_ERR_clear_error >> pure (Right SigInvalid)
                            _ -> Left <$> openSslFailed

-- Conversions ----------------------------------------------------------------

{- | Raw @r‖s@ to the DER libcrypto demands.

Ownership is the subtle part: @ECDSA_SIG_set0@ /takes/ both bignums on success, so
they must not also carry finalizers — that would free them twice. They are freed
by hand on the paths before the transfer, and by the signature's finalizer after
it. The whole sequence sits under 'mask_' so no abort can land between an
allocation and the thing that will own it.
-}
rawToDer :: ByteString -> IO (Either CryptoError ByteString)
rawToDer raw
    | BS.length raw /= rawSigLength = pure (Left SigOutOfRange)
    | otherwise = mask_ $ do
        r <- bin2bn (BS.take 32 raw)
        s <- bin2bn (BS.drop 32 raw)
        if r == nullPtr || s == nullPtr
            then do
                when (r /= nullPtr) (c_BN_free r)
                when (s /= nullPtr) (c_BN_free s)
                Left <$> openSslFailed
            else do
                sig <- c_ECDSA_SIG_new
                if sig == nullPtr
                    then c_BN_free r >> c_BN_free s >> (Left <$> openSslFailed)
                    else do
                        ok <- c_ECDSA_SIG_set0 sig r s
                        if ok /= 1
                            then do
                                c_BN_free r
                                c_BN_free s
                                c_ECDSA_SIG_free sig
                                Left <$> openSslFailed
                            else do
                                -- sig owns r and s from here.
                                owned <- newForeignPtr p_ECDSA_SIG_free sig
                                withForeignPtr owned $ \sp -> do
                                    len <- c_i2d_ECDSA_SIG sp nullPtr
                                    if len <= 0
                                        then Left <$> openSslFailed
                                        else do
                                            der <- BSI.create (fromIntegral len) $ \out ->
                                                with out $ \pp -> do
                                                    n <- c_i2d_ECDSA_SIG sp pp
                                                    when (n <= 0) $ error "EventChain.Crypto: i2d_ECDSA_SIG failed after sizing."
                                            pure (Right der)

{- | The DER libcrypto emits back to raw @r‖s@.

@BN_bn2binpad@ into exactly 32 bytes is the range check: it returns -1 rather than
truncating, so an @r@ or @s@ too large to be P-256's is caught here.
-}
derToRaw :: ByteString -> IO (Either CryptoError Sig)
derToRaw der = mask_ $
    BSU.unsafeUseAsCStringLen der $ \(d, dlen) ->
        with (ConstBytes (castPtr d)) $ \pp -> do
            sig <- c_d2i_ECDSA_SIG nullPtr pp (fromIntegral dlen)
            if sig == nullPtr
                then Left <$> openSslFailed
                else do
                    owned <- newForeignPtr p_ECDSA_SIG_free sig
                    withForeignPtr owned $ \sp -> do
                        r <- c_ECDSA_SIG_get0_r sp
                        s <- c_ECDSA_SIG_get0_s sp
                        raw <- BSI.create rawSigLength $ \out -> do
                            okR <- c_BN_bn2binpad r out 32
                            okS <- c_BN_bn2binpad s (out `plusPtr` 32) 32
                            when (okR < 0 || okS < 0) $ error "EventChain.Crypto: r or s exceeds 32 bytes."
                        pure (either (const (Left SigOutOfRange)) Right (sigFromRaw raw))

-- Plumbing -------------------------------------------------------------------

-- | @generator * scalar@, encoded compressed. The point libcrypto will not derive.
derivePoint :: Ptr BIGNUM -> IO (Either CryptoError ByteString)
derivePoint bn = do
    group <- own "EC_GROUP_new_by_curve_name" (c_EC_GROUP_new_by_curve_name nidP256) p_EC_GROUP_free
    withForeignPtr group $ \g -> do
        point <- own "EC_POINT_new" (c_EC_POINT_new g) p_EC_POINT_free
        withForeignPtr point $ \pt -> do
            ok <- c_EC_POINT_mul g pt bn nullPtr nullPtr nullPtr
            if ok /= 1
                then Left <$> openSslFailed
                else do
                    len <- c_EC_POINT_point2oct g pt pointConversionCompressed nullPtr 0 nullPtr
                    if len == 0
                        then Left <$> openSslFailed
                        else do
                            out <- BSI.create (fromIntegral len) $ \buf -> do
                                n <- c_EC_POINT_point2oct g pt pointConversionCompressed buf len nullPtr
                                when (n == 0) $ error "EventChain.Crypto: EC_POINT_point2oct failed after sizing."
                            pure (Right out)

-- | Build an @OSSL_PARAM@ array, or 'Nothing' if any push failed.
buildParams :: (Ptr OSSL_PARAM_BLD -> IO Bool) -> IO (Maybe (ForeignPtr OSSL_PARAM))
buildParams push = do
    bld <- own "OSSL_PARAM_BLD_new" c_OSSL_PARAM_BLD_new p_OSSL_PARAM_BLD_free
    withForeignPtr bld $ \b -> do
        ok <- push b
        if not ok
            then pure Nothing
            else do
                params <- c_OSSL_PARAM_BLD_to_param b
                if params == nullPtr
                    then pure Nothing
                    else Just <$> newForeignPtr p_OSSL_PARAM_free params

-- | @EVP_PKEY_fromdata@ against a fresh EC context.
fromdata :: CInt -> ForeignPtr OSSL_PARAM -> IO (Maybe (ForeignPtr EVP_PKEY))
fromdata selection params = do
    ctx <- own "EVP_PKEY_CTX_new_from_name" (withCString "EC" $ \n -> c_EVP_PKEY_CTX_new_from_name nullPtr n nullPtr) p_EVP_PKEY_CTX_free
    withForeignPtr ctx $ \c -> withForeignPtr params $ \ps -> do
        okInit <- c_EVP_PKEY_fromdata_init c
        if okInit /= 1
            then pure Nothing
            else alloca $ \out -> do
                poke out nullPtr
                ok <- c_EVP_PKEY_fromdata c out selection ps
                k <- peek out
                if ok /= 1 || k == nullPtr
                    then pure Nothing
                    else Just <$> newForeignPtr p_EVP_PKEY_free k

-- | A digest context of our own. Mutable, so never shared.
newMdCtx :: IO (ForeignPtr EVP_MD_CTX)
newMdCtx = own "EVP_MD_CTX_new" c_EVP_MD_CTX_new p_EVP_MD_CTX_free

{- | Allocate a C object and hand its release to the garbage collector.

'mask_' spans the allocation and the finalizer being attached: an abort in that
window would strand a pointer nothing would ever free.
-}
own :: String -> IO (Ptr a) -> FinalizerPtr a -> IO (ForeignPtr a)
own what new free = mask_ $ do
    p <- new
    when (p == nullPtr) $ error ("EventChain.Crypto: " <> what <> " returned NULL (out of memory).")
    newForeignPtr free p

-- | A scalar as a bignum, released when the action returns.
withBignum :: ByteString -> (Ptr BIGNUM -> IO a) -> IO a
withBignum bs act = do
    bn <- own "BN_bin2bn" (bin2bn bs) p_BN_free
    withForeignPtr bn act

bin2bn :: ByteString -> IO (Ptr BIGNUM)
bin2bn bs = BSU.unsafeUseAsCStringLen bs $ \(p, n) -> c_BN_bin2bn (castPtr p) (fromIntegral n) nullPtr

-- | An @OSSL_PARAM@ name. All of them are ASCII literals from OpenSSL's headers.
withNamed :: String -> (CString -> IO a) -> IO a
withNamed = withCString

-- | Drain the error queue into a 'CryptoError'.
openSslFailed :: IO CryptoError
openSslFailed = OpenSslFailed . fromIntegral <$> c_ERR_get_error

-- | 'traverse' that stops at the first 'Left', without pulling in a transformer.
traverseEither :: (a -> IO (Either e b)) -> [a] -> IO (Either e [b])
traverseEither f = go []
  where
    go acc [] = pure (Right (reverse acc))
    go acc (x : xs) =
        f x >>= \case
            Left e -> pure (Left e)
            Right y -> go (y : acc) xs
