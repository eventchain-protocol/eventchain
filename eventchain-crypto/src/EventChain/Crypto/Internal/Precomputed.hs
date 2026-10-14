{- | ECDSA-P256 verification from a precomputed key: the fixed-base kernel.

An AOF is runs of one Producer's key, so the Verifier checks thousands of
signatures against a point it has already seen. @EVP_PKEY_verify@ cannot use
that: each call is a general scalar multiplication of the key. A table of the
key's multiples, built once, turns @u1·G + u2·Q@ into two table walks with no
doublings at all — and the walk, @p256_scalarmulbase@, is s2n-bignum's, with a
machine-checked proof against the object code (ADR-0004 as amended).

== What is measured

On this project's dev machine, 2026-10-14, mains power: libcrypto's verify at
32–33 µs; this kernel at 14.5 µs in C and the same table geometry, with the
table ~500 µs per key. Zero disagreements with libcrypto on 10,000 valid,
10,000 tampered and five crafted edge-case signatures. The Haskell numbers are
the crypto bench's to record, not this comment's.

== Table geometry

Blocksize 7: the scalar is consumed seven bits at a time, 37 blocks for 256 bits
plus the carry, and each block holds the 64 multiples @2^(7i)·j·P@ for
@j = 1..64@ in Montgomery-affine form, laid out exactly as @p256_scalarmulbase@
documents them. The other half of each block's digits comes from negating a
stored entry, which the walk does itself. 151 552 bytes per key, and one more
for the generator, built on first use. Measured in C against blocksizes 4–8:
7 is the fastest walk; 8 loses it to the cache.

== What the proofs say, and where this module relies on it

Every function called here carries a HOL Light proof in upstream's
@arm/proofs/@. The ones with preconditions:

* @p256_montjmixadd@ is proven for a Jacobian @p1@ that may be infinity and an
  affine @p2@ that cannot be, provided @p1 ≠ p2@. In the table build, @p1@ is
  @j·P@ for @j ≥ 2@ and @p2@ is @P@, never equal for a point of prime order. In
  the final sum, @u1·G@ and @u2·Q@ are compared first; equal goes to the
  doubling, opposite is infinity and the signature is invalid.
* @p256_scalarmulbase@ is proven for any scalar, reducing it mod @n@ itself,
  and encodes infinity as @(0, 0)@. The @u1 = 0@ case is handled before the
  walk rather than by decoding that.
* @bignum_montinv_p256@ returns zero for zero, which is why the result's @Z@ is
  tested before inverting it.

== Constant time, and who may not rely on it

The walk is the one s2n-bignum ships for secret scalars, so it is constant-time
by construction. Nothing here needs that: every scalar a verifier handles is
public. The Producer must never reach for this module with a private scalar —
it signs through libcrypto, and nothing here offers it a signing primitive.

== Why the result is a list and not an 'Either'

'EventChain.Crypto.Internal.Ecdsa.verifyBatch' answers in 'Either' because libcrypto can fail to answer. Nothing
here can: there is no allocation after the scratch buffer, no error queue, and
no call that returns a status. A signature either verifies or does not. The
one invariant that cannot be violated by any input — @u2 = r/s@ reducing to
zero — is an 'error', because reaching it would mean the arithmetic is wrong.
-}
module EventChain.Crypto.Internal.Precomputed
    ( PrecomputedKey
    , precomputeKey
    , precomputedKeyPublic
    , verifyBatchPrecomputed
    ) where

import Control.Monad (forM_, when)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Unsafe qualified as BSU
import Data.Word (Word64)
import EventChain.Crypto.Internal.Digest (digestChunk)
import EventChain.Crypto.Internal.Ecdsa (PublicKey, SigCheck (..), publicKeyPoint)
import EventChain.Crypto.Internal.Foreign
import EventChain.Crypto.Types.Internal.Bytes (SignedBytes, signedBytesRaw)
import EventChain.Crypto.Types.Internal.Key (Sig, sigRaw)
import Foreign.ForeignPtr (ForeignPtr, mallocForeignPtrBytes, withForeignPtr)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (pokeArray)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)

-- Types ----------------------------------------------------------------------

{- | A public key and the table of its multiples.

Compares and shows as the 'PublicKey' it was built from: the table is a
function of the point, so two tables for one point are one key. The point was
proven on the curve when the 'PublicKey' was promoted; the table adds speed and
no fact.
-}
data PrecomputedKey = PrecomputedKey (ForeignPtr Word64) PublicKey

instance Eq PrecomputedKey where
    a == b = precomputedKeyPublic a == precomputedKeyPublic b

instance Ord PrecomputedKey where
    compare a b = compare (precomputedKeyPublic a) (precomputedKeyPublic b)

instance Show PrecomputedKey where
    show k = "PrecomputedKey " <> show (precomputedKeyPublic k)

-- | The key the table was built for.
precomputedKeyPublic :: PrecomputedKey -> PublicKey
precomputedKeyPublic (PrecomputedKey _ k) = k

-- Geometry -------------------------------------------------------------------

-- | Bits of scalar per table block.
blocksize :: Word64
blocksize = 7

-- | Stored multiples per block: @2^(blocksize - 1)@. The rest are negations.
entriesPerBlock :: Int
entriesPerBlock = 64

-- | Blocks: every @i@ with @blocksize * i <= 256@.
blocks :: Int
blocks = 37

tableEntries :: Int
tableEntries = blocks * entriesPerBlock

-- | Bytes in one field element, affine point, Jacobian point.
limb, affine, jacobian :: Int
limb = 32
affine = 64
jacobian = 96

-- Tables ---------------------------------------------------------------------

{- | Build the table for a key. ~500 µs of curve arithmetic in C; see the bench
for what the same loop costs from here.
-}
precomputeKey :: PublicKey -> PrecomputedKey
precomputeKey key = unsafePerformIO $ do
    let (x, y) = publicKeyPoint key
    tab <- buildTable x y
    pure (PrecomputedKey tab key)
{-# NOINLINE precomputeKey #-}

-- | The generator's table, built on first use and shared by every verify.
generatorTable :: ForeignPtr Word64
generatorTable = unsafePerformIO (buildTable generatorX generatorY)
{-# NOINLINE generatorTable #-}

-- | P-256's generator, as the standard prints it. Any slip here fails every known answer.
generatorX, generatorY :: ByteString
generatorX = BS.pack [0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96]
generatorY = BS.pack [0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5]

{- | The group order @n@ as limbs, pinned once: the range check's right-hand side.

The same constant the signing side keeps as bytes; here it is compared by
@bignum_lt@, which wants limbs.
-}
groupOrder :: ForeignPtr Word64
groupOrder = unsafePerformIO $ do
    p <- mallocForeignPtrBytes limb
    withForeignPtr p $ \q -> pokeArray q [0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000]
    pure p
{-# NOINLINE groupOrder #-}

-- | One, in Montgomery form: the @Z@ of an affine point lifted to Jacobian.
montgomeryOne :: ForeignPtr Word64
montgomeryOne = unsafePerformIO $ do
    p <- mallocForeignPtrBytes limb
    withForeignPtr p $ \q -> allocaBytes limb $ \one -> do
        pokeArray one [1, 0, 0, 0]
        c_bignum_tomont_p256 q one
    pure p
{-# NOINLINE montgomeryOne #-}

{- | The table of a point's multiples, from its affine coordinates.

Each block's 64 entries are accumulated in Jacobian form by one doubling and
62 mixed additions of the block base, then the next block's base is one more
doubling of the last. Every entry is then made affine at once: one field
inversion for the whole table by Montgomery's trick, plus two per block for
the base's own affine copy, against the 2 368 a naive build would pay.
-}
buildTable :: ByteString -> ByteString -> IO (ForeignPtr Word64)
buildTable xBytes yBytes = do
    tab <- mallocForeignPtrBytes (tableEntries * affine)
    withForeignPtr tab $ \t ->
        withForeignPtr montgomeryOne $ \one ->
            allocaBytes (tableEntries * jacobian) $ \jac ->
                allocaBytes (tableEntries * limb) $ \acc ->
                    allocaBytes (16 * limb) $ \scratch -> do
                        let at :: Ptr Word64 -> Int -> Ptr Word64
                            at p k = p `plusPtr` k
                            base = scratch
                            baseAffine = scratch `at` jacobian
                            raw = scratch `at` (jacobian + affine)
                            z2 = raw `at` limb
                            z3 = z2 `at` limb
                            zi = z3 `at` limb
                            zi2 = zi `at` limb
                            zi3 = zi2 `at` limb
                            inv = zi3 `at` limb
                            tmp = inv `at` limb
                            jacAt k = jac `at` (k * jacobian)
                            zOf k = jacAt k `at` affine
                            entry k = t `at` (k * affine)

                        -- base = (x, y, 1) in Montgomery-Jacobian.
                        BSU.unsafeUseAsCString xBytes $ \p -> c_bignum_frombebytes_4 raw (castPtr p)
                        c_bignum_tomont_p256 base raw
                        BSU.unsafeUseAsCString yBytes $ \p -> c_bignum_frombebytes_4 raw (castPtr p)
                        c_bignum_tomont_p256 (base `at` limb) raw
                        copyBytes (base `at` affine) one limb

                        forM_ [0 .. blocks - 1] $ \i -> do
                            let blk = i * entriesPerBlock
                            -- The block base, affine, for the mixed additions.
                            c_bignum_montsqr_p256 z2 (base `at` affine)
                            c_bignum_montinv_p256 zi z2
                            c_bignum_montmul_p256 baseAffine base zi
                            c_bignum_montmul_p256 z3 z2 (base `at` affine)
                            c_bignum_montinv_p256 zi z3
                            c_bignum_montmul_p256 (baseAffine `at` limb) (base `at` limb) zi
                            -- j = 1 is the base; j = 2 is a doubling, never a mixed add of equals.
                            copyBytes (jacAt blk) base jacobian
                            c_p256_montjdouble (jacAt (blk + 1)) base
                            forM_ [2 .. entriesPerBlock - 1] $ \j ->
                                c_p256_montjmixadd (jacAt (blk + j)) (jacAt (blk + j - 1)) baseAffine
                            -- 2 * (64 * P_i) = 2^7 * P_i: the next block's base.
                            c_p256_montjdouble base (jacAt (blk + entriesPerBlock - 1))

                        -- Montgomery's trick over every Z: acc_k = Z_0 * ... * Z_(k-1).
                        copyBytes acc one limb
                        forM_ [1 .. tableEntries - 1] $ \k ->
                            c_bignum_montmul_p256 (acc `at` (k * limb)) (acc `at` ((k - 1) * limb)) (zOf (k - 1))
                        c_bignum_montmul_p256 tmp (acc `at` ((tableEntries - 1) * limb)) (zOf (tableEntries - 1))
                        c_bignum_montinv_p256 inv tmp
                        forM_ [tableEntries - 1, tableEntries - 2 .. 0] $ \k -> do
                            c_bignum_montmul_p256 zi inv (acc `at` (k * limb)) -- 1 / Z_k
                            c_bignum_montmul_p256 tmp inv (zOf k) -- drop Z_k from the running inverse
                            copyBytes inv tmp limb
                            c_bignum_montsqr_p256 zi2 zi
                            c_bignum_montmul_p256 zi3 zi2 zi
                            c_bignum_montmul_p256 (entry k) (jacAt k) zi2
                            c_bignum_montmul_p256 (entry k `at` limb) (jacAt k `at` limb) zi3
    pure tab

-- Verification ---------------------------------------------------------------

{- | Verify a chunk of (precomputed key, message, signature) triples.

The chunk shape is that of 'EventChain.Crypto.Internal.Ecdsa.verifyBatch': messages prehashed through the batched
SHA-256 kernel, one scratch buffer for the whole chunk, one answer per triple
in order. What it does not need is the per-run context: the table /is/ the
per-key state, and it was built when the key was.
-}
verifyBatchPrecomputed :: [(PrecomputedKey, SignedBytes, Sig)] -> [SigCheck]
verifyBatchPrecomputed [] = []
verifyBatchPrecomputed triples = unsafePerformIO $
    withForeignPtr generatorTable $ \tabG ->
        withForeignPtr groupOrder $ \n ->
            withForeignPtr montgomeryOne $ \one ->
                allocaBytes (32 * limb) $ \scratch -> do
                    let digests = digestChunk [signedBytesRaw m | (_, m, _) <- triples]
                        go acc [] = pure (reverse acc)
                        go acc (((PrecomputedKey tabQ _, _, signature), digest) : rest) = do
                            !answer <- withForeignPtr tabQ $ \tq -> verifyOne scratch n one tabG tq digest (sigRaw signature)
                            go (answer : acc) rest
                    go [] (zip triples digests)
{-# NOINLINE verifyBatchPrecomputed #-}

{- | One signature against one table.

Standard ECDSA: @w = s^-1@, @u1 = e·w@, @u2 = r·w@, @R = u1·G + u2·Q@, valid
when @R@ is finite and @x(R) mod n = r@. Range checks first: @r@ and @s@ in
@[1, n-1]@, which libcrypto also enforces and the differential suite relies on
both sides agreeing about.
-}
verifyOne :: Ptr Word64 -> Ptr Word64 -> Ptr Word64 -> Ptr Word64 -> Ptr Word64 -> ByteString -> ByteString -> IO SigCheck
verifyOne scratch n one tabG tabQ digest signature = do
    let at :: Ptr Word64 -> Int -> Ptr Word64
        at p k = p `plusPtr` k
        r = scratch
        s = r `at` limb
        eRaw = s `at` limb
        e = eRaw `at` limb
        w = e `at` limb
        u1 = w `at` limb
        u2 = u1 `at` limb
        prod = u2 `at` limb -- 8 limbs
        t = prod `at` (2 * limb) -- 12 limbs of modinv scratch
        r1 = t `at` (3 * limb) -- affine u1·G
        r2 = r1 `at` affine -- affine u2·Q
        p1 = r2 `at` affine -- Jacobian u1·G
        p2 = p1 `at` jacobian -- Montgomery-affine u2·Q
        p3 = p2 `at` affine -- Jacobian sum
        z2 = p3 `at` jacobian
        zi = z2 `at` limb
        xm = zi `at` limb
        x = xm `at` limb
        xr = x `at` limb

    BSU.unsafeUseAsCString signature $ \p -> do
        c_bignum_frombebytes_4 r (castPtr p)
        c_bignum_frombebytes_4 s (castPtr p `plusPtr` 32)
    BSU.unsafeUseAsCString digest $ \p -> c_bignum_frombebytes_4 eRaw (castPtr p)

    rNonzero <- c_bignum_nonzero_4 r
    sNonzero <- c_bignum_nonzero_4 s
    rBelow <- c_bignum_lt 4 r 4 n
    sBelow <- c_bignum_lt 4 s 4 n
    if rNonzero == 0 || sNonzero == 0 || rBelow == 0 || sBelow == 0
        then pure SigInvalid
        else do
            c_bignum_mod_n256_4 e eRaw
            c_bignum_modinv 4 w s n t
            c_bignum_mul_4_8 prod e w
            c_bignum_mod_n256 u1 8 prod
            c_bignum_mul_4_8 prod r w
            c_bignum_mod_n256 u2 8 prod

            u2Nonzero <- c_bignum_nonzero_4 u2
            when (u2Nonzero == 0) $ error "EventChain.Crypto: u2 = r/s reduced to zero for r, s in [1, n-1]."
            c_p256_scalarmulbase r2 u2 blocksize tabQ
            c_bignum_tomont_p256 p2 r2
            c_bignum_tomont_p256 (p2 `at` limb) (r2 `at` limb)

            u1Nonzero <- c_bignum_nonzero_4 u1
            summed <-
                if u1Nonzero == 0
                    then do
                        -- u1·G is infinity: the sum is u2·Q, lifted to Jacobian.
                        copyBytes p3 p2 affine
                        copyBytes (p3 `at` affine) one limb
                        pure True
                    else do
                        c_p256_scalarmulbase r1 u1 blocksize tabG
                        c_bignum_tomont_p256 p1 r1
                        c_bignum_tomont_p256 (p1 `at` limb) (r1 `at` limb)
                        copyBytes (p1 `at` affine) one limb
                        sameX <- c_bignum_eq 4 r1 4 r2
                        if sameX == 0
                            then c_p256_montjmixadd p3 p1 p2 >> pure True
                            else do
                                sameY <- c_bignum_eq 4 (r1 `at` limb) 4 (r2 `at` limb)
                                if sameY == 0
                                    then pure False -- u1·G = -(u2·Q): the sum is infinity
                                    else c_p256_montjdouble p3 p1 >> pure True
            if not summed
                then pure SigInvalid
                else do
                    zNonzero <- c_bignum_nonzero_4 (p3 `at` affine)
                    if zNonzero == 0
                        then pure SigInvalid
                        else do
                            c_bignum_montsqr_p256 z2 (p3 `at` affine)
                            c_bignum_montinv_p256 zi z2
                            c_bignum_montmul_p256 xm p3 zi
                            c_bignum_demont_p256 x xm
                            c_bignum_mod_n256_4 xr x
                            same <- c_bignum_eq 4 xr 4 r
                            pure (if same /= 0 then SigValid else SigInvalid)
