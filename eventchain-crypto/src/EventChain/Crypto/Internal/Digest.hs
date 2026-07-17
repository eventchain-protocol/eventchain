{- | SHA-256 over a chunk of things, at libcrypto's speed.

The API takes chunks and never single values (ADR-0004), and the measurements say
why. On this project's dev machine, at a ~300-byte line:

* one @EVP_MD_CTX@ and one fetched @EVP_MD@, reused across the chunk: __101 ns/line__ (2.97 GB/s)
* the obvious one-shot @EVP_Digest@ per line: __228 ns/line__ (1.32 GB/s)

That 2.3× is what a chunk buys, and it is context and algorithm reuse rather than
call overhead — an @unsafe@ foreign call is ~7.5 ns, which at 101 ns of work is
real but not the story. ADR-0004 reasoned from call overhead and reached the right
answer for an adjacent reason.

Hashing is pure, and says so. SHA-256 of some bytes is a function; wrapping it in
'IO' would put an effect on something that has none and infect every caller — the
Verifier's fold most of all, which @docs/plan.md@ requires be pure. The escape is
'unsafePerformIO' and not the dupable variant: this allocates a C object, and
duplicating the work would build two where one was wanted. The cost is one
@noDuplicate#@ per /chunk/.

Nothing here can fail on the caller's input. Any 'ByteString' has a SHA-256. If
libcrypto cannot fetch SHA-256 at all the installation is broken, which is not a
condition to thread through every signature as an 'Either' — so 'sha256' throws,
loudly, once, at first use.
-}
module EventChain.Crypto.Internal.Digest
    ( hashLines
    , hashPayloads
    ) where

import Control.Exception (mask_)
import Control.Monad (unless, when)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe qualified as BSU
import EventChain.Crypto.Internal.Foreign
import EventChain.Crypto.Types.Internal.Bytes (LineBytes, PayloadBytes, lineBytesRaw, payloadBytesRaw)
import EventChain.Crypto.Types.Internal.Hash (LineHash (..), PayloadHash (..), sha256Length)
import Foreign.C.String (withCString)
import Foreign.C.Types (CInt, CUInt)
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import System.IO.Unsafe (unsafePerformIO)

{- | The SHA-256 algorithm object, fetched once for the life of the process.

An @EVP_MD@ is immutable once fetched, so one is enough and sharing it is what
libcrypto intends — cardano-base holds its @secp256k1@ context exactly this way.
@NOINLINE@ is what makes "once" true: without it GHC may duplicate the CAF and
fetch repeatedly, which is the entire cost this avoids. 'mask_' closes the window
between the fetch and the finalizer, where an abort would strand the object.

Throws if SHA-256 is unavailable. That is a broken libcrypto, not an input.
-}
sha256 :: ForeignPtr EVP_MD
sha256 = unsafePerformIO . mask_ $ do
    md <- withCString "SHA256" $ \name -> c_EVP_MD_fetch nullPtr name nullPtr
    when (md == nullPtr) $
        error "EventChain.Crypto: libcrypto cannot fetch SHA256. The installation is broken."
    newForeignPtr c_EVP_MD_free md
{-# NOINLINE sha256 #-}

{- | Below this many bytes, an update is an @unsafe@ call.

An @unsafe@ call cannot be preempted and holds its capability until it returns,
so the length of the buffer decides the length of a garbage-collection stall —
and __an AOF line's length is chosen by whoever wrote the file__. The Verifier
reads files strangers wrote, so an unbounded @unsafe@ update would hand a
stranger a lever on our runtime: a single 1 GB line would pin a capability for
about half a second.

Above the threshold the call is @safe@, costing ~89 ns to release and reacquire
the capability — which against ~340 µs of hashing for 1 MB is nothing. Below it,
~7.5 ns against ~100 ns is worth having. @cryptohash-sha256@ draws the same line
at the same place; crypton, whose update also takes a caller-sized buffer, simply
marks it @safe@ always.
-}
safeUpdateThreshold :: Int
safeUpdateThreshold = 4096

-- | SHA-256 of each Entry's line bytes. The digests are independent; only the caller's chain is not.
hashLines :: [LineBytes] -> [LineHash]
hashLines = map LineHash . digestChunk . map lineBytesRaw

-- | SHA-256 of each Payload's content.
hashPayloads :: [PayloadBytes] -> [PayloadHash]
hashPayloads = map PayloadHash . digestChunk . map payloadBytesRaw

{- | The kernel: one context and one algorithm, reused down the chunk.

The context is reset per item rather than rebuilt, which is the whole point.
-}
digestChunk :: [ByteString] -> [ByteString]
digestChunk [] = []
digestChunk inputs = unsafePerformIO $ do
    ctx <- mask_ $ do
        p <- c_EVP_MD_CTX_new
        when (p == nullPtr) $ error "EventChain.Crypto: EVP_MD_CTX_new failed (out of memory)."
        newForeignPtr p_EVP_MD_CTX_free p
    withForeignPtr sha256 $ \md ->
        withForeignPtr ctx $ \c ->
            mapM (digestOne c md) inputs

-- | One digest into a freshly allocated, Haskell-owned 32 bytes.
digestOne :: Ptr EVP_MD_CTX -> Ptr EVP_MD -> ByteString -> IO ByteString
digestOne ctx md input = do
    ok <- c_EVP_DigestInit_ex2 ctx md nullPtr
    check "EVP_DigestInit_ex2" ok

    unless (BS.null input) $
        BSU.unsafeUseAsCStringLen input $ \(p, len) -> do
            let update = if len < safeUpdateThreshold then c_EVP_DigestUpdate else c_EVP_DigestUpdate_safe
            check "EVP_DigestUpdate" =<< update ctx (castPtr p) (fromIntegral len)

    -- The output buffer is ours, and C only fills it: bytestring's own shape for
    -- exactly this, and the reason no C allocation is involved in the answer.
    BSI.create sha256Length $ \out ->
        alloca $ \lenPtr -> do
            check "EVP_DigestFinal_ex" =<< c_EVP_DigestFinal_ex ctx out (lenPtr :: Ptr CUInt)

{- | libcrypto returning 0 from a digest call is a malfunction, not a verdict.

There is no input that makes SHA-256 fail, so this cannot be reached by anything
a caller wrote. Reaching it means libcrypto is broken, and a broken hash is not
something to return an 'Either' about — every chain hash in the file would be
wrong and silence would be the worst outcome.
-}
check :: String -> CInt -> IO ()
check what ok =
    when (ok /= 1) $ do
        code <- c_ERR_get_error
        error $ "EventChain.Crypto: " <> what <> " failed (OpenSSL error " <> show code <> ")."
