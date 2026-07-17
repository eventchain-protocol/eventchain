{- | What the kernels actually run at, on this machine, compiled.

Not a test, and deliberately not a gate. Throughput is a property of the machine
it is measured on, so a pass\/fail threshold in a suite would fail on a slower
box and say nothing true. ADR-0004's baselines were recorded as artifacts rather
than assertions, and these are recorded the same way — in
@docs\/research\/@, next to the numbers they are compared against.

Run it with @cabal run eventchain-crypto:bench@. It must be compiled: the same
loop under @cabal repl@ measures ~28x slower, because bytecode is not what ships.
-}
module Main (main) where

import Control.Exception (evaluate)
import Control.Monad (forM_)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C8
import Data.Time.Clock (diffUTCTime, getCurrentTime)
import EventChain.Crypto
import EventChain.Crypto.Types
import Text.Printf (printf)

main :: IO ()
main = do
    let sk = expect (privateKey (BS.pack ([1 .. 31] <> [7])))
        pub = expect (publicKey (privateKeyPublic sk))
        msg = signedBytes (C8.replicate 300 'x')
        sig = expect (sign sk msg)
        line = expect (lineBytes (C8.replicate 300 'x'))
        -- Forced before the clock starts: an unforced `replicate` would be
        -- built inside the timed region and billed to the kernel.
        chunk = replicate 200000 line

    _ <- evaluate (length chunk)

    printf "%-22s %14s %14s\n" "kernel" "measured" "floor"

    -- Chain hashing: one chunk, AOF-sized lines. Each digest is forced to
    -- WHNF, not just the spine -- the spine alone would let result
    -- construction escape the clock.
    hashRate <- time 200000 (evaluate (foldl' (\ !a h -> h `seq` a) () (hashLines chunk)))
    printf "%-22s %10.2f GB/s %9.2f GB/s\n" "hash 300B lines" (hashRate * 300 / 1e9) (1.6 :: Double)

    -- The hot kernel. One key, loaded once -- which is the whole design.
    verifyRate <- time 5000 (evaluate (verifyBatch (replicate 5000 (pub, msg, sig))))
    printf "%-22s %10.0f /s   %9.0f /s\n" "verify (1 core)" verifyRate (24500 :: Double)

    signRate <- time 2000 (forM_ [1 .. 2000 :: Int] $ \i -> evaluate (sign sk (signedBytes (C8.pack (show i)))))
    printf "%-22s %10.0f /s   %9s\n" "sign (RFC 6979)" signRate "-"

    putStrLn ""
    putStrLn "Floors are ADR-0004's baselines (30.6k verify/s/core, ~2 GB/s) less 20%."

-- | Operations per second, for an action doing @n@ of them.
time :: Int -> IO a -> IO Double
time n act = do
    t0 <- getCurrentTime
    _ <- act
    t1 <- getCurrentTime
    pure (fromIntegral n / realToFrac (diffUTCTime t1 t0))

expect :: (Show e) => Either e a -> a
expect (Right a) = a
expect (Left e) = error ("benchmark setup failed: " <> show e)
