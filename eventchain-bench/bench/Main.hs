{- | What the Verifier runs at, end to end, on this machine, compiled.

Not a test, and deliberately not a gate. Throughput is a property of the
machine it is measured on, so a pass\/fail threshold would fail on a slower box
and say nothing true. The numbers are recorded in @docs\/research\/@ next to the
kernel baselines they are compared against.

Three rows, because the question a parallel Verifier raises is which stage
is the ceiling once signatures are spread across cores:

* /decode/ — framing, the token fold, base64, and the canonical bytes a
  signature is checked over. Everything the fold does to a line that is not
  crypto, run sequentially.
* /signatures/ — the signature kernel alone over this file's own keys,
  messages and signatures, one chunk after another: what one thread of
  libcrypto costs on these lines, measured in the same process and minutes
  as the row below it.
* /verify/ — the whole fold, every verdict forced, on as many capabilities as
  the RTS was given. Capabilities are not cores: the signature check is a
  @safe@ foreign call, so even @-N1@ overlaps libcrypto with the next chunk's
  work. The two rows above are the sequential references; this one is never
  sequential.

Run it with @cabal run eventchain-bench:verify@, then again with
@-- +RTS -N@ to see what the cores add. It must be compiled: the same fold
under @cabal repl@ measures many times slower, because bytecode is not what
ships.
-}
module Main (main) where

import Control.Exception (evaluate)
import Data.ByteString qualified as BS
import Data.ByteString.Builder qualified as B
import Data.ByteString.Lazy qualified as LBS
import Data.Text qualified as T
import Data.Time.Clock (diffUTCTime, getCurrentTime)
import EventChain (ChainedEvent (..), EventKind (..), ProducedLine (..), entryId, genesisHash, payloadRef, produce)
import EventChain.Crypto (PrivateKey, PublicKey, SigCheck, privateKey, privateKeyPublic, publicKey, verifyBatch)
import EventChain.Crypto.Types (LineHash, Sig, SignedBytes, lineBytesRaw, payloadHashFromBytes)
import EventChain.Verify (Verdict (..), verify)
import EventChain.Verify.Canonical (canonicalBytesRaw, canonicalize, signingMessage)
import EventChain.Verify.Types (Entry (..), ProducedProof (..))
import EventChain.Verify.Wire (decodeLine, decodedEntry, decodedObject, frameFile)
import GHC.Conc (numCapabilities)
import Text.Printf (printf)

{- | Lines in the measured file.

Enough chunks that a dozen workers' last round is a small fraction of the
run: at 256 lines a chunk this is ~390 chunks, and the idle tail of the final
round costs ~2% rather than the ~10% it cost at 20k lines.
-}
lineCount :: Int
lineCount = 100000

main :: IO ()
main = do
    let file = aof lineCount
    size <- evaluate (LBS.length file)
    printf "%d lines, %d bytes, %d capabilities\n\n" lineCount size numCapabilities
    printf "%-22s %12s %14s\n" "stage" "µs/line" "lines/s"

    -- Everything but the crypto: frame, decode, canonicalize. Each line's
    -- canonical bytes are forced, so the Builder and the copy out of it are
    -- inside the clock, as they are inside the fold.
    decodePerLine <- perLine (evaluate (foldl' (\n bs -> BS.length bs `seq` n + 1) (0 :: Int) (decodedCanonical file)))
    row "decode, sequential" decodePerLine

    -- The signature kernel alone, over this file's own keys, messages and
    -- signatures, in the fold's chunk size, one chunk after another.
    let triples = signatureTriples file
    _ <- evaluate (length triples)
    sigPerLine <- perLine (evaluate (foldl' (\n c -> c `seq` n + 1) (0 :: Int) (concatMap batch (chunksOf 256 triples))))
    row "signatures, sequential" sigPerLine

    -- The fold. Forcing a verdict to WHNF forces every check behind it, so the
    -- count is also the proof that the work happened — and a file this bench
    -- wrote that does not verify is a broken bench, not a finding.
    sound <- perLineCounting $ do
        verdicts <- either (fail . show) pure (verify file)
        evaluate (foldl' countSound 0 verdicts)
    row ("verify, -N" <> show numCapabilities) (fst sound)
    if snd sound == lineCount
        then pure ()
        else fail (show (snd sound) <> " of " <> show lineCount <> " lines verified Sound")
  where
    row name us = printf "%-22s %12.2f %14.0f\n" (name :: String) us (1e6 / us)

    countSound :: Int -> Verdict -> Int
    countSound n = \case
        Sound _ -> n + 1
        _ -> n

{- | A Producer-written AOF of @n@ lifecycle Entries under one key — the shape
of a real file, which is runs of one signer — rendered the way the Producer
documents: each line, then @0x0a@.
-}
aof :: Int -> LBS.ByteString
aof n = B.toLazyByteString (foldMap render (chain producerKey event [1 .. n]))
  where
    render p = B.byteString (lineBytesRaw p.line) <> B.word8 0x0a

    event :: LineHash -> Int -> ChainedEvent
    event prev i =
        ChainedEvent
            { entryId = entryId (T.pack ("evt-" <> show i))
            , payloadHash = digest i
            , payloadRef = payloadRef (T.pack ("ref-" <> show i))
            , prevHash = prev
            , kind = Lifecycle
            }

    -- Any 32 bytes are a payload hash claim; the Verifier never resolves them
    -- here, so what they are a digest of does not matter.
    digest i = case payloadHashFromBytes (BS.pack (take 32 (cycle (encodeInt i)))) of
        Right h -> h
        Left err -> error ("32 bytes refused as a digest: " <> show err)

    encodeInt i = map fromIntegral [i, i `div` 256, i `div` 65536, i `div` 16777216]

{- | Produce a chain: the first event from genesis, each one after linked to
the line before it — the digest 'produce' handed back, never one recomputed.
-}
chain :: PrivateKey -> (LineHash -> a -> ChainedEvent) -> [a] -> [ProducedLine]
chain key event = go genesisHash
  where
    go _ [] = []
    go prev (x : rest) = case produce key (event prev x) of
        Right p -> p : go p.lineHash rest
        Left err -> error ("produce failed on a key libcrypto accepted: " <> show err)

-- | Each line's canonical bytes, through the Verifier's own framer and decoder.
decodedCanonical :: LBS.ByteString -> [BS.ByteString]
decodedCanonical file = case frameFile file of
    Left err -> error ("framing refused the bench's own file: " <> show err)
    Right lns ->
        [ canonicalBytesRaw (canonicalize (decodedObject d))
        | (pos, raw) <- lns
        , let d = either (\e -> error ("the bench's own line did not decode: " <> show e)) id (decodeLine pos raw)
        ]

-- | Every line's signature check, as the fold would hand it to the seam.
signatureTriples :: LBS.ByteString -> [(PublicKey, SignedBytes, Sig)]
signatureTriples file = case frameFile file of
    Left err -> error ("framing refused the bench's own file: " <> show err)
    Right lns ->
        [ (key proof.publicKey, signingMessage (canonicalize (decodedObject d)), proof.signature)
        | (pos, raw) <- lns
        , let d = either (\e -> error ("the bench's own line did not decode: " <> show e)) id (decodeLine pos raw)
        , let proof = (decodedEntry d).producedProof
        ]
  where
    -- One promotion, as the fold's per-chunk map arranges for a one-key file.
    key claim
        | claim == privateKeyPublic producerKey = promoted
        | otherwise = error "the bench's own file carries a key it did not sign with"
    promoted = case publicKey (privateKeyPublic producerKey) of
        Right k -> k
        Left err -> error ("the producer's own key is off the curve: " <> show err)

batch :: [(PublicKey, SignedBytes, Sig)] -> [SigCheck]
batch triples = case verifyBatch triples of
    Right checks -> checks
    Left err -> error ("libcrypto did not answer: " <> show err)

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = let (h, t) = splitAt n xs in h : chunksOf n t

-- | RFC 6979 §A.2.5's key, the one every fixture in this repository signs with.
producerKey :: PrivateKey
producerKey = case privateKey (BS.pack [0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21]) of
    Right k -> k
    Left err -> error ("RFC 6979's own key was rejected: " <> show err)

-- | Microseconds per line, for an action over 'lineCount' lines.
perLine :: IO a -> IO Double
perLine act = fst <$> perLineCounting (act >> pure 0)

-- | 'perLine', keeping what the action counted.
perLineCounting :: IO Int -> IO (Double, Int)
perLineCounting act = do
    t0 <- getCurrentTime
    n <- act
    t1 <- getCurrentTime
    pure (realToFrac (diffUTCTime t1 t0) * 1e6 / fromIntegral lineCount, n)
