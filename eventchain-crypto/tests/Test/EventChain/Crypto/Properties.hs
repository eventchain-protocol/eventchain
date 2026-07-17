{-# LANGUAGE OverloadedStrings #-}

{- | Properties, driven by generators that are trying to break the marshalling.

This is where the FFI is actually tested. A fuzzer was considered and rejected on
evidence: AFL++ cannot instrument GHC's output (its instrumentation is a clang
pass GHC never traverses), and on macOS/arm64 only its FRIDA mode runs at all —
which would instrument the RTS and garbage collector along with our code. ASan is
no better here: bytestring allocates through GHC's /pinned heap/ rather than libc
@malloc@, so ASan's redzones never surround the buffers we hand to libcrypto, and
an over-read inside a pinned block is invisible to it. crypton,
libsodium-bindings, HsOpenSSL and cardano-base ship no fuzzer either.

What is left is the thing that actually matches the risk. libcrypto is fuzzed
upstream by OSS-Fuzz; what is ours is the marshalling, and marshalling breaks on
lengths and encodings — a space small and structured enough to generate
hostilely rather than to search.

So the generators below are adversarial on purpose: wrong lengths, off-by-one
lengths, empty, huge, all-zero, all-@0xFF@, valid-but-off-curve, and values at
the exact boundaries of the group order.
-}
module Test.EventChain.Crypto.Properties
    ( tests
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Either (rights)
import EventChain.Crypto
import EventChain.Crypto.Types
import Hedgehog
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.EventChain.Crypto.Hex (unhex)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "properties"
        [ testGroup "hashing" hashProps
        , testGroup "keys" keyProps
        , testGroup "signatures" sigProps
        ]

-- Generators -----------------------------------------------------------------

{- | Bytes that could be anything, at lengths that could break something.

The upper bound crosses the 4 KiB threshold where an update becomes a @safe@
call, so both branches are generated rather than only the common one.
-}
genBytes :: Gen ByteString
genBytes =
    Gen.choice
        [ Gen.bytes (Range.linear 0 64)
        , Gen.bytes (Range.linear 4090 4102) -- either side of the threshold
        , Gen.bytes (Range.singleton 0)
        , BS.replicate <$> Gen.int (Range.linear 0 5000) <*> pure 0x00
        , BS.replicate <$> Gen.int (Range.linear 0 5000) <*> pure 0xFF
        ]

-- | A line's content: non-empty, no @0x0a@, valid UTF-8. Generated, then filtered by the type.
genLine :: Gen LineBytes
genLine = Gen.mapMaybe (either (const Nothing) Just . lineBytes) (Gen.utf8 (Range.linear 1 300) Gen.unicode)

{- | 33 bytes shaped like a compressed point, mostly /not/ on the curve.

About half of all @x@ have no @y@, so an arbitrary generator already produces
off-curve points about half the time. The explicit cases are the ones an
arbitrary generator would essentially never reach.
-}
genClaimedKey :: Gen ClaimedKey
genClaimedKey =
    Gen.mapMaybe (either (const Nothing) Just . claimedKey) $
        Gen.choice
            [ BS.cons <$> Gen.element [0x02, 0x03] <*> Gen.bytes (Range.singleton 32)
            , BS.cons 0x02 (BS.replicate 32 0x00) <$ Gen.constant ()
            , BS.cons 0x03 (BS.replicate 32 0xFF) <$ Gen.constant ()
            ]

-- | Anything that might be offered as a 33-byte point, including things that are not.
genPointBytes :: Gen ByteString
genPointBytes =
    Gen.choice
        [ BS.cons <$> Gen.element [0x02, 0x03] <*> Gen.bytes (Range.singleton 32) -- right shape
        , BS.cons <$> Gen.element [0x00, 0x01, 0x04, 0x05, 0xFF] <*> Gen.bytes (Range.singleton 32) -- bad prefix
        , Gen.bytes (Range.linear 0 40) -- any length, including 32 and 34
        , pure BS.empty
        ]

-- | 32 bytes, weighted towards the boundaries of @[1, n-1]@.
genScalarBytes :: Gen ByteString
genScalarBytes =
    Gen.choice
        [ Gen.bytes (Range.singleton 32)
        , pure (BS.replicate 32 0x00) -- zero: not a key
        , pure (BS.replicate 32 0xFF) -- far above the order
        , pure orderBytes -- exactly n: not a key
        , pure (BS.init orderBytes <> BS.singleton 0x50) -- n-1: the largest key there is
        , pure (BS.replicate 31 0x00 <> BS.singleton 0x01) -- 1: the smallest
        , Gen.bytes (Range.linear 0 40) -- wrong lengths
        ]

orderBytes :: ByteString
orderBytes = unhex "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"

-- | A usable key, for the properties that need one.
genPrivateKey :: Gen PrivateKey
genPrivateKey = Gen.mapMaybe (either (const Nothing) Just . privateKey) (Gen.bytes (Range.singleton 32))

{- | How a failing property prints a key.

t'PrivateKey' has no 'Show', which is why this exists rather than 'forAll'. The
counterexample a shrink reports is the /public/ point — enough to reproduce the
failure against the same key, without a secret ending up in a test log. The
absence of that instance is doing its job here.
-}
showKey :: PrivateKey -> String
showKey k = "PrivateKey for " <> show (privateKeyPublic k)

-- Hashing --------------------------------------------------------------------

hashProps :: [TestTree]
hashProps =
    [ testProperty "a digest is 32 bytes, whatever went in" . property $ do
        bs <- forAll genBytes
        BS.length (payloadHashRaw (one (hashPayloads [payloadBytes bs]))) === 32
    , testProperty "a chunk hashes each item exactly as a chunk of one would" . property $ do
        -- The whole point of the batch is context reuse. If reusing a context
        -- leaked state between items, this is what would catch it -- and nothing
        -- else would, because each digest would still be 32 plausible bytes.
        ls <- forAll (Gen.list (Range.linear 0 20) genLine)
        hashLines ls === concatMap (\l -> hashLines [l]) ls
    , testProperty "hashing is a function" . property $ do
        ls <- forAll (Gen.list (Range.linear 0 8) genLine)
        hashLines ls === hashLines ls
    , testProperty "distinct lines hash distinctly" . property $ do
        a <- forAll genLine
        b <- forAll (Gen.filter (/= a) genLine)
        assert (hashLines [a] /= hashLines [b])
    ]

-- Keys -----------------------------------------------------------------------

keyProps :: [TestTree]
keyProps =
    [ testProperty "any 33 bytes are answered, never crashed on" . property $ do
        c <- forAll genClaimedKey
        case publicKey c of
            Left err -> err === KeyNotOnCurve
            Right k -> publicKeyClaim k === c
    , testProperty "the shape check admits only 33 bytes leading 0x02 or 0x03" . property $ do
        bs <- forAll genPointBytes
        case claimedKey bs of
            Right c -> do
                BS.length (claimedKeyRaw c) === 33
                assert (BS.head (claimedKeyRaw c) `elem` [0x02, 0x03])
            Left _ ->
                assert (BS.length bs /= 33 || BS.head bs `notElem` [0x02, 0x03])
    , testProperty "any 32 bytes are answered as a scalar, never crashed on" . property $ do
        bs <- forAll genScalarBytes
        case privateKey bs of
            Left (ScalarWrongLength n) -> n === BS.length bs
            Left err -> do
                assert (err == ScalarRejected)
                -- Rejection is exactly the out-of-range cases, no others.
                assert (BS.all (== 0) bs || bs >= orderBytes)
            Right k -> do
                let pt = claimedKeyRaw (privateKeyPublic k)
                BS.length pt === 33
                assert (BS.head pt `elem` [0x02, 0x03])
    , testProperty "a derived point is always on the curve" . property $ do
        -- privateKey derives the point itself, so this is the round trip that
        -- says the derivation and the promotion agree.
        k <- forAllWith showKey genPrivateKey
        case publicKey (privateKeyPublic k) of
            Left err -> annotateShow err >> failure
            Right pub -> publicKeyClaim pub === privateKeyPublic k
    ]

-- Signatures -----------------------------------------------------------------

sigProps :: [TestTree]
sigProps =
    [ testProperty "what was signed, verifies" . property $ do
        k <- forAllWith showKey genPrivateKey
        msg <- forAll genBytes
        let pub = expect (publicKey (privateKeyPublic k))
        case sign k (signedBytes msg) of
            Left err -> annotateShow err >> failure
            Right sig -> verifyBatch [(pub, signedBytes msg, sig)] === Right [SigValid]
    , testProperty "signing is deterministic (RFC 6979)" . property $ do
        k <- forAllWith showKey genPrivateKey
        msg <- forAll genBytes
        sign k (signedBytes msg) === sign k (signedBytes msg)
    , testProperty "a signature is 64 bytes" . property $ do
        k <- forAllWith showKey genPrivateKey
        msg <- forAll genBytes
        case sign k (signedBytes msg) of
            Left err -> annotateShow err >> failure
            Right sig -> BS.length (sigRaw sig) === 64
    , testProperty "a different message does not verify" . property $ do
        k <- forAllWith showKey genPrivateKey
        msg <- forAll genBytes
        other <- forAll (Gen.filter (/= msg) genBytes)
        let pub = expect (publicKey (privateKeyPublic k))
        case sign k (signedBytes msg) of
            Left err -> annotateShow err >> failure
            Right sig -> verifyBatch [(pub, signedBytes other, sig)] === Right [SigInvalid]
    , testProperty "a tampered signature is invalid, not an error" . property $ do
        k <- forAllWith showKey genPrivateKey
        msg <- forAll genBytes
        i <- forAll (Gen.int (Range.linear 0 63))
        let pub = expect (publicKey (privateKeyPublic k))
        case sign k (signedBytes msg) of
            Left err -> annotateShow err >> failure
            Right sig -> do
                let raw = sigRaw sig
                    flipped = BS.take i raw <> BS.singleton (BS.index raw i + 1) <> BS.drop (i + 1) raw
                case sigFromRaw flipped of
                    Left err -> annotateShow err >> failure
                    Right bad ->
                        -- Either verdict is fine; a CryptoError is not. Flipping
                        -- a bit must never make libcrypto malfunction, and an
                        -- r or s pushed out of range must be refused rather
                        -- than crashed on.
                        case verifyBatch [(pub, signedBytes msg, bad)] of
                            Right [_] -> success
                            Left SigOutOfRange -> success
                            other -> annotateShow other >> failure
    , testProperty "another key's signature does not verify" . property $ do
        a <- forAllWith showKey genPrivateKey
        b <- forAllWith showKey (Gen.filter (\k -> privateKeyPublic k /= privateKeyPublic a) genPrivateKey)
        msg <- forAll genBytes
        let pubB = expect (publicKey (privateKeyPublic b))
        case sign a (signedBytes msg) of
            Left err -> annotateShow err >> failure
            Right sig -> verifyBatch [(pubB, signedBytes msg, sig)] === Right [SigInvalid]
    , testProperty "a batch answers each triple, in order" . property $ do
        k <- forAllWith showKey genPrivateKey
        msgs <- forAll (Gen.list (Range.linear 0 10) genBytes)
        let pub = expect (publicKey (privateKeyPublic k))
            sigs = rights (map (sign k . signedBytes) msgs)
            triples = zipWith (\m s -> (pub, signedBytes m, s)) msgs sigs
        verifyBatch triples === Right (map (const SigValid) triples)
    , testProperty "a batch is its items, verified separately" . property $ do
        k <- forAllWith showKey genPrivateKey
        pairs <- forAll (Gen.list (Range.linear 0 6) ((,) <$> genBytes <*> genBytes))
        let pub = expect (publicKey (privateKeyPublic k))
            triples =
                [ (pub, signedBytes verifyAs, sig)
                | (signAs, verifyAs) <- pairs
                , Right sig <- [sign k (signedBytes signAs)]
                ]
        -- Catches a context reused across a batch leaking state between items.
        verifyBatch triples === traverse (\t -> one <$> verifyBatch [t]) triples
    ]

{- | The one answer a chunk of one produces.

The kernels take chunks, so even a single vector comes back in a list. This is
'head' with the expectation written down, so a batch that silently returned the
wrong number of digests fails here rather than being read past.
-}
one :: [a] -> a
one [x] = x
one xs = error ("expected exactly one result, got " <> show (length xs))

{- | Take the success, or fail the test naming the error.

A vector that does not load is a broken test, not a finding, so this errors
rather than threading an 'Either' through every assertion. Named because
@let Right x = ...@ is the same thing with the diagnosis left out.
-}
expect :: (Show e) => Either e a -> a
expect (Right a) = a
expect (Left e) = error ("expected success, got " <> show e)
