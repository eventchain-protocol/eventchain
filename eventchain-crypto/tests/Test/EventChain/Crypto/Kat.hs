{-# LANGUAGE OverloadedStrings #-}

{- | Known-answer tests: bytes we did not choose.

This is the gate ADR-0004 asks for, and it is deliberately not the one
@docs/plan.md@ originally specified. That said "ECDSA sign/verify against OpenSSL
CLI-generated fixtures" — but the CLI is the same libcrypto we call, so a fixture
from it proves our wiring and nothing about our correctness. Both sides would
have to be wrong in the same way to notice, which is exactly the failure a shared
implementation produces.

RFC 6979 and FIPS 180-2 publish /the answers/. If our output matches those, it
matches something written before this project existed by people who did not know
about it. That is what a known-answer test is worth.
-}
module Test.EventChain.Crypto.Kat
    ( tests
    ) where

import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C8
import EventChain.Crypto
import EventChain.Crypto.Types
import Hedgehog (property, withTests, (===))
import Test.EventChain.Crypto.Hex (hex, unhex)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "known answers"
        [ testGroup "SHA-256 (FIPS 180-2)" sha256Kats
        , testGroup "ECDSA P-256 (RFC 6979 A.2.5)" rfc6979Kats
        ]

{- | FIPS 180-2's own examples, plus the empty string.

The long one matters for a reason beyond SHA-256 being right: it is over the
4 KiB threshold where an update becomes a @safe@ foreign call, so it is the only
vector that exercises that branch at all.
-}
sha256Kats :: [TestTree]
sha256Kats =
    [ vector "abc" "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    , vector
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    , vector "" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    , testCase "1 000 000 x 'a' (crosses the safe-call threshold)" $
        hex (payloadHashRaw (one (hashPayloads [payloadBytes (BS.replicate 1000000 0x61)])))
            @?= "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    ]
  where
    -- Lines are hashed as LineBytes; the empty string is not a line (a line has
    -- content), so it goes through the payload kernel. Same digest either way --
    -- the types differ, not the algorithm.
    vector input expected
        | BS.null input =
            testCase "empty string" $
                hex (payloadHashRaw (one (hashPayloads [payloadBytes input]))) @?= expected
        | otherwise = testCase (show (C8.unpack input)) $ case lineBytes input of
            Left err -> assertFailure ("not a line: " <> show err)
            Right l -> hex (lineHashRaw (one (hashLines [l]))) @?= expected

{- | RFC 6979 A.2.5 — P-256 with SHA-256, the key and messages the RFC publishes.

Two things are proven here at once. That our signatures are correct, and that
OpenSSL's deterministic mode /is/ RFC 6979 rather than merely repeatable: a
scheme that produced the same nonce every time by some other rule would pass a
determinism test and fail these.
-}
rfc6979Kats :: [TestTree]
rfc6979Kats =
    [ testCase "the RFC's key derives the RFC's public point" $
        -- A.2.5 publishes Ux; the compressed form is 03||Ux because Uy is odd.
        hex (claimedKeyRaw (privateKeyPublic key))
            @?= "03" <> "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    , signature
        "sample"
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    , signature
        "test"
        "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
        "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
    , testCase "signing twice gives identical bytes" $
        sign key (signedBytes "sample") @?= sign key (signedBytes "sample")
    , testProperty "every RFC signature verifies against the RFC's key" . withTests 1 . property $ do
        let pub = expect (publicKey (privateKeyPublic key))
            s1 = expect (sign key (signedBytes "sample"))
            s2 = expect (sign key (signedBytes "test"))
        verifyBatch [(pub, signedBytes "sample", s1), (pub, signedBytes "test", s2)]
            === Right [SigValid, SigValid]
    ]
  where
    signature message r s =
        testCase (show (C8.unpack message)) $
            case sign key (signedBytes message) of
                Left err -> assertFailure ("sign failed: " <> show err)
                Right sig -> hex (sigRaw sig) @?= r <> s

-- | RFC 6979 A.2.5's private key @x@.
key :: PrivateKey
key = case privateKey (unhex "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721") of
    Right k -> k
    Left err -> error ("RFC 6979's own key was rejected: " <> show err)

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
