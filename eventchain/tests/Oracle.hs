{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

{- | ADR-0007's grader: every fabricated envelope faces tweag @webauthn@'s
independent reading of W3C §7.2.

The package's API is shaped for a relying party mid-ceremony, so this suite
synthesizes the ceremony the envelope never had: the origin and RP ID the
fabricator fixed, a user handle (a ceremony artifact the Mint envelope does
not model — WebAuthn carries it beside the assertion, not inside it — so it
is supplied on both sides of the oracle's equality check), and the COSE
credential record the oracle wants where the format carries a SEC1 point.
None of that synthesis weakens the grading: what the oracle re-derives — the
client data's meaning, the flags, the signed message, the signature — is
exactly what the Verifier's hand-written checks claim to have gotten right.

Two divergences are pinned rather than papered over, at the bottom of the
list: the oracle tolerates a duplicated @client_data_json@ member (its parser
keeps one arbitrarily — the very ambiguity ADR-0007 makes fatal), and 0.11
predates Level 3's BE/BS consistency rule. Each is asserted as the oracle's
verdict, so the day an upgrade closes the gap this suite says so instead of
quietly agreeing harder.

The oracle's internals use crypton's legacy ECDSA module; that is its
business and never on our hot path — this whole suite is the one build
crypton may enter (AGENTS.md), and it grades one envelope at a time.
-}
module Main (main) where

import Codec.CBOR.Write qualified as CBOR
import Codec.Serialise qualified as Serialise
import Crypto.Hash (hash)
import Crypto.WebAuthn.Cose.PublicKey qualified as Cose
import Crypto.WebAuthn.Cose.PublicKeyWithSignAlg qualified as Cose
import Crypto.WebAuthn.Cose.SignAlg qualified as Cose
import Crypto.WebAuthn.Encoding.Binary (decodeAuthenticatorData, decodeCollectedClientData)
import Crypto.WebAuthn.Model.Defaults (coaAllowCredentialsDefault)
import Crypto.WebAuthn.Model.Kinds (CeremonyKind (Authentication))
import Crypto.WebAuthn.Model.Types qualified as M
import Crypto.WebAuthn.Operation.Authentication (verifyAuthenticationResponse)
import Crypto.WebAuthn.Operation.CredentialEntry (CredentialEntry (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Validation (Validation (Failure, Success))
import EventChain (Attestation (..))
import EventChain.Crypto.Types
    ( authenticatorBytesRaw
    , claimedKeyRaw
    , clientDataBytesRaw
    , lineHashRaw
    , sigRaw
    )
import Test.EventChain.Mint
    ( duplicateChallenge
    , flagged
    , mismatchedTarget
    , soundAttestation
    , tamperedAuthData
    , tamperedClientData
    , targetHash
    , wrongChallenge
    )
import Test.Tasty (defaultMain, testGroup)
import Test.Tasty.HUnit (Assertion, assertFailure, testCase)

main :: IO ()
main =
    defaultMain $
        testGroup
            "mint-oracle (tweag webauthn grades the fabricator)"
            [ testCase "the sound envelope verifies under the oracle" (expectAccept (soundAttestation targetHash))
            , testCase "UP unset: the oracle rejects too" (expectReject (flagged 0x00))
            , testCase "wrong challenge: the oracle rejects too" (expectReject wrongChallenge)
            , testCase "tampered authenticator data: the oracle rejects too" (expectReject tamperedAuthData)
            , testCase "tampered client data: the oracle rejects too" (expectReject tamperedClientData)
            , testCase "mismatched target: the oracle rejects too" (expectReject mismatchedTarget)
            , testCase "duplicated client-data member: the oracle shrugs — pinned divergence" (expectAccept duplicateChallenge)
            , testCase "BS without BE: 0.11 predates the L3 rule — pinned divergence" (expectAccept (flagged 0x11))
            ]

expectAccept :: Attestation -> Assertion
expectAccept a = case oracle a of
    Right () -> pure ()
    Left err -> assertFailure ("the oracle rejected: " <> err)

expectReject :: Attestation -> Assertion
expectReject a = case oracle a of
    Left _ -> pure ()
    Right () -> assertFailure "the oracle accepted an envelope our checks reject"

{- | One envelope through the oracle's whole path: its binary decoders, its
COSE key loading, its §7.2 checks, its signature arithmetic.

The ceremony's challenge is the Mint's own @target_hash@ — what a relying
party minting this attestation would have asked the authenticator to sign —
so a mismatched envelope fails the oracle for the same reason it fails us.
-}
oracle :: Attestation -> Either String ()
oracle a = do
    ccd <-
        named "client data" $
            decodeCollectedClientData @'Authentication (clientDataBytesRaw a.clientDataJson)
    ad <-
        named "authenticator data" $
            decodeAuthenticatorData @'Authentication (authenticatorBytesRaw a.authenticatorData)
    entry <- credentialEntry (claimedKeyRaw a.attesterKey)
    let credential =
            M.Credential
                { M.cIdentifier = credentialId
                , M.cResponse =
                    M.AuthenticatorResponseAuthentication
                        { M.araClientData = ccd
                        , M.araAuthenticatorData = ad
                        , M.araSignature = M.AssertionSignature (rawSigToDer (sigRaw a.assertionSig))
                        , M.araUserHandle = Nothing
                        }
                , M.cClientExtensionResults = M.AuthenticationExtensionsClientOutputs{M.aecoCredProps = Nothing}
                }
        options =
            M.CredentialOptionsAuthentication
                { M.coaChallenge = M.Challenge (lineHashRaw a.target)
                , M.coaTimeout = Nothing
                , M.coaRpId = Nothing
                , M.coaAllowCredentials = coaAllowCredentialsDefault
                , M.coaUserVerification = M.UserVerificationRequirementPreferred
                , M.coaExtensions = Nothing
                }
    case verifyAuthenticationResponse origins rpIdHash (Just userHandle) entry options credential of
        Failure errs -> Left (show errs)
        Success _ -> Right ()
  where
    named what = either (Left . ((what <> ": ") <>) . T.unpack) Right

    origins = M.Origin "https://eventchain.test" :| []
    rpIdHash = M.RpIdHash (hash (TE.encodeUtf8 ("eventchain.test" :: Text)))
    userHandle = M.UserHandle "eventchain-oracle"
    credentialId = M.CredentialId "eventchain-oracle-cred"

{- | The stored credential record a relying party would hold: our SEC1 point,
re-encoded as the COSE_Key CBOR the oracle's model demands.
-}
credentialEntry :: ByteString -> Either String CredentialEntry
credentialEntry compressed = do
    (x, y) <- decompress compressed
    key <-
        plain
            ( Cose.checkPublicKey
                (Cose.PublicKeyECDSA Cose.ECDSAPublicKey{Cose.ecdsaCurve = Cose.CoseCurveP256, Cose.ecdsaX = x, Cose.ecdsaY = y})
            )
    cose <- plain (Cose.makePublicKeyWithSignAlg key (Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA256))
    pure
        CredentialEntry
            { ceCredentialId = M.CredentialId "eventchain-oracle-cred"
            , ceUserHandle = M.UserHandle "eventchain-oracle"
            , cePublicKeyBytes = M.PublicKeyBytes (CBOR.toStrictByteString (Serialise.encode cose))
            , ceSignCounter = M.SignatureCounter 0
            , ceTransports = []
            }
  where
    plain = either (Left . T.unpack) Right

{- | A SEC1 compressed P-256 point as affine coordinates.

Twenty lines of textbook arithmetic rather than a dependency: p ≡ 3 (mod 4),
so the square root is one modular exponentiation, and the result is checked
by squaring — a point that fails the check is a broken fixture, not a case.
-}
decompress :: ByteString -> Either String (Integer, Integer)
decompress point
    | BS.length point /= 33 = Left ("a compressed point has 33 bytes, got " <> show (BS.length point))
    | prefix /= 0x02 && prefix /= 0x03 = Left ("not a compressed-point prefix: " <> show prefix)
    | ySquared /= (y * y) `mod` p = Left "the x coordinate has no square root: not a point on P-256"
    | otherwise = Right (x, y)
  where
    prefix = BS.head point
    x = bytesToInteger (BS.tail point)

    -- y² = x³ − 3x + b over GF(p), and p ≡ 3 (mod 4) makes the square root
    -- one exponentiation. The prefix names y's parity; p is odd, so negation
    -- flips it.
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    ySquared = (modPow x 3 + (p - (3 * x) `mod` p) + b) `mod` p

    root = modPow ySquared ((p + 1) `div` 4)
    y
        | even root == (prefix == 0x02) = root
        | otherwise = p - root

    modPow base e = go (base `mod` p) e 1
      where
        go _ 0 acc = acc
        go bse ex acc
            | odd ex = go ((bse * bse) `mod` p) (ex `div` 2) ((acc * bse) `mod` p)
            | otherwise = go ((bse * bse) `mod` p) (ex `div` 2) acc

    bytesToInteger = BS.foldl' (\acc w -> acc * 256 + fromIntegral w) 0

{- | A 64-byte @r‖s@ signature as the DER @SEQUENCE@ the oracle decodes.

The third such encoder in this repository, and each is deliberate:
@eventchain-crypto@ keeps one unexported, the OpenSSL gate wrote its own to
stay independent of it, and the oracle gets a third for the same reason —
an encoder borrowed from the thing under test grades nothing.
-}
rawSigToDer :: ByteString -> ByteString
rawSigToDer raw = tagged 0x30 (tagged 0x02 (unsigned r) <> tagged 0x02 (unsigned s))
  where
    (r, s) = BS.splitAt 32 raw
    tagged tag body = BS.pack [tag, fromIntegral (BS.length body)] <> body
    unsigned bs
        | BS.null stripped = BS.singleton 0x00
        | BS.head stripped >= 0x80 = BS.cons 0x00 stripped
        | otherwise = stripped
      where
        stripped = BS.dropWhile (== 0x00) bs
