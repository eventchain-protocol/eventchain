{-# LANGUAGE OverloadedStrings #-}

{- | The Mint vectors: fabricated envelopes, frozen as bytes under
@vectors/mint/@, one file per case.

This module plays two parts the library refuses to. It is the /browser/,
writing @clientDataJSON@ bytes and assembling authenticator data — the
Producer emits those blobs opaque and never authors them — and for the
decode-level cases it is the /malicious producer/, hand-assembling member
lists the real 'EventChain.Produce.produce' cannot emit and signing them
honestly, because a Verifier's rejection rules can only be exercised by lines
that break them.

Every fabrication is deterministic — fixed keys, RFC 6979 signing, fixed
authenticator fields — so each committed file is rebuilt and compared, never
seeded, exactly as @vectors/v0-lifecycle.jsonl@ is (the M3 pattern,
@docs/plan.md@). The Verifier's suite adjudicates the committed files and
names no symbol of ours; the envelope cases and their expected verdicts are
ADR-0007's list.

One deliberate asymmetry: except where the case says otherwise, the Produced
Proof on every line here is /valid/. A broken envelope under a broken
signature would test two rejections at once and isolate neither; the
interesting attacker is the producer whose line is honestly signed and whose
envelope is the lie.
-}
module Test.EventChain.Mint
    ( tests
    , mintVectors

      -- * The fabrications, for the oracle suite
      -- $oracle
    , targetHash
    , absentHash
    , soundAttestation
    , flagged
    , wrongChallenge
    , tamperedAuthData
    , tamperedClientData
    , duplicateChallenge
    , mismatchedTarget
    ) where

-- \$oracle
-- The @mint-oracle@ suite re-judges these same fabrications under tweag
-- @webauthn@'s independent reading of §7.2 (ADR-0007). They are exported as
-- values rather than re-read from the committed files so the oracle faces
-- exactly what the fabricator built, envelope by envelope, without a codec of
-- ours in between.

import Data.Aeson qualified as Aeson
import Data.Base64.Types (extractBase64)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as Base64Url
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import Data.Word (Word8)
import EventChain
import EventChain.Crypto
    ( PrivateKey
    , hashClientData
    , privateKey
    , privateKeyPublic
    , sign
    )
import EventChain.Crypto.Types
    ( ClaimedKey
    , LineHash
    , PayloadHash
    , Sig
    , authenticatorBytes
    , claimedKey
    , claimedKeyRaw
    , clientDataBytes
    , clientDataHashRaw
    , lineBytesRaw
    , lineHashRaw
    , payloadHashFromBytes
    , payloadHashRaw
    , sigFromRaw
    , sigRaw
    , signedBytes
    )
import EventChain.EntryObject (Member (..), MemberValue, entryObject, memberValue)
import EventChain.Wire (encodeLine)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.EventChain.Fixtures (chainFrom, producerKey, unhex)
import Test.EventChain.Vectors (findRepoRoot)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

tests :: TestTree
tests =
    testGroup
        "Test.EventChain.Mint"
        ( [ testCase ("vectors/mint/" <> name <> " is what this fabricator builds") (vectorIsCurrent name bytes)
          | (name, bytes) <- mintVectors
          ]
            <> [testCase "vectors/mint/cross-soft-webauthn.jsonl wraps the committed foreign envelope" crossIsCurrent]
        )

-- Keys -----------------------------------------------------------------------

{- | The attester these envelopes sign with: a fixed scalar, distinct from the
Producer's.

Only its validity and its fixedness are load-bearing, as with 'producerKey':
whether signing is arithmetically right was settled by @eventchain-crypto@'s
known answers, and RFC 6979 makes the same messages the same signatures
forever, which is what lets these files be rebuilt instead of seeded.
-}
attesterPriv :: PrivateKey
attesterPriv = case privateKey (unhex "0000000000000000000000000000000000000000000000000000000000000002") of
    Right k -> k
    Left err -> error ("the attester's fixed scalar was rejected: " <> show err)

-- | The point the attester's line carries.
attesterClaim :: ClaimedKey
attesterClaim = privateKeyPublic attesterPriv

-- The browser's half ---------------------------------------------------------

{- | Client data as a browser writes it, byte for byte.

The member set and order are one browser's plausible output, not a rule —
W3C fixes the members' meaning, never their serialization — and that is why
the bytes travel in the envelope instead of being rebuilt: the only thing
every consumer must agree on is their hash. @crossOrigin@ is here as a
boolean deliberately; the entry codec's strings-only rule stops at this
blob's edge (ADR-0007), and a vector should prove it.
-}
clientDataFor :: Text -> ByteString
clientDataFor challenge =
    "{\"type\":\"webauthn.get\",\"challenge\":\""
        <> TE.encodeUtf8 challenge
        <> "\",\"origin\":\"https://eventchain.test\",\"crossOrigin\":false}"

{- | Authenticator data at its structural minimum: RP ID hash, flags, and a
zero signature counter — 37 bytes, nothing trailing.

The RP ID hash is SHA-256 of @eventchain.test@, computed by openssl once and
inlined: a fabricated authenticator still names /some/ relying party, and the
oracle suite hands its grader that same expectation.
-}
authDataWith :: Word8 -> ByteString
authDataWith flags = rpIdHash <> BS.singleton flags <> BS.replicate 4 0
  where
    -- printf 'eventchain.test' | openssl dgst -sha256
    rpIdHash = unhex "2f209cffc67f7356616c01e7593f50386d40ae9423e383eebee881d0c5874b29"

-- | UP set and nothing else: present user, no backup eligibility, consistent.
soundFlags :: Word8
soundFlags = 0x01

{- | Sign an assertion the way an authenticator does: over
@authenticatorData ‖ SHA-256(clientDataJSON)@.
-}
assertOver :: ByteString -> ByteString -> Sig
assertOver authData cData =
    case sign attesterPriv (signedBytes (authData <> digest)) of
        Right s -> s
        Left err -> error ("the attester's fixed key failed to sign: " <> show err)
  where
    digest = case hashClientData [clientDataBytes cData] of
        [h] -> clientDataHashRaw h
        hs -> error (show (length hs) <> " digests for one client data")

{- | A sound Attestation of the target: the challenge is the target's hash,
base64url, exactly as the @target_hash@ member will spell it.
-}
soundAttestation :: LineHash -> Attestation
soundAttestation target =
    attestationOf target (authDataWith soundFlags) (clientDataFor (b64url (lineHashRaw target)))

{- | Assemble an Attestation whose assertion honestly signs exactly the two
blobs it carries. Every dishonest variant below starts from this and lies
about one thing.
-}
attestationOf :: LineHash -> ByteString -> ByteString -> Attestation
attestationOf target authData cData =
    Attestation
        { target = target
        , attesterKey = attesterClaim
        , assertionSig = assertOver authData cData
        , authenticatorData = authenticatorBytes authData
        , clientDataJson = clientDataBytes cData
        }

-- The vectors ----------------------------------------------------------------

{- | Every committed Mint vector: file name under @vectors/mint/@, and the
bytes the fabricator builds for it.

Each file is a two-line AOF — a lifecycle target, then the Mint under test —
so a failure names its case by file rather than by line arithmetic in one
long chain. The two decode-level cases sit in their own files of necessity: a
malformed line halts the fold, so nothing after it would be adjudicated.
-}
mintVectors :: [(FilePath, ByteString)]
mintVectors =
    [ ("sound.jsonl", aof [targetLine, mintLine (soundAttestation targetHash)])
    , ("up-unset.jsonl", aof [targetLine, mintLine (flagged 0x00)])
    , ("bs-without-be.jsonl", aof [targetLine, mintLine (flagged 0x11)])
    , ("wrong-challenge.jsonl", aof [targetLine, mintLine wrongChallenge])
    , ("tampered-authdata.jsonl", aof [targetLine, mintLine tamperedAuthData])
    , ("tampered-clientdata.jsonl", aof [targetLine, mintLine tamperedClientData])
    , ("duplicate-clientdata-member.jsonl", aof [targetLine, mintLine duplicateChallenge])
    , ("orphan.jsonl", aof [targetLine, mintLine (soundAttestation absentHash)])
    , ("mismatched-target.jsonl", aof [targetLine, mintLine mismatchedTarget])
    , ("missing-v.jsonl", aof [targetLine, handMint Nothing])
    , ("unknown-v.jsonl", aof [targetLine, handMint (Just "2")])
    ]

{- | Flags chosen by the case; the assertion honestly signs what it carries,
so only the flag rule under test fails.
-}
flagged :: Word8 -> Attestation
flagged flags =
    attestationOf targetHash (authDataWith flags) (clientDataFor (b64url (lineHashRaw targetHash)))

{- | The challenge names 32 zero bytes; everything else is sound. Check 3 and
only check 3 says no.
-}
wrongChallenge :: Attestation
wrongChallenge =
    attestationOf targetHash (authDataWith soundFlags) (clientDataFor (b64url (BS.replicate 32 0)))

{- | The assertion signed one authenticator data; the envelope carries
another, structurally fine (UV joined UP). Only the signature knows.
-}
tamperedAuthData :: Attestation
tamperedAuthData =
    (soundAttestation targetHash)
        { authenticatorData = authenticatorBytes (authDataWith 0x05)
        }

{- | The assertion signed one client data; the envelope carries another whose
two read members still say the right things. Only the hash knows.
-}
tamperedClientData :: Attestation
tamperedClientData =
    (soundAttestation targetHash)
        { clientDataJson =
            clientDataBytes
                ( "{\"type\":\"webauthn.get\",\"challenge\":\""
                    <> TE.encodeUtf8 (b64url (lineHashRaw targetHash))
                    <> "\",\"origin\":\"https://evil.example\",\"crossOrigin\":false}"
                )
        }

{- | Two @challenge@ members, byte-identical, honestly signed. The signature
verifies — it covers bytes, not meaning — and the line still dies: which
member a reader takes is exactly the ambiguity ADR-0007 makes fatal, and no
browser emits it.
-}
duplicateChallenge :: Attestation
duplicateChallenge = attestationOf targetHash (authDataWith soundFlags) doubled
  where
    doubled =
        "{\"type\":\"webauthn.get\",\"challenge\":\""
            <> c
            <> "\",\"challenge\":\""
            <> c
            <> "\",\"origin\":\"https://eventchain.test\"}"
    c = TE.encodeUtf8 (b64url (lineHashRaw targetHash))

{- | The envelope binds the target; the @target_hash@ member names a hash the
file also contains, but not that one.
-}
mismatchedTarget :: Attestation
mismatchedTarget = (soundAttestation targetHash){target = absentHash}

-- The chain under the cases --------------------------------------------------

-- | The lifecycle Entry every Mint here attests, produced normally.
targetProduced :: ProducedLine
targetProduced = case chainFrom producerKey [lifecycleEvent] of
    [p] -> p
    ps -> error (show (length ps) <> " lines from one event")
  where
    lifecycleEvent =
        ChainedEvent
            { entryId = entryId "evt-001"
            , payloadHash = fixedPayload
            , payloadRef = payloadRef "aof/2026-07/001"
            , prevHash = genesisHash
            , kind = Lifecycle
            }

targetLine :: ByteString
targetLine = lineBytesRaw targetProduced.line

targetHash :: LineHash
targetHash = targetProduced.lineHash

{- | A hash no line in any of these files has: the digest of a line that was
produced and thrown away. Orphan Mints need a target that is real
arithmetic and absent evidence.
-}
absentHash :: LineHash
absentHash = case chainFrom producerKey [thrownAway] of
    [p] -> p.lineHash
    ps -> error (show (length ps) <> " lines from one event")
  where
    thrownAway =
        ChainedEvent
            { entryId = entryId "evt-never-appended"
            , payloadHash = fixedPayload
            , payloadRef = payloadRef "aof/2026-07/nowhere"
            , prevHash = genesisHash
            , kind = Lifecycle
            }

{- | A Mint line produced normally: the library emits it, so it carries
@"v":"1"@ and the full member set by construction.
-}
mintLine :: Attestation -> ByteString
mintLine a = case produce producerKey (mintEvent (Mint a)) of
    Right p -> lineBytesRaw p.line
    Left err -> error ("produce refused a mint event: " <> show err)

{- | The Mint's own six commitments, shared by every case so the envelope is
the only thing that varies.
-}
mintEvent :: EventKind -> ChainedEvent
mintEvent k =
    ChainedEvent
        { entryId = entryId "mint-001"
        , payloadHash = fixedPayload
        , payloadRef = payloadRef "aof/2026-07/mint-001"
        , prevHash = targetHash
        , kind = k
        }

{- | The malicious producer's door: the sound Mint's members with the @v@
declaration omitted or replaced by the case's choice, honestly signed.

'EventChain.Produce.produce' cannot emit these lines — the codec always
declares what its members oblige — so the member list is assembled by hand
and signed with the library's own signing message, the way an attacker
holding a valid key would. The Produced Proof on the result verifies; the
declaration is the only lie.
-}
handMint :: Maybe Text -> ByteString
handMint vLabel = lineBytesRaw (encodeLine signedO)
  where
    a = soundAttestation targetHash

    unsigned =
        [ (EntryId, memberValue "mint-001")
        , (PayloadHash, b64Member (payloadHashRaw fixedPayload))
        , (PayloadRef, memberValue "aof/2026-07/mint-001")
        , (PrevHash, b64Member (lineHashRaw targetHash))
        , (PublicKey, b64Member (claimedKeyRaw (privateKeyPublic producerKey)))
        , (Kind, memberValue "mint")
        , (TargetHash, b64Member (lineHashRaw targetHash))
        , (AttesterKey, b64Member (claimedKeyRaw attesterClaim))
        , (AssertionSig, b64Member (sigRaw a.assertionSig))
        , (AuthenticatorData, b64Member (authDataWith soundFlags))
        , (ClientDataJson, b64Member (clientDataFor (b64url (lineHashRaw targetHash))))
        ]
            <> [(V, memberValue label) | Just label <- [vLabel]]

    proof = case sign producerKey (messageOf unsigned) of
        Right s -> s
        Left err -> error ("the producer's fixed key failed to sign: " <> show err)

    signedO = object (unsigned <> [(Signature, b64Member (sigRaw proof))])

    messageOf ms = signedBytes (canonicalBytesRaw (signingMessage (object ms)))

    object ms = case entryObject ms of
        Right o -> o
        Left err -> error ("a hand-built member list was refused: " <> show err)

-- The envelope nobody here wrote ---------------------------------------------

{- | The cross-ecosystem vector: a Mint whose envelope came out of
soft-webauthn's software authenticator (built on python-fido2's primitives),
generated once by @vectors/mint/cross/generate.py@ and committed as
@envelope.json@.

The fixture is input, not output — the foreign device's key is random, so the
envelope cannot be rebuilt here, and what this test asserts is the
deterministic half: that the committed line is exactly the committed envelope
wrapped by this Producer. What the /envelope/ proves is ADR-0007's
cross-ecosystem claim, and the Verifier's suite proves it by adjudicating the
line Sound: two implementations of the authenticator's side of §6.1, sharing
no code and no language, agreeing about what a sound envelope is.
-}
crossIsCurrent :: IO ()
crossIsCurrent = do
    root <- findRepoRoot
    fixture <- BS.readFile (root </> "vectors" </> "mint" </> "cross" </> "envelope.json")
    envelope <- either (assertFailure . ("envelope.json: " <>)) pure (Aeson.eitherDecodeStrict fixture)
    line <- either assertFailure pure (crossLine envelope)
    vectorIsCurrent "cross-soft-webauthn.jsonl" (aof [targetLine, line])

-- | The committed foreign envelope, wrapped into a produced Mint line.
crossLine :: Map.Map Text Text -> Either String ByteString
crossLine envelope = do
    akey <- shaped "attester_key" claimedKey =<< field "attester_key"
    asig <- shaped "assertion_sig" sigFromRaw =<< field "assertion_sig"
    authData <- authenticatorBytes <$> field "authenticator_data"
    cData <- clientDataBytes <$> field "client_data_json"
    let event =
            (mintEvent (Mint Attestation{target = targetHash, attesterKey = akey, assertionSig = asig, authenticatorData = authData, clientDataJson = cData}))
                { entryId = entryId "mint-cross-001"
                , payloadRef = payloadRef "aof/2026-07/mint-cross-001"
                }
    case produce producerKey event of
        Right p -> Right (lineBytesRaw p.line)
        Left err -> Left ("produce refused the cross event: " <> show err)
  where
    field name = case Map.lookup name envelope of
        Nothing -> Left ("envelope.json lacks " <> show name)
        Just text -> case Base64Url.decodeBase64UnpaddedUntyped (TE.encodeUtf8 text) of
            Right bs -> Right bs
            Left err -> Left (show name <> " is not unpadded base64url: " <> show err)

    shaped name f bs = case f bs of
        Right a -> Right a
        Left err -> Left (show name <> " has the wrong shape: " <> show err)

-- Plumbing -------------------------------------------------------------------

{- | Terminated per JSON Lines §3, final terminator included, like the
lifecycle vector.
-}
aof :: [ByteString] -> ByteString
aof lns = BS.concat [l <> "\n" | l <- lns]

fixedPayload :: PayloadHash
fixedPayload = case payloadHashFromBytes (unhex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") of
    Right h -> h
    Left err -> error ("a fixed payload hash was refused: " <> show err)

b64url :: ByteString -> Text
b64url = extractBase64 . Base64Url.encodeBase64Unpadded

b64Member :: ByteString -> MemberValue
b64Member = memberValue . b64url

{- | The committed bytes are still what this fabricator builds; the reasons a
mismatch matters are 'Test.EventChain.Vectors'' reasons.
-}
vectorIsCurrent :: FilePath -> ByteString -> IO ()
vectorIsCurrent name bytes = do
    root <- findRepoRoot
    let path = root </> "vectors" </> "mint" </> name
    exists <- doesFileExist path
    if not exists
        then assertFailure ("No vector at " <> path <> ". Generate it from this fabricator and commit it.")
        else do
            committed <- BS.readFile path
            committed @?= bytes
