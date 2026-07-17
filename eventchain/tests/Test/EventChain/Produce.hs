{-# LANGUAGE OverloadedStrings #-}

{- | The M2 gate: an AOF this package wrote, graded by tools that have never
seen it.

@docs/plan.md@ asked for "the OpenSSL CLI — not our Verifier — to check every
line's signature against its canonical bytes", and the question that bar leaves
open is /whose/ canonical bytes. Handing OpenSSL the output of
"EventChain.Canonical" puts our canonicalizer back in the path and reduces the
exercise to a sign/verify round-trip, which @eventchain-crypto@'s known-answer
tests already settled against RFC 6979. It would pass while a line said
something its signature did not cover — which is the one failure this milestone
is in a position to catch, and the reason the Producer is built before the
Verifier at all.

So nothing of ours derives the message:

1. @aeson@ parses the line, which is also what establishes it is JSON at all.
2. The @signature@ member comes out.
3. @Data.Aeson.RFC8785.encodeCanonical@ canonicalizes what remains — the
   oracle, not us. It grades here for the reason it grades in
   "Test.EventChain.Canonical": it shares no code with the thing it grades.
4. The OpenSSL CLI verifies the line's own signature under the line's own
   @public_key@ over those bytes.

The library appears in that path exactly once: it wrote the file. Everything
that reads it is a stranger, which is the position @docs/plan.md@ says v0 must
be judged from.

The CLI is doing something the oracle cannot, and it is not the arithmetic.
Loading a 33-byte compressed point out of a SPKI wrapper and reading a 64-byte
@r‖s@ signature as DER is an /interop/ claim: those encodings are ADR-0002's
choice, and a third party has to be able to consume them.

Importing the oracle here is not a gate violation. @gates:no-jcs-oracle-import@
matches the /library's/ imports, because the grader may not be the graded; a
test is where a grader belongs.
-}
module Test.EventChain.Produce (tests) where

import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Aeson.RFC8785 (encodeCanonical)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as Base64Url
import Data.ByteString.Lazy qualified as LBS
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import EventChain
import EventChain.Crypto (hashLines)
import EventChain.Crypto.Types (lineBytes, lineBytesRaw, lineHashRaw)
import EventChain.EntryObject (Member (..), memberName)
import Hedgehog (Gen, Property, evalIO, forAll, property, withTests, (===))
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import System.Exit (ExitCode (..))
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import System.Process (readProcessWithExitCode)
import Test.EventChain.Fixtures (chainFrom, genEvent, genLabelWith, producerKey, unhex)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "EventChain.Produce"
        [ testProperty "every line of an AOF verifies to OpenSSL over the oracle's message" verifiesToOpenSsl
        , testProperty "OpenSSL rejects a line whose label was altered" rejectsTamper
        , testProperty "each line names the previous line's bytes" chainsToPreviousLine
        ]

{- | How many entries the AOF gate builds.

Small on purpose: each line costs a signature and an @openssl@ process, and the
claim does not get truer with more of them. Breadth over event /content/ belongs
to the pure properties here and in "Test.EventChain.Wire", which run hundreds of
cases for the price of none of this.
-}
entryCount :: Int
entryCount = 8

{- | Labels the oracle can be asked about without disagreeing for reasons that
are not ours.

@aeson@'s canonicalizer emits @\\u0008@ and @\\u000c@ where RFC 8785 §3.2.2.2
requires @\\b@ and @\\f@. We follow the RFC, so a label carrying either would
have the oracle derive different bytes and OpenSSL would reject a line that is
correct — the test would be measuring the oracle's known defect.
"Test.EventChain.Canonical" pins those two against the RFC's own table instead,
which is the only honest way to grade a point the oracle is wrong about.

Everything else hostile stays in, and belongs in: a label is opaque text with no
encoding requirement (@docs/paper-amendments.md@ PA-03), so the escaping that
reaches a line is exactly what the oracle is here to check.
-}
genOracleSafeLabel :: Gen Text
genOracleSafeLabel = genLabelWith (\c -> c /= '\b' && c /= '\f')

-- | The lines of an AOF built from these events, first one from genesis.
aofOf :: [ChainedEvent] -> [ByteString]
aofOf = map (lineBytesRaw . (.line)) . chainFrom producerKey

{- | The gate. Every line of a produced AOF verifies under OpenSSL against a
signing message the oracle derived from that line.

One AOF per run rather than a hundred: the cost is processes, and the labels
vary across runs, so the suite sees new escaping over time while any single
failure still shrinks to the label that caused it.
-}
verifiesToOpenSsl :: Property
verifiesToOpenSsl = withTests 1 . property $ do
    events <- forAll (Gen.list (Range.singleton entryCount) (genEvent genOracleSafeLabel))
    verdicts <- evalIO (opensslVerdicts (aofOf events))
    verdicts === replicate entryCount True

{- | The negative control, without which the gate proves nothing.

A verification that cannot fail is not a verification. Altering the @entry_id@
leaves the line valid JSON — the point is a signature that no longer covers the
message, not a parse error, which would exercise @aeson@ rather than the
Producer.
-}
rejectsTamper :: Property
rejectsTamper = withTests 1 . property $ do
    event <- forAll (genEvent genOracleSafeLabel)
    verdicts <- evalIO (opensslVerdicts (map tamper (aofOf [event])))
    verdicts === [False]
  where
    -- Appending to the label always changes it, whatever it was, and keeps it a
    -- string -- so the only thing that has changed is what the signature covers.
    tamper line = case Aeson.eitherDecodeStrict line of
        Right (Aeson.Object o) ->
            let bumped = Aeson.String (textAt EntryId line <> "!")
             in LBS.toStrict (Aeson.encode (Aeson.Object (KeyMap.insert (key EntryId) bumped o)))
        _ -> error "a produced line is not an object"

{- | Each line's @prev_hash@ is the digest of the previous line's bytes; the
first is the genesis sentinel.

Honest about its own weight: the harness chains by carrying
'EventChain.Produce.lineHash' forward, so continuity holds by construction and
this cannot fail for a reason that would matter. What it grades is the two steps
between that value and the wire — that 'EventChain.Produce.produce' hands back a
digest of the line it returned rather than of something else, and that
"EventChain.Wire" writes it as the base64url of those bytes.

Real chain verification needs a reader handed only the file. That is the
Verifier, which does not exist yet — the whole reason this milestone is graded
by an oracle and a CLI instead.
-}
chainsToPreviousLine :: Property
chainsToPreviousLine = withTests 30 . property $ do
    events <- forAll (Gen.list (Range.linear 1 6) (genEvent genOracleSafeLabel))
    let ls = aofOf events
        claimed = map (unbase64 . textAt PrevHash) ls
        expected = lineHashRaw genesisHash : map digestOf (init ls)
    claimed === expected
  where
    digestOf raw = case lineBytes raw of
        Left err -> error ("a produced line is not a line: " <> show err)
        Right l -> case hashLines [l] of
            [h] -> lineHashRaw h
            hs -> error ("one line gave " <> show (length hs) <> " digests")

-- | The member's name, as a key into what @aeson@ parsed.
key :: Member -> Key.Key
key = Key.fromText . memberName

-- | The text at a member of a produced line. A broken test if it is not there.
textAt :: Member -> ByteString -> Text
textAt m line = case Aeson.eitherDecodeStrict line of
    Right (Aeson.Object o) -> case KeyMap.lookup (key m) o of
        Just (Aeson.String t) -> t
        other -> error (show (memberName m) <> " is " <> show other <> ", not a string")
    Right v -> error ("a produced line decoded to " <> show v)
    Left err -> error ("a produced line is not JSON: " <> err)

{- | Ask OpenSSL about each line, and report only what it said.

Anything that goes wrong before OpenSSL — a line that will not parse, a member
that is not base64url — is a broken test rather than a verdict, and errors
rather than being folded into 'False'. A gate that reports "rejected" when it
meant "I could not read this" is a gate that passes its negative control for the
wrong reason.
-}
opensslVerdicts :: [ByteString] -> IO [Bool]
opensslVerdicts ls =
    withSystemTempDirectory "eventchain-m2" $ \dir ->
        traverse (opensslVerifies dir) (zip [0 :: Int ..] ls)

-- | One line: the oracle derives the message, OpenSSL judges the signature.
opensslVerifies :: FilePath -> (Int, ByteString) -> IO Bool
opensslVerifies dir (index, line) = do
    let object = case Aeson.eitherDecodeStrict line of
            Right (Aeson.Object o) -> o
            Right v -> error ("line " <> show index <> " decoded to " <> show v)
            Left err -> error ("line " <> show index <> " is not JSON: " <> err)

        -- The oracle's canonicalization of the line minus its signature.
        -- Nothing of ours contributes a byte to this.
        message = LBS.toStrict (encodeCanonical (Aeson.Object (KeyMap.delete (key Signature) object)))

        path name = dir </> (show index <> "-" <> name)

    BS.writeFile (path "msg.bin") message
    BS.writeFile (path "sig.der") (rawSigToDer (unbase64 (textAt Signature line)))
    BS.writeFile (path "pub.der") (compressedPointToSpki (unbase64 (textAt PublicKey line)))

    (code, _, _) <-
        readProcessWithExitCode
            "openssl"
            [ "pkeyutl"
            , "-verify"
            , "-pubin"
            , "-inkey"
            , path "pub.der"
            , "-keyform"
            , "DER"
            , "-rawin"
            , "-digest"
            , "sha256"
            , "-in"
            , path "msg.bin"
            , "-sigfile"
            , path "sig.der"
            ]
            ""

    pure (code == ExitSuccess)

{- | A 64-byte @r‖s@ signature as the DER @SEQUENCE@ OpenSSL wants.

Written here rather than reached for. @eventchain-crypto@ has one internally and
does not export it, which is the right call and leaves this test with an
independent encoder — if the two ever disagree, OpenSSL says so here.

Single-byte lengths throughout, and that is not an assumption: the longest this
can produce is 70 content bytes, well under the 128 where DER's long form
starts.
-}
rawSigToDer :: ByteString -> ByteString
rawSigToDer raw = tagged 0x30 (tagged 0x02 (unsigned r) <> tagged 0x02 (unsigned s))
  where
    (r, s) = BS.splitAt 32 raw

    tagged tag body = BS.pack [tag, fromIntegral (BS.length body)] <> body

    -- DER integers are signed and minimally encoded: drop leading zeros, then
    -- put one back if the top bit would otherwise read as negative.
    unsigned bs
        | BS.null stripped = BS.singleton 0x00
        | BS.head stripped >= 0x80 = BS.cons 0x00 stripped
        | otherwise = stripped
      where
        stripped = BS.dropWhile (== 0x00) bs

{- | A 33-byte compressed P-256 point wrapped as a SubjectPublicKeyInfo, the
only shape OpenSSL will load a public key from.

The prefix is fixed for this curve and this point form: a @SEQUENCE@ of
(@SEQUENCE@ of @id-ecPublicKey@ and @prime256v1@) and a @BIT STRING@ of 34
bytes — one unused-bits byte plus the point. Read off
@openssl ec -conv_form compressed -outform DER@ rather than recalled, and
written as the hex that command prints so the two can be compared by eye.
-}
compressedPointToSpki :: ByteString -> ByteString
compressedPointToSpki point = unhex "3039301306072a8648ce3d020106082a8648ce3d030107032200" <> point

{- | base64url in, bytes out, through the untyped door.

Untyped on purpose. The typed encoder's wrapper is a claim the encoder makes
about its own output, which is worth nothing to a reader; what a line hands you
is text, and whether that text is unpadded base64url is the question rather than
the premise.
-}
unbase64 :: Text -> ByteString
unbase64 t = case Base64Url.decodeBase64UnpaddedUntyped (TE.encodeUtf8 t) of
    Right bs -> bs
    Left err -> error ("a member is not unpadded base64url: " <> show err)
