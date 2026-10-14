{-# LANGUAGE OverloadedStrings #-}

{- | The Mint envelope checks: the relying-party-free subset of W3C Web
Authentication §7.2, plus the challenge-equals-target-hash rule that binds an
assertion to its chain position (ADR-0007).

Hand-written on the shared crypto kernels, and fifty-odd lines because the
job is small: the signed message is one concatenation and one hash the
specification states in a sentence, and the signature arithmetic was proven
at M1 by published known answers. The tweag @webauthn@ package — whose
independent reading of §7.2 grades this module — is confined to a test
suite and is never a dependency of this library (ADR-0007).

§7.2 is written for a relying party mid-ceremony, so its steps divide
cleanly: those computable from the envelope alone run here; those needing an
RP-supplied expectation (origin, RP ID hash, UV policy) or a stored
credential record (signCount) have no possible input in a pure verifier and
are documented ignored in ADR-0007, not silently skipped.

What runs here is /structure/: 'envelopeChecks' answers every check except
the signature itself, which is batched through the crypto seam with the
Produced Proofs — "EventChain.Verify" builds the message with
'assertionMessage' and stitches the kernel's answer back as
'AssertionInvalid'.
-}
module EventChain.Verify.WebAuthn
    ( EnvelopeFault (..)
    , envelopeChecks
    , assertionMessage
    ) where

import Data.Aeson.Decoding.ByteString (bsToTokens)
import Data.Aeson.Decoding.Tokens (TkArray (..), TkRecord (..), Tokens (..))
import Data.Aeson.Key qualified as Key
import Data.Bits (testBit)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Text (Text)
import Data.Text qualified as T
import EventChain.Crypto.Types
    ( AuthenticatorBytes
    , ClientDataBytes
    , ClientDataHash
    , SignedBytes
    , authenticatorBytesRaw
    , clientDataBytesRaw
    , clientDataHashRaw
    , signedBytes
    )
import EventChain.Verify.Types.Internal.Attestation (WebAuthnEnvelope (..))

{- | A check from ADR-0007's list that ran and said no.

One vocabulary for the whole envelope, wherever the check runs: the
structural checks produce most of these, and "EventChain.Verify" stitches the
batched signature answer back as 'AssertionInvalid' and a key the curve
refused as 'AttesterKeyOffCurve' — so a report speaks one language about a
Mint no matter which tier caught it.
-}
data EnvelopeFault
    = -- | The client data is not UTF-8 (check 1).
      ClientDataNotUtf8
    | -- | The client data is not JSON (check 1). Carries the parser's complaint.
      ClientDataNotJson Text
    | -- | The client data is JSON, but not an object (check 1).
      ClientDataNotAnObject
    | {- | A member name appears twice in the client data (ADR-0007's reading
      rules): two @challenge@ members is the same ambiguous read as two
      @prev_hash@ members. No browser emits duplicates; presence marks
      fabrication or tampering. Carries the name as written.
      -}
      ClientDataDuplicate Text
    | {- | @type@ or @challenge@ carries a non-string value, which W3C types
      as @DOMString@. Carries the member's name.
      -}
      ClientDataNotText Text
    | {- | @type@ or @challenge@ is absent, so its check has nothing to run
      on. Carries the member's name.
      -}
      ClientDataIncomplete Text
    | {- | @C.type@ is not @webauthn.get@ (check 2): a registration response
      is not an attestation. Carries what it was instead.
      -}
      NotAnAssertion Text
    | {- | @C.challenge@ is not the @target_hash@ member's text (check 3) —
      the binding rule ADR-0002 §3 fixed, landing on §7.2's wording exactly:
      our challenge /is/ the target entry's line hash, so "equals the
      base64url encoding of pkOptions.challenge" is this string equality.
      -}
      ChallengeMismatch
        { challenge :: Text
        , declared :: Text
        }
    | {- | Fewer than the 37 bytes §6.1 makes structural: rpIdHash (32) ‖
      flags (1) ‖ signCount (4). Carries the actual length (check 4).
      -}
      AuthenticatorDataTruncated Int
    | {- | The UP bit is not set (check 5). Unconditional in §7.2; no real
      authenticator omits it, so its absence marks a fabricated envelope.
      -}
      UserPresenceUnset
    | {- | BS set while BE is not (check 6): a credential backed up but never
      eligible for backup. Stateless internal consistency; same tripwire.
      -}
      BackupStateInconsistent
    | {- | The assertion signature is not the attester key's over the
      envelope's message (check 7). Answered at the crypto seam, in batches.
      -}
      AssertionInvalid
    | {- | The @attester_key@ is 33 well-formed bytes naming no point on
      P-256, so there is no key to check the assertion against.
      -}
      AttesterKeyOffCurve
    deriving stock (Eq, Show)

{- | Checks 1 through 6: everything except the signature, which needs the
crypto seam and is batched there by the fold.

The client-data group and the authenticator-data group are independent and
both report — a tampered envelope is not entitled to hide its second problem
behind its first. Within each group the checks chain, because a value that
did not parse has no members to read.

The target arrives as the @target_hash@ member's /text/, not the decoded
hash: check 3 is string equality between two base64url encodings, per §7.2's
own framing, and re-encoding decoded bytes to compare would put a second
encoder where the rule is about the first one's output.
-}
envelopeChecks :: Text -> WebAuthnEnvelope -> [EnvelopeFault]
envelopeChecks targetHashText env =
    clientDataFaults targetHashText env.clientDataJson
        <> authenticatorDataFaults env.authenticatorData

{- | The message the assertion signs: @authenticatorData ‖ SHA-256(clientDataJSON)@.

The digest arrives rather than being computed: "EventChain.Verify" hashes a
chunk's client data in one crossing of the seam (ADR-0004's batching), and
this function is the claim that §7.2's "binary concatenation of authData and
hash" is what those two quantities form.
-}
assertionMessage :: WebAuthnEnvelope -> ClientDataHash -> SignedBytes
assertionMessage env h =
    signedBytes (authenticatorBytesRaw env.authenticatorData <> clientDataHashRaw h)

-- Client data ----------------------------------------------------------------

{- | Checks 1–3: the client data decodes, and its two read members say what an
assertion over this target must say.

The nested document is authored by browsers, not by this format, so the
entry-level closed vocabulary (ADR-0002 §5) is explicitly out of scope inside
it (ADR-0007): unknown members are tolerated and skipped unread — their bytes
are covered by the signature, and their meaning is a browser's business, not
a claim this Verifier attests. Values are typed per W3C, so the entry codec's
strings-only rule cannot apply and does not; only @type@ and @challenge@ must
be strings, because those are the two that are read.
-}
clientDataFaults :: Text -> ClientDataBytes -> [EnvelopeFault]
clientDataFaults targetHashText cData
    | not (BS.isValidUtf8 raw) = [ClientDataNotUtf8]
    | otherwise = case readMembers (bsToTokens raw) of
        Left fault -> [fault]
        Right members -> typeFault members <> challengeFault members
  where
    raw = clientDataBytesRaw cData

    typeFault members = case Map.lookup "type" members of
        Nothing -> [ClientDataIncomplete "type"]
        Just t
            | t == "webauthn.get" -> []
            | otherwise -> [NotAnAssertion t]

    challengeFault members = case Map.lookup "challenge" members of
        Nothing -> [ClientDataIncomplete "challenge"]
        Just c
            | c == targetHashText -> []
            | otherwise -> [ChallengeMismatch{challenge = c, declared = targetHashText}]

{- | The top-level string-valued members by name — duplicates fatal, everything
else skipped whole.

A fold over the same token stream the entry codec uses, for the same reason:
@decode@ collapses duplicates silently, and two @challenge@ members are
exactly the ambiguity being policed. The duplicate rule runs over the
top-level names only — inside a skipped value nothing is read, so nothing can
be misread; a duplicate buried in an unread extension changes no byte of what
this Verifier attests.

A non-string value under a name nobody reads is skipped like the rest; under
@type@ or @challenge@ it is 'ClientDataNotText', because those are read as
W3C types them.
-}
readMembers :: Tokens ByteString String -> Either EnvelopeFault (Map Text Text)
readMembers = \case
    TkRecordOpen record -> pairs Set.empty Map.empty record
    TkErr err -> Left (ClientDataNotJson (T.pack err))
    TkLit _ _ -> Left ClientDataNotAnObject
    TkText _ _ -> Left ClientDataNotAnObject
    TkNumber _ _ -> Left ClientDataNotAnObject
    TkArrayOpen _ -> Left ClientDataNotAnObject
  where
    pairs :: Set Text -> Map Text Text -> TkRecord ByteString String -> Either EnvelopeFault (Map Text Text)
    pairs seen acc = \case
        TkPair key value
            | Set.member name seen -> Left (ClientDataDuplicate name)
            | otherwise -> case value of
                TkText t rest -> pairs seen' (Map.insert name t acc) rest
                other
                    | isRead name -> Left (ClientDataNotText name)
                    | otherwise -> pairs seen' acc =<< skipValue other
          where
            name = Key.toText key
            seen' = Set.insert name seen
        TkRecordEnd _ -> Right acc
        TkRecordErr err -> Left (ClientDataNotJson (T.pack err))

    isRead n = n == "type" || n == "challenge"

{- | Consume one JSON value from the token stream, reading nothing.

W3C reserves the right for clients to add members of any shape — @crossOrigin@
is a boolean in the specification itself — so a skipped value may be an
object, an array, or any scalar. Signed, unread, unparsed, like the
authenticator data's extensions.
-}
skipValue :: Tokens k String -> Either EnvelopeFault k
skipValue = \case
    TkLit _ rest -> Right rest
    TkText _ rest -> Right rest
    TkNumber _ rest -> Right rest
    TkArrayOpen arr -> skipArray arr
    TkRecordOpen record -> skipRecord record
    TkErr err -> Left (ClientDataNotJson (T.pack err))
  where
    skipArray = \case
        TkItem item -> skipArray =<< skipValue item
        TkArrayEnd rest -> Right rest
        TkArrayErr err -> Left (ClientDataNotJson (T.pack err))

    skipRecord = \case
        TkPair _ value -> skipRecord =<< skipValue value
        TkRecordEnd rest -> Right rest
        TkRecordErr err -> Left (ClientDataNotJson (T.pack err))

-- Authenticator data ---------------------------------------------------------

{- | Checks 4–6: the layout §6.1 makes structural, and the two flag rules.

Trailing bytes past the 37 — extensions, attested credential data — are
covered by the assertion signature and not parsed (ADR-0007): nothing is read
from them, so nothing can be misread. The flag byte sits at offset 32; UP is
bit 0, BE bit 3, BS bit 4. UV (bit 2) is deliberately not examined — §7.2
conditions it on RP policy no pure verifier can hold, and ADR-0007 records
why rejecting on it would encode a policy the format cannot ground.
-}
authenticatorDataFaults :: AuthenticatorBytes -> [EnvelopeFault]
authenticatorDataFaults authData
    | BS.length raw < 37 = [AuthenticatorDataTruncated (BS.length raw)]
    | otherwise = userPresence <> backupState
  where
    raw = authenticatorBytesRaw authData
    flags = BS.index raw 32

    userPresence
        | testBit flags 0 = []
        | otherwise = [UserPresenceUnset]

    backupState
        | testBit flags 4 && not (testBit flags 3) = [BackupStateInconsistent]
        | otherwise = []
