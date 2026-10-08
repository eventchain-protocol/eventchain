{- | The reference Verifier: AOF bytes in, a typed per-entry verdict out.

Pure, and handed nothing. No clock, no network, no config, no Producer — the
same position a stranger is in, holding the file and a published document.
Everything this module concludes it concluded from bytes, which is what makes
the conclusion worth anything.

Two checks at v0, both from @docs/protocol.md@'s verification section:
/continuity/ — each line's @prev_hash@ is the digest of the previous line's
bytes — and /attribution/ — the signature is the claimed key's, over the entry's
canonical bytes. Payload commitment needs a caller-supplied lookup and arrives
with the finalized report at M5; minted-status derivation is a separate fold at
M4, kept separate because it joins each Mint to a target that precedes it and so
costs O(n) memory where this pass costs O(1).

/The promotion is typed./ A t'VerifiedEntry' cannot be built anywhere but here,
so a function that demands one has a compile-time guarantee the machinery ran.
Claims flow in from "EventChain.Verify.Wire"; facts flow out of this module;
nothing else converts between them.
-}
module EventChain.Verify
    ( -- * What the fold establishes
      VerifiedEntry
    , verifiedPosition
    , verifiedEntry
    , verifiedLineHash
    , Fault (..)
    , Verdict (..)

      -- * The fold
    , verify
    , genesisHash
    ) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.List (zipWith5)
import Data.List.NonEmpty (NonEmpty, nonEmpty)
import Data.Map.Lazy (Map)
import Data.Map.Lazy qualified as Map
import Data.Text (Text)
import EventChain.Crypto (CryptoError (..), PublicKey, SigCheck (..), hashClientData, hashLines, publicKey, verifyBatch)
import EventChain.Crypto.Types (ClaimedKey, LineHash, Sig, SignedBytes, lineHashFromBytes, sha256Length)
import EventChain.Verify.Canonical (canonicalize, signingMessage)
import EventChain.Verify.EntryObject (EntryObject (..), MintMembers (..))
import EventChain.Verify.Types
    ( Attestation (..)
    , ChainPosition
    , Entry (..)
    , EntryKind (..)
    , ProducedProof (..)
    , WebAuthnEnvelope (..)
    )
import EventChain.Verify.WebAuthn (EnvelopeFault (..), assertionMessage, envelopeChecks)
import EventChain.Verify.Wire
    ( DecodeError
    , DecodedEntry
    , FramingError
    , decodeLine
    , decodedEntry
    , decodedLine
    , decodedObject
    , frameFile
    )

{- | An Entry the machinery has discharged: its chain link holds and its
signature is its claimed key's, over its own canonical bytes.

The constructor is unexported and this module is the only one that can run the
checks, so holding one of these /is/ the evidence. That is rule 8 of
@docs/plan.md@ doing its job: a fact type defined anywhere but the module that
establishes the fact makes "sole constructor" a convention someone has to be
told about.

It carries the line's digest because the next entry's chain link is that value,
and because a Mint references its target by it (M4) — recomputing it later from
a re-serialization is the one thing ADR-0002 §1 forbids.
-}
data VerifiedEntry = VerifiedEntry
    { position :: ChainPosition
    , entry :: Entry
    , lineHash :: LineHash
    }
    deriving stock (Eq, Show)

-- | Where in the file this Entry sits.
verifiedPosition :: VerifiedEntry -> ChainPosition
verifiedPosition v = v.position

-- | The Entry, now that its claims have been discharged.
verifiedEntry :: VerifiedEntry -> Entry
verifiedEntry v = v.entry

-- | SHA-256 of this line's bytes — the protocol's entry hash.
verifiedLineHash :: VerifiedEntry -> LineHash
verifiedLineHash v = v.lineHash

{- | A check that ran and said no.

'ChainMismatch' names what was expected against what was claimed, because
"verification failed at line 5000" sends a reader back to the file with nothing
to look for.
-}
data Fault
    = {- | The line's @prev_hash@ is not the digest of the previous line's bytes;
      at position zero, not the genesis sentinel.
      -}
      ChainMismatch
        { expected :: LineHash
        , claimed :: LineHash
        }
    | {- | The @public_key@ is 33 well-formed bytes naming no point on P-256, so
      there is nobody to attribute the Entry to.
      -}
      KeyOffCurve
    | {- | The signature is not this key's over these canonical bytes. Nothing is
      wrong except the claim.
      -}
      SignatureInvalid
    | {- | A Mint's envelope failed one of ADR-0007's checks. One wrapper per
      finding, so a report lists each the way it lists every other fault; the
      check's own vocabulary is the Verifier's WebAuthn module's.
      -}
      AttestationFault EnvelopeFault
    deriving stock (Eq, Show)

{- | What the fold established about one line.

Four outcomes, because they are four different things and collapsing any two
loses what a reader needs. In particular 'Undecided' is not a fault: libcrypto
failing to answer is a broken installation, and reporting it as a bad signature
would pronounce an AOF forged because our machine was. That is the distinction
@eventchain-crypto@ draws between 'SigInvalid' and a t'CryptoError', carried
through to the report rather than flattened at the last step.
-}
data Verdict
    = -- | The line is an Entry, and both checks held.
      Sound VerifiedEntry
    | -- | The line is not an Entry at all. Always the last verdict: see 'verify'.
      Malformed DecodeError
    | -- | The line is an Entry, and at least one check said no.
      Unsound ChainPosition (NonEmpty Fault)
    | {- | No verdict was reached: libcrypto did not answer attribution, and no
      other check found a fault. Says nothing about the Entry.

      A decided fault outranks this. A chain mismatch is established by hashing,
      which either answers or throws — so when attribution goes unanswered on a
      line whose link already failed, the line is 'Unsound' with the faults that
      were found, and the malfunction surfaces on the lines that had none.
      -}
      Undecided ChainPosition CryptoError
    deriving stock (Eq, Show)

{- | The sentinel a first entry's @prev_hash@ must be: 32 zero bytes.

There is no previous line to hash at position zero, so the format fixes a value
rather than leaving the member optional — a line whose shape depended on where
it sat would need two codecs, and would let a producer omit the member to dodge
the check.
-}
genesisHash :: LineHash
genesisHash = case lineHashFromBytes (BS.replicate sha256Length 0) of
    Right h -> h
    Left err -> error ("EventChain.Verify: the genesis sentinel is not a hash: " <> show err)

{- | How many lines are folded per crossing of the crypto seam.

Batching is mandatory rather than a tuning knob left at one: at SHA-NI speed a
300-byte hash is roughly 150ns, about what a single FFI call costs, so a call
per line would spend the hardware acceleration on call overhead (ADR-0004).
Large enough to amortize the crossing, small enough that folding a
billion-entry AOF holds a chunk rather than a file.
-}
chunkSize :: Int
chunkSize = 256

{- | Verify an AOF: continuity and attribution, one forward streaming pass.

Verdicts come out lazily against a lazy file, so folding a large AOF holds a
chunk rather than all of it. The 'Either' resolves after three bytes — framing
has exactly one whole-file failure, a byte order mark, and everything else a
file can do wrong belongs to a line and is reported at that line's position.

/A malformed line halts the fold,/ so a 'Malformed' verdict is always the last
one in the list. This is the plan's "hard error with a line number" in a
streaming shape: past a line that is not an Entry there is no next @prev_hash@
to check and no signature to check, so continuing would report positions rather
than findings. What precedes it stands — those verdicts were reached from bytes
that parsed.
-}
verify :: LBS.ByteString -> Either FramingError [Verdict]
verify file = fold genesisHash . chunksOf chunkSize <$> frameFile file

{- | Fold the chunks, carrying the one piece of state the chain has: the digest
of the last line read.

Carried as a t'LineHash' computed from the line that was actually read, which is
the whole of ADR-0002 §1 — the alternative, recomputing it from the parsed view,
is the forgery the codec's pairing exists to refuse.
-}
fold :: LineHash -> [[(ChainPosition, ByteString)]] -> [Verdict]
fold _ [] = []
fold prev (chunk : rest) = case chunkVerdicts prev chunk of
    (verdicts, Nothing) -> verdicts
    (verdicts, Just prev') -> verdicts <> fold prev' rest

{- | One chunk: decode every line, hash them all in one call, judge the
Produced Proofs in one crossing and the Mint assertions in another.

Two crossings rather than one interleaved batch, and the split is the
batching working instead of failing: 'EventChain.Crypto.verifyBatch' reuses
its verification context only while consecutive triples carry equal keys, an
AOF is mostly runs of one Producer's key, and splicing each Mint's attester
key into the middle of a run would break the run to save a call that costs
less than the reuse it destroys.

Returns the digest to carry forward, or 'Nothing' if the chunk halted on a
malformed line, in which case no later chunk runs.
-}
chunkVerdicts :: LineHash -> [(ChainPosition, ByteString)] -> ([Verdict], Maybe LineHash)
chunkVerdicts prev lns =
    ( zipWith5 judge decoded hashes links attributions envelopes <> foldMap (pure . Malformed) halt
    , maybe (Just (lastOr prev hashes)) (const Nothing) halt
    )
  where
    (decoded, halt) = spanDecoded lns

    entries = map snd decoded
    hashes = hashLines (map decodedLine entries)
    links = chainFaults prev (zip entries hashes)
    attributions = attributionResults entries
    envelopes = envelopeResults entries

    -- Verdict precedence, uniform across every check the fold runs: a decided
    -- fault outranks an unanswered question. A chain mismatch is established
    -- by hashing and an envelope's structure by reading, both of which either
    -- answer or throw -- so when a crypto seam goes silent on a line that
    -- already has findings, the line is Unsound with what was found, and the
    -- malfunction surfaces on the lines that had none.
    judge (pos, d) h link attribution (envStructural, assertion) =
        case [e | Left e <- [attribution, assertion]] of
            [] -> case nonEmpty answered of
                Just faults -> Unsound pos faults
                Nothing -> Sound VerifiedEntry{position = pos, entry = decodedEntry d, lineHash = h}
            err : _ -> case nonEmpty answered of
                Just faults -> Unsound pos faults
                Nothing -> Undecided pos err
      where
        answered = link <> envStructural <> foldMap answerOf [attribution, assertion]
        answerOf = either (const []) id

    lastOr d [] = d
    lastOr _ hs = last hs

{- | Decode until a line is not an Entry, keeping what came before it.

The prefix is kept rather than discarded with the chunk: those lines parsed, and
what was established about them was established from their own bytes. Which line
broke the file is the finding, and dropping its predecessors' verdicts would
hide where the good part ended.
-}
spanDecoded :: [(ChainPosition, ByteString)] -> ([(ChainPosition, DecodedEntry)], Maybe DecodeError)
spanDecoded [] = ([], Nothing)
spanDecoded ((pos, raw) : more) = case decodeLine pos raw of
    Left err -> ([], Just err)
    Right d -> let (rest, halt) = spanDecoded more in ((pos, d) : rest, halt)

{- | Each line's claimed @prev_hash@ against the digest of the line before it.

The first line in the file is checked against the genesis sentinel; every other
against the line that actually preceded it, whatever that line said about
itself.
-}
chainFaults :: LineHash -> [(DecodedEntry, LineHash)] -> [[Fault]]
chainFaults _ [] = []
chainFaults expectedPrev ((d, h) : more) = fault : chainFaults h more
  where
    claimedPrev = (decodedEntry d).prevHash
    fault
        | claimedPrev == expectedPrev = []
        | otherwise = [ChainMismatch{expected = expectedPrev, claimed = claimedPrev}]

{- | Whether each line's key is on the curve, and whether each signature is that
key's — the whole chunk in one crossing.

A key naming no point on P-256 is a fault about the line. libcrypto failing to
answer is not, and the two arrive as different constructors of t'CryptoError'
precisely so this function does not have to guess which it is looking at. A
malfunction takes down the whole chunk's verdicts rather than one line's,
because it is not evidence about any line.
-}
attributionResults :: [DecodedEntry] -> [Either CryptoError [Fault]]
attributionResults decoded = case traverse (prepare promoted) decoded of
    Left err -> map (const (Left err)) decoded
    Right prepared -> case verifyBatch [t | Checkable t <- prepared] of
        Left err -> map (const (Left err)) decoded
        Right checks -> stitch [KeyOffCurve] answered prepared checks
  where
    answered SigValid = []
    answered SigInvalid = [SignatureInvalid]

    -- One promotion per distinct key in the chunk, never one per line.
    -- Promoting is a ~15 µs EVP_PKEY load against a ~34 µs verify, an AOF is
    -- mostly runs of one Producer's key, and 'verifyBatch' reuses its
    -- verification context only while consecutive triples carry equal keys —
    -- so the lines of a run must share one t'PublicKey', or every line pays
    -- the load and the reuse never happens. The map is value-lazy on purpose:
    -- each distinct key is one thunk, loaded the first time a line needs it.
    promoted = Map.fromList [(c, publicKey c) | d <- decoded, let c = claimOf d]
    claimOf d = (decodedEntry d).producedProof.publicKey

{- | A line's signature, ready to judge — or a key that cannot carry one.

'KeyRejected' is not an error and not yet a fault: it is a line that will not
reach the batch, and the batch's results have to be stitched back around it.
-}
data Checkable
    = KeyRejected
    | Checkable (PublicKey, SignedBytes, Sig)

{- | Promote the claimed key and derive the signing message from what the line said.

The key comes through the chunk's shared promotion map, so a run of lines under
one Producer's key holds one loaded key rather than a copy per line. The default
is a direct promotion and nothing relies on it being unreachable — a claim
missing from a map built over this same chunk cannot happen, but a fresh load
answers it identically if it somehow did.
-}
prepare :: Map ClaimedKey (Either CryptoError PublicKey) -> DecodedEntry -> Either CryptoError Checkable
prepare promoted d = case Map.findWithDefault (publicKey claim) claim promoted of
    Left KeyNotOnCurve -> Right KeyRejected
    Left err -> Left err
    Right k -> Right (Checkable (k, message, proof.signature))
  where
    proof = (decodedEntry d).producedProof
    claim = proof.publicKey
    message = signingMessage (canonicalize (decodedObject d))

{- | Put a batch's answers back beside the lines they are about.

'verifyBatch' answers one t'SigCheck' per triple, in order, and lines whose key
was rejected supplied no triple. A mismatched answer count in either direction
is a broken contract, so it is an error rather than a verdict: a Verifier that
quietly ran out of answers — or quietly had answers left over, which means the
pairing above them slipped — would report faults against the wrong lines.

Parameterized over the fault vocabulary because both signature streams stitch
identically and mean differently: a Produced Proof's rejected key is
'KeyOffCurve' where an assertion's is the envelope's own
'AttesterKeyOffCurve', and the answer @no@ is 'SignatureInvalid' on one side
of the seam and 'AssertionInvalid' on the other.
-}
stitch :: [Fault] -> (SigCheck -> [Fault]) -> [Checkable] -> [SigCheck] -> [Either CryptoError [Fault]]
stitch rejectedKey answered = go
  where
    go [] [] = []
    go (KeyRejected : more) checks = Right rejectedKey : go more checks
    go (Checkable _ : more) (c : checks) = Right (answered c) : go more checks
    go (Checkable _ : _) [] =
        error "EventChain.Verify: verifyBatch answered fewer checks than it was given."
    go [] (_ : _) =
        error "EventChain.Verify: verifyBatch answered more checks than it was given."

{- | What each line's Mint envelope establishes: structural findings, and the
assertion's answer from the crypto seam. A lifecycle line contributes nothing
to either.

Structure and signature separate on purpose, because they fail differently:
the checks of ADR-0007 are pure reads that always answer, while the assertion
crosses the seam and can go unanswered — and 'chunkVerdicts' must not let a
malfunction there swallow a finding here.

The batching mirrors the Produced Proofs': every Mint's client data is hashed
in one crossing ('hashClientData'), every assertion judged in another
('verifyBatch'), and each attester key is promoted once per chunk however
many Mints it signed.
-}
envelopeResults :: [DecodedEntry] -> [([Fault], Either CryptoError [Fault])]
envelopeResults decoded = map result (zip [0 :: Int ..] decoded)
  where
    result (i, d) = case (decodedEntry d).kind of
        LifecycleEntry -> ([], Right [])
        MintEntry _ ->
            ( Map.findWithDefault [] i structurals
            , Map.findWithDefault (Right []) i answers
            )

    mints :: [(Int, Text, Attestation)]
    mints =
        [ (i, targetText d, a)
        | (i, d) <- zip [0 ..] decoded
        , MintEntry a <- [(decodedEntry d).kind]
        ]

    -- The codec builds a MintEntry from the line's own Mint members, so a
    -- decoded Mint without them cannot happen; answering with an error keeps
    -- the invariant loud instead of quietly re-encoding the decoded hash.
    targetText d = case (decodedObject d).mint :: Maybe MintMembers of
        Just m -> m.targetHash
        Nothing -> error "EventChain.Verify: a Mint decoded without its members."

    structurals =
        Map.fromList
            [ (i, map AttestationFault (envelopeChecks t a.envelope))
            | (i, t, a) <- mints
            ]

    -- One digest crossing for the chunk's client data, then one message per
    -- Mint: authenticatorData ‖ SHA-256(clientDataJSON), the claim the
    -- Verifier's WebAuthn module owns.
    digests = hashClientData [a.envelope.clientDataJson | (_, _, a) <- mints]
    messages = zipWith (\(_, _, a) h -> assertionMessage a.envelope h) mints digests

    promoted = Map.fromList [(a.attesterKey, publicKey a.attesterKey) | (_, _, a) <- mints]

    answers :: Map Int (Either CryptoError [Fault])
    answers = case traverse checkable (zip mints messages) of
        Left err -> Map.fromList [(i, Left err) | (i, _, _) <- mints]
        Right prepared -> case verifyBatch [t | (_, Checkable t) <- prepared] of
            Left err -> Map.fromList [(i, Left err) | (i, _, _) <- mints]
            Right checks ->
                Map.fromList
                    ( zip
                        (map fst prepared)
                        (stitch [AttestationFault AttesterKeyOffCurve] answered (map snd prepared) checks)
                    )
      where
        answered SigValid = []
        answered SigInvalid = [AttestationFault AssertionInvalid]

    checkable ((i, _, a), message) = case Map.findWithDefault (publicKey claim) claim promoted of
        Left KeyNotOnCurve -> Right (i, KeyRejected)
        Left err -> Left err
        Right k -> Right (i, Checkable (k, message, a.assertionSig))
      where
        claim = a.attesterKey

{- | Split a list into fixed-size chunks, lazily.

Written here rather than depended on: @chunksOf@ is in neither @base@ nor
@containers@, and @split@ is a package for four lines.
-}
chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = let (h, t) = splitAt n xs in h : chunksOf n t
