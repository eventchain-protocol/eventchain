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

/Verification resumes./ A holder checks each Entry once, when it arrives, and
never again: it keeps the position and digest of the last line it verified as
a t'Checkpoint', and 'verifyFrom' folds only the lines after it. The whole-file
'verify' is the same fold started from the genesis sentinel.

/Chunks run in parallel./ The only thing one line needs from another is the
digest of the line before it, and a digest is a function of raw bytes — so the
chain's sequential part is framing and one hash per chunk, and every chunk's
decoding and signature checks are independent work. The fold fans chunks out
across however many capabilities the RTS was given, through a bounded buffer
that keeps a large file's memory at a few chunks. One capability is not one
core here: the signature check is a @safe@ foreign call that releases its
capability for the microseconds it runs, and the runtime spends that time on
the next chunk's spark, so even @-N1@ overlaps the kernel with the work around
it (measured: @docs/research/2026-10-verifier-throughput.md@).

/Attribution runs on a precomputed key./ A chunk promotes each distinct key
once and builds the table of its multiples with it (ADR-0004 as amended), so
each signature is two fixed-base table walks rather than a general scalar
multiplication. The table is a function of a key already proven on the curve;
it adds no fact. A run of one key across chunks builds it once: the spine
hands each chunk the promotion of the key its predecessor's last line signed
with, read from that one line, and a chunk whose lines carry that key shares
the thunk rather than making its own. Mint assertions stay on libcrypto's
verify: they are rare, and their attester keys are not runs.
-}
module EventChain.Verify
    ( -- * What the fold establishes
      VerifiedEntry
    , verifiedPosition
    , verifiedEntry
    , verifiedLineHash
    , Fault (..)
    , Verdict (..)

      -- * Where a resumed fold starts
    , Checkpoint
    , checkpoint
    , checkpointFrom
    , checkpointIndex
    , checkpointHash

      -- * The fold
    , verify
    , verifyFrom
    , genesisHash
    ) where

import Control.Parallel.Strategies (evalList, evalTuple2, parBuffer, rseq, using)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.List (zipWith5)
import Data.List.NonEmpty (NonEmpty, nonEmpty)
import Data.Map.Lazy (Map)
import Data.Map.Lazy qualified as Map
import Data.Text (Text)
import Data.Word (Word64)
import EventChain.Crypto (CryptoError (..), PrecomputedKey, SigCheck (..), hashClientData, hashLines, precomputeKey, publicKey, verifyBatch, verifyBatchPrecomputed)
import EventChain.Crypto.Types (ClaimedKey, LineHash, Sig, SignedBytes, lineBytes, lineHashFromBytes, sha256Length)
import EventChain.Verify.Canonical (canonicalize, signingMessage)
import EventChain.Verify.EntryObject (EntryObject (..), MintMembers (..))
import EventChain.Verify.Types
    ( Attestation (..)
    , ChainPosition
    , Entry (..)
    , EntryKind (..)
    , ProducedProof (..)
    , WebAuthnEnvelope (..)
    , chainPositionIndex
    )
import EventChain.Verify.Types.Internal.Entry (chainPosition)
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
    , frameLines
    )
import GHC.Conc (numCapabilities)

{- | An Entry the machinery has discharged: its chain link holds and its
signature is its claimed key's, over its own canonical bytes.

The constructor is unexported and this module is the only one that can run the
checks, so holding one of these /is/ the evidence. That is rule 8 of
@docs/plan.md@ doing its job: a fact type defined anywhere but the module that
establishes the fact makes "sole constructor" a convention someone has to be
told about.

Under 'verifyFrom' the evidence is conditional: the first link was checked
against a t'Checkpoint' the caller supplied, and the type cannot vouch for what
the caller stored. A holder that trusts its own record of what it verified
trusts these exactly as far; one that does not should fold from the start.

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

{- | The last Entry a holder verified: its position, and the digest of its
line. What 'verifyFrom' starts from, and what a holder keeps between runs.

A claim, not a fact — the same tier as a @prev_hash@ read off a line. It can be
built from a t'VerifiedEntry' this module produced ('checkpoint') or from the
two values a holder stored ('checkpointFrom'), and the type does not know which;
it is exactly as trustworthy as the holder's own record of what it checked.
That is the paper's model of a holder, which verifies each Entry once, when it
arrives, and compares digests ever after.

Only the chain's state. The Minted join ("EventChain.Verify.Minted") carries
every Sound digest seen, which a tail does not have; a holder that resumes the
fold and wants minted status must keep that index too, and does not get it here.
-}
data Checkpoint = Checkpoint
    { lastPosition :: ChainPosition
    , lastHash :: LineHash
    }
    deriving stock (Eq, Show)

-- | The checkpoint a verified Entry is: where the fold may next resume.
checkpoint :: VerifiedEntry -> Checkpoint
checkpoint v = Checkpoint{lastPosition = v.position, lastHash = v.lineHash}

{- | A checkpoint from what a holder stored: the index 'checkpointIndex' gave
it, and the digest 'checkpointHash' gave it.

This is the only way a position enters this package from outside the framer,
and it enters as a claim: nothing checks that a line ever sat there, because
the holder is the only one who could know.
-}
checkpointFrom :: Word64 -> LineHash -> Checkpoint
checkpointFrom index digest = Checkpoint{lastPosition = chainPosition index, lastHash = digest}

-- | The ordinal of the checkpointed line, counted from zero: what to store.
checkpointIndex :: Checkpoint -> Word64
checkpointIndex c = chainPositionIndex c.lastPosition

-- | The digest of the checkpointed line: what to store, and what the next line must name.
checkpointHash :: Checkpoint -> LineHash
checkpointHash c = c.lastHash

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

{- | How many chunks may be in flight ahead of the consumer.

Twice the capabilities: enough that no worker waits on the consumer to reach
the next chunk, small enough that a billion-entry file still holds a few
thousand lines. Never zero, so a chunk can be sparked ahead even on one
capability — where it runs whenever the consumer's chunk is inside a @safe@
libcrypto call and the capability is free.
-}
inFlight :: Int
inFlight = 2 * numCapabilities

{- | Verify an AOF from its first byte: continuity and attribution, one
forward pass.

Verdicts come out lazily against a lazy file, so folding a large AOF holds
'inFlight' chunks rather than all of it. The 'Either' resolves after three
bytes — framing has exactly one whole-file failure, a byte order mark, and
everything else a file can do wrong belongs to a line and is reported at that
line's position.

/A malformed line halts the fold,/ so a 'Malformed' verdict is always the last
one in the list. This is the plan's "hard error with a line number" in a
streaming shape: past a line that is not an Entry there is no next @prev_hash@
to check and no signature to check, so continuing would report positions rather
than findings. What precedes it stands — those verdicts were reached from bytes
that parsed.
-}
verify :: LBS.ByteString -> Either FramingError [Verdict]
verify file = fold genesisHash <$> frameFile file

{- | Verify the lines after a checkpoint: the same fold as 'verify', started
from the holder's last verified line instead of the genesis sentinel.

The bytes are the file's tail — everything after the @0x0a@ that ended the
checkpointed line — and the first line in them is checked against the
checkpoint's digest exactly as any line is checked against the one before it.
A tail that does not chain to the checkpoint is 'Unsound' at its first line,
with the mismatch named; a tail that chains to it continues the holder's
evidence from where it stopped. Positions continue the count too, so a verdict
here names the same line it would in a fold from the start.

No 'Either', because the one file-level failure is about a file's first bytes
and these are not a file's first bytes.
-}
verifyFrom :: Checkpoint -> LBS.ByteString -> [Verdict]
verifyFrom c = fold c.lastHash . frameLines (chainPosition (checkpointIndex c + 1))

{- | Fold the lines in chunks, each chunk's work independent of the rest.

The chain hands each chunk exactly one thing from before it that a verdict
depends on: the digest of the line it follows. That digest is a function of
raw bytes, so 'boundary' computes it from the previous chunk's last line
without waiting for that chunk to be decoded or judged — and with it in hand,
a chunk's decoding, hashing and signature checks depend on nothing outside
the chunk. The chunks are fanned out through a bounded spark buffer; forcing
each verdict to constructor forces every check behind it, which is why no
deep evaluation is needed.

One more thing travels the same way, and no verdict depends on it: the
promotion of the key the previous chunk's last line signed with (@seed@),
decoded from that one line on the spine. A chunk whose lines carry that key
uses the shared thunk, so a run of one Producer's key across the file builds
its table once rather than once per chunk; a chunk under some other key
promotes its own as before. The seed is at most one key, so the spine holds
one table, not one per key the file ever named.

Carried as a t'LineHash' computed from the line that was actually read, which is
the whole of ADR-0002 §1 — the alternative, recomputing it from the parsed view,
is the forgery the codec's pairing exists to refuse.

A chunk that halts on a malformed line ends the fold at that verdict. The chunk
after it may have been evaluated speculatively — wasted work on a file that was
going to be refused anyway — and its verdicts are never emitted, so what the
caller sees is what the sequential fold would have said.
-}
fold :: LineHash -> [(ChainPosition, ByteString)] -> [Verdict]
fold prev lns = untilHalt (map (\(p, s, c) -> chunkVerdicts p s c) staged `using` parBuffer inFlight (evalTuple2 (evalList rseq) rseq))
  where
    chunks = chunksOf chunkSize lns

    -- Each chunk paired with the digest it follows and the seed it inherits.
    -- A chunk whose last line is not well-formed has no boundary, and the
    -- chunk after it is not staged: that chunk halts, so nothing after it
    -- would be read.
    staged = zip3 (prev : untilNothing (map boundary chunks)) seeds chunks

    untilNothing = foldr (\m acc -> maybe [] (: acc) m) []

    -- The seed a chunk inherits: its predecessor's last key, promoted once.
    -- Kept when it is the key already seeded, so a run shares one thunk;
    -- replaced otherwise, so the spine never holds more than one table.
    seeds = scanl seed Map.empty (map lastKey chunks)
    seed inherited = \case
        Just c
            | Map.member c inherited -> inherited
            | otherwise -> Map.singleton c (precomputeKey <$> publicKey c)
        Nothing -> Map.empty

    untilHalt [] = []
    untilHalt ((verdicts, halt) : rest) = verdicts <> maybe (untilHalt rest) (const []) halt

{- | The key the chunk after this one is likely to see: its last line's, read
by decoding that one line on the spine — ~7 µs per chunk against a ~520 µs
table build saved per chunk of a run. 'Nothing' for a line that is not an
Entry, and then the chunk after it is not staged anyway.
-}
lastKey :: [(ChainPosition, ByteString)] -> Maybe ClaimedKey
lastKey chunk = case decodeLine pos raw of
    Right d -> Just (decodedEntry d).producedProof.publicKey
    Left _ -> Nothing
  where
    (pos, raw) = last chunk

{- | The digest the chunk after this one must chain to: its last line's,
computed from the raw bytes — the same bytes 'chunkVerdicts' hashes, and so
the same digest, reached without that chunk's decode.

'Nothing' when the last line is not even well-formed bytes: there is no digest
to chain to, and no chunk that would need one.
-}
boundary :: [(ChainPosition, ByteString)] -> Maybe LineHash
boundary chunk = case lineBytes (snd (last chunk)) of
    Left _ -> Nothing
    Right ln -> case hashLines [ln] of
        [h] -> Just h
        hs -> error ("EventChain.Verify: " <> show (length hs) <> " digests for one line.")

{- | One chunk: decode every line, hash them all in one call, judge the
Produced Proofs in one crossing and the Mint assertions in another.

Two crossings rather than one interleaved batch, because they are two
kernels: Produced Proofs go through the precomputed key's fixed-base verify,
Mint assertions through libcrypto's. An AOF is mostly runs of one Producer's
key, which is what a table per key pays for; an attester key signs once per
Mint and would pay the table for one walk.

Returns the verdicts and, if the chunk halted on a malformed line, the error
it halted on — already the chunk's last verdict, returned beside the list so
the fold can stop without scanning for it.
-}
chunkVerdicts :: LineHash -> Promoted -> [(ChainPosition, ByteString)] -> ([Verdict], Maybe DecodeError)
chunkVerdicts prev inherited lns =
    ( zipWith5 judge decoded hashes links attributions envelopes <> foldMap (pure . Malformed) halt
    , halt
    )
  where
    (decoded, halt) = spanDecoded lns

    entries = map snd decoded
    hashes = hashLines (map decodedLine entries)
    links = chainFaults prev (zip entries hashes)
    attributions = attributionResults inherited entries
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
answer the promotion is not, and the two arrive as different constructors of
t'CryptoError' precisely so this function does not have to guess which it is
looking at. A malfunction takes down the whole chunk's verdicts rather than
one line's, because it is not evidence about any line. The verify itself
cannot malfunction — 'EventChain.Crypto.verifyBatchPrecomputed' answers in a
plain list — so the only 'Left' here is the promotion's.
-}
attributionResults :: Promoted -> [DecodedEntry] -> [Either CryptoError [Fault]]
attributionResults inherited decoded = case traverse (prepare promoted) decoded of
    Left err -> map (const (Left err)) decoded
    Right prepared -> stitch [KeyOffCurve] answered prepared (verifyBatchPrecomputed [t | Checkable t <- prepared])
  where
    answered SigValid = []
    answered SigInvalid = [SignatureInvalid]

    -- One promotion and one table per distinct key in the chunk, never one
    -- per line — and none at all for the key the chunk inherited, whose
    -- thunk is the previous chunk's. Promoting is a ~15 µs EVP_PKEY load and
    -- the table ~520 µs of curve arithmetic, against a ~15 µs verify; an AOF
    -- is mostly runs of one Producer's key, so a run pays for one table where
    -- a chunk on its own would pay ~2 µs a line. The map is value-lazy on
    -- purpose: each distinct key is one thunk, loaded and tabulated the first
    -- time a line needs it.
    promoted = Map.fromList [(c, Map.findWithDefault (precomputeKey <$> publicKey c) c inherited) | d <- decoded, let c = claimOf d]
    claimOf d = (decodedEntry d).producedProof.publicKey

-- | Promotions by claim: the chunk's own, or the one it inherited from the spine.
type Promoted = Map ClaimedKey (Either CryptoError PrecomputedKey)

{- | A line's signature, ready to judge — or a key that cannot carry one.

'KeyRejected' is not an error and not yet a fault: it is a line that will not
reach the batch, and the batch's results have to be stitched back around it.

Parameterized over the key because the two signature streams run on two
kernels: a Produced Proof's key is a t'PrecomputedKey', an assertion's a
t'EventChain.Crypto.PublicKey', and the stitching below never looks at either.
-}
data Checkable k
    = KeyRejected
    | Checkable (k, SignedBytes, Sig)

{- | Promote the claimed key and derive the signing message from what the line said.

The key comes through the chunk's shared promotion map, so a run of lines under
one Producer's key holds one loaded key and one table rather than a copy per
line. The default is a direct promotion and nothing relies on it being
unreachable — a claim missing from a map built over this same chunk cannot
happen, but a fresh load answers it identically if it somehow did.
-}
prepare :: Promoted -> DecodedEntry -> Either CryptoError (Checkable PrecomputedKey)
prepare promoted d = case Map.findWithDefault (precomputeKey <$> publicKey claim) claim promoted of
    Left KeyNotOnCurve -> Right KeyRejected
    Left err -> Left err
    Right k -> Right (Checkable (k, message, proof.signature))
  where
    proof = (decodedEntry d).producedProof
    claim = proof.publicKey
    message = signingMessage (canonicalize (decodedObject d))

{- | Put a batch's answers back beside the lines they are about.

A batch answers one t'SigCheck' per triple, in order, and lines whose key
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
stitch :: [Fault] -> (SigCheck -> [Fault]) -> [Checkable k] -> [SigCheck] -> [Either CryptoError [Fault]]
stitch rejectedKey answered = go
  where
    go [] [] = []
    go (KeyRejected : more) checks = Right rejectedKey : go more checks
    go (Checkable _ : more) (c : checks) = Right (answered c) : go more checks
    go (Checkable _ : _) [] =
        error "EventChain.Verify: a signature batch answered fewer checks than it was given."
    go [] (_ : _) =
        error "EventChain.Verify: a signature batch answered more checks than it was given."

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
