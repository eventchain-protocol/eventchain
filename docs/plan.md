# Plan: minimal implementation (v0)

Library-only v0 of the open EventChain protocol layer with the
two-levels-of-proof addendum. No CLI, no frontend, no network. The
deliverable is: a producer that appends entries, a verifier that folds
over an AOF, a normative wire-format document, and golden test vectors
other implementations can verify against.

The producer and the verifier are **separate packages that share no format
logic** (ADR-0005). A verifier that imports the producer's canonicalizer
attests self-consistency, not conformance; the vectors are evidence only
because the two sides derive the wire format independently. Crypto goes the
other way — one shared package, because agreement there is the requirement
rather than the question, and a known-answer test against OpenSSL gates it
without needing a dissenter.

Vocabulary: [CONTEXT.md](../CONTEXT.md). Locked decisions:
[ADR-0001](adr/0001-two-levels-of-proof.md) (proof model),
[ADR-0002](adr/0002-wire-format-fill-ins.md) (byte-level rules),
[ADR-0005](adr/0005-verifier-is-a-separate-package.md) (the split).

## What v0 proves end-to-end

A Producer appends level-1 entries to an AOF; a verifier, given only the
file (plus optional payload access), reports per entry: chain intact,
signature valid, payload committed, and Minted vs Produced-Proof status.
Mint creation requires a real authenticator (browser/device) and is out
of v0; mint *verification* is fully in, exercised via fabricated WebAuthn
envelopes in test vectors.

The word *only* is doing work in that sentence. The verifier is handed a
file and no privileges: no clock, no network, no config, and — since
ADR-0005 — not the Producer's source either. Everything it concludes it
concluded from bytes plus a published document, which is the same position
a stranger is in. That is what makes the conclusion worth anything.

## Type discipline — the core of the plan

Everything else derives from this section. See
[ADR-0003](adr/0003-no-bare-types.md).

**Rules, non-negotiable:**

1. **No bare types cross a module edge.** `String` appears nowhere in the
   library. `Text`/`ByteString` never carry domain meaning in a
   signature — every domain quantity is an opaque newtype.
2. **No `Any`-shaped types in the core.** `aeson`'s `Value` (Haskell's
   `Any` for JSON) lives only transiently inside the Wire decoder and
   appears in no exported signature. No `Dynamic`, no stringly maps.
3. **Unexported constructors, validating smart constructors.** Where a
   type has a shape to check, the constructor is unexported and a
   validating function is the only door, so holding one proves the check
   ran (exact lengths for hashes/signatures, point encoding for keys,
   base64url well-formedness). Invalid values are unrepresentable, not
   checked-later. Where there is nothing to check — `EntryId`,
   `PayloadRef`, `PayloadBytes`, `ChainPosition` — the newtype buys
   labelling and nothing more, and must say so rather than borrow the
   sentence above.
4. **No `ToJSON`/`FromJSON` instances on core types.** Serialization is
   Wire's explicit codec, full stop — a derived instance would be a
   second serialization path that silently bypasses the exact-bytes
   invariant.
5. **No naked `Bool`/`Int` verdicts.** Failures are enumerated sums with
   positions; verification levels are a type, not documentation.
6. **Typed errors per boundary.** Error text is rendered at the edge;
   errors as data are sums the caller can match on.
7. **Precise, not fancy.** The plainest construct that makes the bad
   state a type error wins; distinctness is what buys safety, not
   cleverness. `LineHash` and `PayloadHash` are two newtypes rather
   than one phantom-tagged `Hash subject` — same compile error, and no
   `phantom` role leaking through the abstraction (roles are exported
   even when constructors are not) for a `type role ... nominal` line
   to plug. A type-level feature earns its place by preventing a bug.

**Core type inventory** (shapes are the decision; names bind):

| Type | Carries | Package | Only constructed by |
| --- | --- | --- | --- |
| `LineBytes` | Exact AOF line as read/written | crypto | `lineBytes` (shape check) |
| `PayloadBytes` | Payload content from caller lookup | crypto | caller edge |
| `LineHash`, `PayloadHash` | SHA-256, one type per subject: they do not compare | crypto | claim tier: `lineHashFromBytes` / `payloadHashFromBytes` (any 32 bytes). Computed only by Crypto, from the matching byte type |
| `ClaimedKey` | 33 bytes shaped like a compressed point | crypto | `claimedKey` |
| `PublicKey` | Validated P-256 point | crypto | Crypto |
| `Sig` | 64-byte `r‖s` | crypto | Crypto (DER normalized away) |
| `ChainedEvent` | An occurrence's commitment plus its chain linkage and its `EventKind`; unsigned, not yet an Entry | eventchain | caller edge |
| `CanonicalBytes` | JCS signing message | each, separately | that package's own Canonical |
| `EntryId`, `PayloadRef` | Opaque labels, no security weight | each, separately | — |
| `Entry` | Sum by Kind: lifecycle vs mint (`LineHash` target + envelope) — a mint without a target is unrepresentable | verify | `Verify.Wire` |
| `DecodedEntry` | The (LineBytes, EntryObject, Entry) triple | verify | `Verify.Wire` |
| `WebAuthnEnvelope` | authenticatorData + clientDataJSON, exact transmitted bytes | verify | `Verify.Wire` |
| `AuthenticatorBytes`, `ClientDataBytes`, `ClientDataHash` | The envelope's blobs by provenance, and the digest the assertion message embeds — computed only by Crypto | crypto | blobs: claim tier (no shape); digest: Crypto |
| `ChainPosition` | Ordinal in the AOF | verify | `Verify` |

The claim tier turns out to be almost entirely Verifier-side, and that is not
an accident of layout: a claim is what reading bytes someone else wrote
produces. The Producer *computes* a hash, *holds* a key and *makes* a
signature; it never claims any of them. What it takes instead is a
`ChainedEvent`.

The name is `LineHash`, not `EntryHash`: ADR-0002 makes the *line bytes*
the thing hashed, so the name says the bytes rather than the concept they
stand for. `LineHash` **is** the protocol's entry hash.

What the compiler refuses: comparing a payload hash to an entry hash
(different types, neither coercible); minting without a target (an
`Attestation` carries one); verifying a WebAuthn envelope with the
raw-ECDSA path or vice versa; smuggling an unvalidated key or malformed
signature into the core.

What it does **not** refuse, and the distinction is load-bearing:
`lineHashFromBytes` builds a `LineHash` from any 32 bytes, so *hashing a
re-serialization typechecks*. It has to — `Verify.Wire` reads a claimed
`prev_hash` off a line and cannot verify it. The chain rule is enforced one
tier up: `EventChain.Crypto` is the only module that can **compute** a digest,
and its API takes `LineBytes` to produce a `LineHash`. The guarantee is the
shape of that API, not of `LineHash`. An earlier draft of this table claimed
"`Hash Entry` requires `LineBytes`"; it never did.

That API shape is also why `LineBytes` and the hash types sit in the shared
crypto package rather than being written twice. They carry no format
judgment — a length, an encoding, and which subject a digest is *of*. Nothing
in them is a decision two implementations could reach differently, so
duplicating them would manufacture no evidence while splitting the FFI's
memory-safety obligation in two.

### Claims vs facts — two tiers of guarantee

A smart constructor proves **shape**, not **truth**. At the boundary we
necessarily trust the supplier's field to be a hash and not an arbitrary
string — construction validates structure (length, encoding, on-curve)
and the resulting value is a well-formed *claim*. Whether a claimed
`LineHash` actually equals SHA-256 of its line bytes, or a `Sig`
actually verifies, is a relation between values that only the
verification machinery can discharge.

The promotion is itself typed: the Verify fold is the sole constructor
of verified evidence — a `VerifiedEntry` (name binds later) cannot be
built anywhere else, so any downstream function that demands one has a
compile-time guarantee the machinery ran. Claim types flow in from
`Verify.Wire`; fact types flow out of `Verify`; nothing else converts
between them. Both tiers live in `eventchain-verify`, because both are
about bytes someone else wrote.

**8. A fact-tier type is defined in the module that makes it.** This is
what makes the paragraph above true rather than aspirational. A type
whose meaning is "some machinery ran" gets its constructor unexported
*from the module that runs the machinery* — then no other module can
forge one and the compiler says so. Defining it in a shared types module
and exporting the constructor internally makes "sole constructor" a
convention every future contributor must be told about, which is not a
guarantee. So: `CanonicalBytes` lives in each package's own `Canonical`,
`PublicKey` in `Crypto`, `VerifiedEntry` in `Verify`, `DecodedEntry` in
`Verify.Wire`.

Package boundaries make rule 8 sharper than module boundaries ever did.
Inside one package an unexported constructor is enforced by the export
list; across packages it is enforced by `build-depends`, and
`eventchain-verify` cannot forge a Producer's type because it cannot name
one. The rule and the architecture are now the same mechanism.

## Package architecture

Three packages, one `cabal.project` (ADR-0005). Between packages the boundary
is `build-depends`, which a machine can check; inside one it is the old rule —
each module is one boundary with one reason to exist, all small.

| Package | Role | Depends on |
| --- | --- | --- |
| `eventchain-crypto` | The language seam, and the decision-free types it operates on | — |
| `eventchain` | The Producer: `ChainedEvent` in, signed AOF line out | `eventchain-crypto` |
| `eventchain-verify` | The Verifier: AOF bytes in, typed report out | `eventchain-crypto` |

**`eventchain-verify` must never depend on `eventchain`.** That single edge's
absence is what makes the golden vectors evidence rather than a tautology, so
`cabal test all` asserts it (`gates:verifier-independence`); it is not a
convention.

### `eventchain-crypto` — shared, and deliberately so

| Module | Owns | Why it is a boundary |
| --- | --- | --- |
| `EventChain.Crypto.Types` | The types the kernels operate on: `LineBytes`, `PayloadBytes`, `LineHash`, `PayloadHash`, `ClaimedKey`, `PublicKey`, `Sig`; since M4 also the Mint envelope's byte blobs (`AuthenticatorBytes`, `ClientDataBytes`) and the digest the assertion message embeds (`ClientDataHash`). Decision-free — lengths and encodings, no format judgment. | Both sides must name the same quantities to call the same kernels. Nothing here encodes a choice two implementations could make differently, so sharing it forfeits no evidence. |
| `EventChain.Crypto` | Our thin (~200-line), hand-written, **batched** FFI to system libcrypto: SHA-256 over chunks of lines and of Mint client data, ECDSA-P256 verify/sign (RFC 6979 via OpenSSL ≥3.2), raw compressed-point key loading. See [ADR-0004](adr/0004-crypto-kernels-libcrypto-ffi.md). | The language seam, and the only memory-unsafe code in the system — writing it twice doubles that obligation to buy nothing, since known-answer tests against OpenSSL gate it without a second opinion. Nothing outside may import the FFI; batching is mandatory (per-line calls burn the hardware acceleration on call overhead). Relinking against aws-lc's C core later touches nothing else. |

### `eventchain` — the Producer

Implements the paper as literally as the type discipline allows. It **never
parses JSON**: no parser dependency, no JSON-accepting attack surface.

| Module | Owns | Why it is a boundary |
| --- | --- | --- |
| `EventChain.ChainedEvent` | What a Producer is handed: an occurrence's commitment (payload hash and ref, entry id) plus its chain linkage (the predecessor's `LineHash`), and its `EventKind` — `Lifecycle`, or `Mint` carrying the Attestation's envelope as opaque crypto types (M4). Unsigned, and not yet an Entry. | The Producer's whole input in one type. An Entry carries a Produced Proof; this is what exists before there is one, so the two are not the same type and a signature cannot be assumed. The Kind is a constructor, never a string a caller spells. |
| `EventChain.EntryObject` | The AOF's JSON shape as the Producer emits it: the `Member` name vocabulary and the flat string-valued object. | The member names are the format's, not the encoder's and not the canonicalizer's. Both need them; neither should own them. |
| `EventChain.Canonical` | RFC 8785 (JCS) serialization of an entry minus its `signature` member — the signing message — and `CanonicalBytes` itself, constructor unexported. | Fabricating the signing message is signing a message of your choosing, so only this module may. Note what changed: this is now one of **two** canonicalizers by design (`eventchain-verify` has its own), and their agreement is the gate. |
| `EventChain.Wire` | Encode only: a `ChainedEvent` and a key → an `EntryObject`, and that → line bytes. Owns base64url and the order members are written in. | The exact-bytes invariant (below) starts here — the bytes signed and chained are the bytes written. |
| `EventChain.Internal.Json` (hidden) | JSON syntax for the vocabulary: braces, commas, RFC 8785 §3.2.2.2 escaping, over an already-ordered member list. | `Canonical` and `Wire` must escape identically or a line says what its signature does not cover. ADR-0005 gates that across *packages*, where two encoders agreeing is evidence; inside one package a second copy is graded by nothing, so this is one copy on purpose. `Canonical` keeps the decisions (drop `signature`, sort by name) and `Wire` keeps its own (order, base64url) — syntax is what is shared, never judgment. |
| `EventChain.Produce` | Given a `ChainedEvent` and a producer key, build the next signed line, and hand back that line's `LineHash`. Pure construction; the caller does IO. | The chain's one piece of carried state is the last line's hash, and it is deliberately *not* held here — it arrives as the next `ChainedEvent`'s `prevHash`, because a producer that restarted must recover it from the file rather than from memory. What lives here is the rule for advancing it: the next `prev_hash` is the digest of the line you actually wrote, which is why `produce` returns it rather than leaving the caller to recompute it from something else. |

### `eventchain-verify` — the Verifier

Reads AOFs written by anyone. It accepts untrusted JSON because that is
inherently the job, and derives the wire format from `docs/wire-format.md`
and the vectors rather than from `eventchain`'s source.

| Module | Owns | Why it is a boundary |
| --- | --- | --- |
| `EventChain.Verify.Types` | The claim tier: `Entry`, `ChainPosition`, `Attestation`. What a line asserts before anything is discharged. An exposed facade over hidden `EventChain.Verify.Types.Internal.*` — aeson's shape for `Data.Aeson.Types` over `Data.Aeson.Types.Internal`, and the same shape `EventChain.Crypto.Types` has. | Parse-don't-validate. Claims are what reading someone else's bytes produces; the Producer computes these values and never claims them, which is why they live here and not there. The facade is what makes rule 8 hold at the *package* edge: a hidden module's unexported constructor cannot be named from outside no matter what a caller imports. |
| `EventChain.Verify.Wire` | File framing (JSON Lines §3; the no-BOM rule) and the line codec, decode direction: line bytes → `EntryObject` → `Entry`, base64url in. Strict — unknown member, bad encoding, missing field, **duplicate member** ⇒ hard error with line number. Owns `DecodedEntry`. | Owns the exact-bytes invariant (below): the only place a (bytes, object, parsed) triple is made. Framing is here rather than in its own module because it is what JSON Lines calls the same job — and it builds no value, so the Producer's no-JSON-parser rule is not what separates them. |
| `EventChain.Verify.EntryObject` | The member vocabulary and flat object, re-derived from the normative document. | Independently written on purpose. If it disagrees with `eventchain`'s, one of them is wrong and the vectors say so — that is the gate working. |
| `EventChain.Verify.Canonical` | The second RFC 8785 implementation and its own `CanonicalBytes`. | Same reason. Two canonicalizers that agree are evidence; one shared canonicalizer is an assumption. |
| `EventChain.Verify.WebAuthn` | Mint envelope verification, hand-written on the shared crypto kernels: the RP-free subset of W3C §7.2 plus the challenge-equals-target-hash rule (ADR-0007, superseding the tweag-`webauthn` delegation first booked here). | The construction is a concatenation and a hash; the tweag package's independent reading of §7.2 grades ours from a test suite, and crypton never enters a library build. |
| `EventChain.Verify` | The streaming fold: chain continuity, attribution, payload commitment, and the per-line envelope checks for Mints. Emits a typed per-entry report with the verification level achieved. | The reference verifier is the open-source artifact; it must be pure (file bytes in, verdict out — no clock, no network, no config). |
| `EventChain.Verify.Minted` | Minted-status derivation: the O(n) join of each Sound Mint to the Sound Entry its target hash names, orphans reported with the hash they claim. | Split from the streaming fold at M4 because the two passes cost differently — the join carries every hash seen where the fold carries one — and a caller who wants continuity over a billion-entry file should not pay for a join it did not ask for. |

Test-only fabrication (synthetic producers, fake authenticator envelopes,
golden-vector generator) lives in a separate internal library so it can
never ship inside the real one.

### The exact-bytes invariant

ADR-0002 makes line bytes load-bearing: `prev_hash` covers them, and a
Mint references its target by the hash of them. Therefore a decoded entry
must carry its original line bytes alongside the parsed view — hashing a
re-serialization would be wrong by construction. `EventChain.Verify.Wire` is
the single place where (bytes, parsed) pairs are created, and the pairing is
the architectural decision:

```
DecodedEntry = (line bytes as read) + (object as read) + (parsed Entry)
entry hash   = SHA256(line bytes)     -- never SHA256(serialize(parsed))
```

M3 added the middle term, and it is the same argument one level down. The signing
message is `JCS(entry minus signature)`, and JCS runs over the object's *member
text*, so the Verifier must canonicalize what the line **said** rather than a
re-encoding of what it made of it. Re-deriving the object from the `Entry` means
base64url-encoding a `LineHash` back to text with a second encoder — and while
our decoder rejects non-canonical base64url, so the round trip is a bijection
today, "is a bijection" is an argument that has to be re-proved every time the
format moves. Carrying what was read costs one field and needs no argument.

The invariant is why the parse cannot be lifted out of `eventchain-verify`
into a caller or a frontend. A caller that handed the Verifier a parsed
structure would leave nothing to hash; one that handed it both bytes *and* a
structure would supply an unverified pairing, which is the exact forgery the
type exists to refuse. The Verifier accepts bytes and parses them itself, or
the guarantee is a comment.

On the Producer's side the invariant runs the other way and needs no pair:
`eventchain` builds the line, so the bytes it signs and chains are the bytes
it wrote, and there is no claim to check.

### Verifier shape: composable folds, memory honesty

Chain continuity + attribution + payload commitment are a single forward
streaming pass: O(1) memory, and signature checks parallelize (they
dominate wall-clock at ~10⁹ entries; hashing runs at GB/s).

Minted-status derivation is different: a Mint arrives *after* its target,
so matching requires remembering every prior entry hash — O(n) state,
~32 GB at 10⁹ entries. v0 keeps this join as a **separate composable
fold** with an in-memory index and documents the limit; a disk-backed
index can replace it later without touching verification. Not merging
these two passes is the decision.

### Verification report

Levels, mirroring the paper: chain-only → attribution → payload-checked →
(future) anchored. Payload access is a caller-supplied lookup; an
unavailable payload (RBAC) is reported as *unchecked at that level*,
distinct from a hash mismatch, which is a hard failure.

A level says how far checking got given the *inputs available*; a fault says a
check ran and said no. Keeping those apart is what makes the RBAC case
expressible at all — and it is why M3 ships no level type. Continuity and
attribution need nothing but the file, so at M3 every check that exists runs on
every entry and there is exactly one level to be at. The type arrives at M5 with
payload commitment, which is the first check a caller can fail to supply the
input for.

What M3 does ship is the fault side, and it is four-way rather than two: an
entry is `Sound`, `Unsound` with the faults, `Malformed` (the line is not an
entry, and the fold halts), or `Undecided` — libcrypto did not answer.
`Undecided` is not a fault, and flattening it into one would report a broken
installation as a forged AOF. That is `eventchain-crypto`'s `SigInvalid`-versus-
`CryptoError` distinction carried through to the report rather than discarded at
the last step.

## Wire-format details settled in this plan

Reviewable here, normative once in `docs/wire-format.md` (written as part
of v0, alongside the vectors):

- **Genesis:** first entry's `prev_hash` = base64url of 32 zero bytes.
- **`kind`:** optional member; absent means lifecycle event. Present as
  `"mint"` for Mint entries, which also carry `target_hash` and the
  WebAuthn envelope. Keeps upstream 6-field files parseable unchanged.
- **`v`:** the revision declaration (ADR-0006). A JSON string, equality-only
  against a closed label set; absent declares the paper's base six members,
  `"1"` declares the addendum vocabulary. Emitted only where the base does
  not suffice — in v0, on Mint lines — so lifecycle output stays
  byte-identical to a paper-only implementation's.
- **`entry_id`:** opaque producer-chosen label, no security weight, no
  uniqueness requirement; the entry hash is the only real reference.
- **Signatures:** raw 64-byte `r‖s`, base64url. DER never appears on a line
  and so never reaches a codec: it is what OpenSSL hands back when signing
  and what an authenticator hands back when minting, and
  `eventchain-crypto` normalizes it away at those two sources. (An earlier
  draft put this "at the Wire boundary", which named a module that never sees
  a DER byte.)
- **Public keys:** SEC1 compressed points (33 bytes), base64url.
- **Member order on the line:** free, and spent rather than saved. RFC 8785
  sorts the *signing message*, so what order a producer writes members in
  changes nothing a signature covers — `docs/paper-amendments.md` PA-01 says so
  outright ("producers are free to choose it"). `eventchain` writes the `Member`
  vocabulary's declaration order, which is `docs/protocol.md`'s table order for
  the six members the paper defines, with the addendum's after them.

  **The six sort to that same order under RFC 8785**, so a v0 lifecycle line is
  byte-identical to `JCS(entry)`. That is arithmetic about six names, not a rule,
  and `kind` breaks it at M4 (RFC 8785 puts it second; we write it seventh).
  Nothing may rest on the coincidence: the chain covers line bytes as written
  (ADR-0002 §1), and a verifier that recanonicalized before hashing would agree
  with every line we currently emit and then fail on the first legal file written
  by anyone else. M5 owes the vectors a line that catches exactly that — see
  there.
- **Line framing:** [JSON Lines](https://jsonlines.org/) §3 settles this, and
  `docs/wire-format.md` cites it rather than restating it: the terminator is
  `0x0a`, so a line's content is every byte before it and a `0x0d` preceding
  the terminator is content, hashed with the rest. A CRLF-terminated file is
  therefore valid JSON Lines whose lines each end in `0x0d`, and it chains to
  different hashes than the LF-terminated original — ADR-0002's middlebox
  consequence, not a rule of its own.

## Toolchain

GHC **9.12.4**, and only that: it is what gets built, so it is what
`tested-with` claims. 9.10.3 and 9.14.1 (first GHC LTS) were named here on the
strength of a CI matrix that has since been deleted along with the rest of the
GitHub Actions workflow — it never built them either. They are unclaimed rather
than known-broken, and widening is one line and a green build.

`default-language: GHC2024` declared explicitly, plus `StrictData`,
`DerivingVia`, `PatternSynonyms`, `NoFieldSelectors`, `OverloadedRecordDot`
(`OverloadedRecordUpdate` is banned — still experimental). cabal-install ≥3.16
(ghcup's recommended; 3.18 as it lands), `cabal-version: 3.14`. `cabal check`,
fourmolu and hlint are local commands, run by hand; nothing runs them for you,
and the docs no longer pretend otherwise.
Evidence for all of this: [docs/research/2026-07-haskell-ecosystem.md](research/2026-07-haskell-ecosystem.md).

## Dependencies

System: OpenSSL `libcrypto` ≥3.2 (via `pkgconfig-depends`; zlib-class
prerequisite), needed only by `eventchain-crypto`.

Per package, because the split is what keeps each list short:

- **`eventchain-crypto`** — `bytestring`, and the system libcrypto. Nothing
  else; it is a seam, not a library.
- **`eventchain`** — `base64`, `bytestring`, `text`, `containers`. **No JSON
  parser**: the Producer emits JSON and never reads it, so `aeson` is absent here
  and that absence is the point.

  `base64` was picked for being typed and rejecting non-canonical input, which is
  a property of its *decoders* — so it buys nothing on this side, where the
  Producer only encodes and an encoder has no invalid input to reject. That
  justification is the Verifier's; here the package is a plain encoder, and it is
  here because base64url is not worth hand-rolling. Both libraries depending on it
  is not an ADR-0005 problem: that rule is about *our* format logic — member
  vocabulary, JCS, the codec, the Entry model — not about third-party encoders,
  the same way both sides share `bytestring` and libcrypto.
- **`eventchain-verify`** — `aeson` (≥2.3) as the *parser*, `base64`,
  `unliftio` (pooled parallel verification), `zlib` (incremental gzip),
  `bytestring`, `text`, `containers`. `webauthn` (tweag) was booked here as
  a library dependency for mint envelopes; ADR-0007 supersedes that — the
  check is hand-written on `eventchain-crypto`, and the package enters one
  test suite as the oracle that grades it.

JCS is hand-written in each of `eventchain` and `eventchain-verify`
(string-only members make it ~30 lines), and each is conformance-tested
against `Data.Aeson.RFC8785` independently. **Neither library may import
`Data.Aeson.RFC8785`** — the oracle is evidence only because it shares no
code with the thing it grades, and a dependency on it turns the gate into a
tautology that still passes every test.

The Verifier's use of `aeson` is the *tokenizer*, not `decode`: the object is
folded from `Data.Aeson.Decoding.Tokens` straight into the member vocabulary,
so no `Value` is ever built. This is not a stylistic preference. `decode`
silently collapses duplicate members to the first
(`Data.Aeson.Decoding.Conversion`: "the first duplicate key in objects wins"),
which would make a line carrying two `prev_hash` members verify against one of
them arbitrarily — precisely the ambiguity the format must reject. The token
stream preserves both, so the duplicate is detectable and fatal. As a bonus
the fold is *less* work per line than `decode`, which is itself the same
tokenizer followed by a `KeyMap` build we would discard.

Explicitly avoided: HsOpenSSL (no EC API), streamly (pre-1.0 churn), crypton
in any library build (enters transitively via `webauthn`, which ADR-0007
confines to a test suite), `base64-bytestring` (stale), `zstd` bindings
(stale).

## Testing and vectors

Per repo testing policy: no mock-based tests. Test surface is (a) golden
vectors — committed AOF fixtures with expected verdicts, valid and
deliberately broken (bad chain, bad sig, bad payload hash, orphan mint,
mint challenge mismatch) — which double as the cross-implementation
interop suite; (b) parametrized tests for the pure branching cores only:
codec round-trip, JCS output, verifier fold verdicts.

The vectors live at the top of the repo, in `vectors/`, and both sides face
them: `eventchain` generates, `eventchain-verify` adjudicates. Because neither
imports the other, "the Producer's output verifies" is a claim about the *format*
rather than about a shared function, and a disagreement is a real finding rather
than a broken build. The two JCS implementations are the sharpest case — if they
ever diverge, one is wrong about RFC 8785 and the vectors are what say so.

The generating side is a golden test rather than a generator anything runs on
demand: `eventchain`'s suite rebuilds the committed bytes from fixed events and
compares. A file regenerated by the thing it grades is not evidence, and the
comparison is possible only because `produce` is pure and ADR-0004's nonce is
RFC 6979's — the same events under the same key are the same bytes forever, with
nothing to seed. A failure there is one of exactly two findings, and they are not
the same: either the format changed on purpose and every downstream verifier
needs telling, or the Producer changed what it emits and nobody meant it to.

Two gates are structural rather than about behaviour, and they are test suites
in `gates/` because a convention would not survive a year:

- `eventchain-verify` does not `build-depends` on `eventchain`
  (`gates:verifier-independence`, which walks the resolved install plan's
  transitive closure — the edge that matters is the one somebody adds through a
  third package, which a `build-depends` grep would miss).
- Neither library imports `Data.Aeson.RFC8785` (`gates:no-jcs-oracle-import`,
  which matches import lines rather than the bare string: naming the oracle in
  prose is how a documented divergence stays documented).

They are tests rather than a pipeline so that a fresh clone gets them by running
the tests it would run anyway, with nothing to install or remember.

## Blast radius and risks

- **Own FFI = own memory-safety obligations.** ~200 lines against
  libcrypto's EVP API, quarantined in one module, validated in M1
  against OpenSSL CLI fixtures and the measured baselines (30.6k
  verify/s/core, ~2 GB/s hashing on the dev machine). Precedent for the
  pattern: `libsodium-bindings`, Cardano's crypto FFI.
- **The gate costs a second implementation, and can rot quietly.** Two JCS
  encoders and two member vocabularies must both stay correct, and the
  cheapest way for a future contributor to fix a divergence is to share the
  code — which passes every test while destroying the evidence.
  `gates:verifier-independence` is the only thing standing there, which is why
  it is a gate and not a guideline.
- **Independence of packages is not independence of authors.** Both sides
  written from the same head can be wrong the same way, so the split is a
  weaker oracle than aeson is for JCS. It catches divergence, not shared
  misreading; `docs/wire-format.md` and third-party implementations are what
  catch the latter.
- **WebAuthn scope:** v0 verifies assertion signatures only — no
  attestation-statement/registration validation (that is
  directory/Helios territory).
- **Addendum divergence:** `kind`/`target_hash` are additive; upstream
  files remain valid input, and our files remain chain-valid to any
  raw-bytes verifier.
- **Greenfield:** no existing consumers; every interface here is new
  surface, nothing is broken by shipping it.

## Milestones

Ordered so that each milestone's proof needs nothing the next one builds.
`eventchain-crypto` goes first because both other packages wait on it and it
carries the FFI risk; the Producer goes before the Verifier because OpenSSL
can grade the Producer without our Verifier existing.

0. **M0 — the split:** three packages under one `cabal.project`; the code
   already written moves to its home. Reorganisation only; no new behaviour.

   | Package | Exposed | Hidden |
   | --- | --- | --- |
   | `eventchain-crypto` | `EventChain.Crypto.Types` | `.Types.Internal.{Bytes,Hash,Key,Error}` |
   | `eventchain` | `EventChain`, `.Canonical`, `.EntryObject` | — |
   | `eventchain-verify` | `EventChain.Verify.Types` | `.Types.Internal.{Entry,Attestation}` |

   `EntryId` and `PayloadRef` get their Producer-side copy at **M2**, not here:
   nothing in `eventchain` references them, and their home is
   `EventChain.ChainedEvent`, which M2 builds. The Verifier's copy moves now
   because `Entry` uses it.

   Proof: everything builds, the JCS oracle test still passes unchanged (a diff
   in its output would mean the move was not a move), and `cabal check` passes
   per package.

   The two structural gates above were claimed here as CI assertions and were
   not: the workflow that would have run them was never wired up, and the
   `build-depends` walker had no caller. They became `gates/` test suites at M1,
   which is when they first ran on anything but a person's say-so.
1. **M1 — the seam and the kernels:** `eventchain-crypto` — the decision-free
   types plus the batched FFI. Proof: ECDSA sign/verify against OpenSSL
   CLI-generated fixtures; SHA-256 against published known-answer vectors;
   batched-call throughput within ~20% of the spike baselines. Validates the
   FFI risk first, before anything depends on its shape.
2. **M2 — the Producer:** `eventchain` — `ChainedEvent`, `EntryObject`,
   `Canonical`, `Wire` (encode), `Produce`. Much of this is already written.
   Proof: JCS matches RFC 8785 (aeson oracle + RFC examples); produce N entries
   into an AOF and have **nothing of ours derive what is checked** — aeson parses
   each line, `Data.Aeson.RFC8785` canonicalizes it minus `signature`, and the
   **OpenSSL CLI** verifies the line's own signature under the line's own
   `public_key` over those bytes. The Producer is correct before a Verifier
   exists to agree with it.

   This bar is sharper than the one first written here, which asked only that the
   CLI "check every line's signature against its canonical bytes" and left open
   *whose* canonical bytes. If they are ours, the check reduces to a sign/verify
   round-trip that M1's known-answer tests already settled, and it would pass while
   a line said something its signature did not cover — the one failure this
   milestone is placed here to catch. Letting the oracle derive the message costs
   nothing (aeson is already the test dependency, and the line has to be parsed
   either way) and puts the library in the path exactly once: it wrote the file.

   The CLI still earns its place, and not for the arithmetic. Loading a
   compressed point out of an SPKI wrapper and reading a raw `r‖s` signature as
   DER is an *interop* claim about ADR-0002 §4's encodings, and a third party has
   to be able to consume them.

   Same move as M1, and for the same reason: that milestone's own bar asked for
   OpenSSL CLI fixtures, which are the same libcrypto we call, so they would have
   graded our wiring rather than our correctness. Published known answers replaced
   them. A proof bar written before the code exists is a guess about what will be
   checkable; it is worth re-asking once it is.
3. **M3 — the Verifier:** `eventchain-verify` — its own member vocabulary,
   its own JCS, the Entry model, the strict token-fold codec, and the
   streaming fold (continuity + attribution). Proof: it verifies M2's AOF
   having never imported `eventchain`; its JCS matches the oracle
   independently; corrupt any byte and verification fails at the right
   position; duplicate members, non-string values and unknown members are
   rejected with a line number.

   Both things M3 booked are settled, and the tables above say so rather than
   this list:

   - **Where `DecodedEntry` is defined.** Rule 8 won, as booked: it lives in
     `Verify.Wire`. It also grew a third field — see the exact-bytes invariant.
   - **No BOM.** The framer owns it, as booked, and rejects a byte order mark
     *as a BOM* rather than letting aeson refuse it as bad JSON: "line 0 is not
     JSON" sends a reader hunting a syntax error in a line that has none.

   What M3 did not settle, and deliberately: **the report type has no levels
   yet.** ADR-0003 rule 5 wants verification levels to be a type, and at M3 there
   is exactly one — every check the fold can run, it runs, because no check here
   depends on an input a caller might not have. A one-constructor sum is
   documentation wearing a type's clothes, and "precise, not fancy" says to wait.
   Payload commitment is the second level and the first one that can be
   *unchecked* rather than failed (RBAC), so M5 introduces the type along with
   the thing that makes it mean something.

   **The vector arrives here, not at M5.** M3's proof needs an AOF that
   `eventchain-verify` did not build, and `gates:verifier-independence` seeds on
   every unit of that package — test suites included — so the Verifier's tests
   cannot call the Producer for one. `vectors/v0-lifecycle.jsonl` is committed and
   both sides face it: `eventchain`'s suite rebuilds it from fixed events and
   asserts the committed bytes are still what it emits (RFC 6979 makes signing
   deterministic, so there is nothing to seed), and `eventchain-verify`'s suite
   reads the file and adjudicates it. Neither names the other. M5 extends the
   directory with the broken cases and the non-canonical-order line; what M3
   proves with it is that two member vocabularies, two JCS implementations and two
   readings of ADR-0002 agree — across a `build-depends` edge that does not exist.
4. **M4 — mint:** WebAuthn envelope verification + minted-status fold.
   Proof: fabricated-envelope vectors verify; orphan/mismatched mints
   rejected.

   What M4 needed settled arrived before its code, as ADR-0002 §5 asked:
   ADR-0006 designs the revision declaration (`v`, below in the wire-format
   list) that lets `kind` be the first added member without leniency, and
   ADR-0007 makes the envelope members normative, fixes the RP-free check
   set, and supersedes the tweag-`webauthn` library delegation in favour of
   a hand-written check the package grades from a test suite. The mint
   vectors extend `vectors/` by the M3 pattern — `eventchain`'s suite
   fabricates deterministically, the Verifier's suite adjudicates the
   committed file, and the fabricated envelopes face the oracle too.

   What M4 settled in code, recorded here as M3's were:

   - **Per-Kind completeness.** ADR-0006 closes names per revision; the
     Kind's members needed the same treatment, and got it: the Mint group
     exists whole or not at all, anchored by `kind` — a `target_hash` on a
     kindless line is refused (`MemberOutsideKind`), a `kind` without its
     group is a missing member, and a bare `"v":"1"` on a lifecycle line
     stays valid exactly as ADR-0006 says. The Verifier's new rejections:
     `UnknownRevision`, `MemberOutsideRevision`, `MemberOutsideKind`,
     `UnknownKind`.
   - **The Producer's input stayed one type.** `ChainedEvent` gained
     `EventKind` (`Lifecycle` | `Mint Attestation`) rather than a second
     entry point: `produce` stays total and uniform across Kinds, and the
     Kind is a constructor a caller reaches for, never a string it spells.
     The envelope arrives as opaque crypto types and is emitted unread — the
     no-JSON-parser property is untouched.
   - **Envelope checks run in the streaming pass.** Every ADR-0007 check is
     per-line — the challenge rule is string equality against the line's own
     `target_hash` text — so they cost O(1) like continuity, and only the
     target join lives in the separate O(n) fold, now
     `EventChain.Verify.Minted` (backward-looking on purpose: a Mint
     precedes its target only in a rewritten file, and orphans carry the
     hash they claim). Assertions batch through the same `verifyBatch`
     kernel as Produced Proofs, as a second crossing per chunk rather than
     spliced into the first: interleaving attester keys into a producer-key
     run would break the context reuse the batching exists for.
   - **The envelope's byte types are crypto's.** `AuthenticatorBytes`,
     `ClientDataBytes` and the `ClientDataHash` digest joined the shared
     types — provenance labels and a length, no format judgment — so both
     sides name the same quantities and the client-data digest crosses the
     seam batched (`hashClientData`).
   - **The cross-ecosystem vector is soft-webauthn's.** ADR-0007 first
     credited "python-fido2's software authenticator"; python-fido2 ships
     none, and the correction is the `soft-webauthn` package's
     `SoftWebauthnDevice`, built on python-fido2's primitives. Its envelope
     is committed as a fixture (`vectors/mint/cross/`), wrapped
     deterministically into `cross-soft-webauthn.jsonl`, and adjudicated
     Sound — two implementations of the authenticator's construction,
     sharing no language, agreeing.
   - **The oracle runs, and earned its keep immediately.** The `mint-oracle`
     suite synthesizes the ceremony tweag `webauthn`'s RP-shaped API demands
     (origin, RP ID hash, a user handle the envelope does not model, the
     SEC1 point re-encoded as a COSE_Key) and faces every fabrication to it:
     the sound envelope verifies, the rejections reject. Its first run
     caught a fabricated `rpIdHash` constant that claimed to be
     `SHA-256("eventchain.test")` and was not — exactly the class of error a
     second implementation exists to catch. Two divergences are pinned as
     the oracle's verdicts rather than papered over: its aeson-based parse
     tolerates the duplicated client-data member we make fatal, and 0.11
     predates Level 3's BE/BS rule. `webauthn` 0.11 caps base <4.20, so
     `cabal.project` scopes `allow-newer` to it and holds jose and the
     crypton-x509 family inside the release's own windows.
5. **M5 — publish the contract:** payload-commitment checks, report type
   finalized, `docs/wire-format.md` written, golden vectors committed. The
   document must state every rule currently living only in code, and cite
   JSON Lines and RFC 8785 for the rules they already own; the M3 work is what
   surfaces the rest. v0 done when a stranger could reimplement from docs +
   vectors alone.

   One vector is booked here rather than left to be rediscovered: **an AOF whose
   members are written in a non-canonical order and which still verifies.**
   Everything `eventchain` emits happens to be `JCS(entry)` (see "Member order on
   the line" above), so every vector generated from it is consistent with a rule
   we do not have — that the chain covers `SHA256(JCS(entry))`. A third party who
   built a verifier on that reading would pass our whole suite and then reject the
   first legal file written by anyone else, and we would have handed them the
   misreading ourselves. The vector has to be written by hand, because the
   Producer cannot emit a counterexample to its own order.

## Out of scope for v0

OpenTimestamps anchor verification; mint creation (needs authenticator
frontend); multi-signature custody Kind; Hub, RBAC, payload storage,
distribution; key registration/organisational directory; CLI.
