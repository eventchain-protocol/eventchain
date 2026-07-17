# Plan: minimal implementation (v0)

Library-only v0 of the open EventChain protocol layer with the
two-levels-of-proof addendum. No CLI, no frontend, no network. The
deliverable is: a producer that appends entries, a verifier that folds
over an AOF, a normative wire-format document, and golden test vectors
other implementations can verify against.

Vocabulary: [CONTEXT.md](../CONTEXT.md). Locked decisions:
[ADR-0001](adr/0001-two-levels-of-proof.md) (proof model),
[ADR-0002](adr/0002-wire-format-fill-ins.md) (byte-level rules).

## What v0 proves end-to-end

A Producer appends level-1 entries to an AOF; a verifier, given only the
file (plus optional payload access), reports per entry: chain intact,
signature valid, payload committed, and Minted vs Produced-Proof status.
Mint creation requires a real authenticator (browser/device) and is out
of v0; mint *verification* is fully in, exercised via fabricated WebAuthn
envelopes in test vectors.

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
3. **Unexported constructors, validating smart constructors.** Holding a
   value proves it was validated (curve membership for keys, exact
   lengths for hashes/signatures, base64url well-formedness). Invalid
   values are unrepresentable, not checked-later.
4. **No `ToJSON`/`FromJSON` instances on core types.** Serialization is
   Wire's explicit codec, full stop — a derived instance would be a
   second serialization path that silently bypasses the exact-bytes
   invariant.
5. **No naked `Bool`/`Int` verdicts.** Failures are enumerated sums with
   positions; verification levels are a type, not documentation.
6. **Typed errors per boundary.** Error text is rendered at the edge;
   errors as data are sums the caller can match on.
7. **Every phantom-tagged newtype declares `type role ... nominal`.**
   GHC infers the permissive `phantom` role for unused parameters, so
   without the annotation `coerce` relabels `Hash Entry` as
   `Hash Payload` even with hidden constructors — silently defeating
   the tagging. Tag vocabularies use `type data` (closed kinds, no
   term-level junk).

**Core type inventory** (shapes are the decision; names bind):

| Type | Carries | Only constructed by |
| --- | --- | --- |
| `LineBytes` | Exact AOF line as read/written | Wire |
| `CanonicalBytes` | JCS signing message | Canonical |
| `PayloadBytes` | Payload content from caller lookup | caller edge |
| `Hash subject` | SHA-256, phantom-tagged: `Hash Entry` ≠ `Hash Payload` | Crypto, from the matching byte type only |
| `PublicKey` | Validated P-256 point | Crypto |
| `Sig` | 64-byte `r‖s` | Crypto (DER normalized away) |
| `WebAuthnEnvelope` | authenticatorData + clientDataJSON, typed challenge | WebAuthn |
| `EntryId`, `PayloadRef` | Opaque labels, no security weight | Wire |
| `Entry` | Sum by Kind: lifecycle vs mint (`Hash Entry` target + envelope) — a mint without a target is unrepresentable | Wire / Produce |
| `DecodedEntry` | The (LineBytes, Entry) pair | Wire |
| `ChainPosition` | Ordinal in the AOF | Verify |

What the compiler now refuses: hashing a re-serialization instead of the
line bytes (`Hash Entry` requires `LineBytes`); comparing a payload hash
to an entry hash (different types); minting without a target; verifying
a WebAuthn envelope with the raw-ECDSA path or vice versa; smuggling an
unvalidated key or malformed signature into the core.

### Claims vs facts — two tiers of guarantee

A smart constructor proves **shape**, not **truth**. At the boundary we
necessarily trust the supplier's field to be a hash and not an arbitrary
string — construction validates structure (length, encoding, on-curve)
and the resulting value is a well-formed *claim*. Whether a claimed
`Hash Entry` actually equals SHA-256 of its line bytes, or a `Sig`
actually verifies, is a relation between values that only the
verification machinery can discharge.

The promotion is itself typed: the Verify fold is the sole constructor
of verified evidence — a `VerifiedEntry` (name binds later) cannot be
built anywhere else, so any downstream function that demands one has a
compile-time guarantee the machinery ran. Claim types flow in from Wire;
fact types flow out of Verify; nothing else converts between them.

## Module architecture

Each module is one boundary with one reason to exist. All are small; the
public API is re-exported from `EventChain` only.

| Module | Owns | Why it is a boundary |
| --- | --- | --- |
| `EventChain.Types` | The core type inventory above; smart constructors and nothing else. | Parse-don't-validate. The type discipline section is this module's spec. |
| `EventChain.Wire` | JSONL line codec: line bytes ⇄ Entry. base64url. Strict: unknown shape, bad encoding, missing field ⇒ hard error with line number. | Owns the exact-bytes invariant (below). The only module that knows JSON field names. |
| `EventChain.Canonical` | RFC 8785 (JCS) serialization of an entry minus its `signature` member — the level-1 signing message. | Canonicalization must exist in exactly one place, used by both producer and verifier, or signatures drift. |
| `EventChain.Crypto` | Our thin (~200-line), hand-written, **batched** FFI to system libcrypto: SHA-256 over chunks of lines, ECDSA-P256 verify/sign (RFC 6979 via OpenSSL ≥3.2), raw compressed-point key loading. See [ADR-0004](adr/0004-crypto-kernels-libcrypto-ffi.md). | The language seam. Nothing else may import the FFI; batching is mandatory (per-line calls burn the hardware acceleration on call overhead). Relinking against aws-lc's C core later touches nothing else. |
| `EventChain.WebAuthn` | Mint envelope verification delegated to the tweag `webauthn` package (COSE/ES256, assertion checks); this module owns only the challenge-equals-target-hash rule and the claim-type boundary around it. | WebAuthn's message construction is a distinct protocol; quarantine it — and its crypton dependency — from the hot path. |
| `EventChain.Produce` | Appending: given producer key + payload commitment + chain head, build the next signed line. Pure construction; the caller does IO. | Producer state (last line hash) is the only mutable thing in the system; keep it in one place. |
| `EventChain.Verify` | The fold(s): chain continuity, attribution, payload commitment, minted-status derivation. Emits a typed per-entry report with the verification level achieved. | The reference verifier is the open-source artifact; it must be pure (file bytes in, verdict out — no clock, no network, no config). |

Test-only fabrication (synthetic producers, fake authenticator envelopes,
golden-vector generator) lives in a separate internal library so it can
never ship inside the real one.

### The exact-bytes invariant

ADR-0002 makes line bytes load-bearing: `prev_hash` covers them, and a
Mint references its target by the hash of them. Therefore a decoded entry
must carry its original line bytes alongside the parsed view — hashing a
re-serialization would be wrong by construction. `EventChain.Wire` is the
single place where (bytes, parsed) pairs are created, and the pairing is
the architectural decision:

```
DecodedEntry = (line bytes as read) + (parsed Entry)
entry hash   = SHA256(line bytes)     -- never SHA256(serialize(parsed))
```

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

## Wire-format details settled in this plan

Reviewable here, normative once in `docs/wire-format.md` (written as part
of v0, alongside the vectors):

- **Genesis:** first entry's `prev_hash` = base64url of 32 zero bytes.
- **`kind`:** optional member; absent means lifecycle event. Present as
  `"mint"` for Mint entries, which also carry `target_hash` and the
  WebAuthn envelope. Keeps upstream 6-field files parseable unchanged.
- **`entry_id`:** opaque producer-chosen label, no security weight, no
  uniqueness requirement; the entry hash is the only real reference.
- **Signatures:** raw 64-byte `r‖s`, base64url; DER from OpenSSL/WebAuthn
  normalized at the Wire boundary.
- **Public keys:** SEC1 compressed points (33 bytes), base64url.

## Toolchain

GHC **9.12.4** primary (mid-2026 stable bleeding edge: full HLS 2.14
support, Stackage nightly compiler); CI matrix 9.10.3 / 9.12.4 / 9.14.1
(first GHC LTS). `default-language: GHC2024` declared explicitly, plus
`StrictData`, `DerivingVia`, `PatternSynonyms`, `NoFieldSelectors`,
`OverloadedRecordDot` (`OverloadedRecordUpdate` is banned — still
experimental). cabal-install ≥3.16 (ghcup's recommended; 3.18 as it
lands), `cabal-version: 3.14`, `cabal check` as a hard CI gate. fourmolu + hlint; `haskell-actions/setup` in CI.
Evidence for all of this: [docs/research/2026-07-haskell-ecosystem.md](research/2026-07-haskell-ecosystem.md).

## Dependencies

System: OpenSSL `libcrypto` ≥3.2 (via `pkgconfig-depends`; zlib-class
prerequisite). Haskell: `aeson` (≥2.3), `base64` (typed, rejects
non-canonical input), `webauthn` (tweag; mint envelopes), `unliftio`
(pooled parallel verification), `zlib` (incremental gzip), `bytestring`,
`text`, `containers`. JCS is hand-written (string-only members make it
~30 lines), conformance-tested against `Data.Aeson.RFC8785`. Explicitly
avoided: HsOpenSSL (no EC API), streamly (pre-1.0 churn), crypton as a
direct dependency (enters transitively via `webauthn` only),
`base64-bytestring` (stale), `zstd` bindings (stale).

## Testing and vectors

Per repo testing policy: no mock-based tests. Test surface is (a) golden
vectors — committed AOF fixtures with expected verdicts, valid and
deliberately broken (bad chain, bad sig, bad payload hash, orphan mint,
mint challenge mismatch) — which double as the cross-implementation
interop suite; (b) parametrized tests for the pure branching cores only:
codec round-trip, JCS output, verifier fold verdicts.

## Blast radius and risks

- **Own FFI = own memory-safety obligations.** ~200 lines against
  libcrypto's EVP API, quarantined in one module, validated in M1
  against OpenSSL CLI fixtures and the measured baselines (30.6k
  verify/s/core, ~2 GB/s hashing on the dev machine). Precedent for the
  pattern: `libsodium-bindings`, Cardano's crypto FFI.
- **WebAuthn scope:** v0 verifies assertion signatures only — no
  attestation-statement/registration validation (that is
  directory/Helios territory).
- **Addendum divergence:** `kind`/`target_hash` are additive; upstream
  files remain valid input, and our files remain chain-valid to any
  raw-bytes verifier.
- **Greenfield:** no existing consumers; every interface here is new
  surface, nothing is broken by shipping it.

## Milestones

1. **M1 — bytes and crypto:** Types, Wire, Canonical, Crypto. Proof:
   codec round-trips; JCS matches RFC 8785 (aeson oracle + RFC
   examples); FFI sign/verify against OpenSSL CLI-generated fixtures;
   batched-call throughput within ~20% of the spike baselines.
   Validates the FFI risk first.
2. **M2 — chain:** Produce + the streaming fold (continuity +
   attribution). Proof: produce N entries, verify; corrupt any byte,
   verification fails at the right position.
3. **M3 — mint:** WebAuthn envelope verification + minted-status fold.
   Proof: fabricated-envelope vectors verify; orphan/mismatched mints
   rejected.
4. **M4 — publish the contract:** payload-commitment checks, report
   type finalized, `docs/wire-format.md` written, golden vectors
   committed. v0 done when a stranger could reimplement from docs +
   vectors alone.

## Out of scope for v0

OpenTimestamps anchor verification; mint creation (needs authenticator
frontend); multi-signature custody Kind; Hub, RBAC, payload storage,
distribution; key registration/organisational directory; CLI.
