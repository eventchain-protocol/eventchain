# Ecosystem research digest — July 2026

Five parallel research passes (toolchain, crypto, JSON/streaming, type
practice, native-kernel FFI) plus local spike benchmarks, run 2026-07-16
to pin this project to the stable bleeding edge. Decisions extracted
into [ADR-0003](../adr/0003-no-bare-types.md),
[ADR-0004](../adr/0004-crypto-kernels-libcrypto-ffi.md) and
[the plan](../plan.md); this file keeps the evidence.

## Spike benchmarks (Apple M4 Max, single core, 2026-07-16)

ECDSA P-256 verify — the hot kernel (~95% of CPU at scale):

| Backend | verifies/s | µs/op |
| --- | --- | --- |
| aws-lc-rs (Rust, BoringSSL-lineage asm) | 36,336 | 27.5 |
| ring (Rust, BoringSSL-lineage asm) | 33,551 | 29.8 |
| OpenSSL 3.6 libcrypto | 30,583 | 32.7 |
| crypton `Crypto.PubKey.ECDSA` (fast P256 path) | 10,429 | 95.9 |
| RustCrypto p256 (pure Rust) | 7,061 | 141.6 |
| crypton `Crypto.PubKey.ECC.ECDSA` (legacy generic) | 602 | 1,662 |

SHA-256 at ~300-byte lines (chain hashing is sequential — single-core
throughput is the wall-clock): aws-lc-rs 2.98 GB/s ≈ ring 2.78 ≈
OpenSSL ~1.9–2.9 — crypton 0.32 GB/s (9×), pure-software C.

Lessons: the cliff is vetted-asm lineage vs everything else, not
language (pure Rust lost to crypton's fast path). crypton's *legacy*
ECDSA module is a 60× trap — never use it. Spike sources lived in the
session scratchpad; numbers above are the artifact.

## Verdicts by area

**Toolchain.** GHC 9.12.4 primary (full HLS 2.14 support, Stackage
nightly, top adoption); 9.14.1 is GHC's first LTS — CI matrix 9.10.3 /
9.12.4 / 9.14.1; GHC 10.0 still blocked on RTS bugs mid-2026. GHC2024
declared explicitly (not compiler default until 10.0). cabal-install
3.18.1, `cabal-version: 3.14`, `cabal check` as CI gate (mirrors the
Hackage upload gate). fourmolu (formatter consensus), hlint 3.10, stan
still beta. CI via `haskell-actions/setup` v2.11. Dead: stack for new
libs, `build-type: Custom` (→ `Hooks`), stylish-haskell.

**Crypto.** HsOpenSSL has *no EC/ECDSA at all* (module list verified;
RSA/DSA only — 15-year gap). botan-low: funded and active but pre-1.0,
mid-refactor, sign/verify exposure unconfirmed. crypton: maintained,
adequate off hot path. `base64` (typed, rejects non-canonical input)
over stale `base64-bytestring`. tweag `webauthn`: active (commits July
2026), ES256/COSE server-side assertion verification — our mint path.
OpenTimestamps: one immature Haskell impl (deprecated cryptonite dep +
live Bitcoin node) — out of v0, fork-basis at best.

**Native kernels (Rust/Zig question).** No maintained Haskell↔Rust
pipeline exists (Well-Typed hs-bindgen is C-only and alpha;
cargo-cabal/curryrs dead); no successful Hackage precedent ships a
cargo-built core; the cost lands on every downstream builder. Cardano —
the closest precedent, which even prototyped Rust FFI tooling — ships
hot-path crypto as C behind hand-written FFI. Zig: pre-1.0, breaking
changes ongoing, open stdlib-ECDSA correctness bug, documented
Haskell-linking footgun. Direct thin FFI to libcrypto
(`libsodium-bindings` pattern) gets asm-class performance with only the
C toolchain GHC already requires. Key sizing fact: at SHA-NI speed a
300-byte hash ≈ 150ns ≈ one FFI call — **kernel API must be batched**
(many lines per call), or the acceleration is spent on call overhead.

**JSON / streaming.** aeson 2.3.x, hand-written `FromJSON`, strict
decoding; even the new decoding path materializes a `Value`, so the
measured-bottleneck escalation is json-syntax (alive, assoc-list
objects suit ≤9-field lines) or hermes-json (vendored simdjson C++ in
cbits — the proven no-cargo native-vendoring pattern). aeson ships
`Data.Aeson.RFC8785` since 2.2.1 — generic and slow-shaped, but a
maintained **conformance oracle** for our hand-rolled JCS subset.
Streaming: streamly still pre-1.0/churning — avoid; hand-rolled chunked
strict-ByteString line fold (evidence-backed) or thin conduit.
Parallelism: `unliftio` `pooledMapConcurrentlyN` over bounded batches.
Gzip: `zlib` incremental (active); Haskell `zstd` bindings stale (2021).

**Type practice.** GHC2024 + explicit `StrictData`, `DerivingVia`,
`PatternSynonyms`, `NoFieldSelectors`, `OverloadedRecordDot`
(`OverloadedRecordUpdate` still experimental — banned). `type data`
(GHC ≥9.6) for tag vocabularies. **Landmine: phantom parameters infer
role `phantom`, so `coerce` freely relabels `Hash Entry` as
`Hash Payload` even with hidden constructors — every phantom-tagged
newtype requires `type role ... nominal`.** Library errors: closed
per-boundary sums via `Either`; no mtl/effect-system constraints in
public signatures; `ExceptT`-over-IO antipattern confirmed. Claims→facts
promotion pattern (parse-don't-validate / GDP lineage): implement
locally with unexported constructors; no `gdp` dependency.
