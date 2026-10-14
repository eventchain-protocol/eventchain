# Crypto kernels via our own thin, batched FFI to libcrypto

The two CPU kernels — SHA-256 chain hashing and ECDSA-P256 signature
verification at potentially billions of entries — are implemented as a
hand-written, minimal (~200-line) Haskell FFI layer over the system
OpenSSL `libcrypto` (EVP APIs), living entirely inside
`EventChain.Crypto`. Everything else — types, protocol, verifier folds —
is Haskell. Measured on Apple M4 Max (2026-07-16): libcrypto verifies at
30.6k ops/s/core and hashes at ~2–3 GB/s; the best pure-ecosystem
Haskell path (crypton's fast P256) is 3.5× slower on verify and 9× on
hashing, and chain hashing is sequential so that gap is wall-clock.

The FFI surface is **batched by design**: at SHA-NI speed a 300-byte
hash (~150ns) costs the same as an FFI call, so per-line calls would
burn the acceleration on overhead. The kernel API takes chunks of lines
per call, never single lines.

## Considered options

- **HsOpenSSL** (the original pick) — rejected on evidence: it exposes
  no EC/ECDSA at the Haskell API level at all (RSA/DSA only; verified
  against the 0.11.7.11 module list). The original decision assumed a
  thin-but-present EC surface; there is none.
- **Rust core (aws-lc-rs)** — measured +19% verify over OpenSSL, but no
  maintained Haskell↔Rust build tooling, no successful Hackage
  precedent for a cargo-built core, breaks plain `cabal install` /
  Stackage / cross-compilation. Cardano explored Rust interop and still
  shipped its hot-path crypto as C behind hand-written FFI. If the +19%
  is ever needed: aws-lc's *C* libcrypto builds standalone without
  Rust — relink this same FFI against it, zero code change.
- **Zig kernel** — pre-1.0, ongoing breaking changes, open stdlib-ECDSA
  correctness bug, documented Haskell-linking footgun. Revisit post-1.0.
- **botan-low** — funded and promising but pre-1.0, mid-refactor, and
  its sign/verify wrapper surface was unconfirmed at decision time.
- **Pure crypton** — correct and dependency-light, but a measured 3.5×/9×
  hot-path cost with no offsetting benefit given the FFI is ~200 lines.
  crypton still enters the tree transitively via the `webauthn` package
  (mint envelope verification — low-volume, off the hot path), which is
  fine.

## Consequences

- System OpenSSL (≥3.2 for RFC 6979 deterministic ECDSA nonces) becomes
  a build/runtime prerequisite — the same class of prerequisite as zlib,
  with the same `pkgconfig-depends` handling.
- The seam discipline hardens: nothing outside `EventChain.Crypto` may
  import the FFI; the module exports batched, typed operations only.
- Signature verification parallelizes across cores on top of the
  batched calls (bounded worker pools); the sequential chain-hash walk
  runs at libcrypto speed on one core.

## Amendment, 2026-10-14: ECDSA-P256 verification moves to vendored s2n-bignum

The decision above stands for everything except one kernel. Signature
verification — 83% of the Verifier's per-line cost, one ECDSA-P256 verify
at ~32 µs on this machine — now runs on AWS's s2n-bignum assembly, vendored
into `eventchain-crypto` under `cbits/s2n-bignum/`, rather than on
`EVP_PKEY_verify`. Signing, SHA-256, key loading and the DER conversions stay
on libcrypto; so does the prerequisite.

**Why.** libcrypto's verify is a general-purpose variable-base multiplication
of the public key. The Verifier's shape is different: an AOF is runs of one
Producer's key, so a table of that key's multiples, built once per key, turns
both scalar multiplications into fixed-base walks. s2n-bignum exposes exactly
that (`p256_scalarmulbase` over a caller-built table) and nothing in libcrypto's
public API does. Measured 2026-10-14 (M4 Max, mains, OpenSSL 3.6.3, s2n-bignum
`4d1356a7`), 10,000 signatures, context-reused `EVP_PKEY_verify` against the
table walk at blocksize 7:

| | µs / verify | table build per key |
| --- | --- | --- |
| `EVP_PKEY_verify`, today's path | 32.1–33.0 | — |
| s2n-bignum fixed-base, blocksize 7 | 14.5 | ~500 µs |
| ratio | **2.25** | |

Zero disagreements with libcrypto on 10,000 valid, 10,000 tampered and five
crafted edge-case signatures. The spike and its record live outside the
repository, as ADR-0004's original spike did; the numbers carry into
`docs/research/` when the Verifier is wired.

**What s2n-bignum is, and why it clears the bar the options above did not.**
Hand-written assembly, one function per file, every function carrying a
machine-checked HOL Light proof against the object code — the proofs state
the exceptional-case preconditions precisely (`p256_montjadd` is proven for
infinity on either side and for opposite points, and excludes only equal
finite inputs, which the caller doubles). Apache-2.0 OR ISC OR MIT-0. No build
system to integrate: each `.S` includes one header and assembles with the C
compiler cabal already drives, so it enters as `asm-sources`, not as a
foreign toolchain. That is the distinction from the Rust and Zig options:
those brought a second build system; this brings sixteen files.

**Chosen against.** A hand-written table walk — direct-indexed, unsigned
digits — measured 3.5× at blocksize 7, against the proven walk's 2.25×. The
maintainer declined it: the proven loop is the thing being bought, and a loop
of ours would rest on an argument of ours. Recorded in the spike's results
file as measured and rejected.

**What is vendored.** Exactly the sixteen functions the kernel calls (the
list and the refresh procedure are in `cbits/s2n-bignum/README.md`), arm64
only, behind `if arch(aarch64)`. The x86-64 twins are a separate vendoring,
claimed only once a build has run there.

**Consequences, in addition to the list above.**

- The seam discipline is unchanged: nothing outside `EventChain.Crypto` may
  reach the assembly, and the FFI stays batched (one call per fixed-size
  array, no finalizers). The table is a per-key value the Verifier builds
  where it already promotes keys.
- libcrypto's verify becomes an oracle rather than the implementation. The
  differential harness — RFC 6979 vectors, hostile generators, random
  triples — runs every signature through both and fails on any disagreement.
  That is the gate the vendored code must pass before the Verifier calls it.
- The table walk is constant-time by construction (it is the one s2n-bignum
  ships for secret scalars), which the Verifier does not need and the Producer
  must not rely on: the Producer signs through libcrypto and nothing here
  offers it a scalar multiplication.
- `eventchain-crypto` is no longer wholly BSD-3-Clause: the vendored directory
  carries its own `LICENSE` and `NOTICE`.
