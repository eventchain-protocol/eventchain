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
