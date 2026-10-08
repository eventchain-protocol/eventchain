# EventChain

Haskell libraries for producing and independently verifying hash-chained,
signed proof artifacts. An **AOF** is an append-only JSON Lines file: one
signed **Entry** per line, with **Payloads** stored separately. Anyone holding
a copy can check its chain continuity and signatures offline, without
contacting the system that supplied it.

**[Read the EventChain white paper](https://eventchain-protocol.github.io/)**
· [Quick start](#quick-start)
· [Documentation](#documentation)

## What works today

This is an early, library-only implementation of the EventChain protocol
with a two-level proof addendum. There is no CLI, web UI, or hosted service.

- **Produce:** turn a `ChainedEvent` and a signing key into a signed AOF line
  and its hash. The caller owns file IO.
- **Verify offline:** check chain continuity, ECDSA-P256 signatures, and Mint
  envelopes; return typed per-line verdicts. Reject malformed Entries,
  duplicate members, unknown members, and unsupported Revisions.
- **Derive Minted status:** match valid Mint Entries to earlier verified
  targets in a separate pass.

**Not yet implemented:** integrated Payload-commitment verification and the
standalone wire-format document. OpenTimestamps Anchor verification,
authenticator interaction, key registration, and the Hub's storage and
access-control services are outside the current v0 scope. The
[plan](docs/plan.md#milestones) distinguishes remaining work from the broader
protocol described in the white paper.

## Quick start

### Prerequisites

- **GHC 9.12.4** — the compiler this project targets; other releases are not claimed.
- **cabal-install ≥ 3.16** and the usual GHC/C build toolchain.
- **OpenSSL libcrypto ≥ 3.2**, including development files discoverable through
  `pkg-config`. Deterministic ECDSA signing requires this minimum.
- The **OpenSSL CLI** on `PATH` for the conformance tests.

On macOS with Homebrew:

```sh
brew install openssl@3 pkg-config
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

On Linux, install your distribution's OpenSSL development files and
`pkg-config`; check the actual library release rather than assuming the
system package meets the minimum:

```sh
ghc --numeric-version
cabal --numeric-version
pkg-config --modversion libcrypto
openssl version
```

### Verify an AOF

From the repository root, fetch the package index and open the Verifier in
GHCi. Initial setup downloads dependencies; verification itself is offline.

```sh
cabal update
cabal repl eventchain-verify
```

Cabal starts this REPL in `eventchain-verify/`, so the fixture path below
begins with `../`. Paste these lines at the GHCi prompt:

```haskell
import qualified Data.ByteString.Lazy as BL
import qualified EventChain.Verify as V

aof <- BL.readFile "../vectors/v0-lifecycle.jsonl"
let summarize (V.Sound _) = "Sound"; summarize verdict = show verdict
print (fmap (map summarize) (V.verify aof))
```

Expected result:

```text
Right ["Sound","Sound","Sound","Sound"]
```

Each `Sound` means the corresponding Entry passed continuity and signature
checks. This example abbreviates successful verdicts but retains error
details. It does **not** check Payload contents, human identity, or time of
existence. Type `:quit` to leave GHCi.

The input is the committed [lifecycle AOF](vectors/v0-lifecycle.jsonl), not
mocked data. [Mint vectors](vectors/mint/) also cover valid envelopes,
tampering, unsupported Revisions, and orphan targets.

## How the proof fits together

1. **Produce a proof.** A Producer signs an Entry's commitment and chain
   linkage with its own key. This is the **Produced Proof**. Payload bytes
   stay outside the AOF; the Entry carries their hash and a reference.
2. **Preserve the bytes.** Each Entry's `prev_hash` commits to its predecessor's
   exact line content, framed by [JSON Lines](https://jsonlines.org/).
   Signatures cover the Entry's members except `signature`, canonicalized
   with JCS. The chain hashes bytes; signing canonicalizes members. Do not
   reformat an AOF before verifying it.
3. **Attest later, without rewriting.** A **Mint** Entry carries an
   **Attestation** referencing an earlier Entry by hash, plus a WebAuthn
   assertion envelope. The target is unchanged; its **Minted** status is
   derived, never stored on it.

**Verification has boundaries.** A valid signature establishes attribution
to a key, not that a business claim is true or that the key belongs to a
named person. Mint verification checks the envelope and its target binding;
it is not a complete WebAuthn relying-party ceremony or an identity-directory
check. See the [exact checks and exclusions](docs/adr/0007-mint-envelope-verification.md).
An AOF alone also cannot prove that no later Entries were withheld.

The addendum and byte-level decisions are this implementation's explicit
extensions and clarifications, not claims that the upstream paper specifies
every detail. See [paper amendments](docs/paper-amendments.md).

## Packages and public entry points

Three libraries share one Cabal project:

| Package | Role | Start here |
| --- | --- | --- |
| [`eventchain`](eventchain/) | Producer: `ChainedEvent` → signed line and line hash. Never parses JSON. | [`EventChain`](eventchain/src/EventChain.hs), [`produce`](eventchain/src/EventChain/Produce.hs) |
| [`eventchain-verify`](eventchain-verify/) | Verifier: AOF bytes → typed verdicts; separate Minted-status derivation. | [`verify`](eventchain-verify/src/EventChain/Verify.hs), [`mintedStatus`](eventchain-verify/src/EventChain/Verify/Minted.hs) |
| [`eventchain-crypto`](eventchain-crypto/) | Shared SHA-256 and ECDSA-P256 kernels through a batched libcrypto FFI, plus byte/hash/key types. | [`EventChain.Crypto`](eventchain-crypto/src/EventChain/Crypto.hs) |

**The Producer and Verifier share no format logic.** Their member
vocabularies, canonicalizers, and codecs are implemented separately. Sharing
a broken codec would let both sides agree on the same mistake; independent
implementations make agreement across committed vectors useful evidence.
Crypto is deliberately shared. The [independence decision](docs/adr/0005-verifier-is-a-separate-package.md)
explains the boundary, and [`gates/`](gates/) enforces it through tests.

The Verifier's continuity and signature pass streams through the AOF.
Minted-status derivation is separate because it retains an in-memory index
that grows with the number of Entries.

## Documentation

- **[White paper](https://eventchain-protocol.github.io/)** — the upstream
  protocol, motivation, and broader system model.
- **[Vocabulary](CONTEXT.md)** — the precise meanings of Entry, Producer,
  Produced Proof, Mint, and other domain terms.
- **[Architecture decisions](docs/adr/)** — byte-level rules, package
  independence, Revisions, and Mint verification.
- **[Vectors](vectors/)** — committed AOFs consumed by the Verifier and
  checked against the Producer's output.
- **[Paper amendments](docs/paper-amendments.md)** — specification gaps,
  proposed corrections, and deliberate implementation differences.
- **[Implementation plan](docs/plan.md)** — package contracts, milestones,
  and remaining work; a plan, not a list of shipped features.

## Contributing

Start with the [vocabulary](CONTEXT.md) and [architecture decisions](docs/adr/).
Preserve the Producer/Verifier split: sharing format code to fix a divergence
would remove the evidence the tests are meant to provide.

From the repository root, with the prerequisites above:

```sh
cabal build all
cabal test all
```

The suites cover crypto known answers, both canonicalizers against an
independent JCS oracle, Producer output against OpenSSL, Verifier behavior,
Mint envelopes, and structural dependency gates. Include a reproducing AOF
or test case when reporting a verification discrepancy; never include private
keys or confidential Payloads.

## License

[BSD-3-Clause](LICENSE).
