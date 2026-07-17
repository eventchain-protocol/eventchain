# eventchain

Open Haskell implementation of the [EventChain protocol](https://eventchain.heliosapp.run/):
a zero-trust provenance layer for lifecycle documents, approvals, and
custody transfers.

The proof artifact is an append-only JSON-Lines file (AOF) of
hash-chained, identity-signed events. Any party holding a copy can
verify it locally — offline, without contacting the originating hub or
any third-party service:

1. **Chain continuity** — each entry's `prev_hash` is the SHA-256 of the
   previous *line's bytes*, exactly as written; altering any past entry
   breaks every subsequent hash. The paper says "of the previous entry",
   which names a value where the rule hashes a line — that difference is
   deliberate and is [ADR-0002](docs/adr/0002-wire-format-fill-ins.md) §1,
   filed upstream as
   [PA-02](docs/paper-amendments.md).
2. **Attribution** — each entry is signed with ECDSA-P256; the public
   key travels in the entry itself.
3. **Payload commitment** — entries carry the SHA-256 of their payload,
   never the payload; anyone who obtains the payload can recompute and
   confirm.
4. **Temporal anchoring** (optional) — daily chain-head rollups into
   OpenTimestamps commitments prove *when* a state existed.

The protocol layer uses only published standards — JSONL, SHA-256,
ECDSA-P256, WebAuthn/FIDO2, OpenTimestamps. No custom codecs, binary
envelopes, or vendor SDKs. See [docs/protocol.md](docs/protocol.md) for
the condensed protocol notes this implementation targets.

## Status

Early scaffold. The protocol data model and reference verifier are being
designed; no public API yet.

## Layout

Three packages, one `cabal.project`
([ADR-0005](docs/adr/0005-verifier-is-a-separate-package.md)):

| Package | Role |
| --- | --- |
| `eventchain-crypto` | The crypto seam and the decision-free types it operates on. Shared. |
| `eventchain` | The Producer: a ChainedEvent in, a signed AOF line out. Never parses JSON. |
| `eventchain-verify` | The Verifier: AOF bytes in, a typed report out. |

The Producer and the Verifier **share no format logic** — member vocabulary,
canonicalizer, codec and Entry model are written twice, on purpose.
A verifier that imported the producer's canonicalizer would attest
self-consistency rather than conformance, so their agreement is what the
golden vectors are evidence of. `eventchain-verify` must never
`build-depend` on `eventchain`.

A fourth directory, `gates/`, ships nothing and is depended on by nothing: it
holds that boundary and the JCS-oracle boundary as test suites, so `cabal test
all` is what asserts them rather than a convention someone has to remember.

## Building

Requires GHC 9.12.4 and cabal ≥ 3.16. Other GHC versions are unclaimed — not
known-broken, just unbuilt.

`eventchain-crypto` needs system OpenSSL **libcrypto ≥ 3.2** (for RFC 6979
deterministic ECDSA), found via `pkg-config`. It is a prerequisite of the same
class as zlib. On macOS, Homebrew's `openssl@3` is keg-only, so point
`pkg-config` at it:

```sh
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
```

A stock Linux LTS ships OpenSSL 3.0.x, which is below the floor; the build fails
at solve time rather than at runtime, which is the intent.

```sh
cabal build all
cabal test all
```

`cabal test all` runs the conformance suite, the crypto known-answer tests, and
the two structural gates.

## License

[BSD-3-Clause](LICENSE)
