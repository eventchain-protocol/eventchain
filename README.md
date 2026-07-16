# eventchain

Open Haskell implementation of the [EventChain protocol](https://eventchain.heliosapp.run/):
a zero-trust provenance layer for lifecycle documents, approvals, and
custody transfers.

The proof artifact is an append-only JSON-Lines file (AOF) of
hash-chained, identity-signed events. Any party holding a copy can
verify it locally — offline, without contacting the originating hub or
any third-party service:

1. **Chain continuity** — each entry's `prev_hash` is the SHA-256 of the
   previous entry; altering any past entry breaks every subsequent hash.
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

## Building

Requires GHC ≥ 9.6 and cabal ≥ 3.10.

```sh
cabal build
```

## License

[BSD-3-Clause](LICENSE)
