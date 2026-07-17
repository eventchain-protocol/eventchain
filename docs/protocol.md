# EventChain protocol notes

Condensed from the specification at <https://eventchain.heliosapp.run/>
(notably *How EventChain Works* and *Open Verification, Helios
Implementation*). This is the contract the implementation targets; the
website remains the source of truth.

Where implementing it showed the text cannot be implemented as written —
`entry.data()` undefined, `prev_hash` not saying how an entry becomes bytes,
field encodings existing only as examples — the gap is quoted and given
proposed wording in `docs/paper-amendments.md`, and filled for our purposes by
ADR-0002. Read that file before concluding the paper settles a byte-level
question.

## Append-only file (AOF)

A JSON-Lines document: one event per line. Payload content is never
embedded in the AOF — it is stored separately (encrypted, RBAC-gated in
the Hub) and only committed to by hash.

Every entry carries the same structure:

| Field          | Meaning                                              |
| -------------- | ---------------------------------------------------- |
| `entry_id`     | Unique identifier (e.g. `evt-042`)                   |
| `payload_hash` | SHA-256 of the payload content                       |
| `payload_ref`  | Index key into external (Hub) payload storage        |
| `prev_hash`    | SHA-256 of the previous entry                        |
| `public_key`   | Signer's public key                                  |
| `signature`    | ECDSA-P256 signature over the entry data             |

The AOF carries no human-readable signer identifiers — only the public
key. Signer context (name, role, organisation) lives in the payload;
the organisational directory maps public keys to people internally.

## Cryptography

- **Hashing:** SHA-256 throughout (chain links and payload commitments).
- **Signatures:** ECDSA-P256. Human signers hold keys in WebAuthn/FIDO2
  authenticators; devices sign from TPM / PUF / secure element.
- **Ordering:** a single-threaded event processor appends entries, so
  the chain is totally ordered.
- **Multi-party events:** custody transfers are multi-signature entries —
  both transferring and receiving party sign the same event.
- **Time anchoring:** each day the Hub rolls the current chain head into
  an OpenTimestamps commitment (one Bitcoin transaction per day
  regardless of event volume).

## Verification

Three independent checks, plus an optional temporal one:

```
VerifyChain(AOF)
  FOR i ← length(AOF) − 1 DO
    IF i > 0 THEN
      AOF[i].prev_hash = SHA256(AOF[i − 1])
    END IF
  END FOR

VerifyAttribution(entry)
  ECDSA_P256_Verify(
    publicKey ← entry.public_key,
    message   ← entry.data(),
    signature ← entry.signature)

VerifyPayload(entry, payload)
  SHA256(payload) = entry.payload_hash

FullAudit(AOF, payloads, OTS_receipts)
  VerifyChain(AOF)
  FOR EACH entry IN AOF DO
    VerifyAttribution(entry)
    VerifyPayload(entry, payloads[entry.payload_ref])
  END FOR
  FOR EACH receipt IN OTS_receipts DO
    VerifyOTS(AOF, receipt)
  END FOR
```

Requirements by verification level:

| Level              | Needs                                          |
| ------------------ | ---------------------------------------------- |
| Chain continuity   | AOF file only; offline                         |
| Attribution        | AOF file only; public keys are embedded        |
| Payload commitment | AOF + payload bytes (Hub API or CSV/JSON export) |
| Full audit         | AOF + payloads + OTS receipts                  |

## Open / proprietary boundary

The protocol layer (file format, hashing, signatures, verification) is
entirely open: JSONL, SHA-256, ECDSA-P256, WebAuthn/FIDO2, HTTP
webhooks/REST for integration. The proprietary layer is Helios business
logic — deciding *which* lifecycle actions become evidence and enforcing
RBAC on payload visibility. Access policy is operational (visibility);
integrity is mathematical.

This repository implements the open protocol layer: the AOF data model
and the reference verifier.
