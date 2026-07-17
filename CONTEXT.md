# EventChain

Open protocol layer for zero-trust provenance: an append-only file of
hash-chained, identity-signed events that verifies offline. This repo
implements the proof artifact and its verification, not the Helios
business-logic layer.

## Language

### Proof artifact

**AOF**:
The append-only JSON-Lines proof artifact; one Entry per line, hash-chained in append order.
_Avoid_: ledger, log, chain file

**Entry**:
An immutable, signed record in the AOF. Once appended, never modified.
_Avoid_: event (reserve for the business occurrence an Entry records), row, record

**Payload**:
The content an Entry commits to by hash. Lives outside the AOF; never embedded.
_Avoid_: body, document

**Chain**:
The total order of Entries established by each Entry referencing the hash of its predecessor.

**Anchor**:
An OpenTimestamps commitment of the chain head, proving the chain existed in a state at a time.
_Avoid_: timestamp, notarization

### Two levels of proof (addendum to upstream EventChain)

**Kind**:
The taxonomy of Entries. A lifecycle Entry records a business event; a Mint Entry attests an earlier Entry. New Kinds extend the protocol without touching existing ones.
_Avoid_: type, tag

**Producer**:
Any source that emits events into the chain: a device signing its own measurements, a service ingesting an external stream (e.g. emails from a specific sender), a client carrying a human's passkey. Every Producer holds a signing key and signs with its own — a passkey where a human is present, an equivalent key held directly where the Producer is headless. The Hub is never a Producer: it holds no key and signs nothing.
_Avoid_: sensor (too narrow), source, publisher; the Hub

**Produced Proof**:
The claim every Entry carries at append time: this event happened, at this chain position, originating from this Producer — signed with the Producer's key.
_Avoid_: provisional signature, soft proof

**ChainedEvent**:
What a Producer is handed: an event's commitment (payload hash and ref, entry id) plus its chain linkage (the predecessor's entry hash). Unsigned, and not yet an Entry — an Entry carries a Produced Proof and this is what exists before there is one. "Event" here is the business occurrence, used as this glossary reserves it.
_Avoid_: unsigned entry, draft entry, pending entry

**Produce**:
Append an Entry carrying its Produced Proof: turn a ChainedEvent into a signed AOF line. Level one; happens immediately.
_Avoid_: stage, draft, submit

**Attestation**:
The claim a Mint Entry adds: a named human vouches the referenced Entry is true, with a hardware-held key traceable to them through the organisational directory.
_Avoid_: approval, endorsement

**Mint**:
An Entry Kind carrying an Attestation. References its target by entry hash; appending one never mutates the target. Level two; may happen long after Produce.
_Avoid_: finalize, confirm, countersign

**Minted**:
Derived status of an Entry referenced by at least one Mint Entry. The Verifier derives status by folding over the AOF; status is never stored on the Entry itself. Unminted entries stand at Produced Proof level — that is a level, not a defect.
_Avoid_: provisional (implies the level-one proof is incomplete)

### Verification

**Verifier**:
The offline checker: chain continuity, attribution, payload commitments, and (optionally) Anchors. Needs only the AOF for the first two. A separate package that shares no format logic with the Producer (ADR-0005) — it re-derives the wire format from the normative document, so that its agreement is evidence rather than a shared assumption. Crypto is the deliberate exception: both sides call the same kernels.
_Avoid_: validator, auditor

**Hub**:
The role-gated payload store and AOF distributor. Helios territory; out of scope here except as the thing `payload_ref` points into, and as a consumer that imports these packages. Holds no signing key and signs nothing: it receives already-signed Entries and appends them. Nothing in an AOF rests on the Hub having behaved — not content, and (because `prev_hash` is signed) not order either.
_Avoid_: calling it a Producer
