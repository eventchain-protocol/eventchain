# Two levels of proof in one AOF (produce/mint addendum)

Upstream EventChain assumes every entry is signed at append time by a human
passkey or a hardware-resident device key — attestation and existence are
simultaneous. In practice hardware is not always present at the moment an
event occurs, so we extend the protocol with two proof levels in a single
chain: every Entry carries a **Produced Proof** (Producer-signed: a device
for its own data, an ingesting service for external streams, the Hub as
receiver-of-record for human UI actions), and a human **Attestation**
accrues later as a separate **Mint** Entry Kind referencing its target by
entry hash. Minted status is derived by the verifier fold, never stored.

## Considered options

- **Minted-only AOF + external DB for unattested events** — rejected:
  events awaiting attestation would sit in a mutable store with no
  tamper-evident existence or timing proof, reopening the fabrication
  window the addendum exists to close.
- **Two AOFs (receipt journal + evidence chain)** — rejected for v0: same
  proofs as one chain, but two anchors and cross-file references.
- **Software-signed "provisional" entries pretending to be attestations** —
  rejected as theatre; the produce-phase signature claims only what its key
  can prove (receipt/origin), not authorship.

## Consequences

- The AOF contains two claim strengths; the verifier must report which
  level each Entry stands at.
- Mint entries never mutate their target, so the hash chain is preserved;
  upstream verifiers that ignore unknown fields still validate the chain.
- Chain position plus the daily anchor gives every event anchored
  existence and ordering from the moment it is produced, before any human
  attests it.
