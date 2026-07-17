# Two levels of proof in one AOF (produce/mint addendum)

Upstream EventChain assumes every entry is signed at append time by a human
passkey or a hardware-resident device key — attestation and existence are
simultaneous. In practice hardware is not always present at the moment an
event occurs, so we extend the protocol with two proof levels in a single
chain: every Entry carries a **Produced Proof** (Producer-signed: a device
for its own data, an ingesting service for external streams, a client
carrying the human's passkey for human UI actions), and a human
**Attestation** accrues later as a separate **Mint** Entry Kind referencing
its target by entry hash. Minted status is derived by the verifier fold,
never stored.

Whatever emits the event signs it, with its own key. **The Hub is never a
Producer:** it holds no signing key, and no signature it made appears in an
AOF. An earlier draft of this ADR named it receiver-of-record for human UI
actions; that would have put a key the file must not trust inside the file.
Since the Produced Proof also covers `prev_hash` (ADR-0002 §2), neither an
Entry's content nor its position rests on the Hub having behaved — which is
what the paper's "verification requires no trust in the Hub" needs in order
to be true (`docs/paper-amendments.md` PA-08).

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
