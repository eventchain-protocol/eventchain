# The Verifier is a separate package; crypto is shared

Verification is evidence only when the Verifier shares no format logic with
the Producer. A canonicalizer bug living in code both sides import makes them
agree: the Producer emits what the Verifier expects, every golden vector
passes, and the defect ships. This is the reasoning already applied to the JCS
conformance gate — `aeson` is the oracle *because* it shares no code with our
canonicalizer — raised one level, from the module to the artifact.

So v0 is three packages in one repo, one `cabal.project`:

- **`eventchain-crypto`** — the batched libcrypto FFI (ADR-0004) and the
  decision-free types it operates on: `LineBytes`, `PayloadBytes`,
  `LineHash`, `PayloadHash`, `ClaimedKey`, `PublicKey`, `Sig`. Both sides
  depend on it.
- **`eventchain`** — the Producer. Takes a `ChainedEvent`, canonicalizes,
  hashes, signs, emits an AOF line. It implements the paper as literally as
  the type discipline allows. **It never parses JSON**, so it carries no JSON
  parser and no JSON-accepting attack surface.
- **`eventchain-verify`** — the Verifier. Reads an AOF, accepts untrusted
  JSON because that is inherently its job, and folds. Its format logic —
  member vocabulary, JCS, the line codec, the Entry model — is written
  independently and imports nothing from `eventchain`.

The split is asymmetric on purpose, and the asymmetry is the decision:
**format logic is gated by disagreement; crypto is gated by agreement.**

Whether two sides derive the same signing message from the same entry is the
question the golden vectors exist to answer, so sharing that code voids the
answer rather than answering it. Whether they compute the same SHA-256 is not
a question but a requirement, and it is checkable against OpenSSL CLI fixtures
without a second implementation — a known-answer test needs no dissenter. The
FFI is also the only memory-unsafe code in the system; writing it twice
doubles that obligation and buys no evidence with it.

The Verifier being separate is not merely hygiene. `docs/plan.md` calls v0
done "when a stranger could reimplement from docs + vectors alone", and an
independently written Verifier is the first execution of that test — the one
place where a format decision that lives in code but never reached
`docs/wire-format.md` becomes visible before a third party finds it.

That class is real, and the first instance is already closed. An earlier draft
of this ADR cited it live: ADR-0002 said `prev_hash` covers "the previous
line's exact UTF-8 bytes (trailing newline excluded)", which for a CRLF file
did not say whether the CR belonged to the line or the terminator — and the
code had quietly decided, rejecting `0x0D`. Reading JSON Lines §3 at the
source settled it against us: the terminator is `0x0a`, so a `0x0d` before it
is content and is hashed with the rest. The code was wrong, not merely
undocumented; ADR-0002 §1 now says so and `lineBytes` rejects only `0x0a`.

The live instance is the byte order mark. JSON Lines requires UTF-8 without
one; nothing we have written says whether an AOF may carry one, and nothing
checks. It is a file-level rule rather than a line-level one, so it belongs to
the Verifier's framer — booked into `docs/plan.md` M3. It is the same shape as
the CRLF case: a rule that is real, unwritten, and invisible until someone
builds a reader from the document alone.

## Considered options

- **One library holding both roles** (the superseded plan) — rejected: the
  Verifier would import the Producer's canonicalizer, member vocabulary and
  codec, so the vectors would attest self-consistency rather than
  conformance. It also puts a JSON parser inside the Producer, which has no
  use for one.
- **Verifier depends on `eventchain` for Types + Canonical** — rejected: the
  same defect, smaller. A shared canonicalizer bug still blesses itself; the
  JSON surface separating cleanly does not redeem that.
- **Verifier independent down to its own crypto** — rejected: doubles the
  hand-written FFI and its memory-safety obligations, and gains nothing,
  because crypto correctness is established by known-answer tests against
  OpenSSL rather than by a second opinion. Sharing here is the rare case
  where tight coupling is the correct answer.
- **Verifier in a separate repository** — rejected for v0: it would be the
  strongest independence signal, but it splits the golden vectors' home and
  forces cross-repo release coordination on `eventchain-crypto` before either
  side is stable. `build-depends` enforces the boundary within one project, and
  a test suite can assert it. Revisit once the wire format is normative.

## Consequences

- `eventchain` gains no JSON parser; `aeson` is a Verifier-only dependency.
  The Producer's line codec is encode-only.
- Two hand-written JCS implementations exist, each gated against `aeson`
  independently. That is the cost of the gate, and it is the point of it.
- The claim tier is largely Verifier-side: `Entry`, `DecodedEntry`,
  `ChainPosition` and `Attestation` describe reading a line someone else
  wrote, which the Producer never does. `ChainedEvent` — the commitment and
  chain linkage of a business event, unsigned and not yet an Entry — is what
  `eventchain` takes instead.
- `eventchain`'s package description must stop advertising verification.
- The boundary is only real while `eventchain-verify` does not
  `build-depends` on `eventchain`. That is asserted by `cabal test all`
  (`gates:verifier-independence`), not left to convention.

  This ADR originally said "That is a CI assertion", and for the length of M0 it
  was not true of anything: no workflow ran, and the walker that would have
  checked it had no caller. The sentence was the load-bearing one in this
  ADR — the argument here is precisely that a convention would not survive a
  year — so it is recorded rather than quietly corrected.
- Every rule the Producer enforces about a line's bytes must reach
  `docs/wire-format.md` (M5, where the plan places the document), because a
  third party cannot read our code — and now neither can our Verifier.
