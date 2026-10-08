# The mint check is fifty lines of ours, graded by the ecosystem's implementation

ADR-0002 §3 fixed that a Mint carries the WebAuthn envelope and that the
challenge must equal the target entry hash, and named none of the envelope's
members. The four names have lived in `eventchain`'s `EntryObject` as "this
module's invention... the weakest thing in the format". `docs/plan.md`
delegated their verification to the tweag `webauthn` package. This ADR makes
the members normative, fixes exactly which W3C checks run, and supersedes the
delegation.

All spec quotations below are from the W3C Web Authentication Level 3
specification, §6.1 (authenticator data) and §7.2 (Verifying an
Authentication Assertion), read at source.
<https://www.w3.org/TR/webauthn-3/>

## The envelope members, now normative

| Member | Content | Encoding |
| --- | --- | --- |
| `attester_key` | The attesting authenticator's P-256 public key | SEC1 compressed point, base64url — `public_key`'s form |
| `assertion_sig` | The assertion signature | raw 64-byte `r‖s`, base64url — `signature`'s form; the authenticator's DER is normalized away at the source, per the wire-format list in `docs/plan.md` |
| `authenticator_data` | The authenticator data structure, exact signed bytes | base64url |
| `client_data_json` | The client data, the exact bytes the authenticator hashed | base64url |

`attester_key` travels in the entry because v0 has no key directory; who the
key belongs to is a claim the directory layer (out of v0) will ground. What
the envelope proves here is internal: this key signed this challenge, and the
challenge is this chain position.

## Which checks run: every step that needs no relying party

The Verifier is pure — file bytes in, verdict out, no clock, no network, no
config (`docs/plan.md`). §7.2 is written for a relying party mid-ceremony,
so its steps divide cleanly: those computable from the envelope alone run;
those needing an RP-supplied expectation or a stored credential record have
no possible input here and are documented ignored, not silently skipped.

Runs, in order:

1. `client_data_json` decodes as UTF-8 and parses as JSON (reading rules
   below).
2. "Verify that the value of `C.type` is the string `webauthn.get`" — a
   registration response is not an attestation.
3. "Verify that the value of `C.challenge` equals the base64url encoding of
   `pkOptions.challenge`." Our challenge *is* the target entry's line hash,
   so this is string equality between `C.challenge` and the `target_hash`
   member's text — the binding rule ADR-0002 §3 already fixed, landing on
   spec wording exactly.
4. `authenticator_data` is at least 37 bytes: `rpIdHash` (32) ‖ `flags` (1)
   ‖ `signCount` (4), per §6.1. Trailing bytes (extensions) are covered by
   the signature and not parsed.
5. "Verify that the UP bit of the `flags` in `authData` is set." §6.1:
   "Bit 0: User Present (UP) result." Unconditional in §7.2; no real
   authenticator omits it, so its absence marks a fabricated envelope.
6. "If the BE bit of the `flags` in `authData` is not set, verify that the
   BS bit is not set." Stateless internal consistency; same fabrication
   tripwire.
7. "Let `hash` be the result of computing a hash over the `cData` using
   SHA-256," then "verify that `sig` is a valid signature over the binary
   concatenation of `authData` and `hash`" — ECDSA-P256 under
   `attester_key`, via the same `eventchain-crypto` kernel that verifies
   Produced Proofs, batched with them.

Ignored, and why:

- **Origin, `topOrigin`, `crossOrigin`, `rpIdHash`** — every one is "verify
  ... expected by the Relying Party". There is no Relying Party; an
  expectation supplied by caller config would be an unverified claim wearing
  a check's clothes.
- **UV** — §7.2 is conditional by construction: "Determine whether user
  verification is required for this assertion... If user verification was
  determined to be required, verify that the UV bit... is set. **Otherwise,
  ignore the value of the UV flag.**" Requiredness is RP policy
  (`pkOptions.userVerification`), and no policy source exists in a pure
  verifier. Nor would the bit prove what its name suggests: WebAuthn binds a
  credential to a device; UV says the device ran its local lock, not who
  held it. If a directory ever grounds an identity claim worth policing, a
  later revision (ADR-0006) can require the bit; rejecting on it today would
  encode a policy the format cannot ground.
- **`signCount`** — clone detection against a stored credential record,
  meaningless without ceremony state.
- **Extension outputs** — signed, unread, unparsed (step 4).

## Reading `client_data_json`

The nested document is authored by browsers, not by this format, so the
entry-level closed vocabulary (ADR-0002 §5) is explicitly out of scope
inside it — W3C reserves the right for clients to add members, and an
unknown member here is a browser doing its job, not an unread claim our
signature covers: the Producer's signature covers the blob's exact bytes,
and its meaning to us is two members. The rules:

- Unknown members are tolerated.
- Values are typed per W3C (`crossOrigin` is a boolean, so the entry codec's
  strings-only rule cannot apply and does not).
- **Any duplicate member name is fatal.** Two `challenge` members is the
  same ambiguous read as two `prev_hash` members — the verifier reads one
  while another consumer reads the other. No browser emits duplicates;
  presence marks fabrication or tampering.
- Only `type` and `challenge` are read.

## Implementation home, and who grades it

The checks live in `EventChain.Verify.WebAuthn`, hand-written on
`eventchain-crypto` — the message construction is one concatenation and one
hash the spec states in a sentence, and the signature arithmetic was proven
at M1 by published known answers. The tweag `webauthn` package is **never a
`build-depends` of any library**: it enters exactly one test suite, as the
oracle — every fabricated envelope must verify under our fifty lines *and*
under an implementation that shares none of them. That is `aeson`'s JCS role
reprised: the grader stays outside the graded. A single vector additionally
cross-checked against a non-Haskell implementation (the `soft-webauthn`
package's `SoftWebauthnDevice` — a software authenticator built on
python-fido2's primitives, which ship no authenticator of their own) extends
the evidence across ecosystems, as the OpenSSL CLI did at M2.

This supersedes `docs/plan.md`'s module table, which delegated the check to
the package inside the library. The package's API is shaped for a relying
party mid-ceremony — expected origin, expected RP ID, COSE credential
records — none of which exists here (`attester_key` is SEC1, not COSE), so
using it meant synthesizing a ceremony to satisfy an API, inside the
verification path, with its `crypton` dependency in the build. As the
oracle it contributes the thing it actually has — an independent reading of
§7.2 — and `crypton` is confined to test builds, retiring AGENTS.md's
hot-path quarantine by removing the thing quarantined.

## Vectors

`eventchain`'s suite fabricates the envelopes — it already plays this role
for `vectors/v0-lifecycle.jsonl`, and `gates:verifier-independence` bars the
Verifier's suites from producing what they adjudicate. Fabrication is
deterministic (fixed test keys, RFC 6979 signing, fixed `authenticator_data`
fields), so the committed bytes are rebuilt and asserted, not seeded. The
committed set covers, beyond the sound Mint: UP unset; BS without BE; wrong
challenge; tampered `authenticator_data`; tampered `client_data_json`;
duplicate member inside `client_data_json`; orphan Mint (target absent);
mismatched `target_hash`; Mint without `v`; unknown `v` label (ADR-0006).

## Consequences

- The four member names leave "recorded nowhere else" status; PA-09's
  weakest-thing caveat closes, and `docs/wire-format.md` (M5) inherits the
  rules stated here.
- `eventchain` gains Mint emission: the envelope arrives as opaque bytes and
  is emitted, never parsed — the no-JSON-parser property is untouched.
- The minted-status fold is unchanged from `docs/plan.md`: a separate O(n)
  join, deliberately not merged into the streaming pass.
- AGENTS.md's crypton constraint updates: not "keep it off the hot path" but
  "test builds only, as the oracle's transitive dependency".
