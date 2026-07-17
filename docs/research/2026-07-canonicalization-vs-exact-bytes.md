# Chain bytes: canonicalization vs exact bytes

Evidence behind ADR-0002 §1 — why `prev_hash` covers the previous line's
exact bytes rather than `SHA256(JCS(previous entry))`. Gathered 2026-07-17,
when the paper's wording ("SHA-256 of previous entry", which denotes a *value*
where SHA-256 needs *octets*) put the choice back in question. See
`docs/paper-amendments.md` PA-02.

**Outcome: ADR-0002 §1 stands unchanged. The paper is what needs amending.**

## The one-line reason

Every system that canonicalizes before hashing adopted it for a **functional**
requirement — deduplication, encoding-independence, or signing an information
model. None adopted it for a security property. We have none of those three
requirements, and we do have the one that argues against it.

## Precedent survey

The field splits, and the split is not the finding — the *reasons* are.

| System | Approach | Stated reason |
| --- | --- | --- |
| DSSE / in-toto | Byte-exact (PAE over raw payload) | Security — explicit, argued |
| Git | Byte-exact over its own serialization | Content-addressing |
| Certificate Transparency (RFC 6962/9162) | Byte-exact (opaque submitted DER) | No raw-vs-canonical rationale documented; the `0x00`/`0x01` domain separation is for second-preimage resistance, a different question |
| Sigstore Rekor | Canonicalized (bespoke per-type, **not** JCS) | Deduplication |
| Amazon QLDB | Canonicalized (Ion Hash) | Encoding-independence (Ion is both text and binary) |
| W3C VC Data Integrity | Canonicalized (URDNA2015, or JCS) | Signing an RDF information model |

Rekor is our closest analogue — a transparency log of signed objects — and it
canonicalizes. Its reason, from Sigstore's own docs:

> The canonicalization of contents is important as we should have one record
> per unique signed object in the transparency log.

That is a dedup requirement. An AOF is append-only and every entry is meant to
be distinct; two entries that canonicalize alike are not a record to merge but
a chain to break. Rekor's reason does not transfer, and its canonicalization
is a bespoke Go struct field-selection, not JCS — do not cite it as JCS
precedent.

CT's precertificate path is worth knowing about and is *not* a counterexample:
it hashes a **reconstructed** `TBSCertificate` (poison extension stripped,
issuer/AKI possibly rewritten, RFC 6962 §3.2), but the stated purpose is that
the log entry match the eventual issued certificate — traceability, not
canonicalization.

## The argument against canonicalizing, from DSSE

`secure-systems-lab/dsse`, `background.md` — the only place in the survey where
a project argues the choice on security grounds:

> Two semantically different payloads could have the same canonical encoding.
> Although there are currently no known attacks on Canonical JSON, there have
> been attacks in the past on other canonicalization schemes. It is safer to
> avoid canonicalization altogether.

> It requires the verifier to parse the payload before verifying, which is
> both error-prone—too easy to forget to verify—and an unnecessarily increased
> attack surface.

> The preferred solution is to transmit the encoded byte stream exactly as it
> was signed, which the verifier verifies before parsing.

DSSE's honesty is worth preserving: it admits it has no named attack on
Canonical JSON to point to, and the "attacks in the past on other
canonicalization schemes" is uncited in the document. Treat it as a design
posture with a plausible mechanism, not as a demonstrated exploit.

**Why the first quote is sharper for a chain than for a signature.** If two
lines canonicalize alike they share a `prev_hash` preimage. An attacker who
rewrites every line's whitespace and member order produces a *different file*
with an *identical chain* and *valid signatures* — the chain stops identifying
the artifact it chains. Raw bytes make the chain identify the file exactly,
which is the property an artifact that travels and is archived needs.

## The JOSE working group said it as a requirement

RFC 7165 §6.3, desideratum D2 — a working-group requirements document, not a
blog:

> Avoid JSON canonicalization to the extent possible. That is, all other things
> being equal, techniques that rely on fixing a serialization of an object
> (e.g., by encoding it with base64url) are preferred over those that require
> converting an object to a canonical form.

RFC 7515 (JWS) itself contains **no** rationale for the choice — the word
"canonical" appears once, about unrelated string comparison. The mechanism is
in 7515; the reason is in 7165. Do not cite 7515 for the reason.

## What RFC 8785 does and does not give us

Relevant because ADR-0002 §2 already depends on JCS for signing, and PA-02
would have doubled that surface.

- **Not Standards Track.** Independent Submission, Informational. It never had
  IETF consensus review. Mike Jones (JWS co-author) on the JOSE list in 2020:
  "I was surprised to see this RFC, because very little discussion of it
  happened on the JOSE mailing list." That is a process objection, not a
  technical one — do not over-read it.
- **§5 Security Considerations is scoped to single-object sign-then-verify.**
  It says nothing about hash chains, replay, or reordering of canonicalized
  entries. Our use would have been outside what the section was written for.
- **No duplicate-member defense.** §3.1 says input "MUST NOT exhibit duplicate
  property names" — an input precondition. Unlike NaN, Infinity and lone
  surrogates, which each carry a "MUST cause a compliant JCS implementation to
  terminate with an appropriate error", duplicates get no detection
  requirement. JCS will not catch them for you; `EntryObject.entryObject`
  does.
- **Verified Errata 7920 (2024):** `-0` and `0` canonicalize to identical
  bytes. Two distinguishable inputs, one output, acknowledged after
  publication.
- **No Unicode normalization**, deliberately (§3.1): "all components involved
  in a scheme depending on JCS MUST preserve Unicode string data 'as is'".

**Most of this does not reach us**, and the honest reason is the input type,
not our care: an `EntryObject`'s values are all JSON strings and its member
names are all ASCII, so the number hazards (`-0`, 2^53, subnormals, ES6
`NumberToString`) and the UTF-16 ordering hazard are unreachable by
construction. `EventChain.Canonical` already documents this. The findings
above are why that property must stay true rather than drift.

## Why §2 keeps JCS and §1 does not need it

They are not the same decision, and the asymmetry is structural rather than a
preference.

The paper puts `signature` **inside** the entry object it signs. You cannot
sign raw bytes when the signature is one of the bytes — so something must
define "the entry without its signature", and that is a canonicalization
whether or not it is called one. JWS escapes canonicalization only by changing
the *shape*: `BASE64URL(header).BASE64URL(payload).signature` puts the signed
region outside the signature. DSSE's PAE does the same with length prefixes.

So §2's JCS is **forced by the paper's entry shape**, and §1's is **free** —
the previous line's bytes are already sitting there, complete, with nothing to
remove. The evidence above bears only on the free one.

(A JWS-shaped restructuring of the entry would retire §2's canonicalization
too. It is out of scope for v0 — it would rewrite Table 6.2 entirely — but it
is the honest answer to "could we drop JCS altogether", and PA-07's resolution
touches the same seam. Recorded, not proposed.)

## Sources

- RFC 7165 §6.3 — <https://www.rfc-editor.org/rfc/rfc7165>
- RFC 7515 §2, §5.1, §10.12 — <https://www.rfc-editor.org/rfc/rfc7515.html>
- RFC 8785 §3.1, §3.2.2.2, §3.2.2.3, §5, App. B — <https://www.rfc-editor.org/rfc/rfc8785>
- RFC 8785 Errata 7920, 6292 — <https://www.rfc-editor.org/errata/rfc8785>
- DSSE `background.md`, `protocol.md` — <https://github.com/secure-systems-lab/dsse>
- RFC 6962 §2.1, §3.1, §3.2, §3.4 — <https://www.rfc-editor.org/rfc/rfc6962.txt>
- RFC 9162 §3.2, §4.7 — <https://www.rfc-editor.org/rfc/rfc9162.txt>
- Sigstore, Pluggable Types — <https://docs.sigstore.dev/logging/pluggable-types/>
- W3C RDF Dataset Canonicalization §7.1 — <https://www.w3.org/TR/rdf-canon/>
- Ion Hash Specification 1.0 — <https://amazon-ion.github.io/ion-hash/docs/spec.html>
- Pro Git §10.2 — <https://git-scm.com/book/en/v2/Git-Internals-Git-Objects>
- JOSE list, 2020 — <https://www.mail-archive.com/jose@ietf.org/msg05343.html>
