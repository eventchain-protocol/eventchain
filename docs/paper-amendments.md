<!-- This file is long because it is one submittable erratum list: each entry
needs the paper's verbatim text, the defect, and drop-in wording, and the
entries cross-reference each other. Splitting it per-amendment would break the
thing it is for. It will grow as M3 surfaces more. -->

# Paper amendments

Errata this implementation proposes to the EventChain paper at
<https://eventchain.heliosapp.run/>, for submission upstream.

The paper is the source of truth (`docs/protocol.md`); this file records where
implementing it revealed the text cannot be implemented as written. Each entry
quotes the paper verbatim, states the defect as a consequence rather than an
opinion, and gives **drop-in wording** the paper can adopt. An entry without
proposed wording is a complaint, not an erratum.

**This is the outward face of ADR-0002.** ADR-0002 records what we decided in
order to ship; this records what the paper must say so that a stranger
deciding independently lands in the same place. The bar is the paper's own,
from §7 *Open Verification, Helios Implementation*:

> Nothing requires a custom codec, binary envelope, or vendor SDK to parse or
> validate. A verifier built from the specification can confirm any AOF —
> past, present, or produced by a different Hub implementation.

Every entry below is a case where a verifier built from the specification
alone cannot do that.

**Status:** `proposed` — drafted, not yet submitted. `researching` — our own
resolution is unsettled, so proposed wording would be premature.
`submitted` / `accepted` — upstream state.

| # | Subject | Status |
| --- | --- | --- |
| PA-01 | `entry.data()` undefined | proposed |
| PA-02 | `prev_hash` serialization undefined | proposed |
| PA-03 | Field encodings exist only as examples | proposed |
| PA-04 | JSON Lines named, never cited | proposed |
| PA-05 | Genesis `prev_hash` undefined | proposed |
| PA-06 | Duplicate members unaddressed | proposed |
| PA-07 | `VerifyAttribution` cannot verify WebAuthn | proposed |
| PA-08 | Signature's coverage of `prev_hash` unstated — Hub owns ordering | proposed |
| PA-09 | Our divergences, recorded | — |
| PA-10 | Unpaired surrogate escapes unaddressed | proposed |
| PA-11 | Table 6.2's exhaustiveness unstated | proposed |

---

## PA-01 — `entry.data()` is used but never defined

**Status:** proposed

**Paper says** (§6, Figure 6.3):

```
VerifyAttribution(entry)
  ECDSA_P256_Verify(
    publicKey ← entry.public_key,
    message   ← entry.data(),
    signature ← entry.signature
  )
END
```

`entry.data()` appears here and nowhere else in the paper.

**Defect.** `VerifyAttribution` is the paper's central algorithm and is not
implementable. Two independent implementations will choose different byte
sequences and neither verifies the other's entries. Every question that
matters hides inside the undefined call: which members are covered, whether
the signature covers itself, member ordering, and how an object becomes
octets.

**Proposed amendment.** Add to §6, following Table 6.2:

> **`entry.data()`.** `entry.data()` is the JSON Canonicalization Scheme
> [RFC 8785] serialization of the entry object with its `signature` member
> removed and every other member retained.
>
> Removal is by member name and applies to exactly the member named
> `signature`; a signature cannot cover itself. Every other member the entry
> carries is covered — coverage follows the object, not Table 6.2, so a
> member introduced by a later revision of this specification is signed by
> the same rule, by a verifier of that revision. Whether an entry carrying a
> member outside the verifier's vocabulary is *valid* is not a serialization
> question, and is answered separately (see PA-11).
>
> Because RFC 8785 orders members by name, the order in which a producer
> writes members on the line does not affect `entry.data()`, and producers
> are free to choose it.
>
> An entry object carrying the same member name twice has no `entry.data()`:
> RFC 8785 defines no canonicalization of such input. A verifier rejects the
> entry (see PA-06).

**Our resolution.** ADR-0002 §2; implemented as `signingMessage` in
`eventchain/src/EventChain/Canonical.hs`, which removes exactly the `signature` member
and canonicalizes the rest.

---

## PA-02 — "SHA-256 of the previous entry" never says how an entry becomes bytes

**Status:** proposed

**Paper says** (§6, Table 6.2): `prev_hash` — "SHA-256 of previous entry".
And (§6): "the SHA-256 hash of the previous entry". And (§6, Figure 6.3):

```
VerifyChain(AOF)
  FOR i ← length(AOF) − 1 DO
    IF i > 0 THEN
      AOF[i].prev_hash = SHA256(AOF[i − 1])
    END IF
  END FOR
END
```

**Defect.** `AOF[i − 1]` denotes an entry — the paper indexes the AOF as a
sequence of entries and defines it as "a JSON-Lines document: one event per
line", so an entry is a JSON *value*. SHA-256 is defined over *octets*. The
paper never bridges the two, so the chain rule is not implementable and two
implementations produce different chains over identical events.

This is PA-01's gap in a second place. They must be resolved together: a
reader who guesses twice may guess inconsistently, leaving an entry with two
different byte images depending on which check is running.

**Proposed amendment.** Replace the `prev_hash` row's Purpose in Table 6.2
with "SHA-256 of the previous line's bytes", and add to §6:

> **Chain bytes.** `prev_hash` is the SHA-256 digest of the previous line's
> content: every byte between the preceding line terminator (or the start of
> the file) and the previous line's own `0x0a` terminator, hashed exactly as
> written. The digest covers the line's bytes, not the entry's members: no
> canonicalization is applied, and a re-serialization of the entry that a JSON
> parser would consider equivalent produces a different `prev_hash`.
>
> The AOF is therefore readable by any JSON Lines consumer, and rewritable by
> none: an AOF whose lines have been reformatted, re-ordered within the
> object, or re-indented is a different artifact and fails chain verification
> at its first altered line. This is intended. The chain identifies the file,
> not the data the file describes.

And amend Figure 6.3's `VerifyChain` so `SHA256(AOF[i − 1])` reads as the hash
of line `i − 1`'s bytes rather than of an entry.

**Our resolution.** ADR-0002 §1 stands. Evidence:
`docs/research/2026-07-canonicalization-vs-exact-bytes.md`. In short: every
surveyed system that canonicalizes before hashing (Rekor, QLDB, VC Data
Integrity) adopted it for a functional requirement — deduplication,
encoding-independence, signing an information model — and we have none of the
three. DSSE argues the converse on security grounds, and its point that "two
semantically different payloads could have the same canonical encoding" is
sharper for a chain than for a signature: canonical chaining would let an
attacker reformat every line and produce a different file with an identical
chain and valid signatures.

Note that this makes the paper's own wording the defect. "SHA-256 of previous
entry" names a *value*; the rule hashes a *line*. The two coincide only when
nobody reformats the file, which is exactly the case the rule exists for.

---

## PA-03 — Field encodings exist only as examples, and the examples disagree with each other

**Status:** proposed

**Paper says** (§6, Table 6.2), the Example column — the prose states no
encoding for any binary field:

| Field | Example | Decodes to |
| --- | --- | --- |
| `payload_hash` | `a1b2c3d4...` | hex |
| `prev_hash` | `f7e6d5c4...` | hex |
| `public_key` | `MFkw...` | base64 of `3059301306072a8648ce3d020106082a8648ce3d03010703420004…` — X.509 SubjectPublicKeyInfo DER, `id-ecPublicKey` + `prime256v1`, `BIT STRING` leading `04` (SEC1 **uncompressed** point) |
| `signature` | `MEUCIQDx...` | base64 of `3045022100f1…` — `SEQUENCE`(69) `INTEGER`(33), a DER `ECDSA-Sig-Value` |

**Defect.** Four binary fields, four encodings that exist only as ellipsed
examples. A verifier built from the specification cannot read an AOF: "SHA-256
of the payload content" does not say hex or base64, and "Signer's public key"
does not say DER SPKI or raw SEC1, compressed or uncompressed. The examples
are the only signal, which makes them load-bearing by accident, and they mix
conventions — hex for hashes, base64 for keys and signatures.

They are also self-consistent in a way worth preserving: DER SPKI is what
`openssl ec -pubout` emits, and a DER `ECDSA-Sig-Value` is what a WebAuthn
authenticator returns in `response.signature`. Read together they describe a
real policy — *store what the crypto libraries hand you* — which the paper
should adopt in prose or disclaim.

**Proposed amendment.** Add to §6, following Table 6.2:

> **Field encodings.** The Example column is illustrative and non-normative.
> Every field of the entry object is a JSON string. Binary fields are encoded
> as follows:
>
> - `payload_hash`, `prev_hash`: base64url without padding [RFC 4648 §5] of
>   the 32-byte SHA-256 digest.
> - `public_key`: base64url without padding of the 33-byte SEC1 compressed
>   point [SEC 1 §2.3.3].
> - `signature`: base64url without padding of the 64-byte concatenation
>   `r ‖ s`, each a 32-byte big-endian unsigned integer.
>
> `entry_id` and `payload_ref` are opaque strings and carry no encoding
> requirement.

(This wording proposes our choice — base64url throughout, compact forms — for
the reason in ADR-0002 §4: hex costs ~13% in line size at billions of entries,
and DER admits multiple encodings of one signature. If upstream prefers the
library-native policy its examples imply, the amendment is the same shape with
the other values, and we adopt it — the defect is the silence, not the choice.)

**Our resolution.** ADR-0002 §4 and `docs/plan.md`. **This diverges from every
example in Table 6.2** — see PA-09.

---

## PA-04 — JSON Lines is named as a standard but never cited

**Status:** proposed

**Paper says** (§6): "EventChain combines three primitives: a hash-chained
JSONL file…"; "The append-only file (AOF) is a JSON-Lines document: one event
per line." And (§7): "Every component is a published standard with multiple
independent implementations: JSONL, SHA-256, WebAuthn/FIDO2, HTTP webhooks."

**Defect.** JSONL is claimed as a published standard and not cited. Its three
requirements — UTF-8 with no byte order mark; each line a valid JSON value, a
blank line being none; and `0x0a` as terminator — must otherwise be invented
by each reader.

Whether the terminator rule reaches the *chain* depends on PA-02. If
`prev_hash` covers a line's bytes, the rule decides whether a `0x0d` is
hashed, and a CRLF-terminated file chains differently from an LF-terminated
one carrying identical events. If `prev_hash` covers `JCS(entry)`, the
question cannot arise. The paper is silent on a question whose very existence
depends on another thing the paper does not state.

**Proposed amendment.** In §6, where the AOF is introduced:

> The append-only file (AOF) is a JSON Lines document
> [<https://jsonlines.org/>]: UTF-8 encoded, no byte order mark, one JSON
> value per line, lines terminated by `0x0a`. One event per line.

And in §7's standards list, cite JSON Lines rather than naming "JSONL".

**Our resolution.** ADR-0002 §4 cites it normatively; `AGENTS.md` carries the
standing rule that JSON Lines owns framing and we cite rather than restate it.

---

## PA-05 — The genesis entry's `prev_hash` is undefined

**Status:** proposed

**Paper says** (§6, Figure 6.3): the chain loop guards with `IF i > 0`, so the
first entry is skipped. Table 6.2 lists `prev_hash` with no note of it being
optional or special at the head of a chain.

**Defect.** The first entry's `prev_hash` is unconstrained — absent, empty,
zero, or arbitrary all conform. A verifier cannot reject a forged chain head,
because no rule says what a chain head looks like. Worse, nothing marks a
chain's true origin: an AOF truncated from the front verifies completely,
since every remaining entry still chains to its predecessor. "Altering any
past entry breaks every subsequent hash" (§6) holds; *removing the beginning*
does not.

**Proposed amendment.** Add to §6, following Table 6.2:

> **Genesis.** The first entry of an AOF carries a `prev_hash` of 32 zero
> bytes, encoded as any other hash. A verifier rejects an AOF whose first
> entry carries any other value. Chain verification therefore begins at
> `i = 0` rather than `i = 1`, and an AOF from which leading entries have been
> removed fails at its first entry.

And amend Figure 6.3's `VerifyChain` to check the genesis value rather than
skip index 0.

**Our resolution.** `docs/plan.md` — base64url of 32 zero bytes.

---

## PA-06 — Duplicate object members are unaddressed

**Status:** proposed

**Paper says** — nothing. The AOF is JSON Lines and each line a JSON value; no
rule constrains repeated member names.

**Defect.** RFC 8259 §4 says member names "SHOULD be unique" and defines no
behaviour when they are not. Implementations differ; most parsers silently
keep the first or the last. An entry carrying two `prev_hash` members
therefore verifies against whichever one the verifier's parser happens to
keep, and an attacker who can predict the parser writes one line that chains
two ways. For a proof artifact that is a forgery vector. It also gates PA-01:
RFC 8785 defines no canonicalization over input with duplicate members, so
`entry.data()` does not exist for such an entry.

**Proposed amendment.** Add to §6, following Table 6.2:

> **Duplicate members.** An entry object in which any member name appears more
> than once is invalid. A verifier rejects it, and rejects the AOF containing
> it. This is a verifier obligation: an implementation MUST NOT rely on a JSON
> parser's default resolution of duplicate names, which varies between
> parsers and would let one line verify two ways.

**Our resolution.** `EntryObject.entryObject` refuses `DuplicateMember`
structurally; `AGENTS.md` requires the Verifier to fold
`Data.Aeson.Decoding.Tokens` rather than call `decode`, because the token
stream preserves duplicates while `decode` collapses them.

---

## PA-07 — `VerifyAttribution` cannot verify the WebAuthn signatures the paper requires

**Status:** proposed

**Paper says** (§6): "identity-bound signatures (WebAuthn passkeys for humans,
TPM or PUF credentials for devices)". Table 6.2: `signature` — "ECDSA-P256
signature (WebAuthn/FIDO2)", example `MEUCIQDx...`. And Figure 6.3:

```
VerifyAttribution(entry)
  ECDSA_P256_Verify(
    publicKey ← entry.public_key,
    message   ← entry.data(),
    signature ← entry.signature
  )
END
```

**Defect.** A WebAuthn authenticator does not sign a message of the caller's
choosing. W3C Web Authentication Level 3 §6.1.2:

> The format for assertion signatures, which sign over the concatenation of an
> authenticator data structure and the hash of the serialized client data, are
> compatible with the FIDO U2F authentication signature format

and §8.2:

> Verify that `sig` is a valid signature over the concatenation of
> `authenticatorData` and `clientDataHash` using the credential public key

So no passkey will ever produce a signature over `entry.data()`.
`VerifyAttribution` can verify a device signature — a TPM signs what it is
asked to sign — and can never verify a human's. Table 6.2's own example
signature is a DER `ECDSA-Sig-Value` of exactly the shape an authenticator
returns, which suggests the WebAuthn reading is the intended one.

This is most likely underspecification rather than a broken claim — the same
class as PA-01 and PA-03. The paper probably intends what ADR-0001 makes
explicit: a Producer signature over the entry, with a human's passkey
operating at a second level the paper does not detail. But the text as written
gives two sentences that point opposite ways, and a reader must guess which.

Table 6.2 also lists no member carrying `authenticatorData` or
`clientDataJSON`. Without them the signed message cannot be reconstructed
later, so the entry structure cannot hold a verifiable WebAuthn assertion at
all — the missing algorithm and the missing fields are one defect.

**Proposed amendment.** The paper must choose. Either:

> **(a)** `signature` is a raw ECDSA-P256 signature over `entry.data()`,
> produced by a key the signing system holds directly — TPM, PUF, secure
> element, or a server-held key. A WebAuthn assertion by a human is carried in
> additional members alongside `authenticatorData` and `clientDataJSON`, with
> the assertion's challenge bound to the entry it attests, and is verified by
> the Web Authentication algorithm rather than by `VerifyAttribution`.

or:

> **(b)** Table 6.2 gains members carrying `authenticatorData` and
> `clientDataJSON`, and `VerifyAttribution` gains a branch: where the entry
> carries a WebAuthn envelope, the verified message is the concatenation of
> `authenticatorData` and `SHA-256(clientDataJSON)`, and the verifier checks
> that the challenge in `clientDataJSON` binds the entry.

(a) is the smaller change to the paper's structure and the one we implement.
Either way the sentence "ECDSA-P256 signature (WebAuthn/FIDO2)" in Table 6.2
conflates two mechanisms and should name only one.

**Our resolution.** ADR-0001 (two levels of proof) and ADR-0002 §3 —
effectively (a). Every Entry carries a Producer's Produced Proof over
`entry.data()`; a Mint additionally carries the WebAuthn envelope as ordinary
members, which the Producer's signature covers — binding the attestation to
its chain position. The two levels are why our `entry.data()` stays uniform
across kinds. ADR-0007 names the envelope's members and fixes which Web
Authentication checks a relying-party-less verifier runs.

---

## PA-08 — Nothing says the signature covers `prev_hash`, so the Hub owns ordering

**Status:** proposed

**Paper says** (§6): "Verification requires no trust in the Hub, the host, or
network security: the file proves itself."

Table 6.2 lists `prev_hash` as a member; Figure 6.3 signs `entry.data()`,
which is undefined (PA-01). Whether the signature covers `prev_hash` is
therefore unstated, and the paper's apparent intent is that a producer signs
its own event — a document or a measurement — with the Hub supplying
`prev_hash` when it appends.

**Defect.** Under that reading, chain *position* is asserted by the Hub alone.
A Hub that is compromised, coerced, or merely buggy can take a validly signed
event and place it anywhere in the chain: the signature still verifies,
because it covers only the event; the chain still verifies, because the Hub
recomputed the hashes. Nothing in the file objects. Ordering — the single
thing a hash chain exists to establish — would then require trusting the Hub,
which the quoted sentence says it must not.

If instead the signature covers `prev_hash`, each producer attests its own
position, and no Hub can relocate an entry within a chain or move it between
chains without invalidating a signature it cannot forge. The guarantee moves
from the Hub's good behaviour to the producer's key.

This costs nothing to adopt. `prev_hash` is public — there is no secret to
distribute, no confidentiality boundary crossed, and no extra round trip: the
producer is already being handed the value it must sign.

**Proposed amendment.** PA-01's `entry.data()` definition already covers
`prev_hash` by covering every member except `signature`. Make the consequence
explicit — add to §6:

> Because `prev_hash` is among the members covered by `entry.data()`, each
> producer signs its own position in the chain. An entry cannot be relocated
> within a chain, nor moved to another chain, without invalidating its
> signature. The ordering guarantee therefore rests on the producer's key
> rather than on the Hub's correct behaviour, which is what allows
> verification to require no trust in the Hub. `prev_hash` is public
> information; a producer obtains it before signing and no secret is involved.

**Our resolution.** ADR-0002 §2 already has this property: `entry.data()`
removes only `signature`, so `prev_hash` is signed. It was a consequence of
"remove exactly one member" rather than a stated goal, and it is the stronger
design — recorded here so it stops being an accident.

---

## PA-09 — Our divergences, recorded

**Status:** — (register, not an erratum)

Where this implementation deliberately does something the paper's text or
examples do not describe. If the errata above are accepted these either
disappear or become documented profile deviations.

- **Encodings** (PA-03): base64url throughout, against Table 6.2's hex.
- **Signature and key forms** (PA-03): raw `r‖s` and SEC1 compressed, against
  Table 6.2's DER `ECDSA-Sig-Value` and DER SPKI uncompressed point.
- **`kind`, `target_hash`** (`docs/plan.md`): members Table 6.2 does not list,
  added for the two-proof-level addendum (ADR-0001). Additive in one
  direction only: upstream six-member files stay parseable by us, while a
  verifier without the addendum rejects a file carrying these — under
  PA-11's own rule, correctly. The versioning this bullet once waited on
  exists now: ADR-0006's `v` member has entries carrying addendum members
  declare the revision, so the profile boundary is declared on the line
  rather than discovered by rejection.
- **`attester_key`, `assertion_sig`, `authenticator_data`, `client_data_json`**
  (ADR-0007): the Mint's WebAuthn envelope. ADR-0002 §3 fixes that a Mint
  carries the envelope and names none of its members; ADR-0007 now names
  them and fixes their encodings, closing their "recorded nowhere else"
  period, and `docs/wire-format.md` (M5) inherits the rules. They remain
  ours rather than the paper's: PA-07's resolution upstream is what would
  settle them properly.
- **`entry_id`** (`docs/plan.md`): the paper calls it "Unique entry
  identifier"; we treat it as an opaque producer-chosen label with no
  uniqueness requirement and no security weight, because the entry hash is the
  only reference the protocol relies on.

**Open, not yet drafted:** the paper says "Unique entry identifier" without
naming a uniqueness scope (per file? per Hub? global?) or an enforcement
point. Left unresolved rather than guessed at.

---

## PA-10 — Unpaired surrogate escapes are unaddressed

**Status:** proposed

**Paper says** — nothing. Entries are JSON values (§6), and RFC 8259 knowingly
admits the case. RFC 8259 §8.2:

> However, the ABNF in this specification allows member names and string
> values to contain bit sequences that cannot encode Unicode characters; for
> example, "\uDEAD" (a single unpaired UTF-16 surrogate).

> The behavior of software that receives JSON texts containing such values is
> unpredictable; for example, implementations might return different values
> for the length of a string value or even suffer fatal runtime exceptions.

**Defect.** "Unpredictable" is disqualifying in this format's position, twice
over. `entry_id` and `payload_ref` are opaque strings (PA-03), so a line
carrying `"\ud800"` is a line the paper permits. RFC 8785 serializes strings
over UTF-16 code units, so the canonical form of such a string exists — and
cannot be represented by an implementation whose string type holds Unicode
scalar values only, which is most of them (Haskell's `Text`, Rust's `String`,
a Python `str` in practice). Parsers split: some reject the escape, others
substitute U+FFFD. A substituting verifier canonicalizes a string the producer
never wrote and checks the signature against it; two verifiers disagree about
one line. For a proof artifact that is the same ambiguity class as PA-06, and
the paper says nothing.

**Proposed amendment.** Add to §6, following Table 6.2:

> **Unpaired surrogates.** A member name or member value containing an escape
> sequence that denotes an unpaired UTF-16 surrogate (`\uD800`–`\uDFFF` not
> forming a surrogate pair) is invalid. A verifier rejects the entry, and
> rejects the AOF containing it. An implementation MUST NOT substitute a
> replacement character: doing so canonicalizes a string the producer never
> wrote, and verifies a signature against it.

**Our resolution.** The Verifier refuses the line outright — the tokenizer
rejects the escape, so the line is not JSON to us and is reported with its
line number before anything is hashed or checked against it.
`Test.EventChain.Verify.Wire` pins the rejection so the behaviour is ours
rather than inherited from a dependency's default. The Producer cannot emit
the case: its labels are Unicode scalar values by type. ADR-0002 §4 records
the rule.

---

## PA-11 — Whether Table 6.2 is exhaustive is unstated

**Status:** proposed

**Paper says** (§6): "Every entry carries the same structure", followed by
Table 6.2's six members. Whether the table is exhaustive — whether an entry
carrying a seventh member is an entry at all — is never said.

**Defect.** Two implementations choose opposite defaults and both conform.
The lenient one folds the unrecognised member into `entry.data()` and reports
the entry verified; the strict one rejects the line. One file, two verdicts —
the ambiguity class of PA-06 and PA-10 again, except the divergence is
between whole verifier designs rather than parser defaults.

Leniency is the dangerous default, and this document's own addendum is the
demonstration. A member is the format's only extension point: it is where any
revision — ours adds `kind` and `target_hash` (PA-09) — changes what an entry
*claims*. A six-member verifier that signs over an unrecognised `kind`
verifies a Mint entry's signature and reports a sound lifecycle event: the
attestation semantics vanish while the verdict stands. The signature checks
out precisely because it covers a meaning the verifier never read. Rejection
costs availability of files a verifier cannot yet read; acceptance mis-states
what was proven. For a proof artifact only the first failure is survivable.

**Proposed amendment.** Add to §6, following Table 6.2:

> **Unknown members.** An entry object carrying a member name this
> specification does not define is invalid. A verifier rejects the entry, and
> rejects the AOF containing it. An implementation MUST NOT include an
> unrecognised member in `entry.data()` and report the entry verified — the
> signature would then attest a meaning the verifier did not read. A revision
> of this specification that introduces a member must also state how an entry
> declares the revision it conforms to, so that a verifier rejects what it
> cannot read rather than misreading it.

**Our resolution.** The Verifier's vocabulary is closed: an unknown member
name is a hard error carrying its line number (`UnknownMember`), decided
2026-07 over the lenient alternative. The Producer cannot emit the case — a
`ChainedEvent` is a closed record with no bag of extras. The revision
declaration this amendment obliges is designed: ADR-0006's `v` member,
per-entry, absent-means-base, equality-only — leniency is not its
substitute, and the mechanism needs none. ADR-0002 §5 records the rule.
An earlier draft of PA-01 proposed the opposite ("includes it in
`entry.data()` unchanged") and is corrected above.
