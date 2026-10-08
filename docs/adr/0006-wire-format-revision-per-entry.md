# A revision is declared per entry, and absence declares the base

ADR-0002 §5 closed the member vocabulary and named its own escape hatch:
"evolution is by explicit wire-format versioning (a design still open, wanted
before M4 adds the first new member), never by signing over what was not
read." PA-11's proposed amendment carries the same obligation upstream: "a
revision of this specification that introduces a member must also state how
an entry declares the revision it conforms to." M4 adds the first members the
paper does not list — `kind`, `target_hash`, and the Mint envelope — so the
design is due now. This ADR is it.

## Decision

A new member, `v`. Its value is a JSON string carrying a decimal revision
label; dotted labels (`"1.1"`) are permitted if a later revision wants one.
Comparison is equality only: a verifier knows a closed set of revision
labels, each defining a closed member vocabulary, and an entry declaring a
label outside that set is rejected with its line number — never read
"approximately". No ordering, no compatible-minor arithmetic, no semver.

**Absence declares the base revision**: the paper's six members (its
Table 6.2, summarized in `docs/protocol.md`), exactly. Revision `"1"` is the ADR-0001
addendum: the six, plus `kind`, `target_hash`, the four envelope members
(ADR-0007), plus `v` itself.

**The Producer emits `v` only where the base vocabulary does not suffice** —
in v0, on Mint entries. Lifecycle lines stay six-member and byte-identical to
what a paper-only implementation writes and reads; `vectors/v0-lifecycle.jsonl`
is untouched. A `"v":"1"` on a lifecycle entry is nevertheless *valid* input —
the label admits the vocabulary, it does not mandate exercising it — mirroring
RFC 5280, where basic-fields-only certificates "SHOULD be 1" but "MAY be 2
or 3".

No enforcement machinery is added, and that is the design working rather than
a gap. ADR-0002 §5 already rejects unknown members, and `v` composes with it
from both sides: a base verifier meets `"v":"1"` as an unknown member and
rejects — precisely PA-11's required behaviour toward a revision it cannot
read — while our Verifier meets `kind` on an undeclared line, finds it
outside the base vocabulary, and rejects. The declaration selects which
vocabulary the closed-vocabulary rule closes over; the rule does the rest.

`v` is a member like any other: signed inside `entry.data()`, hashed with the
line's bytes, carried by the entry wherever the entry goes. An entry excerpted
from its file keeps its declaration, which is why the declaration lives on the
entry and not on the file.

## Considered options

- **A JSON number** (`"v":1`) — rejected. Every member value is a JSON
  string; that invariant is why both JCS implementations sidestep RFC 8785's
  hardest requirement entirely
  (`docs/research/2026-07-canonicalization-vs-exact-bytes.md`: the number
  hazards "are unreachable by construction... The findings above are why that
  property must stay true rather than drift"). A number in the signing
  message obliges two independent codecs to implement ECMAScript
  `NumberToString` and to police canonical spelling — wire bytes `1.10`
  re-serialize as `1.1`, so one revision gains two spellings that verify
  identically, or a spelling check nothing else needs. All of it buys the
  removal of two quote characters.
- **Semver semantics** (TUF's `spec_version`, Rekor's `apiVersion`) —
  rejected. The string *carriage* is borrowed from them; the compatibility
  arithmetic is not. TUF §4.3 leaves matching open — "Adopters are free to
  determine what is considered a match (e.g., the version number exactly, or
  perhaps only the major version number (major.minor.fix)" [sic — the
  parenthesis never closes] — which is one file, two verdicts:
  the ambiguity class PA-06/PA-10/PA-11 exist to kill.
- **A file-level header line** — rejected. Chained, it redefines genesis and
  churns every committed vector; unchained, the declaration is the one
  unsigned statement in a file whose premise is that it proves itself. Either
  way an excerpted entry loses its declaration, and PA-11's obligation reads
  "an *entry* declares".
- **Overloading `kind`** — rejected. `kind` is entry taxonomy, not format
  revision; a future member added to lifecycle entries — which carry no
  `kind` — would have nowhere to declare itself.

## Precedent, verified at source

- RFC 5280 §4.1.2.1 — omit-when-base, declare-when-extended: "If only basic
  fields are present, the version SHOULD be 1 (the value is omitted from the
  certificate as the default value)... When extensions are used, as expected
  in this profile, version MUST be 3 (value is 2)."
  <https://www.rfc-editor.org/rfc/rfc5280.html>
- RFC 7515 §4.1.11 (`crit`) — reject-what-you-cannot-read: "If any of the
  listed extension Header Parameters are not understood and supported by the
  recipient, then the JWS is invalid."
  <https://www.rfc-editor.org/rfc/rfc7515.html>
- RFC 6962 §3.2 — an explicit `Version` field inside the signed structure.
  <https://www.rfc-editor.org/rfc/rfc6962.html>
- Sigstore Rekor — per-entry `apiVersion` beside per-entry `kind`, in an
  append-only signed log: the closest living analogue of an AOF.
  <https://github.com/sigstore/rekor/blob/main/openapi.yaml>

## Consequences

- Mint vectors are born declaring `"v":"1"`; lifecycle vectors and the
  Producer's lifecycle output do not change by a byte.
- A paper-only verifier rejects our Mint-bearing files, and PA-09's
  "distinct profile" caveat becomes the mechanism working as specified
  rather than a gap awaiting a design.
- The `Member` vocabularies on both sides of the ADR-0005 wall gain `V`,
  written separately as ever; the Verifier's revision set is a closed type.
- PA-11's upstream proposal can now cite a concrete mechanism for the
  obligation it states.
- `docs/wire-format.md` (M5) states this rule; `CONTEXT.md` carries the
  term **Revision**.
