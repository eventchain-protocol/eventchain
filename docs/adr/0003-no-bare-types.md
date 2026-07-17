# Bare and Any-shaped types are banned from the core

In a proof library the worst bug class is byte confusion — hashing a
re-serialization instead of the original line, comparing a payload hash
to an entry hash, signing the wrong message. We make these compile
errors: every domain quantity is an opaque newtype with an unexported
constructor and a validating smart constructor; bytes are typed by
provenance (`LineBytes` / `CanonicalBytes` / `PayloadBytes`); hashes are
typed by subject (`LineHash`, `PayloadHash`). `String` appears nowhere;
`Text`/`ByteString` never carry domain meaning across a module edge.

`aeson`'s `Value` — the `Any` of JSON — appears nowhere at all. An earlier
draft confined it to "the Wire decoder's internals", conceding it a hiding
place; none is needed. The Producer never parses JSON (ADR-0005), and the
Verifier folds `Data.Aeson.Decoding.Tokens` directly into its member
vocabulary, so no `Value` is ever constructed. The ban is total, and it costs
nothing: building the `Value` would have been strictly more work, and it is
the step that discards duplicate members.

Distinctness is what buys the safety, so the plainest construct that
delivers it wins. `LineHash` and `PayloadHash` are separate newtypes
rather than one `Hash subject` tagged by a phantom: both refuse the
cross-comparison, but an unparameterised newtype with a hidden
constructor cannot be `coerce`d at all, whereas a phantom parameter
leaks a `phantom` role *through* the abstraction — roles are exported
even when constructors are not — and needs `type role ... nominal` to
plug. At two subjects the parameter bought two fewer function
definitions and cost a silent footgun. If the subject vocabulary ever
grows past a handful, revisit; the arithmetic changes, the principle
does not.

The ban extends to what functions return. No naked `Bool` or `Int`
verdicts: failures are enumerated sums carrying their chain position,
and a verification level is a type rather than a sentence in a docstring.
Errors are typed per boundary — closed sums the caller matches on, with
text rendered only at the edge — so no caller ever parses a message to
learn what happened.

## Consequences

- Core types deliberately have **no `ToJSON`/`FromJSON` instances** — a
  derived instance would be a second serialization path bypassing the
  exact-bytes invariant. Each package's explicit codec is the only door.
  Future contributors will be tempted to "fix" this; don't.
- Slightly more ceremony at the edges (smart constructors, unwrapping at
  IO boundaries) in exchange for unrepresentable invalid states in the
  middle.
- Two tiers of guarantee: smart constructors prove *shape* (a
  well-formed claim from a trusted-at-the-boundary supplier);
  cryptographic truth is a relation between values, discharged only by
  the Verify fold, which is the sole constructor of verified-evidence
  types. Nothing else converts a claim into a fact.
