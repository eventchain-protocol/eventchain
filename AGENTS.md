# EventChain — agent guide

Read these first, in order:

1. `CONTEXT.md` — the domain vocabulary. Use these terms exactly.
2. `docs/plan.md` — the v0 plan; the package and module tables give each
   boundary's contract. A plan, not a spec: expect supersession.
3. `docs/adr/0001..0005` — locked decisions. Do not relitigate them;
   if one must move, that's a user conversation, not a code change.
4. `docs/protocol.md` — upstream protocol summary (source of truth is
   the website; the byte-level rules the paper leaves open are ours, per
   ADR-0002).
5. `docs/paper-amendments.md` — where the paper is under-determined or
   contradicted by its own examples, quoted and cited. Errata we intend to
   submit upstream. Add to it the moment implementing something reveals the
   text cannot be implemented as written.
6. `docs/research/` — evidence behind the decisions, cited at source.
   `2026-07-haskell-ecosystem.md` for the toolchain and dependency choices
   including benchmark baselines; `2026-07-canonicalization-vs-exact-bytes.md`
   for why the chain covers line bytes rather than `JCS(entry)`. Read the
   relevant one before reopening a decision it already settled.

## Standing constraints

- **The Producer and the Verifier share no format logic** (ADR-0005).
  `eventchain-verify` must never `build-depends` on `eventchain`; the two
  member vocabularies, JCS encoders and Entry models are written separately
  and their agreement is the evidence. Sharing them to fix a divergence
  passes every test and destroys the thing the tests were for. Crypto is the
  deliberate exception: `eventchain-crypto` is shared by both, because there
  agreement is the requirement rather than the question.
- **A docstring may not name a module across the split.** `eventchain-crypto`'s
  docs name only `EventChain.Crypto.*`; `eventchain`'s never name
  `EventChain.Verify.*`; `eventchain-verify`'s never name the Producer's. A
  haddock link to a module the package cannot import renders silently as prose
  — `cabal haddock` does not warn, because forward references within a package
  (`EventChain.Verify.Wire` before M3) are legitimate and look identical. So
  the dependency edge a docstring draws is one nothing will catch, and it was
  already drawn twice before M0 caught it by hand. Write "the Verifier's codec"
  rather than linking it.
- **JSON Lines owns framing. Cite it; restating it is how we get it wrong.**
  The AOF *is* a JSON Lines document (`CONTEXT.md`, `docs/protocol.md`): a
  conformant JSON Lines reader reads one, and that is the open-protocol
  promise. <https://jsonlines.org/> §3 fixes the terminator at `0x0a`, so a
  line's content is every byte before it and a `0x0d` there is content, hashed
  with the rest — a CRLF file is valid JSON Lines whose lines end in `0x0d`.
  ADR-0002 fills the gaps the *paper* leaves; where JSON Lines or RFC 8785
  already speak they are the source of truth, and one of our rules
  contradicting them is a bug in our code. Read the spec at the source before
  writing a framing rule; a summary of it is not the spec.
- **The Producer never parses JSON.** It emits JSON. No JSON parser belongs
  in `eventchain` — that absence is a security property, not an oversight.
  This is a bound on the *parse* step, not on framing: splitting a file into
  raw line bytes per JSON Lines §3 is framing, and the Verifier's framer does
  it without building a value.
- **aeson is the structural twin.** A `Types` facade over
  `Types.Internal.*` hidden in `other-modules` — aeson's shape for
  `Data.Aeson.Types` over `Data.Aeson.Types.Internal`. Being *stricter* than
  convention (GHC2024, extra warnings, fourmolu) is fine; being *differently
  shaped* is not.
- **Be precise, not fancy.** Use the plainest construct that makes the bad
  state a type error, and stop there — distinctness buys safety, cleverness
  does not. A type-level feature earns its place by preventing a bug, not by
  generalising: `LineHash`/`PayloadHash` are two newtypes, not one
  phantom-tagged `Hash subject` that only leaks a role to plug (ADR-0003).
- **aeson is the JCS oracle. Never import `Data.Aeson.RFC8785` in a
  library.** The conformance gate is evidence only because the two
  implementations share no code; depending on the oracle destroys the gate
  and every test still passes. The *package* is fine where it earns its
  place — `eventchain-verify` uses its tokenizer — but the canonicalizer is
  the grader, never the graded.
- **Fold aeson's tokens; never `decode` a line.** `decode` silently collapses
  duplicate members to the first, so a line with two `prev_hash` members
  would verify against one of them arbitrarily. `Data.Aeson.Decoding.Tokens`
  preserves both, which is what makes the duplicate fatal — and the fold is
  less work per line than `decode`, which is that same tokenizer plus a
  `KeyMap` build we would throw away.
- **crypton never enters a library build.** It arrives transitively via
  tweag `webauthn`, which ADR-0007 confines to one test suite as the oracle
  grading the hand-written mint check — so a `build-depends` on either, in
  any library, is the ADR being violated, not a packaging choice. Never
  touch `Crypto.PubKey.ECC.ECDSA` — the legacy module, measured 60× slower.
- **Batch the crypto FFI.** At SHA-NI speed a 300-byte hash ≈ 150ns ≈
  one FFI call; one call per line spends the acceleration on overhead.
- **Update `CONTEXT.md` and the ADRs the moment a term or decision
  shifts** — the docs are the deliverable, not a byproduct.
- **Toolchain:** GHC 9.12.4 primary (`ghcup set`), cabal ≥3.16; GHC2024 plus
  the extensions declared in each package's `.cabal`. One `cabal.project`
  spans all three.
