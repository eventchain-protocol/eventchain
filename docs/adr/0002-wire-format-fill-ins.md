# Byte-level wire-format decisions

The original EventChain paper defined structure (fields) and algorithms
(SHA-256, ECDSA-P256) but left `entry.data()`, the bytes covered by
`prev_hash`, and the encodings undefined. The current specification defines
those rules. This ADR records the implementation's decisions and the evidence
behind them, with golden test vectors demonstrating the resulting format.

**Scope.** This ADR filled gaps in the paper's original text. Two specifications
already govern territory inside those gaps and reach the wire format by
citation: [JSON Lines](https://jsonlines.org/) defines file framing — what a
line is and where it ends — and RFC 8785 defines canonicalization. Where they
speak they are the source of truth, and `docs/wire-format.md` cites them
rather than paraphrasing them.

Decisions:

1. **Chain bytes:** `prev_hash` = SHA-256 of the previous line's content —
   every byte between the preceding terminator (or the start of file) and its
   own `0x0a` terminator, which JSON Lines §3 fixes ("Line Terminator is
   `'\n'`"). A `0x0d` sitting before the terminator is one of the line's
   content bytes and is hashed with them. No canonicalization — any
   re-serialization of a proof artifact breaks the chain by design.

   The paper's Table 4.1 and specification appendix now state this same
   exact-bytes rule. Evidence for preferring bytes over `SHA256(JCS(entry))`:
   `docs/research/2026-07-canonicalization-vs-exact-bytes.md` — every surveyed
   system canonicalizing before a hash did so for a functional requirement
   (dedup, encoding-independence, information model) that we do not have, and
   canonical chaining would let a reformatted file keep a valid chain, so the
   chain would stop identifying the artifact.
2. **Signed bytes (Produced Proof):** the entry with the `signature`
   member removed, re-serialized per RFC 8785 (JCS: sorted keys,
   minified). Canonicalization exists only inside signing, so producer
   field order stays free without weakening the chain rule above. This is the
   paper's undefined `entry.data()`; the spec now defines it.

   **`prev_hash` is therefore signed, and that is the point rather than a
   side effect.** Removing only `signature` means the producer signs its own
   chain position, so no Hub can relocate an entry within a chain or move it
   between chains without invalidating a signature it cannot forge. Ordering
   rests on the producer's key, not on the Hub behaving — which is what lets
   the paper's "verification requires no trust in the Hub" hold. The
   alternative the paper appears to intend, where a producer signs only its
   own event and the Hub supplies `prev_hash`, hands ordering back to the Hub;
   the spec has since adopted the correction. `prev_hash` is
   public, so signing it costs no secret and no round trip.

   Canonicalizing here is *forced*, not chosen: the paper puts `signature`
   inside the object it signs, and bytes containing a signature cannot be the
   bytes that signature covers, so something must define "the entry without
   its signature". JWS avoids canonicalization only by changing the shape
   (`BASE64URL(header).BASE64URL(payload).signature`). §1 has no such
   constraint — the previous line's bytes are already complete — which is why
   §1 and §2 answer the same-sounding question differently.
3. **Mint signatures:** WebAuthn assertions cannot sign arbitrary bytes —
   they sign `authenticatorData || SHA256(clientDataJSON)` with the
   challenge embedded in `clientDataJSON`. Mint entries therefore carry
   the WebAuthn envelope, and the challenge must equal the target entry
   hash. Verification stays offline. (The envelope's member names,
   encodings, and the exact check set are ADR-0007's.)
4. **Format and encodings:** [JSON Lines](https://jsonlines.org/) retained
   (the protocol's "no custom codec" identity) and normative — its three
   requirements (UTF-8 with no BOM; one JSON value per line; `0x0a`
   terminator) govern the AOF, and a conformant JSON Lines reader reads one.
   Every binary field is base64url (unpadded). Chosen
   over hex (~13% larger lines) and over CBOR (~30% smaller but breaks
   the plain-text promise) with billions-of-entries files in mind; gzip
   at rest is transparent to all proofs because verification runs on
   decompressed bytes.

   One carve-out from "labels are opaque strings", settled at M3: an escape
   sequence denoting an unpaired UTF-16 surrogate (`\uD800`–`\uDFFF` with no
   pair) is invalid and the line carrying it is rejected. RFC 8259 admits the
   syntax and calls receivers' behaviour "unpredictable" (§8.2); its RFC 8785
   canonical form is unrepresentable in scalar-value string types, and a
   parser that substituted U+FFFD would canonicalize a string the producer
   never wrote and verify a signature against it. The spec now carries this
   rule.
5. **Closed vocabulary:** an entry carrying a member name the format does
   not define is invalid, and the line carrying it is rejected with its
   line number. A member is the format's only extension point, so an
   unrecognised one is a line whose signature might cover a meaning the
   verifier did not read. The addendum's `kind` is the live case: a
   six-member reader that shrugged it off would verify a Mint's signature
   and report a sound lifecycle event — attestation semantics gone, the
   checkmark intact. Evolution is by explicit wire-format versioning
   (designed in ADR-0006, as this section asked: a per-entry `v` member,
   absent-means-base, arriving before M4 adds the first new member), never
   by signing over what was not read. The spec now carries this rule.

## Consequences

- Files re-encoded by middleboxes fail verification. Feature, not bug. A tool
  that rewrites the file's terminators to CRLF is one instance: it appends
  `0x0d` to every line's content, so every line hashes differently and the
  chain breaks at the first one.
- Any other implementation needs only this document and the golden
  vectors to interoperate — no reference to our code required.
