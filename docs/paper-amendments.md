# Paper amendments

## PA-02 — `prev_hash` over exact line bytes

**Status: applied.**

The paper's [Table 4.1](https://eventchain-protocol.github.io/how-it-works.html#tbl-aof-entry)
defines `prev_hash` as the SHA-256 hash of the previous line's bytes, and the
[specification appendix](https://eventchain-protocol.github.io/appendix-specification.html#sec-entry-spec)
defines the exact byte range: after the preceding terminator, or the start of
the file, through the byte before the previous line's own `0x0a`.

The implementation applies that rule; it is not a departure from the current
paper. [ADR-0002](adr/0002-wire-format-fill-ins.md) records the decision and
the Producer and Verifier tests cover exact-byte chaining and genesis.
