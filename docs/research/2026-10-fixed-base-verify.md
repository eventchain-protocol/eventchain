# Fixed-base P-256 verification — the kernel is 2.2×, the Verifier 1.4×

Measured 2026-10-14, Apple M4 Max (12 performance + 4 efficiency cores),
mains power, load average 2–4 from the desktop, OpenSSL 3.6.3, GHC 9.12.4,
arm64, s2n-bignum `4d1356a7` (2026-09-29). `cabal run eventchain-bench:verify`
with `-- +RTS -N<n>`, and `cabal run eventchain-crypto:bench`. Every number
is from this session; the October note's rows are not comparable (below).

## What was decided, and on what evidence

ADR-0004 as amended: ECDSA-P256 verification moves from `EVP_PKEY_verify` to
vendored s2n-bignum assembly, with a table of each Producer key's multiples
built once per key and `p256_scalarmulbase` walking it for both scalar
multiplications. The decision was taken on a C spike outside the repository,
whose gate was *zero disagreements with libcrypto and at least 2× per verify*;
the spike and its results file are not in the tree, the way ADR-0004's
original `spike2.c` was not, and the numbers that mattered are here.

### The spike (C, same machine, same session)

10,000 random 32-byte digests signed with `EVP_PKEY_sign`; each verify loop
run five times, best run; context-reused `EVP_PKEY_verify` against the table
walk built from the s2n-bignum calls the kernel now makes.

| blocksize | table entries | table bytes | µs / verify | ratio | table build, µs / key |
| --- | --- | --- | --- | --- | --- |
| 4 | 520 | 33,280 | 17.4 | 1.85 | ~200 |
| 5 | 832 | 53,248 | 15.2–15.5 | 2.10–2.13 | ~245 |
| 6 | 1,376 | 88,064 | 14.7 | 2.21 | ~325 |
| **7** | **2,368** | **151,552** | **14.5** | **2.24** | **~500** |
| 8 | 4,224 | 270,336 | 16.7 | 1.95 | ~835 |

`EVP_PKEY_verify` with a reused context: 32.1–33.0 µs across every run.
Disagreements: 0 of 10,000 valid, 0 of 10,000 tampered (one bit of the
digest, `r` or `s` flipped; neither verifier accepted any), 0 of 5 crafted
edge cases. Blocksize 7 chosen; 8 loses its iteration savings to the cache.

Where the 15.2 µs at blocksize 5 went, each primitive timed alone over 10k
calls: `p256_scalarmulbase` 7.02 µs (twice per verify, so 92% of the path),
`bignum_modinv` mod *n* 0.75, `bignum_montinv_p256` 0.80, `p256_montjmixadd`
102 ns, `p256_montjdouble` 73 ns, `bignum_montmul_p256` 9 ns. For scale,
`p256_scalarmul` — s2n-bignum's *variable*-base multiplication, what a
verify without a table costs — is 29.1 µs, which is roughly libcrypto's whole
verify and says libcrypto is already table-based for both terms.

### The edge cases, from the proofs and then exercised

Read from `arm/proofs/*.ml` — the HOL Light postconditions checked against
the object code, not the source comments:

| function | precondition | consequence for the kernel |
| --- | --- | --- |
| `p256_montjmixadd` | `~(P1 = P2)`; P2 affine, so never infinity | P1 infinity and P1 = −P2 are correct; equal inputs are the caller's to double |
| `p256_montjdouble` | none | doubling infinity is correct |
| `p256_scalarmulbase` | table tabulates P, P on the curve | any scalar, reduced mod *n* itself; infinity encoded `(0, 0)` |
| `bignum_montinv_p256` | none | zero for zero, so test Z before inverting |

Crafted from the private scalar *d* — `e = r·d` makes `u1·G = u2·Q`,
`e = −r·d` makes them opposite, a zero digest makes `u1 = 0`, plus `r = n`
and `s = 0` — all five were rejected by both verifiers, and counters confirmed
the doubling, infinity and `u1 = 0` paths each ran once.

### A hand-written walk, measured and declined

Added to the spike as a third way: a table of unsigned digits (2^bs − 1
entries per block, no negation), indexed directly, one proven mixed add per
nonzero digit. Zero disagreements, same oracle.

| blocksize | s2n walk, µs | ratio | direct walk, µs | ratio | direct table | build / key |
| --- | --- | --- | --- | --- | --- | --- |
| 5 | 15.4 | 2.11 | 12.1 | 2.68 | 103 KB | ~390 µs |
| 6 | 14.3 | 2.25 | 10.5 | 3.07 | 173 KB | ~565 µs |
| 7 | 14.5 | 2.25 | 9.4 | 3.47 | 301 KB | ~900 µs |
| 8 | 16.6 | 1.99 | 8.5 | 3.88 | 522 KB | ~1,550 µs |

Faster because the s2n walk is built for a secret scalar — every iteration
scans the whole block with constant-time selects and conditionally negates —
and the Verifier's scalars are public. Declined by the maintainer: the proven
loop is what is being bought, and a loop of ours would rest on an argument of
ours (a three-line one, but ours). Recorded so the number is not re-derived.

## The kernel in Haskell

`EventChain.Crypto.Internal.Precomputed`: sixteen `capi` imports against
upstream's own header, a `PrecomputedKey` holding the table, and
`verifyBatchPrecomputed`. The table build and the verify are Haskell loops
over `unsafe` leaf calls, the two table walks `safe`. Graded by the
differential suite: RFC 6979 vectors and six properties — valid signatures,
wrong message and wrong key, every byte perturbed, `r`/`s` at the range
edges, arbitrary 64 bytes, interleaved-key batches — every triple through
both verifies, any disagreement a failure.

`cabal run eventchain-crypto:bench`, three runs:

| row | measured | µs |
| --- | --- | --- |
| verify (1 core), libcrypto | 29.3–29.8k /s | 33.6–34.2 |
| verify precomputed | 65.7–67.4k /s | 14.8–15.2 |
| precompute key | 1,915–1,919 /s | 521–522 per key |

Against the C spike's 14.5 µs the Haskell kernel is within 2–5%; the FFI
loop around the leaves costs nothing measurable, including in the table
build, which lands on the C figure exactly.

## The Verifier, before and after, same session

The October note's rows cannot be the baseline: its decode row read 10.6 µs
and today's reads 6.9 with nothing in decode touched, so that machine was in
a different state (load 5–7 then; it suspected OpenSSL 3.6.3 and the suspect
is now cleared — the libcrypto kernel measures 33.8 µs today, not 53).
Instead the unmodified HEAD was built in a second worktree and the same bench
run from both binaries within the same minutes. Two passes each; the
sequential rows are read from the -N1 run, as the October note's trap says.
Worst of two.

| row | libcrypto kernel (HEAD) | fixed-base kernel | ratio |
| --- | --- | --- | --- |
| decode, sequential | 6.92–6.98 µs | 6.81–6.90 µs | — |
| signatures, sequential | 41.2–41.3 µs | 22.4–22.5 µs | 1.83× |
| verify, -N1 | 19.6 µs (51.1k/s) | 15.95 µs (62.7k/s) | 1.23× |
| verify, -N12 | 4.84 µs (206.5k/s) | 3.68 µs (271.7k/s) | 1.31× |
| verify, -N16 | 4.97 µs (201.3k/s) | 3.64 µs (274.6k/s) | 1.37× |

Every verdict Sound on every run. The signatures row includes its own decode
(the triples are built lazily inside the clock), so the kernels on this
file's lines are ~34.3 and ~15.6 µs — the crypto bench's numbers, and 2.2×.

### Why the fold gained 1.3× from a kernel that gained 2.2×

The plan expected 2–2.5× end to end from "83% of the per-line cost is one
verify". That was the *sequential* share. In the parallel fold the per-line
wall time at -N12 was 4.84 µs where (6.9 + 34.3) / 12 ≈ 3.4 would be ideal:
~1.4 µs/line the fold did not explain, and the October note left it as "CPU
work inflates under parallel load", unmeasured. The kernel change moved the
ideal to (6.9 + 15.6 + 2.0 table) / 12 ≈ 2.0 and the measurement to 3.68 —
so the unexplained share is ~1.7 µs/line and is now the *larger* half. The
signature kernel stopped being the ceiling; the fold's own parallel overhead
is, and it did not shrink.

At -N1 the gain is smaller still, 1.23×, for the opposite reason: the old
kernel's 34 µs `safe` call released the capability for long enough to hide
most of the chunk's Haskell work behind it. A 6 µs walk hides less.

### The table, per chunk, and then per run

As first wired, the table was built where keys are promoted — once per
distinct key per 256-line chunk — so a one-key file paid ~520 µs per chunk,
~2 µs a line of CPU, on the chunk's own critical path. Against 19 µs saved
per line that was the right placement to start with. Measured, it was worth
recovering: the spine now decodes each chunk's last line (~7 µs per chunk)
and hands the next chunk the promotion of that line's key as a shared thunk,
so a run of one key across the file builds one table. The seed is at most
one key, so the spine holds one table and memory stays per-chunk; a chunk
under some other key promotes its own as before. Same session, same binary
shape, worst of two, load 4–5 (higher than the runs above):

| row | table per chunk | table per run (seeded) | ratio |
| --- | --- | --- | --- |
| verify, -N1 | 15.95 µs | 13.65 µs (73.3k/s) | 1.17× |
| verify, -N12 | 3.68 µs | 3.41 µs (293.1k/s) | 1.08× |
| verify, -N16 | 3.64 µs | 3.39 µs (294.6k/s) | 1.07× |

At -N1 the table sat on the chunk's own CPU path, which is why it shows
most there. Cumulatively against the unmodified HEAD built beside it:

| row | HEAD | this tree | ratio |
| --- | --- | --- | --- |
| verify, -N1 | 19.6 µs (51.1k/s) | 13.65 µs (73.3k/s) | 1.43× |
| verify, -N12 | 4.84 µs (206.5k/s) | 3.41 µs (293.1k/s) | 1.42× |
| verify, -N16 | 4.97 µs (201.3k/s) | 3.39 µs (294.6k/s) | 1.47× |

## What this changes upstream

- The README's performance section and figures quote this file's final rows.
- The next lever is not crypto. Of the 3.41 µs a line costs at -N12, the
  kernel is ~1.3, decode ~0.6, and ~1.5 is parallel overhead the October
  note already named and nobody has profiled. Before anything else is
  bought: `+RTS -s` and a profile of the fold at -N12 on an idle machine,
  with the unexplained µs/line as the number to account for.
- The fold hands a chunk two things from before it now, and only one of
  them reaches a verdict: the digest is the chain, the seed is a shared
  thunk a chunk would otherwise build itself. `EventChain.Verify`'s fold
  docstring says so.

## Traps

- **Do not compare across sessions.** Decode moved 35% between October and
  today with no change to decode. Build the baseline beside the candidate.
- **Do not read -N1 as single-threaded**, still: a `safe` walk releases the
  capability, and the -N1 row beats the sequential signatures row.
- **`precomputeKey` of one key in a loop times nothing.** GHC shares the
  thunk; the bench builds 200 distinct keys for that row.
- **The spike measured raw digests; the suite measures messages.** The
  crafted equal- and opposite-point cases need a chosen digest and cannot
  be reached through a SHA-256 of anything, so they live in the C spike and
  the proofs, not in the property suite.
