# Verifier throughput — the end-to-end baseline, and what the cores add

Measured 2026-10-13, Apple M4 Max (12 performance + 4 efficiency cores),
OpenSSL 3.6.3, GHC 9.12.4, arm64. `cabal run eventchain-bench:verify`, with
`-- +RTS -N<n>` for the capability count. **On battery, with low power mode
on, and a load average around 5 from other work on the machine.** Every
number here is slower than the July kernel note's for that reason — the
kernel bench run in the same session gave 19.0–19.1k verify/s (~52 µs)
against July's 28.4–29.1k, and 1.23 GB/s hashing against 1.77–1.92 — so
compare rows within this file, and rerun on mains power before quoting any
of them outside it.

## What was measured, and in what order

The benchmark package did not exist before this. The crypto bench times the
kernels in isolation; nothing timed the fold around them, so the first run
below is the Verifier as it stood before the per-chunk fan-out, and the
numbers after it are the same binary shape with the fan-out in. Three rows:

| row | what it times |
| --- | --- |
| decode, sequential | frame, token fold, base64, canonical bytes — everything but crypto |
| signatures, sequential | `verifyBatch` over the file's own triples, one 256-chunk after another |
| verify, -N*n* | the whole fold, every verdict forced |

Lines are ~330 bytes, one Producer key, lifecycle Entries only. 20k lines for
the baseline, 100k after (see "granularity" below).

## Baseline: the sequential fold, one capability

| row | µs/line | lines/s |
| --- | --- | --- |
| decode, sequential | 10.2–10.6 | ~95k |
| signatures, sequential | 63.6 | 15.7k |
| verify (old fold), -N1 | 64.7–65.1 | 15.4k |

Three things this settles:

- **The fold costs ~1 µs around the crypto.** Verify minus signatures is the
  Map build, the key promotion, `zipWith5` and the lazy list plumbing, and
  all of it together is noise against the kernel.
- **Decode is ~10.5 µs/line, a sixth of the total.** Unmeasured until now,
  and guessed at 1–5 µs in the review that prompted this. It is the number
  that decides whether a parallel fold may leave decoding on the sequential
  spine: at a dozen cores the crypto share falls to ~4 µs and 10 µs of
  sequential decode would be the ceiling. So decode went inside the fan-out.
- **GC is not in it.** `+RTS -A64m` cut bytes copied from 66 MB to 18 MB and
  moved the per-line time by nothing. The July hash note's 30 ns/line GC
  finding is real and is 0.05% of this.

The signatures row is 63.6 µs where the kernel bench says 52: the row
includes its own decode (the triples are built lazily inside the clock), so
the kernel on this file's data is ~53 µs — the kernel bench's number, on the
same slow machine.

## The fan-out

The chain hands a chunk one thing from before it: the digest of the line it
follows. That is a function of raw bytes, so the spine computes it from the
previous chunk's last line (`boundary`) without that chunk's decode, and each
chunk's decode, hashing and two signature batches are sparked as a unit
through `parBuffer (2 × capabilities)`. Forcing a verdict to constructor
forces every check behind it, so `rseq` per verdict is the whole strategy.

| capabilities | µs/line | lines/s | vs old fold |
| --- | --- | --- | --- |
| -N1 | 29.6–30.6 | ~33k | 2.1× |
| -N12 | 7.1–7.7 | ~130–140k | 8.5–9× |
| -N16 | 7.2–7.9 | ~127–140k | 8.3–9× |

### One capability is not one core

The -N1 row is faster than the signatures row, which should be impossible if
the fold ran on one thread. `+RTS -s` explains it: at -N1, 390 of 391 sparks
were *converted* (run by a worker, not by the consumer), and mutator CPU time
was 16.8 s against 13.2 s elapsed. `c_EVP_PKEY_verify` is a `safe` foreign
import — chosen in `EventChain.Crypto.Internal.Foreign` so a 34 µs call
would not stall GC — and a `safe` call releases its capability for the
duration. The runtime hands the free capability to a spark worker, which
starts the next chunk, whose own batch releases it again. So even at -N1
libcrypto runs on more than one OS thread while the Haskell work shares one
capability. Consequence for anyone quoting numbers: **a sequential reference
has to be a fold with no sparks**, which is the baseline above and the
signatures row, not `-N1` on the current fold.

### -N16 is not better than -N12

Four of the sixteen cores are efficiency cores. Mutator CPU rose from 21.8 s
(-N12) to 24.6 s (-N16) for the same elapsed, which is the efficiency cores
taking chunks and finishing them late. Capabilities beyond the performance
cores buy nothing here.

### Where the ceiling is, and where it is not

At -N12 the ideal is (10.8 + 53) / 12 ≈ 5.3 µs/line; measured 7.1–7.7. Ruled
out:

- **Granularity.** 20k lines is 79 chunks; the last round leaves 5 of 12
  workers idle, ~10% of the run. 100k lines (391 chunks) gave the same
  number, so the bench now uses 100k.
- **GC.** 0.18 s of 4.4 s CPU at -N12, and `-A64m`, `-qg`, `-qn4` and
  `-A128m -n4m -qn4` all landed within noise of the default.

Not ruled out, and the first thing to measure next: the CPU work itself
inflates under parallel load — ~108 µs of mutator CPU per line at -N12
against 63 at one thread. Some of that is efficiency cores doing a share of
the chunks, some is all-core clocks under low power mode, and the rest is
unknown until it is run on mains power with the machine otherwise idle.

## What decode's 10.5 µs is probably made of

Unmeasured below the row, so this is a list of suspects and not a finding.
Per 330-byte line the bytes are walked roughly seven times: the copy out of
the lazy file (`frameLines`), the UTF-8 shape check (`lineBytes`), the token
fold, five or six base64 decodes each re-encoding `Text` to bytes first, the
canonical rebuild, and two digests. Of those, `Canonical.jsonString` folds
every character through a `Builder` and the token fold builds a
`Map Member Text` per line. A profile before touching any of it.

## What this changes upstream

- `docs/plan.md` had booked `unliftio` pools for this. Its pools run in IO;
  the reference verifier is a pure function and stays one, so the fan-out is
  a `Strategy` from `parallel` and `verify`'s type did not move.
- The RTS flag the July note said belongs to the Verifier executable is still
  the executable's to set, and there is still no executable. The bench ships
  `-rtsopts` so the numbers above can be reproduced with the flags shown.

## Traps

- **Do not read `-N1` as single-threaded** on any fold that sparks; see above.
- **Sequential rows degrade under spare capabilities.** The decode row reads
  10.8 at -N1 and 13.6–14.4 at -N12/-N16 — parallel GC syncing idle
  capabilities. Read the sequential rows from the -N1 run.
- **Never benchmark under `cabal repl`**, for the kernel note's reason.
- **This machine was on battery.** It is the one thing that would change
  every number here at once.

## Mains rerun, the same day

Same machine and binary, on mains power, low power mode off, load average
5–7 from the desktop. Two runs per capability count; the sequential rows
are read from the -N1 run, as the trap above says.

| row | µs/line | lines/s |
| --- | --- | --- |
| decode, sequential | 10.6–10.7 | ~94k |
| signatures, sequential | 63.5–63.8 | 15.7k |
| verify, -N1 | 29.9 | 33.5k |
| verify, -N12 | 8.0 | 125.5k |
| verify, -N16 | 8.0–8.4 | 118.6–125.6k |

Every row is within 2–4% of the battery run, so the battery was not what
made this file slower than July. The kernel bench in the same session
confirms it: 18.9k verify/s and 1.03 GB/s hashing on mains, against July's
28.4–29.1k and 1.77–1.92, while `sign` in the contention bench ran at
37.7k/s — the July sign figure. One thing changed between July and now that
touches verify and hash but not sign: OpenSSL went from 3.6.2 to 3.6.3.
That is a suspect, not a finding; checking it means the kernel bench
against a 3.6.2 build on this machine. Until then, the README quotes these
rows and not July's.

