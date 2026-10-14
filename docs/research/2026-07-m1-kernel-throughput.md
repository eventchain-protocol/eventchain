# M1 kernel throughput — the miss, the fix, and where the last 30 ns live

Measured 2026-07-17, Apple M4 Max, OpenSSL 3.6.2, GHC 9.12.4, arm64.
`cabal run eventchain-crypto:bench`. An earlier revision of this file recorded
a miss: hashing at 1.26–1.52 GB/s against a 1.6 GB/s floor. **The miss is
closed.** Both of M1's throughput criteria are now met, and this file records
how, because the residual numbers constrain what any future "make it faster"
effort can honestly promise.

## The floor, the target, and the ceiling

Three different numbers, and confusing them is easy.

| | hashing (300-byte lines) | ECDSA verify (1 core) |
| --- | --- | --- |
| **Baseline** — ADR-0004's spike, measured in C | ~2 GB/s | 30,583/s |
| **Floor** — the baseline less 20%, which is M1's bar | **1.6 GB/s** | **24,500/s** |
| **Measured** — our Haskell kernel, compiled, default RTS | **1.77–1.92 GB/s** ✓ | **28,372–29,092/s** ✓ |
| **Measured** — same binary, `+RTS -A64m` | **2.17–2.29 GB/s** | (unchanged) |
| **Ceiling** — the same kernel written in C (`spike2.c`) | 2.97 GB/s | 29,530/s |

(Single runs of the bench wobble ~5% — the hash segment times a ~35 ms window,
and one scheduler blip or GC pause moves the answer. Ranges here are five runs;
judge against the worst, not the best.)

Per line at 300 bytes: C does 101 ns, the floor is 188 ns, we do **~165 ns**
with the default RTS and **~131 ns** with a 64 MB allocation area. The
theoretical Haskell floor is ~123 ns — C's 101 plus ~22 ns for three `unsafe`
foreign calls — so the tuned number is within ~8 ns/line of everything this
architecture can give without a C loop, which ADR-0004 does not have.

## What closed the gap

The previous revision guessed "the per-digest pinned 32-byte allocation" and
asked for a profile before believing it. `+RTS -s` confirmed it: the old
kernel allocated ~94 MB and copied ~41 MB during GC for a 200k-line chunk,
because every line paid a pinned `BSI.create` for its digest *and* a pinned
`alloca` for the length out-parameter — two locked-heap allocations against
101 ns of hashing.

`EventChain.Crypto.Internal.Digest.digestChunk` now:

- allocates **one** pinned buffer of `32 × n` per chunk and hands each digest
  out as a 32-byte slice of it (the batch API paying off a second time — the
  handoff's step 3, implemented as written);
- hoists the length out-parameter to one `alloca` per chunk;
- replaces `mapM` plus two `map` traversals with a single accumulating loop
  and `coerce` at the newtype boundary, which is free.

Retention trade recorded in the module: any one digest keeps its whole chunk's
buffer alive, 32 bytes per input. Every real consumer keeps all the digests or
none, so this costs a pathological caller and nobody else.

The benchmark was also lying slightly, in both directions: it built
`replicate 200000 line` inside the timed region (fixed: forced before the
clock) and forced only the result spine (fixed: each digest forced to WHNF).
The fixed benchmark measured the *old* kernel at 1.44 GB/s — the input-list
cost was the ~3% the handoff estimated, and the miss was real.

## Where the last 30 ns live, and why they stay

With the allocation fix, `+RTS -s` shows the residual: the kernel's remaining
allocation is the result list itself — a cons cell, a `ByteString` header and
a `ForeignPtr` box per line, ~56 bytes, which is the minimum a
`[LineHash]` can cost. Those 200k boxes survive until the caller consumes
them, so the default 4 MB nursery copies them repeatedly while the loop runs:
~32 MB copied, ~30 ns/line. Grow the allocation area (`+RTS -A64m`) and the
copying vanishes — 1.3 MB copied, and throughput lands at 2.17–2.29 GB/s,
*above* the C baseline.

So the remaining overhead is not marshalling and not removable from the
library: it is the GC default of the binary that links us. The RTS flag
belongs to the Verifier executable when M3 builds one (`-with-rtsopts`), and
this file is where the number justifying it lives. The library ships no RTS
opinion; the bench gained `-rtsopts` so `+RTS -s` can be run against it, which
changes nothing unless flags are passed.

Also measured, and declined: `-O2` on the library moves the number 1–2%,
inside run-to-run noise, so it stays at cabal's default `-O1` — the same
evidence standard that took `-O2` off the bench.

## The verify kernel, revisited

Verify always passed the floor; it was still carrying per-line costs the chunk
was supposed to amortize, and shedding them took it from 26.8–27.6k/s to
**28.4–29.1k/s** — inside ~2% of the C ceiling, ~5% under the C baseline.
Three changes, in `EventChain.Crypto.Internal.Ecdsa`:

- **`EVP_DigestVerify` → `EVP_PKEY_verify`.** The old path was one-shot per
  init, and each init fetched SHA-256 by name and built an internal
  `EVP_PKEY_CTX` — per-line work on a 34 µs kernel. The new context is
  initialized once and reused: "EVP_PKEY_verify() can be called more than once
  on the same context to have several one-shot operations performed using the
  same parameters" (`EVP_PKEY_verify(3ssl)`, function 3.0+, inside the 3.2
  floor). The context is rebuilt only when the batch switches keys, so a batch
  pays per *run of one signer*, which for an AOF is nearly never.
- **Messages prehashed through our own batched SHA-256 kernel.**
  `EVP_PKEY_verify` takes the digest, not the message — which hands the
  hashing to the kernel this package already made fast, a few hundred ns
  against 34 µs of curve math.
- **DER encoded in Haskell.** Raw `r‖s` to `SEQUENCE { INTEGER r, INTEGER s }`
  is ~20 lines of total code over a length-proven `Sig`; the FFI construction
  it replaced (two BIGNUMs, an `ECDSA_SIG`, a finalizer registration, six
  calls per line) was most of a verify's non-curve cost. Sign, once per
  append, keeps decoding through libcrypto's `d2i`.

Honest caveat: the bench verifies a same-key batch, the best case for context
reuse. A batch that switches keys every line pays `EVP_PKEY_CTX_new_from_pkey`
plus init per switch and lands roughly where the old path was — and the old
path is what it degrades to, not below. The RFC 6979 vectors and the hostile
generators all verify through the new path.

## The ADR-0004 question, now moot

The previous revision asked whether the ±20% band — measured in C, applied to
a Haskell binding — was a bar hashing could ever meet, and flagged that
amending it would be a user conversation. The floor is met in the shipping
configuration and the *baseline* is met with one RTS flag, so the criterion
stands as written and the conversation is unnecessary. The profile-first
discipline is what made it moot: the gap was ours, not the bar's.

## Traps, still live

- **Never benchmark under `cabal repl`.** The same loop measures ~28× slower
  in bytecode; it reads as catastrophic failure and means nothing.
- **Throughput here is a property of this machine.** The bench records, it
  does not assert (see the bench module header); compare against these numbers
  only on comparable hardware.
