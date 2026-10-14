# Hub append rate — what checking each line before appending it costs

Measured 2026-10-14, Apple M4 Max (12 performance + 4 efficiency cores),
macOS 15.6.1, OpenSSL 3.6.3, GHC 9.12.4, cabal 3.16.1.0, arm64, **on mains
power**, low power mode off.
`cabal run eventchain-bench:hub-append -- --seconds 4 --runs 2`. One
`produce` cost 22.4 µs on one thread in this session, the same as the
contention run on mains (22.3 µs, `2026-10-producer-contention.md`); one
checked append cost 65.0 µs on one thread; a 20 ms in-flight delay
delivered 20.89 ms.

## The question

The whitepaper says each submitted line costs the Hub the three checks a
Verifier makes — well formed, predecessor hash, signature — and derives the
Hub's one-thread rate from the Verifier's whole-file throughput: 42 seconds
per million entries (`verify` at `-N1` over a one-million-line AOF, in the
whitepaper's own evidence note of 2026-10-12), so about 24,000 lines a
second on one thread per topic. That is an inference from a different
workload. The Verifier's figure is a fold over a whole file, hashing and
verifying in chunks; a Hub meets lines one at a time, each against the head
it holds at that moment, and must answer each before it can take the next. What was missing was the Hub's own
number, measured with the checks in the path and the same Hub without them
beside it, from one run.

## The harness

`eventchain-bench:hub-append`: the contention harness with a Hub model on
every cell. Four things changed and nothing else:

- **The Hub has two modes** (`Contention.Hub`). *Head-only* is the model the
  contention and batching notes measured: compare the head the submission
  states, write, advance by hashing the bytes written. *Checked* compares the
  stated head the same way — a stale submission is refused without being
  read, the way an append API refuses a failed precondition — and then hands
  every submission that passes to the Verifier's fold, resumed from the Hub's
  own checkpoint (`verifyFrom`; `verify` before the first line, where the
  byte order mark rule also applies). The fold is the production code path
  and makes all three checks: the line is well formed under the exact-bytes
  rules, its `prev_hash` is the head, and its signature verifies under the
  key it carries. The Hub writes only if every verdict is Sound, and takes
  the new head from the digest the fold computed from the bytes it judged;
  it neither hashes again nor trusts a digest from the Producer. The stated
  head is a hint and the fold is the judge: a Producer that lies about the
  head it signed against is caught by the chain check. A submission failing
  any check is *refused* and writes nothing. Nothing in any library changed.
- **One thread sits in front of the Hub** (`Contention.Processor`). Producers
  hand a submission to a queue and wait for the reply; the Hub thread takes
  submissions in arrival order. Both modes run behind the same thread, so
  the two rates in one run differ by the checks alone. The hop is one
  runtime handoff each way — a floor under what a socket and a server's
  request path add, never a ceiling. The contention note kept the hop out
  of its numbers on purpose; this note puts it in on purpose, because the
  question is what a Hub pays, and a Hub is a server.
- **The checks are proven live before anything is timed**
  (`Contention.Refusals`). The Producers only ever submit good lines, so a
  Hub that checked nothing would post a rate and its files would still
  verify. So one checked Hub is first handed a good line, then a line
  signed against the genesis head while stating the current one, a line
  with one byte of its entry id changed after signing, and a line with its
  closing brace missing. Each must come back refused with the fault that
  names it — chain mismatch, signature invalid, malformed — the head must not
  move, a good line must then land as line two, and the Verifier must find
  exactly two Sound lines in the file. The run does not start otherwise. It
  started.
- **The checked append is calibrated** (`timeCheck`). Three thousand chained
  lines are produced beforehand, then appended one at a time through a
  checked Hub with no thread in front of it. That is the Hub's own service
  time per line, with no signature and no hop inside it.

Everything else is the contention harness: one thread and one key per
Producer, sign against the head read, hold in flight for the delay, submit,
sign again on rejection; every file verified afterwards by `eventchain-verify`
— every verdict Sound, line count equal to commits, each Producer's key on
exactly the lines it reports. All 16 files passed.

The sweep crosses Hub {head-only, checked} with Producers {1, 12} and
in-flight delay {0, 20 ms}, saturating load, a batch of one. Eight cells,
two runs of four seconds each.

## The model

The contention model's window, widened by the Hub's service time *s*: with
*w* = signature + delay + *s*, saturating load commits 1/*w* a second
whatever the Producer count, and costs *P* signatures per committed Entry.
*s* is zero for head-only and the calibrated checked append for checked.
The model knows nothing of the hop, and nothing of what a losing submission
costs the Hub thread; both show up below as the gap between `pred` and the
measurement.

## Results

`P` is Producers; `pred` is the model; ranges are two runs; percentiles are
pooled across runs; `fair` is the smallest per-Producer commit count over the
mean, worst run.

```
16 capabilities; one produce 22.4 µs on one thread; 8 cells × 2 runs × 4.0 s
a checked Hub refused a stale, a forged and a malformed line and wrote nothing for them; one checked append 65.0 µs on one thread
an in-flight delay of 20000 µs delivers 20892 µs

hub       load         batch   P    delay |             commits/s      pred |     sig/entry   pred | retry p50/99 |   latency p50/99 µs |  fair
head-only saturating       1   1        0 |           29135-29729     44650 |     1.00-1.00   1.00 |     0/0     |        31/50        |  1.00
head-only saturating       1  12        0 |           10924-10945     44650 |   11.77-11.77  12.00 |     0/177   |        88/16542     |  0.90
head-only saturating       1   1    20 ms |                 46-46        48 |     1.01-1.01   1.00 |     0/0     |     21274/23506     |  1.00
head-only saturating       1  12    20 ms |                 48-49        48 |   11.86-11.90  12.00 |     1/107   |     39661/2246169   |  0.06
checked   saturating       1   1        0 |           11018-11146     11445 |     1.00-1.00   1.00 |     0/0     |        84/302       |  1.00
checked   saturating       1  12        0 |             7465-7574     11445 |   11.98-11.99  12.00 |     0/130   |       128/17474     |  0.85
checked   saturating       1   1    20 ms |                 46-46        48 |     1.01-1.01   1.00 |     0/0     |     21465/23817     |  1.00
checked   saturating       1  12    20 ms |                 47-48        48 |   11.90-11.96  12.00 |     1/124   |     39104/2616179   |  0.06
```

### The two numbers

One head, one thread, one Producer, a batch of one, nothing in flight,
saturating load, from one invocation:

| Hub | committed entries per second |
| --- | --- |
| all three checks before every append | 11,018–11,146 |
| head compare only | 29,135–29,729 |

The checks cost a factor of 2.6–2.7 on this pipeline. The pipeline is
serial at one Producer: the Producer signs (22.4 µs), the line crosses to
the Hub thread, the Hub judges it (65.0 µs), the reply crosses back, and
only then is the next line signed. The model's 1/(22.4 + 65.0 µs) = 11,445
is within 3–4% of the measurement, so the hop is a few microseconds of that
window and the checks are the rest.

The Hub thread's own ceiling is the calibration, not the pipeline: 65.0 µs
per checked line is 15,400 lines a second for a Hub thread that is never
waiting on a signer. At one Producer it waits for one on every line, which
is what the 11.1k measures; at twelve it never waits for a signer and
measures something else (below).

### The hop is inside the head-only number

The head-only row predicts 44,650 — one signature per commit — and measures
29,400. The contention note measured 43,530–45,231 for the same Hub rule
with no thread in front of it. The 12 µs per round that separates them is
the queue: one handoff to the Hub thread and one back, each waking a thread
on another capability. A deployment pays more than this for the same step,
so the head-only figure here is the lowest honest baseline for a Hub with a
request path, and the contention note's figure is the append rule alone.

### Per-line checking costs more per line than whole-file verification

The fold over a whole file costs about 42 µs a line in the whitepaper's
evidence run (`-N1`, a million lines) and 29.6–30.6 µs at `-N1` in
`2026-10-verifier-throughput.md` — a row that note warns is not single
threaded, because the signature check is a `safe` foreign call and the
runtime runs the next chunk's spark while libcrypto holds the first. The
same fold called once per line costs 65.0 µs here. The difference is what
the whole file had been buying: the fold promotes each distinct key once
per *chunk* — a ~15 µs EVP key load against a ~34 µs verify, by the
Verifier's own accounting — and one line per call is one chunk per line, so
every line pays the load; there is no next chunk to overlap libcrypto with;
the batched hash call carries one line; and the framing, chunking and spark
machinery run once per line rather than once per chunk. A Hub that kept
promoted keys across calls would recover the load, the largest of these.
The Verifier offers no such cache, deliberately — it is handed nothing — so
that is a Hub's optimisation to make, and it is noted here for whoever
builds one. The whitepaper's 24,000 a second was the whole-file figure read
as a per-line one; the per-line figure is 15,400 for the Hub thread alone
and 11,100 with one signer in series.

### Twelve Producers lower the rate, because every losing submission is a request

Under the lock model the contention note found twelve Producers cost
throughput modestly (25.3–25.4k against 43.5–45.2k at one), because a stale
submission was refused from a read of the head on the Producer's own thread
and never reached the lock. Behind a thread there is no such shortcut: a
stale submission is still a request, the Hub thread still takes it from the
queue and answers it, and under saturating load eleven of every twelve are
stale. Head-only falls from 29.4k to 10.9k and checked from 11.1k to 7.5k.
The per-commit cost of the Hub thread is one check plus eleven refusals,
and the refusal — a handoff, a compare, a handoff — is about 5 µs here,
read from the difference between the one- and twelve-Producer rows. The
model does not count it and the `pred` column is accordingly wrong at
twelve; what the append rule predicts, twelve signatures per committed
Entry, is what both modes measure (11.77 and 11.98).

A real Hub's refusal costs a request's worth, not 5 µs, so this is the
mechanism and not the magnitude: Producers racing for a head do not only
waste their own signatures, they load the Hub with requests it refuses. The
contention note's remark that a Hub which queues Producers instead of
letting them race would remove the wasted signatures applies to the wasted
requests too.

### What the checks do not change

- **Across a 20 ms hop nothing is different.** Both modes commit 46–48 a
  second at one and at twelve Producers, the contention note's figure. A
  65 µs check inside a 20.9 ms window is a third of a percent of it.
- **Writes are never amplified.** Sixteen files, each with exactly as many
  lines as commits, each verified; the refused lines in the proof wrote
  nothing.
- **Signatures per committed Entry are the Producer count.** As the append
  rule says, in both modes, at both delays.
- **Starvation is the same.** `fair` is 0.06 at twelve Producers across 20 ms
  in both modes; the checks neither cause it nor cure it.

## Traps

- **A Hub that checks nothing posts a rate too.** Every file the harness
  writes verifies in either mode, because the Producers submit good lines.
  The refusal proof exists because without it the checked column would be
  indistinguishable from a mode flag that did nothing; it asserts the fault
  constructor, not just the refusal, so a tamper that happened to produce a
  different fault would fail the run rather than pass it by accident.
- **The processor's shutdown is an exception.** The Hub thread is killed
  when a cell ends, and its exit handler rethrows what killed it on the
  thread that opened it, so that a processor dying mid-run fails the run
  instead of leaving Producers waiting for replies. The first version
  rethrew the kill too, and every cell ended with `thread killed`. The
  handler now lets `ThreadKilled` through and rethrows everything else.
- **Before the first line there is no checkpoint.** `verifyFrom` resumes
  after a line that exists; a Hub at genesis has none, and `checkpointFrom`
  of ordinal minus one would wrap. The first submission is judged with
  `verify` as a file's opening bytes, which is also the only place the byte
  order mark rule can apply, and every later one with `verifyFrom`.
- **The stale-line proof must lie about the head.** A line signed against
  the genesis head and stating the genesis head is refused by the
  precondition, which proves nothing about the fold. It is submitted stating
  the *current* head, so the precondition passes and the fold's chain check
  is what refuses it.
- **Battery changes the ratio, not only the numbers.** A one-second smoke
  run on battery gave 7,323 checked against 20,656 head-only (2.8×) where
  mains gives 11,100 against 29,400 (2.65×); the checked append went from
  99 µs to 65. Both figures here are mains.

## What this changes upstream

- The whitepaper's one-thread Hub rate should be the measured one. Its
  current figure, 24,000 lines a second, is the Verifier's whole-file fold
  divided out per line. Measured with the three checks in the append path:
  the Hub thread's own cost is 65 µs a line (15,400 a second), and the
  committed rate with one Producer feeding it is 11,018–11,146 a second,
  against 29,135–29,729 for the same Hub comparing the head only. The
  fleet arithmetic that used the per-line check cost should use 65 µs.
- Nothing in the libraries. The Verifier's per-call key promotion is a
  cost a Hub can avoid by caching across calls, and that cache belongs in
  the Hub.
- The two earlier notes stand: their Hub had no thread in front of it and
  said so, and the head-only row here is the same rule with the hop added.

## Bibliography entry

```bibtex
@misc{eventchain2026hubappend,
  author = {{EventChain}},
  title = {Hub append rate: what checking each line before appending it costs},
  year = {2026},
  month = oct,
  howpublished = {Reproducible reference-implementation benchmark},
  note = {Measured 14 October 2026; Apple M4 Max on mains power with low power mode off, macOS 15.6.1, GHC 9.12.4, OpenSSL 3.6.3; reference producer against a compare-and-append Hub behind one thread, run two ways from one invocation: comparing the head only, and running the reference verifier's well-formedness, predecessor-hash and signature checks on every line before appending it, with a stale, a forged and a malformed line shown refused before timing. 1 and 12 producers, in-flight delays of 0 and 20 ms, saturating load, batch size 1, 8 cells, two runs of four seconds each, all 16 output files verified. One thread, one producer, nothing in flight: 11,018--11,146 committed entries per second with all three checks, 29,135--29,729 head-only, from the same run. Harness and tables in docs/research/2026-10-hub-append-rate.md}
}
```
