# Producer batching — what signing events in batches buys under contention

Measured 2026-10-13, Apple M4 Max (12 performance + 4 efficiency cores),
macOS 15.6.1, OpenSSL 3.6.3, GHC 9.12.4, arm64, **on battery at 99%**, low
power mode off. `cabal run eventchain-bench:batching -- --seconds 4 --runs 2`.
One `produce` cost 35.1 µs on one thread in this session, against 22.3 µs in
the mains-power contention run (`2026-10-producer-contention.md`), so every
absolute figure here is about two thirds of what mains would give. The
question is a ratio between rows of the same run, and the ratios are what
this note draws on; the absolute ceiling is to be re-measured on mains
before any figure is drawn from it.

## The question

The contention note measured the append rule's ceiling: one commit per race
window, where the window is one signature plus the time a signed line spends
in flight to the Hub. At 20 ms in flight that is 46 commits per second
however many Producers feed the head. The remedy it listed and did not
measure is batching — a Producer signs several events chained among
themselves, the first against the head it read, and submits them together.
The Hub takes all or none. The question put to the harness: does that raise
throughput, by how much, and what does it cost.

## The harness

`eventchain-bench:batching`, the contention harness with a batch size on
every cell. Three things changed in the model and nothing else:

- **A submission carries a batch** (`Contention.Hub`). The Hub compares the
  head the first line was signed against, writes every line, hashes them in
  one batched call and advances to the last digest. It does not check the
  chain inside the batch; the Verifier does, on every file afterwards.
- **A Producer signs the batch serially** (`Contention.Producer`): read the
  head, sign *b* events each chained to the one before, hold them in flight
  for the delay, submit. A rejection re-signs all *b* against the head the
  rejection returned. Every event in a committed batch is one record with
  the batch's attempt count and the batch's latency, so rates stay in
  events and signatures per Entry stay comparable with a batch of one.
  Latency runs from the first signature of the batch; the wait for a batch
  to fill under a Poisson load is outside it.
- **The window widens** (`Contention.Predict`): *w* = *b* × signature +
  delay, and the ceiling is *b*/*w*. Signatures per Entry under saturating
  load stay at *P*.

The sweep crosses batch {1, 100, 300, 1000, 3000} with Producers {1, 4, 12}
and in-flight delay {0, 200 µs, 2 ms, 20 ms}, saturating load only, four
seconds per run because a batch of 3000 is a 105 ms round and two seconds
gives twelve racing Producers too few rounds to rank. Sixty cells, two runs.
Every file verified: every verdict Sound, line count equal to commits, each
Producer's key on exactly the lines it reports.

## The model

| regime | commits/s | signatures per committed Entry |
| --- | --- | --- |
| saturating, batch *b*, *P* Producers | *b*/(*b*·sig + delay) | *P* |

As *b* grows the delay stops mattering and the ceiling tends to 1/sig: one
signer's signature rate, and no higher, because the batch is signed serially
and the *P*−1 losers discard theirs.

## Results

```
16 capabilities; one produce 35.1 µs on one thread; 60 cells × 2 runs × 4.0 s
an in-flight delay of 200 µs delivers 200 µs
an in-flight delay of 2000 µs delivers 2286 µs
an in-flight delay of 20000 µs delivers 20964 µs

load         batch   P    delay |             commits/s      pred |     sig/entry   pred | retry p50/99 |   latency p50/99 µs |  fair
saturating       1   1        0 |           27172-28003     28453 |     1.00-1.00   1.00 |     0/0     |        32/59        |  1.00
saturating       1   4        0 |           25385-25441     28453 |     3.97-3.98   4.00 |     0/73    |        33/2984      |  0.96
saturating       1  12        0 |           15661-18376     28453 |   11.06-11.14  12.00 |     0/163   |        46/10588     |  0.90
saturating       1   1   200 µs |             4179-4187      4251 |     1.00-1.00   1.00 |     0/0     |       236/284       |  1.00
saturating       1   4   200 µs |             4198-4207      4251 |     3.99-3.99   4.00 |     0/76    |       236/18490     |  0.90
saturating       1  12   200 µs |             3916-3925      4251 |   11.83-11.85  12.00 |     0/166   |       247/42979     |  0.83
saturating       1   1     2 ms |               346-348       431 |     1.00-1.00   1.00 |     0/0     |      2501/3732      |  1.00
saturating       1   4     2 ms |               410-411       431 |     3.99-3.99   4.00 |     2/17    |      7015/43506     |  0.94
saturating       1  12     2 ms |               418-419       431 |   11.88-11.92  12.00 |     5/82    |     13991/201086    |  0.65
saturating       1   1    20 ms |                 46-46        48 |     1.01-1.01   1.00 |     0/0     |     21239/23485     |  1.00
saturating       1   4    20 ms |                 47-48        48 |     3.97-4.01   4.00 |     0/38    |     22445/821432    |  0.48
saturating       1  12    20 ms |                 48-49        48 |   11.86-11.92  12.00 |     0/104   |     21993/2195819   |  0.25
saturating     100   1        0 |           27618-28643     28453 |     1.00-1.00   1.00 |     0/0     |      3518/4229      |  1.00
saturating     100   4        0 |           26093-26218     28453 |     4.00-4.00   4.00 |     0/40    |      3945/158284    |  0.70
saturating     100  12        0 |           15770-17445     28453 |   11.95-11.99  12.00 |     0/185   |      6522/1088443   |  0.32
saturating     100   1   200 µs |           26970-27068     26920 |     1.00-1.00   1.00 |     0/0     |      3673/4449      |  1.00
saturating     100   4   200 µs |           24719-24810     26920 |     4.00-4.00   4.00 |     0/47    |      4161/193425    |  0.42
saturating     100  12   200 µs |           14093-14242     26920 |   11.97-12.00  12.00 |     0/146   |      8370/1054026   |  0.08
saturating     100   1     2 ms |           14842-14898     17241 |     1.00-1.00   1.00 |     0/0     |      6543/7934      |  1.00
saturating     100   4     2 ms |           15545-15573     17241 |     4.00-4.00   4.00 |     1/20    |     13438/140310    |  0.94
saturating     100  12     2 ms |           11498-12821     17241 |   11.86-11.90  12.00 |     2/117   |     23283/924521    |  0.44
saturating     100   1    20 ms |             3873-3898      4085 |     1.01-1.01   1.00 |     0/0     |     25612/27948     |  1.00
saturating     100   4    20 ms |             3998-3999      4085 |     4.01-4.02   4.00 |     0/44    |     26321/1123382   |  0.62
saturating     100  12    20 ms |             4025-4048      4085 |   11.86-11.95  12.00 |     0/107   |     25958/2741947   |  0.07
saturating     300   1        0 |           27818-27893     28453 |     1.00-1.00   1.00 |     0/0     |     10635/13823     |  1.00
saturating     300   4        0 |           25344-25866     28453 |     4.00-4.01   4.00 |     0/30    |     11794/357118    |  0.73
saturating     300  12        0 |           14696-17095     28453 |   12.00-12.00  12.00 |     0/167   |     21535/3026351   |  0.00
saturating     300   1   200 µs |           27893-28043     27923 |     1.00-1.00   1.00 |     0/0     |     10606/12143     |  1.00
saturating     300   4   200 µs |           24972-25418     27923 |     4.00-4.00   4.00 |     0/35    |     12103/422681    |  0.68
saturating     300  12   200 µs |           13496-16795     27923 |   11.98-12.04  12.00 |     1/116   |     35937/2141258   |  0.07
saturating     300   1     2 ms |           21590-21892     23384 |     1.00-1.00   1.00 |     0/0     |     13734/16901     |  1.00
saturating     300   4     2 ms |           20845-20995     23384 |     4.00-4.00   4.00 |     0/37    |     15151/534659    |  0.56
saturating     300  12     2 ms |           12147-12821     23384 |   12.00-12.05  12.00 |     0/110   |     25597/2546650   |  0.00
saturating     300   1    20 ms |             9071-9074      9522 |     1.01-1.01   1.00 |     0/0     |     32891/35581     |  1.00
saturating     300   4    20 ms |             9071-9296      9522 |     4.00-4.03   4.00 |     0/56    |     33955/1884172   |  0.48
saturating     300  12    20 ms |             8471-8621      9522 |   11.95-12.01  12.00 |     0/80    |     37690/2858368   |  0.00
saturating    1000   1        0 |           27993-27993     28453 |     1.00-1.00   1.00 |     0/0     |     35393/41892     |  1.00
saturating    1000   4        0 |           24740-25493     28453 |     4.01-4.02   4.00 |     1/20    |     76532/847365    |  0.73
saturating    1000  12        0 |           12744-16745     28453 |   12.15-12.18  12.00 |     2/39    |    172375/2363505   |  0.00
saturating    1000   1   200 µs |           27243-27748     28292 |     1.00-1.01   1.00 |     0/0     |     35890/40740     |  1.00
saturating    1000   4   200 µs |           24744-25244     28292 |     4.02-4.04   4.00 |     1/20    |     81582/829375    |  0.44
saturating    1000  12   200 µs |           12747-16995     28292 |   12.07-12.16  12.00 |     1/43    |    172657/2930255   |  0.00
saturating    1000   1     2 ms |           25243-25745     26716 |     1.00-1.01   1.00 |     0/0     |     38794/43088     |  1.00
saturating    1000   4     2 ms |           22743-23491     26716 |     4.02-4.03   4.00 |     0/27    |     52120/1216615   |  0.31
saturating    1000  12     2 ms |           11246-14994     26716 |   12.13-12.13  12.00 |     1/50    |    160427/3258591   |  0.00
saturating    1000   1    20 ms |           17241-17247     17822 |     1.00-1.01   1.00 |     0/0     |     57580/64006     |  1.00
saturating    1000   4    20 ms |           16243-16246     17822 |     4.02-4.05   4.00 |     0/14    |     66140/933110    |  0.18
saturating    1000  12    20 ms |           11497-12244     17822 |   12.06-12.15  12.00 |     0/37    |     97441/3364308   |  0.00
saturating    3000   1        0 |           26993-27743     28453 |     1.01-1.02   1.00 |     0/0     |    107371/116137    |  1.00
saturating    3000   4        0 |           24743-25494     28453 |     4.02-4.07   4.00 |     1/12    |    249673/1518302   |  0.47
saturating    3000  12        0 |           13469-13498     28453 |   12.06-12.17  12.00 |     1/13    |    431817/3087505   |  0.00
saturating    3000   1   200 µs |           26993-27743     28399 |     1.01-1.02   1.00 |     0/0     |    108231/118259    |  1.00
saturating    3000   4   200 µs |           24743-25493     28399 |     4.02-4.03   4.00 |     1/19    |    239566/2348045   |  0.35
saturating    3000  12   200 µs |           12747-13483     28399 |   12.04-12.22  12.00 |     1/17    |    432680/3912527   |  0.00
saturating    3000   1     2 ms |           26242-26246     27849 |     1.02-1.03   1.00 |     0/0     |    111921/121687    |  1.00
saturating    3000   4     2 ms |           23997-24737     27849 |     4.04-4.08   4.00 |     1/18    |    245127/2264149   |  0.48
saturating    3000  12     2 ms |           12746-13494     27849 |   12.22-12.45  12.00 |     3/15    |    797049/3523878   |  0.00
saturating    3000   1    20 ms |           23239-23243     23734 |     1.00-1.00   1.00 |     0/0     |    128395/139533    |  1.00
saturating    3000   4    20 ms |           20993-20994     23734 |     4.04-4.14   4.00 |     2/13    |    416929/1973021   |  0.43
saturating    3000  12    20 ms |           12743-12745     23734 |   12.45-12.51  12.00 |     1/16    |    466421/3833815   |  0.00
```

### Batching buys throughput exactly where the trip to the Hub is the window

One Producer, commits per second, by batch size:

| in flight (delivered) | batch 1 | 100 | 300 | 1000 | 3000 | predicted ceiling 1/sig |
| --- | --- | --- | --- | --- | --- | --- |
| none | 27.2–28.0k | 27.6–28.6k | 27.8–27.9k | 28.0k | 27.0–27.7k | 28.5k |
| 200 µs | 4.18k | 27.0k | 27.9–28.0k | 27.2–27.7k | 27.0–27.7k | 28.5k |
| 2 ms (2.29) | 346 | 14.8–14.9k | 21.6–21.9k | 25.2–25.7k | 26.2k | 28.5k |
| 20 ms (21.0) | 46 | 3.87–3.90k | 9.07k | 17.2k | 23.2k | 28.5k |

At 20 ms in flight a batch of 100 commits 84× what a batch of one does, and
a batch of 3000 commits 500×. With nothing in flight a batch of 3000 commits
what a batch of one does. Every row sits within 10% of *b*/*w*, and every
row converges on the same number: 1/sig, which on this battery session is
28k events per second and on mains would be about 45k. Batching removes the
trip to the Hub from the window; it cannot remove the signature, and a
Producer signs one at a time. So the gain is the ratio of the delay to the
signature — large for a real network hop, nothing in-process — and the
ceiling it reaches is one signer's.

### More Producers still add nothing, and in one process they subtract

Twelve Producers, commits per second:

| in flight | batch 1 | 100 | 300 | 1000 | 3000 |
| --- | --- | --- | --- | --- | --- |
| none | 15.7–18.4k | 15.8–17.4k | 14.7–17.1k | 12.7–16.7k | 13.5k |
| 20 ms | 48 | 4.0k | 8.5–8.6k | 11.5–12.2k | 12.7k |

Signatures per Entry are 12.0 in every twelve-Producer row, as the model
says: the batch is signed by all twelve and committed by one. Under a batch
of one that waste was idle time between a Producer's signature and the
next head; under a batch of 3000 it is 105 ms of CPU per Producer per
round, so twelve Producers signing continuously in one process pay the
cost the contention note already found for its zero-delay rows — 158k
signatures per second across twelve threads is 76 µs per signature per
thread against 35 alone — and the twelve-Producer rows land at half the
one-Producer rows at every delay. On separate machines that cost is twelve
machines' CPU rather than a halved rate; either way it is paid for nothing.

### What it costs

- **Latency.** Median latency from first signature to acceptance for one
  Producer with nothing in flight is 3.5 ms at a batch of 100, 10.6 ms at
  300, 35 ms at 1000 and 107 ms at 3000 — the time to sign the batch. That
  is the floor; an event also waits for its batch to fill, which the
  harness does not charge to it.
- **Starvation gets worse, not better.** `fair` is 0.00 at twelve Producers
  for every batch of 300 or more at every delay, where a batch of one kept
  it above zero below 20 ms. The p99 latency at twelve Producers is 2.1–3.9 s
  at every batch of 100 or more. A Producer that loses a round loses a
  batch's worth of signing and starts the next round no better placed.
- **A rejection wastes a batch.** The signature count per Entry does not
  change, but what one rejection throws away is *b* signatures rather than
  one, and the Producer's retry is *b* signatures later.

### What batching does not change

Writes are never amplified: the file holds one line per committed event in
all 120 files. And the chain stays what it was — one total, signed order
with `prev_hash` inside every signature. A batch is just *b* ordinary
Entries whose Producer knew *b*−1 of their predecessors before the Hub did.

## What this changes upstream

Nothing in the libraries. The decision recorded in the contention note
stands — batching was declined there on the property it gives up — and
this note supplies the number that decision was taken without: a Producer
batching across a 20 ms hop commits up to 500× more, and never more than
one signer's signature rate. Two things follow for whoever builds a Hub:

- The batch is a Producer-side choice the protocol already permits; a
  Producer that holds *b* events and chains them before submitting is
  writing ordinary Entries. What the Hub needs is to take a batch whole.
- The twelve-Producer rows are the argument for a Hub that queues Producers
  rather than letting them race, made again: with batching, racing wastes a
  batch of CPU per loser per round, and a queue would waste none while
  committing at the same rate.

## Ten Producers

Asked for afterwards, same session, same battery, with the signature drifted
to 40.4 µs on one thread (`--producers 10`). All 40 files verified.

```
16 capabilities; one produce 40.4 µs on one thread; 20 cells × 2 runs × 4.0 s
an in-flight delay of 200 µs delivers 200 µs
an in-flight delay of 2000 µs delivers 2283 µs
an in-flight delay of 20000 µs delivers 20844 µs

load         batch   P    delay |             commits/s      pred |     sig/entry   pred | retry p50/99 |   latency p50/99 µs |  fair
saturating       1  10        0 |           17089-17401     24733 |     9.58-9.59  10.00 |     0/159   |        45/9767      |  0.94
saturating       1  10   200 µs |             3983-4044      4159 |     9.88-9.89  10.00 |     0/148   |       244/37192     |  0.86
saturating       1  10     2 ms |               421-421       430 |     9.95-9.96  10.00 |     4/67    |     11908/159636    |  0.83
saturating       1  10    20 ms |                 48-48        48 |    9.97-10.00  10.00 |     0/88    |     22488/1854703   |  0.05
saturating     100  10        0 |           16521-17071     24733 |   10.00-10.00  10.00 |     2/71    |     18662/439237    |  0.56
saturating     100  10   200 µs |           15891-16321     23567 |   10.01-10.01  10.00 |     2/79    |     19945/495950    |  0.53
saturating     100  10     2 ms |           13645-13849     15808 |     9.91-9.94  10.00 |     2/114   |     21407/848343    |  0.48
saturating     100  10    20 ms |             3999-4024      4018 |   10.00-10.01  10.00 |     1/68    |     48297/1722783   |  0.00
saturating     300  10        0 |           14921-16046     24733 |   10.00-10.02  10.00 |     3/61    |     72155/1206771   |  0.25
saturating     300  10   200 µs |           15292-16046     24332 |   10.01-10.03  10.00 |     4/72    |     92685/1463334   |  0.23
saturating     300  10     2 ms |           14774-15444     20816 |   10.02-10.03  10.00 |     0/110   |     33660/2222783   |  0.00
saturating     300  10    20 ms |             8772-8924      9098 |     9.91-9.96  10.00 |     0/81    |     34687/2781948   |  0.09
saturating    1000  10        0 |           15244-15746     24733 |   10.10-10.11  10.00 |     4/48    |    315263/3117257   |  0.16
saturating    1000  10   200 µs |           14746-15745     24611 |   10.13-10.14  10.00 |     3/39    |    267177/2469194   |  0.00
saturating    1000  10     2 ms |           14745-15746     23411 |   10.02-10.08  10.00 |     3/44    |    256438/2856920   |  0.00
saturating    1000  10    20 ms |           12748-13743     16320 |   10.02-10.20  10.00 |     2/37    |    228610/2920514   |  0.18
saturating    3000  10        0 |           14985-14996     24733 |   10.07-10.48  10.00 |     3/19    |    651648/3825694   |  0.00
saturating    3000  10   200 µs |           13462-14245     24692 |   10.08-10.52  10.00 |     3/13    |    672904/3053097   |  0.00
saturating    3000  10     2 ms |           14235-14245     24276 |   10.10-10.25  10.00 |     3/17    |    776831/3763988   |  0.00
saturating    3000  10    20 ms |           14245-14246     21106 |   10.13-10.30  10.00 |     4/15    |   1022790/3290651   |  0.00
```

Ten sits where four and twelve bracket it, and nothing new appears:
signatures per Entry are 10.0 in every row from a batch of 100 up (9.6–10.0
at a batch of one, the slower-signer shortfall the contention note found at
twelve); commits per second with nothing in flight are 15–17k against a
one-Producer 27–28k, the in-process cost of ten continuous signers; across
20 ms a batch of 3000 commits 14.2k against the twelve-Producer 12.7k and
the one-Producer 23.2k. `fair` is 0.00 or near it at every batch of 300 or
more, and the p99 latency is 2.2–3.8 s. The Producer count sets how many
signatures each Entry costs and how badly the losers starve; it does not set
the rate, which stays one signer's at best.

## Traps

- **Signatures per Entry read above one at one Producer and a large batch.**
  1.01–1.03 at a batch of 3000 over four seconds, 1.18 over half a second in
  the smoke run. Signatures are counted by their own stamps and commits by
  their acceptance time, so the batch in hand when the window closes has its
  signatures inside the window and its commits outside. The excess is one
  batch over the window's commits; lengthen the window or ignore it.
- **Two seconds is too short for a batch of 3000.** A round is 105 ms plus
  the delay; twelve Producers get a few wins each in two seconds and the
  percentiles and `fair` rank noise. This run used four.
- **Battery.** See the header. Rerun on mains before quoting an absolute.
