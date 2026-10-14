# Producer contention — what many signers racing for one head cost

Measured 2026-10-13, Apple M4 Max (12 performance + 4 efficiency cores),
macOS 15.6.1, OpenSSL 3.6.3, GHC 9.12.4, arm64, **on mains power**.
`cabal run eventchain-bench:contention -- --seconds 2 --runs 2`. One
`produce` cost 22.3 µs on one thread in this session. An earlier run the
same day on battery with low power mode is kept at the end of this file: it
is where the harness's traps were found, and the comparison between the two
is the evidence for one finding below.

## The question

A reviewer put it this way: every Producer signs against the current head,
so when concurrent Producers target the same head all but one must retry and
sign again, and "one signature and one write per event" is the cost of a
successful append, not of a multi-Producer workflow.

The README's performance section measures the Verifier and makes no
Producer-side claim, and the quoted phrase appears nowhere in this
repository. The mechanism is nonetheless real for this design: `prev_hash`
is inside the signed message (`docs/protocol.md`, ADR-0002), so a Producer
must know the head before it signs, and `EventChain.Produce` says as much —
the chain is sequential by construction. What was missing was the number.
This note supplies it, measured against what the append rule predicts.

## The harness

`eventchain-bench:contention`, four modules under `bench/contention/`:

- **Hub model** (`Contention.Hub`). One lock owning the head and the file.
  A submission carries a signed line and the head it was signed against; if
  that is the Hub's head the line is written, the Hub hashes the bytes it
  wrote and advances; otherwise nothing is written and the reply carries the
  head to sign against now. Compare-and-swap append, which is the paper's
  "single-threaded event processor" with the only semantics that keep the
  chain intact. No fsync: durability policy is the Hub's business.
- **Producer loop** (`Contention.Producer`). One thread per Producer, each
  with its own key. Read head, build the ChainedEvent, `produce`, hold the
  line in flight for the injected delay (±10% jitter), submit; on rejection
  sign the same event again against the head the rejection returned. Each
  committed event records its signature count and its latency from first
  signature to acceptance; every signature is also stamped on its own, so a
  Producer that never wins still has its signatures counted.
- **Cell** (`Contention.Cell`). A Producer count, a load and a delay, run
  for a fixed wall time, rates taken over the window before the stop flag.
  Every file the Hub wrote is then verified by `eventchain-verify`: every
  verdict Sound, line count equal to commits, and each Producer's key on
  exactly the lines that Producer reports. All 160 files in this run passed.
- **Prediction** (`Contention.Predict`). The model below, evaluated from the
  signature cost and the delay as calibrated at startup.

The sweep crosses Producers {1, 2, 4, 8, 12} — one per performance core at
most, so that Producers never share a capability — with in-flight delay
{0, 200 µs, 2 ms, 20 ms} and load {saturating, Poisson 300, 3,000, 30,000
events/s aggregate}. Eighty cells, two runs of two seconds each.

## The model

Every head advance invalidates every signature in flight. With a window
*w* = signature cost + in-flight delay:

| regime | commits/s | signatures per committed Entry |
| --- | --- | --- |
| saturating, *P* Producers | 1/*w*, independent of *P* | *P* |
| Poisson at aggregate λ below 1/*w* | λ | e^(λ′*w*), λ′ = λ(*P*−1)/*P* |
| Poisson at λ ≥ 1/*w* | saturating | saturating |

The Poisson row counts only the collisions of first attempts; a retry is
itself an arrival, so the formula reads low as λ′*w* approaches one.

## Results

`P` is Producers; `pred` is the model; ranges are two runs; percentiles are
pooled across runs; `fair` is the smallest per-Producer commit count over the
mean, worst run.

```
16 capabilities; one produce 22.3 µs on one thread; 80 cells × 2 runs × 2.0 s
an in-flight delay of 200 µs delivers 200 µs
an in-flight delay of 2000 µs delivers 2281 µs
an in-flight delay of 20000 µs delivers 20940 µs

load           P    delay |             commits/s      pred |     sig/entry   pred | retry p50/99 |   latency p50/99 µs |  fair
saturating     1        0 |           43530-45231     44924 |     1.00-1.00   1.00 |     0/0     |        20/38        |  1.00
saturating     2        0 |           42437-42795     44924 |     1.99-1.99   2.00 |     0/29    |        21/755       |  0.93
saturating     4        0 |           38443-38547     44924 |     3.96-3.97   4.00 |     0/80    |        22/2120      |  0.95
saturating     8        0 |           30435-30776     44924 |     7.75-7.78   8.00 |     0/122   |        25/4190      |  0.88
saturating    12        0 |           25328-25433     44924 |   10.88-10.94  12.00 |     0/140   |        29/6180      |  0.90
saturating     1   200 µs |             4440-4445      4499 |     1.00-1.00   1.00 |     0/0     |       223/257       |  1.00
saturating     2   200 µs |             4425-4427      4499 |     1.99-1.99   2.00 |     0/33    |       224/7862      |  0.93
saturating     4   200 µs |             4412-4415      4499 |     3.98-3.98   4.00 |     0/72    |       226/16765     |  0.84
saturating     8   200 µs |             4360-4373      4499 |     7.93-7.93   8.00 |     0/127   |       227/29682     |  0.87
saturating    12   200 µs |             4279-4284      4499 |   11.75-11.80  12.00 |     0/158   |       229/37782     |  0.86
saturating     1     2 ms |               345-346       434 |     1.00-1.00   1.00 |     0/0     |      2571/3544      |  1.00
saturating     2     2 ms |               385-390       434 |     2.00-2.00   2.00 |     0/7     |      3486/20794     |  0.99
saturating     4     2 ms |               412-413       434 |     4.00-4.00   4.00 |     2/18    |      6841/45408     |  0.87
saturating     8     2 ms |               419-422       434 |     7.97-7.99   8.00 |     4/48    |     11532/114657    |  0.76
saturating    12     2 ms |               422-424       434 |   11.92-11.98  12.00 |     5/76    |     14432/180718    |  0.61
saturating     1    20 ms |                 46-46        48 |     1.01-1.01   1.00 |     0/0     |     21378/23248     |  1.00
saturating     2    20 ms |                 47-47        48 |     2.00-2.02   2.00 |     0/16    |     21415/378054    |  0.74
saturating     4    20 ms |                 47-47        48 |     4.02-4.03   4.00 |     0/61    |     21520/1320087   |  0.34
saturating     8    20 ms |                 47-48        48 |     8.03-8.07   8.00 |     0/75    |     22642/1579134   |  0.00
saturating    12    20 ms |                 48-48        48 |   11.94-11.96  12.00 |     1/62    |     39565/1311327   |  0.00
poisson 300    1        0 |               308-311       300 |     1.00-1.00   1.00 |     0/0     |        61/869       |  1.00
poisson 300    2        0 |               296-306       300 |     1.11-1.12   1.00 |     0/1     |        73/958       |  0.96
poisson 300    4        0 |               298-308       300 |     1.19-1.21   1.01 |     0/2     |        79/659       |  0.84
poisson 300    8        0 |               295-321       300 |     1.21-1.25   1.01 |     0/2     |        82/922       |  0.77
poisson 300   12        0 |               295-305       300 |     1.23-1.23   1.01 |     0/2     |        76/708       |  0.71
poisson 300    1   200 µs |               299-311       300 |     1.00-1.00   1.00 |     0/0     |       265/914       |  1.00
poisson 300    2   200 µs |               303-311       300 |     1.12-1.13   1.03 |     0/2     |       268/1544      |  0.98
poisson 300    4   200 µs |               314-328       300 |     1.18-1.20   1.05 |     0/2     |       271/954       |  0.92
poisson 300    8   200 µs |               285-307       300 |     1.21-1.23   1.06 |     0/2     |       270/1140      |  0.81
poisson 300   12   200 µs |               302-307       300 |     1.21-1.23   1.06 |     0/2     |       274/1209      |  0.70
poisson 300    1     2 ms |               297-302       300 |     1.00-1.00   1.00 |     0/0     |      2642/4134      |  1.00
poisson 300    2     2 ms |               296-309       300 |     1.58-1.65   1.41 |     0/5     |      3432/15630     |  0.98
poisson 300    4     2 ms |               296-304       300 |     2.12-2.27   1.68 |     1/8     |      4546/23057     |  0.87
poisson 300    8     2 ms |               304-310       300 |     2.69-2.73   1.83 |     1/10    |      4677/26227     |  0.79
poisson 300   12     2 ms |               310-311       300 |     2.90-2.92   1.88 |     1/10    |      5673/27292     |  0.79
poisson 300    1    20 ms |                 46-46        48 |     1.01-1.01   1.00 |     0/0     |     21208/23431     |  1.00
poisson 300    2    20 ms |                 46-46        48 |     2.02-2.02   2.00 |     0/30    |     22041/650759    |  0.86
poisson 300    4    20 ms |                 46-47        48 |     4.02-4.03   4.00 |     0/50    |     22371/1074469   |  0.04
poisson 300    8    20 ms |                 47-47        48 |     7.99-8.00   8.00 |     1/57    |     40132/1213142   |  0.00
poisson 300   12    20 ms |                 48-48        48 |   11.76-11.82  12.00 |     0/66    |     22689/1403067   |  0.00
poisson 3000   1        0 |             2995-3050      3000 |     1.00-1.00   1.00 |     0/0     |        33/106       |  1.00
poisson 3000   2        0 |             2966-3023      3000 |     1.41-1.44   1.03 |     0/4     |        38/345       |  0.99
poisson 3000   4        0 |             3051-3052      3000 |     1.86-1.87   1.05 |     0/6     |        53/462       |  0.95
poisson 3000   8        0 |             2979-3013      3000 |     2.23-2.24   1.06 |     1/6     |        71/767       |  0.92
poisson 3000  12        0 |             2990-3004      3000 |     2.33-2.35   1.06 |     1/6     |        71/788       |  0.90
poisson 3000   1   200 µs |             3046-3062      3000 |     1.00-1.00   1.00 |     0/0     |       226/315       |  1.00
poisson 3000   2   200 µs |             3000-3021      3000 |     1.40-1.41   1.40 |     0/6     |       228/1647      |  0.99
poisson 3000   4   200 µs |             2967-3044      3000 |     1.95-2.01   1.65 |     0/9     |       236/2273      |  0.98
poisson 3000   8   200 µs |             2993-2994      3000 |     2.48-2.58   1.79 |     1/11    |       439/2846      |  0.92
poisson 3000  12   200 µs |             2947-3013      3000 |     2.69-2.74   1.84 |     1/10    |       455/2690      |  0.89
poisson 3000   1     2 ms |               349-350       434 |     1.00-1.00   1.00 |     0/0     |      2392/3573      |  1.00
poisson 3000   2     2 ms |               387-390       434 |     2.00-2.00   2.00 |     0/7     |      3482/19993     |  0.95
poisson 3000   4     2 ms |               415-417       434 |     3.98-3.99   4.00 |     2/16    |      6981/42892     |  0.87
poisson 3000   8     2 ms |               425-426       434 |     7.95-7.96   8.00 |     3/52    |     10513/124848    |  0.57
poisson 3000  12     2 ms |               423-426       434 |   11.89-11.89  12.00 |     5/77    |     13907/183948    |  0.70
poisson 3000   1    20 ms |                 46-46        48 |     1.01-1.01   1.00 |     0/0     |     21181/23334     |  1.00
poisson 3000   2    20 ms |                 47-47        48 |     2.01-2.01   2.00 |     0/18    |     21905/421218    |  0.83
poisson 3000   4    20 ms |                 47-47        48 |     4.02-4.02   4.00 |     0/42    |     22120/910629    |  0.13
poisson 3000   8    20 ms |                 47-48        48 |     8.04-8.07   8.00 |     1/87    |     41596/1837632   |  0.00
poisson 3000  12    20 ms |                 48-49        48 |   11.80-11.96  12.00 |     0/77    |     21487/1625451   |  0.00
poisson 30000   1        0 |           29888-29955     30000 |     1.00-1.00   1.00 |     0/0     |        21/47        |  1.00
poisson 30000   2        0 |           29873-30019     30000 |     1.52-1.53   1.40 |     0/17    |        21/468       |  1.00
poisson 30000   4        0 |           29963-30105     30000 |     2.50-2.54   1.65 |     0/27    |        22/801       |  0.98
poisson 30000   8        0 |           29944-29958     30000 |     4.35-5.00   1.79 |     0/48    |        24/1574      |  0.96
poisson 30000  12        0 |           25551-25552     30000 |   10.81-10.83   1.84 |     0/134   |        29/5875      |  0.91
poisson 30000   1   200 µs |             4407-4408      4499 |     1.00-1.00   1.00 |     0/0     |       224/271       |  1.00
poisson 30000   2   200 µs |             4404-4407      4499 |     1.99-2.00   2.00 |     0/28    |       225/6614      |  0.98
poisson 30000   4   200 µs |             4393-4406      4499 |     3.98-3.98   4.00 |     0/74    |       226/17298     |  0.82
poisson 30000   8   200 µs |             4346-4349      4499 |     7.94-7.94   8.00 |     0/131   |       227/30765     |  0.82
poisson 30000  12   200 µs |             4234-4256      4499 |   11.47-11.77  12.00 |     0/143   |       232/35355     |  0.79
poisson 30000   1     2 ms |               350-352       434 |     1.00-1.00   1.00 |     0/0     |      2382/3536      |  1.00
poisson 30000   2     2 ms |               385-387       434 |     1.99-2.00   2.00 |     0/8     |      3463/22960     |  0.84
poisson 30000   4     2 ms |               417-420       434 |     3.99-3.99   4.00 |     2/15    |      6996/38533     |  0.84
poisson 30000   8     2 ms |               419-426       434 |     7.96-7.97   8.00 |     3/51    |      9697/123030    |  0.77
poisson 30000  12     2 ms |               426-426       434 |   11.93-11.95  12.00 |     5/89    |     13807/208134    |  0.61
poisson 30000   1    20 ms |                 46-46        48 |     1.01-1.01   1.00 |     0/0     |     21175/23251     |  1.00
poisson 30000   2    20 ms |                 47-47        48 |     2.01-2.02   2.00 |     0/12    |     21521/273764    |  0.77
poisson 30000   4    20 ms |                 47-47        48 |     4.02-4.02   4.00 |     0/28    |     22333/628920    |  0.55
poisson 30000   8    20 ms |                 48-48        48 |     7.99-8.05   8.00 |     0/82    |     22320/1728273   |  0.00
poisson 30000  12    20 ms |                 48-48        48 |   12.03-12.08  12.00 |     1/78    |     40770/1659020   |  0.00
```

### Writes are never amplified

A rejected attempt writes nothing, so the file holds exactly one line per
committed event. The Verifier check confirms it for every cell: line count
equals commit count in all 160 files of this run, and in the 160 of the
battery run. The "one write per event" half of the quoted claim survives
contention intact. The signature half does not.

### Throughput never scales with Producers

Every row of the saturating block is flat in *P* at one commit per window:

| in flight (delivered) | 1 Producer | 12 Producers | predicted 1/*w* |
| --- | --- | --- | --- |
| none | 43.5–45.2k | 25.3–25.4k | 44.9k |
| 200 µs | 4,440 | 4,280 | 4,499 |
| 2 ms (2.28) | 345 | 423 | 434 |
| 20 ms (20.9) | 46 | 48 | 48 |

Adding a Producer adds signing capacity and no commit capacity, because the
head is one place. The one row that is not flat is the top one: twelve
Producers signing at once in this process commit 25k, not 45k, and their
signature rate — 25.3k × 10.9 ≈ 276k/s across twelve threads — says a
signature costs each of them ~43 µs against 22 alone. That is twelve
signers sharing one package's caches and clock, not the protocol, and it
vanishes the moment any delay is present: at 200 µs every Producer count
sits within 5% of the prediction. Outside this process the network sets the
window, and the signature is a rounding error in it.

### Signatures per committed Entry climb to the Producer count

With any in-flight delay the measured count is within 3% of *P* at every
*P*: 2.0, 4.0, 7.9–8.1, 11.8–12.0. That is the critique's mechanism exactly
— under contention a committed Entry costs one signature per Producer
racing for it. With no delay the count is 10.9 at twelve, the same shortfall
as the throughput row above and for the same reason: a slower signer
completes fewer attempts per round.

### Where "one signature per event" holds

| offered, aggregate | 2 Producers | 12 Producers | predicted at 12 |
| --- | --- | --- | --- |
| 300/s, no delay | 1.11–1.12 | 1.23 | 1.01 |
| 3,000/s, no delay | 1.41–1.44 | 2.33–2.35 | 1.06 |
| 30,000/s, no delay | 1.52–1.53 | 10.8 | 1.84 |
| 300/s, 2 ms | 1.58–1.65 | 2.90–2.92 | 1.88 |

The claim is roughly true at hundreds of events per second and false by
the thousands. It is never exactly true, and the model under-predicts the
cost everywhere, by a fifth of a signature at 300/s and by more than a
signature at 3,000/s. Two suspects, neither ruled out:

- **Retries are arrivals.** The model counts only first-attempt collisions.
  Each retry is a new attempt and a new chance to collide with the next
  event, so the cost compounds as λ′*w* approaches one. The 30,000/s row at
  twelve Producers is this in the open: offered below the one-Producer
  ceiling, it saturates the twelve-signer one and lands at 10.8.
- **The timer clusters arrivals.** Producers wait for their next Poisson
  arrival in `threadDelay`, and the runtime's timer coalesces wakeups, so
  arrivals due in the same tick start together. At 300/s with a 22 µs window
  the model predicts a collision in 0.7% of attempts; the measurement is
  11–23%. Retries cannot compound from 0.7% to that, so this suspect carries
  the zero-delay excess. Checking it means recording actual inter-arrival
  gaps, or spinning for arrivals as the in-flight delay already does below a
  millisecond.

### Compare-and-swap append does not share

`fair` falls as Producers and delay rise: 0.90 at twelve Producers with no
delay, 0.61 at 2 ms, 0.00 at 20 ms — one Producer committed nothing in a
two-second window, at eight Producers as well as twelve, at every offered
load. The p99 latency from first signature to acceptance tells the same
story: 6 ms at twelve Producers with no delay, 0.18 s at 2 ms, 1.3–1.7 s at
20 ms. The append rule has no fairness property; a Producer that loses a
round starts the next from the same place as everyone else and can keep
losing. Jitter of ±10% on the delay was added after a constant delay
phase-locked the Producers so that the same one won every round, and it did
not remove the starvation, only the determinism of who starves.

## The battery run

Same day, same machine, on battery with low power mode on. One `produce`
cost 62.9 µs on one thread, and the timer delivered 3.3 ms for 2 ms and
24.8 ms for 20 ms. The prediction in these rows caps a Poisson load at
e^(λ′*w*) rather than treating an offered rate above 1/*w* as saturating,
which the harness now does.

```
16 capabilities; one produce 62.9 µs on one thread; 80 cells × 2 runs × 2.0 s
an in-flight delay of 200 µs delivers 200 µs
an in-flight delay of 2000 µs delivers 3328 µs
an in-flight delay of 20000 µs delivers 24844 µs

load           P    delay |             commits/s      pred |     sig/entry   pred | retry p50/99 |   latency p50/99 µs |  fair
saturating     1        0 |           12608-13204     15886 |     1.00-1.00   1.00 |     0/0     |        50/447       |  1.00
saturating     2        0 |           13623-15568     15886 |     1.69-1.73   2.00 |     0/23    |        50/2150      |  0.95
saturating     4        0 |           12920-13385     15886 |     2.91-2.94   4.00 |     0/56    |        51/6422      |  0.94
saturating     8        0 |            9598-11972     15886 |     4.55-4.91   8.00 |     0/87    |        51/15300     |  0.79
saturating    12        0 |           11753-13188     15886 |     5.29-5.65  12.00 |     0/92    |        52/20298     |  0.77
saturating     1   200 µs |             2926-2963      3800 |     1.00-1.00   1.00 |     0/0     |       253/2817      |  1.00
saturating     2   200 µs |             3230-3291      3800 |     1.67-1.67   2.00 |     0/22    |       252/12390     |  0.96
saturating     4   200 µs |             3307-3316      3800 |     2.94-2.96   4.00 |     0/53    |       253/26653     |  0.87
saturating     8   200 µs |             3071-3110      3800 |     5.24-5.32   8.00 |     0/85    |       254/48694     |  0.76
saturating    12   200 µs |             2952-3003      3800 |     6.66-6.70  12.00 |     0/95    |       255/71657     |  0.78
saturating     1     2 ms |               249-271       295 |     1.00-1.00   1.00 |     0/0     |      3448/15438     |  1.00
saturating     2     2 ms |               287-313       295 |     1.98-1.99   2.00 |     0/12    |      3486/55750     |  0.74
saturating     4     2 ms |               312-338       295 |     3.78-3.91   4.00 |     1/19    |      5236/104130    |  0.68
saturating     8     2 ms |               340-343       295 |     7.42-7.63   8.00 |     2/51    |      7630/178426    |  0.72
saturating    12     2 ms |               296-297       295 |   11.22-11.24  12.00 |     3/82    |      9780/336319    |  0.55
saturating     1    20 ms |                 40-42        40 |     1.01-1.01   1.00 |     0/0     |     22354/38382     |  1.00
saturating     2    20 ms |                 42-42        40 |     2.02-2.02   2.00 |     0/10    |     23120/278395    |  0.26
saturating     4    20 ms |                 44-45        40 |     3.95-3.97   4.00 |     0/38    |     22672/925679    |  0.53
saturating     8    20 ms |                 45-46        40 |     7.91-8.02   8.00 |     0/55    |     31592/1237294   |  0.27
saturating    12    20 ms |                 44-46        40 |   11.84-12.07  12.00 |     1/72    |     40514/1617257   |  0.00
poisson 300    1        0 |               308-311       300 |     1.00-1.00   1.00 |     0/0     |        85/473       |  1.00
poisson 300    2        0 |               296-306       300 |     1.12-1.13   1.01 |     0/2     |        94/629       |  0.96
poisson 300    4        0 |               298-308       300 |     1.18-1.22   1.01 |     0/2     |        98/2986      |  0.84
poisson 300    8        0 |               295-320       300 |     1.19-1.20   1.02 |     0/2     |        98/3442      |  0.77
poisson 300   12        0 |               293-304       300 |     1.22-1.27   1.02 |     0/2     |       102/4238      |  0.71
poisson 300    1   200 µs |               299-311       300 |     1.00-1.00   1.00 |     0/0     |       283/918       |  1.00
poisson 300    2   200 µs |               309-313       300 |     1.13-1.13   1.04 |     0/2     |       291/1409      |  0.99
poisson 300    4   200 µs |               297-317       300 |     1.21-1.25   1.06 |     0/3     |       298/1610      |  0.93
poisson 300    8   200 µs |               296-306       300 |     1.26-1.29   1.07 |     0/3     |       299/6111      |  0.86
poisson 300   12   200 µs |               302-309       300 |     1.23-1.24   1.08 |     0/2     |       299/2456      |  0.64
poisson 300    1     2 ms |               275-290       295 |     1.00-1.00   1.00 |     0/0     |      3135/12316     |  1.00
poisson 300    2     2 ms |               269-278       295 |     1.88-1.98   1.66 |     0/7     |      3568/48078     |  0.92
poisson 300    4     2 ms |               267-273       295 |     3.27-3.33   2.14 |     1/18    |      5849/112274    |  0.91
poisson 300    8     2 ms |               285-287       295 |     5.18-5.69   2.44 |     2/30    |      8210/132151    |  0.74
poisson 300   12     2 ms |               283-293       295 |     5.38-6.22   2.54 |     2/37    |      7191/183817    |  0.63
poisson 300    1    20 ms |                 42-44        40 |     1.01-1.01   1.00 |     0/0     |     22171/32737     |  1.00
poisson 300    2    20 ms |                 43-43        40 |     2.00-2.01   2.00 |     0/12    |     22542/345425    |  0.70
poisson 300    4    20 ms |                 44-44        40 |     3.97-4.05   4.00 |     0/43    |     25702/1041562   |  0.18
poisson 300    8    20 ms |                 44-45        40 |     7.86-7.87   8.00 |     1/50    |     39503/1164305   |  0.18
poisson 300   12    20 ms |                 43-45        40 |   11.46-11.94  12.00 |     1/48    |     49662/1158988   |  0.00
poisson 3000   1        0 |             2978-3050      3000 |     1.00-1.00   1.00 |     0/0     |        54/525       |  1.00
poisson 3000   2        0 |             2967-3015      3000 |     1.20-1.21   1.10 |     0/4     |        55/956       |  0.99
poisson 3000   4        0 |             3051-3052      3000 |     1.53-1.62   1.15 |     0/7     |        58/3208      |  0.95
poisson 3000   8        0 |             2980-3013      3000 |     1.88-1.92   1.18 |     0/8     |        81/4028      |  0.92
poisson 3000  12        0 |             2990-3005      3000 |     2.00-2.07   1.19 |     0/8     |        87/6505      |  0.90
poisson 3000   1   200 µs |             2802-2837      3000 |     1.00-1.00   1.00 |     0/0     |       254/2867      |  1.00
poisson 3000   2   200 µs |             3046-3046      3000 |     1.53-1.57   1.48 |     0/13    |       255/7220      |  1.00
poisson 3000   4   200 µs |             2952-3071      3000 |     2.20-2.37   1.81 |     0/17    |       264/5900      |  0.97
poisson 3000   8   200 µs |             2881-2950      3000 |     3.28-3.35   2.00 |     0/31    |       269/16350     |  0.96
poisson 3000  12   200 µs |             2874-2948      3000 |     3.93-5.45   2.06 |     0/50    |       273/32697     |  0.89
poisson 3000   1     2 ms |               254-287       295 |     1.00-1.00   1.00 |     0/0     |      3217/13941     |  1.00
poisson 3000   2     2 ms |               305-317       295 |     1.99-1.99   2.00 |     0/8     |      3670/46437     |  0.94
poisson 3000   4     2 ms |               298-313       295 |     3.87-3.89   4.00 |     1/25    |      5070/110841    |  0.74
poisson 3000   8     2 ms |               308-316       295 |     7.62-7.72   8.00 |     2/50    |      9307/185387    |  0.71
poisson 3000  12     2 ms |               313-323       295 |   11.48-11.54  12.00 |     3/78    |     11739/287558    |  0.69
poisson 3000   1    20 ms |                 42-42        40 |     1.01-1.01   1.00 |     0/0     |     22325/35907     |  1.00
poisson 3000   2    20 ms |                 43-43        40 |     2.01-2.01   2.00 |     0/13    |     22696/357506    |  0.84
poisson 3000   4    20 ms |                 43-43        40 |     3.95-4.02   4.00 |     0/31    |     23414/724135    |  0.51
poisson 3000   8    20 ms |                 43-44        40 |     7.93-8.06   8.00 |     0/52    |     30034/1206312   |  0.18
poisson 3000  12    20 ms |                 44-44        40 |   11.96-12.00  12.00 |     0/61    |     31299/1405965   |  0.00
poisson 30000   1        0 |           10907-11973     15886 |     1.00-1.00   1.00 |     0/0     |        50/506       |  1.00
poisson 30000   2        0 |           13134-14093     15886 |     1.61-1.65   2.00 |     0/20    |        50/2110      |  0.97
poisson 30000   4        0 |           12990-13580     15886 |     2.87-2.93   4.00 |     0/53    |        51/5585      |  0.94
poisson 30000   8        0 |           11760-12191     15886 |     4.65-4.74   5.22 |     0/78    |        52/13828     |  0.87
poisson 30000  12        0 |           13055-13494     15886 |     8.88-9.82   5.65 |     0/134   |        56/13326     |  0.92
poisson 30000   1   200 µs |             4143-4145      3800 |     1.00-1.00   1.00 |     0/0     |       236/308       |  1.00
poisson 30000   2   200 µs |             4171-4174      3800 |     2.00-2.00   2.00 |     0/27    |       236/6716      |  0.95
poisson 30000   4   200 µs |             4165-4166      3800 |     3.99-3.99   4.00 |     0/73    |       237/17819     |  0.93
poisson 30000   8   200 µs |             4077-4089      3800 |     7.91-7.93   8.00 |     0/132   |       239/33372     |  0.76
poisson 30000  12   200 µs |             3704-3724      3800 |   11.10-11.12  12.00 |     0/139   |       258/41409     |  0.71
poisson 30000   1     2 ms |               350-353       295 |     1.00-1.00   1.00 |     0/0     |      2365/3527      |  1.00
poisson 30000   2     2 ms |               387-387       295 |     2.00-2.00   2.00 |     0/7     |      3480/20228     |  0.99
poisson 30000   4     2 ms |               414-419       295 |     3.99-3.99   4.00 |     2/18    |      6993/46070     |  0.89
poisson 30000   8     2 ms |               427-427       295 |     7.96-7.96   8.00 |     4/48    |     11423/114977    |  0.59
poisson 30000  12     2 ms |               426-428       295 |   11.91-11.92  12.00 |     4/86    |     11883/202794    |  0.60
poisson 30000   1    20 ms |                 46-46        40 |     1.01-1.01   1.00 |     0/0     |     21155/23181     |  1.00
poisson 30000   2    20 ms |                 47-47        40 |     2.01-2.02   2.00 |     0/14    |     21523/309952    |  0.51
poisson 30000   4    20 ms |                 47-47        40 |     3.99-4.01   4.00 |     0/63    |     22526/1357964   |  0.29
poisson 30000   8    20 ms |                 48-48        40 |     7.99-8.04   8.00 |     1/65    |     40512/1370583   |  0.17
poisson 30000  12    20 ms |                 48-48        40 |   11.95-12.00  12.00 |     0/71    |     22577/1490479   |  0.00
```

What the comparison settles: at twelve Producers with no delay this run
measured 5.5 signatures per Entry where the model says 12, and the mains
run measures 10.9. The gap was the machine — low power mode making the
signers unequal, so that slow ones completed fewer attempts per round — and
not the model. The 300/s rows are the same on battery and on mains
(1.12–1.27 against 1.11–1.23), which is what the timer suspect above
predicts and the retry suspect does not, since the window shrank by two
thirds between the runs.

## Traps

- **`threadDelay` is not a microsecond timer here.** A 200 µs request
  returned after 2.3 ms in the first smoke run, so the sub-millisecond rows
  were the 2 ms rows under another name. In-flight delays below a millisecond
  now spin on the monotonic clock (200 µs delivers 200 µs); above it they use
  the timer and are calibrated at startup (2 ms delivers 2.28 ms on mains,
  3.3 on battery). Predictions use the delivered value. The Poisson arrivals
  still use the timer, which is the second suspect above.
- **A lock with twelve waiters measures the runtime.** The first Hub model
  took its lock for every submission, stale or not, and at twelve Producers
  with no delay throughput fell to 1.5k/s with a p99 latency of 169 ms —
  the runtime's lock handoff, not the protocol. Stale submissions are now
  rejected from a read of the head before the lock and checked again inside
  it; the answer is the same, and the convoy is gone.
- **Count signatures by themselves, not per committed event.** The first
  harness summed the signature counts of committed events. A starved
  Producer's signatures then vanished, and a cell where one Producer
  starved reported 1.0 signatures per Entry and perfect efficiency.
- **Twelve signers in one process are not twelve independent Producers.**
  The zero-delay rows carry the cost of sharing one package; read the
  per-Producer ceiling from the one-Producer row and the contention cost
  from the rows with a delay.
- **Battery changes every number at once.** See the section above.

## What this changes upstream

- The README's performance section now says what appending costs under
  contention, next to what checking costs.
- Nothing in the libraries, by decision. The append rule is the
  protocol's, and the remedies the numbers invite each give up a property
  the ADRs lock: per-Producer sub-chains give up total order across
  Producers; a Hub that chains Producer-attributed events gives up signed
  order, so that reordering by the Hub is caught only by Anchors; batching
  gives up one Entry meaning one event (measured afterwards in
  `2026-10-producer-batching.md`: up to 500× across a 20 ms hop, never above
  one signer's signature rate). Each was put to the maintainer with
  the numbers above and declined — the ceiling is accepted as the price of
  total, signed order. A Hub that queues Producers instead of letting them
  race keeps both properties and would remove the wasted signatures and the
  starvation; it would not raise the ceiling, because the queued Producer
  still waits for its predecessor's line to exist. That is Hub implementation
  territory and is noted here for whoever builds it.
