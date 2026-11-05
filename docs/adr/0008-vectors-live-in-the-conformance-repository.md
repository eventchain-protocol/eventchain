# The golden vectors live in the conformance repository

`docs/plan.md` put the vectors at the top of this repository, in `vectors/`,
because both sides face them and neither owns them: `eventchain` generates,
`eventchain-verify` adjudicates. That reasoning held while those two were the
only parties. They no longer are.

The Hub's acceptor already reads the vectors out of a pinned checkout of this
repository. A TypeScript verifier written from the specification alone is
planned, and a Python one after it. And the specification now states rules
this Verifier does not enforce — heartbeat comparison, and the line-terminator
rules where the paper and JSON Lines disagree — so vectors are owed that this
repository's own suite cannot pass. A vector the host's Verifier fails has no
honest place among the host's fixtures, and a verifier in another language
pinning a Haskell repository for its inputs reads as one implementation
owning what every implementation is graded by.

ADR-0005 declined to move the Verifier to its own repository in part because
that "splits the golden vectors' home". This decision does not split the home.
It moves it, whole.

Decided by the user, 2026-11-05.

## Decision

The vectors move, with their history, to
[`eventchain-protocol/conformance`](https://github.com/eventchain-protocol/conformance),
under `vectors/` there. This repository mounts that one as a git submodule at
`conformance/`, so the vectors are read from `conformance/vectors/` and are
pinned by commit.

The two roles are unchanged. `eventchain`'s suite still rebuilds the committed
bytes from fixed events and compares; `eventchain-verify`'s suite still reads
them blind. Neither generates a vector on demand.

Expected outcomes move too, but not yet. The conformance repository is to
carry a manifest stating, for each vector, the outcome the specification
requires, written from the specification and never from a verifier's output.
It waits on the specification's outcome vocabulary. Until it exists, the
expected verdicts stay where they are, in the two test suites.

## Considered options

- **Leave the vectors here; other verifiers pin this repository** — rejected:
  it is what the Hub does today, and it makes the Haskell implementation the
  owner of the suite that grades it and everyone else. It also leaves no home
  for a vector this Verifier does not yet pass.
- **Copy the vectors into each verifier's repository** — rejected: a vector is
  its exact bytes, and copies are how two implementations come to pass
  different files under one name.
- **Fetch the vectors at test time** — rejected: a test that needs the network
  is not the offline check this project claims, and a fetch of a branch is
  not pinned.

## Consequences

- A clone needs `--recurse-submodules`, or `git submodule update --init`
  afterwards. A missing vector's test failure says so.
- A deliberate format change is two commits in two repositories: the
  regenerated vector in the conformance repository, then the submodule
  pointer here. The golden test fails between them, which is the finding it
  exists to report.
- The Hub's acceptor reads the vectors from its pinned checkout of this
  repository. When its pin passes this change, its conformance test reads
  `conformance/vectors/` in that checkout instead.
- Earlier ADRs and research notes name `vectors/` as it was when they were
  written. They are records and are left as written.
