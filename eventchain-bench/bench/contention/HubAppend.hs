{- | What a Hub that checks each line before appending it commits per second
into one head, on one thread, against the same Hub checking only the head.

The contention and batching sweeps measured the append rule with a Hub that
compares the stated head and writes. A Hub in deployment does more before it
writes: it must know the line is well formed under the exact-bytes rules,
that its @prev_hash@ is the head, and that its signature verifies under the
key it carries, or it is appending bytes it cannot vouch for. This sweep puts
one thread in front of the Hub, as a server has, and runs it two ways from
one invocation — 'HeadOnly', the model the earlier notes used, and 'Checked',
where the Verifier's fold judges every line from the Hub's checkpoint — so
the two rates differ by the checks alone. Before anything is timed the
checked Hub is shown refusing a stale, a forged and a malformed line
("Contention.Refusals"); every file written is verified afterwards as in
every sweep.

Run compiled: @cabal run eventchain-bench:hub-append -- --seconds 4 --runs 2@.
Saturating load, a batch of one, one and twelve Producers, nothing and 20 ms
in flight; @--hubs@, @--producers@ and @--delays@ narrow or widen the grid.
The stanza sets @-N@ because the Producers, the clock and the Hub thread each
need a capability.
-}
module Main (main) where

import System.Environment (getArgs)

import Contention.Cell (Front (..), HubModel (..))
import Contention.Hub (Checks (..))
import Contention.Producer (Load (..))
import Contention.Sweep (Settings (..), parseArgs, runSweep)

defaults :: Settings
defaults =
    Settings
        { wallSeconds = 4
        , runCount = 2
        , jsonPath = Nothing
        , producerCounts = [1, 12]
        , delays = [0, 20000]
        , loads = [Saturating]
        , batches = [1]
        , hubs = [HubModel Thread HeadOnly, HubModel Thread Checked]
        }

main :: IO ()
main = runSweep . parseArgs defaults =<< getArgs
