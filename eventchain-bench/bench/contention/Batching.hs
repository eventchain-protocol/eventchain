{- | Whether signing events in batches buys throughput under contention, and
how much.

The contention sweep's ceiling is one commit per race window, and the window
is one signature plus the time a signed line spends in flight. A Producer that
signs a batch of events chained among themselves and submits them together
still pays one window per submission, but commits the whole batch inside it —
so the ceiling becomes the batch size over a window that is wider by the
extra signatures. Where the in-flight delay dominates the window, that is
nearly the batch size times the throughput; where the signature does, it is
nothing, because the signer was already the ceiling. This sweep measures both
ends, with the batch of one alongside as the row the others are read against.

What batching gives up is not measured here and is not nothing: a rejection
now wastes a batch of signatures rather than one, an event waits for its
batch to fill before it is signed at all, and the Hub takes or refuses a batch
whole. The "Contention.Producer" docs say what the latency column covers.

Run compiled: @cabal run eventchain-bench:batching -- --seconds 2 --runs 2@.
Saturating load only by default, because the question is the ceiling;
@--loads@ accepts Poisson rates in events per second if the question is a
rate below it, and @--batches@, @--producers@ and @--delays@ narrow the grid.
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
        { wallSeconds = 2
        , runCount = 2
        , jsonPath = Nothing
        , producerCounts = [1, 4, 12]
        , delays = [0, 200, 2000, 20000]
        , loads = [Saturating]
        , batches = [1, 100, 300, 1000, 3000]
        , hubs = [HubModel Lock HeadOnly]
        }

main :: IO ()
main = runSweep . parseArgs defaults =<< getArgs
