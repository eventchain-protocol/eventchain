{- | What appending costs when more than one Producer signs against the same
head, measured against what compare-and-swap append predicts.

Not a test, and deliberately not a gate: rates are a property of the machine,
so they are recorded in @docs\/research\/@ and compared there. What is
asserted is correctness — every file the Hub model writes is verified, and
its lines are reconciled against what the Producers report (see
"Contention.Cell").

The sweep crosses load (saturating, then Poisson at three aggregate rates),
Producer count and the in-flight delay, with one event per submission. Two
columns per rate: the measured range across runs, and the prediction from the
signature cost and the delay as calibrated on this machine at startup.

Run compiled: @cabal run eventchain-bench:contention -- --seconds 2 --runs 2@.
The stanza sets @-N@ so the Producers have a capability each; the harness
refuses to run with fewer than the largest Producer count plus one, because
Producers sharing a capability would be measuring the scheduler.
-}
module Main (main) where

import System.Environment (getArgs)

import Contention.Cell (Front (..), HubModel (..))
import Contention.Hub (Checks (..))
import Contention.Producer (Load (..))
import Contention.Sweep (Settings (..), parseArgs, runSweep)

-- | The whole sweep; @--producers@, @--delays@ and @--loads@ narrow it.
defaults :: Settings
defaults =
    Settings
        { wallSeconds = 2
        , runCount = 2
        , jsonPath = Nothing
        , producerCounts = [1, 2, 4, 8, 12]
        , delays = [0, 200, 2000, 20000]
        , loads = [Saturating, Poisson 300, Poisson 3000, Poisson 30000]
        , batches = [1]
        , hubs = [HubModel Lock HeadOnly]
        }

main :: IO ()
main = runSweep . parseArgs defaults =<< getArgs
