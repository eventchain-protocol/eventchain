{- | What compare-and-swap append implies before anything is measured, so a
measured cell is read against a number rather than on its own.

Every head advance invalidates every signature in flight. Under saturating
load that makes each round one commit and one signature per Producer: the
commit rate is one per race window regardless of how many Producers there
are, and the signatures per committed Entry climb linearly with them. Under
Poisson arrivals an attempt loses when another Producer commits inside its
window, which happens with probability @1 - exp(-λ'w)@ for @λ'@ the others'
rate, so an event costs about @exp(λ'w)@ signatures. An offered rate the
window cannot carry is saturating load by another name, and is predicted as
such; below it the retries themselves are arrivals the formula does not
count, so it reads low as @λ'w@ approaches one.

The window is the signature plus the delay as the runtime actually delivers
it, which is why the caller measures both and passes them in. A batch of
@b@ events widens the window to @b@ signatures plus the delay and commits
@b@ events per window, so the ceiling is @b@ over that window: it rises
towards one event per signature as the delay stops mattering, and no
further, because the signer is then the ceiling. Signatures per Entry are
unchanged under saturating load — every Producer still signs every event
once per round — and under Poisson load the collisions are between batches,
which arrive at a @b@th of the event rate.

A Hub that judges a line before writing it holds the head for the time the
judgement takes, and a Producer waits that long for its reply before it can
read the next head: the window is wider by the Hub's service time per
submission. The caller measures that too and passes it in — zero for a Hub
that only compares, the per-line fold for one that checks.
-}
module Contention.Predict
    ( Prediction (..)
    , predict
    ) where

import Contention.Producer (Load (..))

data Prediction = Prediction
    { commitsPerSecond :: Double
    , signaturesPerEntry :: Double
    }

{- | @predict signMicros delayMicros serviceMicros producers batch load@.
@load@'s Poisson rate is the aggregate across Producers, in events.
-}
predict :: Double -> Double -> Double -> Int -> Int -> Load -> Prediction
predict signMicros delayMicros serviceMicros producers batch = \case
    Saturating ->
        Prediction
            { commitsPerSecond = ceiling'
            , signaturesPerEntry = fromIntegral producers
            }
    Poisson aggregate
        | aggregate >= ceiling' -> predict signMicros delayMicros serviceMicros producers batch Saturating
        | otherwise ->
            Prediction
                { commitsPerSecond = aggregate
                , signaturesPerEntry = min (fromIntegral producers) (exp (others aggregate / fromIntegral batch * windowSeconds))
                }
  where
    windowSeconds = (fromIntegral batch * signMicros + delayMicros + serviceMicros) / 1e6
    ceiling' = fromIntegral batch / windowSeconds
    others aggregate = aggregate * fromIntegral (producers - 1) / fromIntegral producers
