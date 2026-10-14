{-# LANGUAGE OverloadedStrings #-}

{- | Assert that @eventchain-verify@ does not depend on @eventchain@.

That edge's absence is what makes the golden vectors evidence. A Verifier
importing the Producer's canonicalizer, member vocabulary or Entry model attests
self-consistency rather than conformance: the Producer emits what the Verifier
expects, every vector passes, and the defect ships. ADR-0005 is the decision;
this is the thing that enforces it, because a convention would not survive a year
and the cheapest way to fix a divergence will always be to share the code.

Walks the resolved plan's transitive closure rather than reading
@build-depends@, because the edge that matters is the one somebody adds
transitively: @eventchain@ arriving via a third package would pass a grep and
still void the gate.
-}
module Main (main) where

import Control.Monad (when)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.IO qualified as TIO
import Gate.Plan (Unit (..), findPlan, loadPlan, unitLabel)
import System.Exit (die, exitFailure, exitSuccess)

-- | The package that must stay ignorant.
verifier :: Text
verifier = "eventchain-verify"

-- | The package it must stay ignorant of.
producer :: Text
producer = "eventchain"

-- | Fails loudly, naming the path by which the forbidden edge was reached.
main :: IO ()
main = do
    plan <- findPlan >>= loadPlan
    let byId = Map.fromList [(u.id, u) | u <- plan]
        seeds = [u | u <- plan, u.pkgName == verifier]

    -- A gate that passes because it found nothing to check has not held.
    when (null seeds) $
        die . T.unpack . T.unlines $
            [ "No " <> verifier <> " unit in the install plan."
            , ""
            , "The gate cannot pass vacuously: either the package is missing from"
            , "cabal.project, or the plan is stale."
            ]

    let (parents, offenders) = closure byId seeds
    if null offenders
        then do
            TIO.putStrLn (verifier <> " does not depend on " <> producer <> ". Boundary holds.")
            exitSuccess
        else do
            TIO.putStrLn ("GATE FAILED: " <> verifier <> " depends on " <> producer <> ".")
            TIO.putStrLn ""
            TIO.putStrLn "That edge is what ADR-0005 forbids: with it, the golden vectors attest"
            TIO.putStrLn "self-consistency rather than conformance, and every test still passes."
            TIO.putStrLn ""
            mapM_ (TIO.putStrLn . ("    " <>) . T.intercalate " -> " . pathTo byId parents) offenders
            exitFailure

{- | Breadth-first over everything the seeds reach, remembering how each unit was
reached so a failure can name the path rather than only the verdict.

Returns the parent links and every unit belonging to the forbidden package.
-}
closure :: Map Text Unit -> [Unit] -> (Map Text Text, [Text])
closure byId seeds = go (Set.fromList seedIds) seedIds Map.empty []
  where
    seedIds = [u.id | u <- seeds]

    go _ [] parents offenders = (parents, reverse offenders)
    go seen (current : queue) parents offenders =
        case Map.lookup current byId of
            Nothing -> go seen queue parents offenders
            Just unit ->
                let fresh = [d | d <- unit.depends, not (Set.member d seen), Map.member d byId]
                    found = [d | d <- fresh, fmap (.pkgName) (Map.lookup d byId) == Just producer]
                 in go
                        (foldr Set.insert seen fresh)
                        (queue <> fresh)
                        (foldr (`Map.insert` current) parents fresh)
                        (found <> offenders)

-- | The chain of components by which an offender was reached, seed first.
pathTo :: Map Text Unit -> Map Text Text -> Text -> [Text]
pathTo byId parents = reverse . climb
  where
    climb node = label node : maybe [] climb (Map.lookup node parents)
    label node = maybe node unitLabel (Map.lookup node byId)
