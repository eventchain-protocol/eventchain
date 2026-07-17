{-# LANGUAGE OverloadedStrings #-}

{- | Cabal's resolved install plan, located and read.

The plan is what a dependency gate must read. @build-depends@ is a statement of
intent by one package about itself; the plan is what the solver actually decided,
across every package, including the edges nobody wrote down. A gate that greps
@build-depends@ answers a different, easier question than the one that matters.

Nothing here knows what the plan is being asked. That belongs to each gate.
-}
module Gate.Plan
    ( Unit (..)
    , unitLabel
    , findPlan
    , loadPlan
    ) where

import Data.Aeson (FromJSON (parseJSON), withObject, (.!=), (.:), (.:?))
import Data.Aeson qualified as A
import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Gate.Root (findRepoRoot)
import System.Directory (doesFileExist)
import System.Exit (die)
import System.FilePath ((</>))

{- | One configured thing the solver decided to build: a library, a test suite, an
external dependency.

Only what a gate needs. The plan carries a great deal more, and reading fields we
do not use would invite depending on them.
-}
data Unit = Unit
    { id :: Text
    , pkgName :: Text
    , componentName :: Maybe Text
    , depends :: [Text]
    }
    deriving stock (Eq, Show)

{- | How a unit is named in a failure: @eventchain:test:conformance@.

Cabal omits @component-name@ for a plain library, which is the common case and
reads as @lib@ everywhere else in cabal's own output.
-}
unitLabel :: Unit -> Text
unitLabel u = u.pkgName <> ":" <> fromMaybe "lib" u.componentName

{- | Every unit id this one builds against.

Cabal reports a component's dependencies at the top level for a single-component
unit and under @components@ when it splits them. Read both, rather than assuming
the shape this project happens to produce today — the gate would still pass, and
would have stopped answering the question.

@exe-depends@ is deliberately not read: a build-tool edge cannot make one
package's modules importable from another, so it cannot void the boundary.
-}
instance FromJSON Unit where
    parseJSON = withObject "install-plan unit" $ \o -> do
        i <- o .: "id"
        p <- o .: "pkg-name"
        c <- o .:? "component-name"
        top <- o .:? "depends" .!= []
        comps <- o .:? "components" .!= Map.empty
        pure
            Unit
                { id = i
                , pkgName = p
                , componentName = c
                , depends = top <> concatMap componentDepends (Map.elems (comps :: Map Text ComponentDepends))
                }

-- | The one field we want out of a split unit's components.
newtype ComponentDepends = ComponentDepends [Text]

componentDepends :: ComponentDepends -> [Text]
componentDepends (ComponentDepends ds) = ds

instance FromJSON ComponentDepends where
    parseJSON = withObject "component" $ \o -> ComponentDepends <$> o .:? "depends" .!= []

-- | The plan file's one interesting member.
newtype Plan = Plan [Unit]

instance FromJSON Plan where
    parseJSON = withObject "plan.json" $ \o -> Plan <$> o .: "install-plan"

{- | The plan cabal last resolved, beside @cabal.project@.

Absent is a hard error, not an empty plan: this gate must not pass by failing to
look.
-}
findPlan :: IO FilePath
findPlan = do
    root <- findRepoRoot
    let candidate = root </> "dist-newstyle" </> "cache" </> "plan.json"
    found <- doesFileExist candidate
    if found then pure candidate else die (missing candidate)
  where
    missing candidate =
        unlines
            [ "No install plan at " <> candidate <> "."
            , ""
            , "This gate reads the plan cabal resolved; it cannot answer without one."
            , "Run:"
            , ""
            , "    cabal build --dry-run all --enable-tests"
            ]

{- | Read the plan, or fail saying so.

A malformed or unreadable plan is a hard error rather than an empty list: a gate
that cannot see the graph has not established that the graph is clean.
-}
loadPlan :: FilePath -> IO [Unit]
loadPlan path = do
    bytes <- LBS.readFile path
    case A.eitherDecode bytes of
        Right (Plan units) -> pure units
        Left err ->
            die . T.unpack . T.unlines $
                [ "Could not read " <> T.pack path <> " as an install plan:"
                , "  " <> T.pack err
                , ""
                , "The gate cannot answer without the graph, so this is a failure"
                , "rather than a pass."
                ]
