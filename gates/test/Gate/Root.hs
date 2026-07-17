{- | Where the project starts.

Cabal runs a test suite from its own package directory, so a gate that asks about
the project as a whole cannot look beside itself. It has to find the root, and it
has to fail loudly rather than quietly examine nothing if it cannot: a gate that
passes because it looked in the wrong place is worse than no gate, because it
reports the same word.
-}
module Gate.Root
    ( findRepoRoot
    ) where

import System.Directory (doesFileExist, getCurrentDirectory)
import System.Exit (die)
import System.FilePath (takeDirectory, (</>))

{- | The directory holding @cabal.project@, found by walking up from the working
directory.

@cabal.project@ is the marker because it is what defines the project these gates
are about, and @dist-newstyle@ sits beside it.
-}
findRepoRoot :: IO FilePath
findRepoRoot = getCurrentDirectory >>= go
  where
    go dir = do
        found <- doesFileExist (dir </> "cabal.project")
        if found
            then pure dir
            else
                let up = takeDirectory dir
                 in if up == dir then die missing else go up

    missing =
        unlines
            [ "No cabal.project above the working directory."
            , ""
            , "This gate asks a question about the whole project and cannot find it,"
            , "so it fails rather than reporting a boundary it never looked at."
            ]
