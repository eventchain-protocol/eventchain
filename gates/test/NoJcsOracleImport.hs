{-# LANGUAGE OverloadedStrings #-}

{- | Assert that no library imports @Data.Aeson.RFC8785@.

aeson's canonicalizer is the oracle our two hand-written JCS encoders are graded
against, and it is evidence only because it shares no code with the thing it
grades. A library that imports it turns the conformance gate into a restatement
of our own code — which still passes every test, which is exactly why this is a
gate and not a guideline.

The oracle is welcome in a /test suite/; that is what an oracle is for. Only the
three @src@ trees are searched.

Matches import lines rather than the bare string. "EventChain.Canonical"'s
haddock names the module in prose to record where aeson and the RFC disagree
(aeson emits @\\u0008@ where §3.2.2.2 requires @\\b@), and that prose is wanted.
Naming the oracle is how the divergence stays documented; importing it is the
thing being forbidden.
-}
module Main (main) where

import Control.Monad (filterM, forM, unless)
import Data.ByteString qualified as BS
import Data.Char (isSpace)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Text.IO qualified as TIO
import Gate.Root (findRepoRoot)
import System.Directory (doesDirectoryExist, listDirectory)
import System.Exit (die, exitFailure, exitSuccess)
import System.FilePath (makeRelative, takeExtension, (</>))

-- | The grader. Never the graded.
oracleModule :: Text
oracleModule = "Data.Aeson.RFC8785"

-- | The trees that ship. Test suites are exempt: grading is what the oracle is for.
libraryTrees :: [FilePath]
libraryTrees =
    [ "eventchain-crypto" </> "src"
    , "eventchain" </> "src"
    , "eventchain-verify" </> "src"
    ]

-- | A file and the line number an offending import sits on.
data Offence = Offence FilePath Int Text

-- | Fails loudly, naming every file and line that imports the oracle.
main :: IO ()
main = do
    root <- findRepoRoot
    let trees = map (root </>) libraryTrees

    -- A gate that scans nothing reports the same word as a gate that passed.
    missing <- filterM (fmap not . doesDirectoryExist) trees
    unless (null missing) $
        die . unlines $
            ["These library source trees do not exist:"]
                <> map ("    " <>) missing
                <> [ ""
                   , "The gate cannot pass without looking. Either a package moved and this"
                   , "list is stale, or the checkout is incomplete."
                   ]

    files <- concat <$> mapM haskellFiles trees
    offences <- concat <$> forM files (scan root)

    if null offences
        then do
            TIO.putStrLn $
                "No library imports "
                    <> oracleModule
                    <> ". ("
                    <> T.pack (show (length files))
                    <> " files across "
                    <> T.pack (show (length trees))
                    <> " trees.)"
            exitSuccess
        else do
            TIO.putStrLn ("GATE FAILED: a library imports " <> oracleModule <> ".")
            TIO.putStrLn ""
            TIO.putStrLn "The oracle is evidence only because it shares no code with the thing it"
            TIO.putStrLn "grades. Depending on it makes the conformance gate a tautology that still"
            TIO.putStrLn "passes every test."
            TIO.putStrLn ""
            mapM_ report offences
            exitFailure
  where
    report (Offence path n line) =
        TIO.putStrLn ("    " <> T.pack path <> ":" <> T.pack (show n) <> ": " <> T.strip line)

-- | Every @.hs@ file under a directory.
haskellFiles :: FilePath -> IO [FilePath]
haskellFiles dir = do
    entries <- listDirectory dir
    fmap concat . forM entries $ \entry -> do
        let path = dir </> entry
        isDir <- doesDirectoryExist path
        if isDir
            then haskellFiles path
            else pure [path | takeExtension path == ".hs"]

{- | Every offending import in one file.

Decoded as UTF-8 explicitly rather than through the locale: these sources carry
non-ASCII (@r‖s@), and a gate whose answer depends on the environment's encoding
is not a gate.
-}
scan :: FilePath -> FilePath -> IO [Offence]
scan root path = do
    bytes <- BS.readFile path
    case TE.decodeUtf8' bytes of
        Left err -> die (path <> " is not valid UTF-8: " <> show err)
        Right text ->
            pure
                [ Offence (makeRelative root path) n line
                | (n, line) <- zip [1 ..] (T.lines text)
                , importsOracle line
                ]

{- | Does this line import the oracle?

@import@, then optionally @qualified@ (GHC2024 also allows it after the module
name, which this still catches because the module name follows @import@ either
way), then the module. A prefix match, as the rule has always been: a submodule
of the oracle is the oracle.
-}
importsOracle :: Text -> Bool
importsOracle raw = case afterKeyword "import" (T.stripStart raw) of
    Nothing -> False
    Just rest -> oracleModule `T.isPrefixOf` fromMaybe rest (afterKeyword "qualified" rest)

{- | The text after a bare keyword, if the line starts with it.

The trailing-space check is what keeps @importFoo@ from reading as @import Foo@.
-}
afterKeyword :: Text -> Text -> Maybe Text
afterKeyword keyword text = do
    rest <- T.stripPrefix keyword text
    case T.uncons rest of
        Just (c, _) | isSpace c -> Just (T.stripStart rest)
        _ -> Nothing
