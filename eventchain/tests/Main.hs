-- | The conformance gates. Pure functions with real branching only; nothing mocked.
module Main (main) where

import Test.EventChain.Canonical qualified as Canonical
import Test.EventChain.EntryObject qualified as EntryObject
import Test.Tasty (defaultMain, testGroup)

main :: IO ()
main =
    defaultMain $
        testGroup
            "eventchain"
            [ EntryObject.tests
            , Canonical.tests
            ]
