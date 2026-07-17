{- | The Producer's gates. Nothing mocked, and nothing of ours grading itself.

Two kinds of test, and the split is the testing policy rather than a layout.
'EntryObject' and 'Canonical' are pure functions with real branching. 'Wire' and
'Produce' are graded by outside readers — @aeson@ parses what we emit, its RFC
8785 canonicalizer derives what we signed, and the OpenSSL CLI judges the
signature. The Producer is correct before a Verifier exists to agree with it, or
the agreement would not have been worth having.
-}
module Main (main) where

import Test.EventChain.Canonical qualified as Canonical
import Test.EventChain.EntryObject qualified as EntryObject
import Test.EventChain.Produce qualified as Produce
import Test.EventChain.Vectors qualified as Vectors
import Test.EventChain.Wire qualified as Wire
import Test.Tasty (defaultMain, testGroup)

main :: IO ()
main =
    defaultMain $
        testGroup
            "eventchain"
            [ EntryObject.tests
            , Canonical.tests
            , Wire.tests
            , Produce.tests
            , Vectors.tests
            ]
