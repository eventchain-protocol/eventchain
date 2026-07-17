-- | The crypto gates: published known answers, and properties over hostile inputs.
module Main (main) where

import Test.EventChain.Crypto.Kat qualified as Kat
import Test.EventChain.Crypto.Properties qualified as Properties
import Test.Tasty (defaultMain, testGroup)

main :: IO ()
main =
    defaultMain $
        testGroup
            "eventchain-crypto"
            [ Kat.tests
            , Properties.tests
            ]
