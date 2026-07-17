{-# LANGUAGE OverloadedStrings #-}

{- | What an entry object refuses to be.

The only thing 'entryObject' can reject is a member given twice: a 'Member'
outside the vocabulary cannot be named and a non-string value cannot be
built, so the type system has the rest.
-}
module Test.EventChain.EntryObject (tests) where

import EventChain.EntryObject
    ( Member
    , ObjectError (..)
    , entryObject
    , memberValue
    )
import Hedgehog (Gen, Property, forAll, property, (===))
import Hedgehog.Gen qualified as Gen
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "EventChain.EntryObject"
        [ testProperty "a member given twice is refused, not resolved" refusesDuplicates
        ]

genMember :: Gen Member
genMember = Gen.element [minBound .. maxBound]

{- | Last-wins would answer a question it cannot answer: which of the two
members the signature covered. So there is no object.
-}
refusesDuplicates :: Property
refusesDuplicates = property $ do
    m <- forAll genMember
    ms <- forAll (Gen.shuffle [(m, memberValue "a"), (m, memberValue "b")])
    entryObject ms === Left (DuplicateMember m)
