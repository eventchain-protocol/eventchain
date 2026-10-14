{- | The Verifier's gates. Nothing mocked, and nothing of ours grading itself.

Three kinds of test, and the split is what ADR-0005 buys. 'Canonical' is graded
by @aeson@'s RFC 8785 implementation, which shares no code with ours. 'Wire' is
graded by hand-written malformed lines, because what it does with bytes someone
else wrote is the whole of its job and our own encoder could not produce the
inputs. 'Fold' is graded by a file: an AOF the Producer wrote, read by a package
that cannot name the Producer.

The last of those is the milestone. Two member vocabularies, two
canonicalizers and two readings of ADR-0002 agree — and they agree across a
@build-depends@ edge that does not exist, which is the only reason the agreement
is worth anything.
-}
module Main (main) where

import Test.EventChain.Verify.Canonical qualified as Canonical
import Test.EventChain.Verify.Fold qualified as Fold
import Test.EventChain.Verify.Mint qualified as Mint
import Test.EventChain.Verify.Wire qualified as Wire
import Test.Tasty (defaultMain, testGroup)

main :: IO ()
main =
    defaultMain $
        testGroup
            "eventchain-verify"
            [ Canonical.tests
            , Wire.tests
            , Fold.tests
            , Mint.tests
            ]
