{- | Minted status, derived: which Entries the file's Mints attest, and which
Mints attest nothing the file contains.

Derived and never stored — ADR-0001 fixes that. A stored minted flag would be
a claim like any other; what the fold computes here is a fact about the file,
recomputable by anyone holding it, which is the only kind of minted status an
offline verifier can honestly report.

A separate pass on purpose, not a branch of "EventChain.Verify"'s fold: the
join needs every hash seen so far, so it costs O(n) memory where the
streaming pass costs O(1), and a caller who wants continuity and attribution
over a billion-entry file should not pay a join it did not ask for
(@docs/plan.md@).

Only 'EventChain.Verify.Sound' entries participate, on both sides of the
join. An Unsound Mint's claims are not facts, so it attests nothing; an
Unsound target is not an Entry the file proved, so a Mint naming its hash is
an orphan — the attestation may be genuine, but genuine about something this
file does not establish.

/A target precedes its Mint./ ADR-0001's Attestation "accrues later as a
separate Mint Entry", so the join looks backward and only backward: a Mint
whose target appears later in the file names a hash that did not exist when
the Mint was appended, which is either fabrication or a rewritten file, and
crediting it would let one file carry both orders. The forward-looking Mint is
reported as the orphan it is.
-}
module EventChain.Verify.Minted
    ( MintedReport (..)
    , OrphanMint (..)
    , mintedStatus
    ) where

import Data.List.NonEmpty (NonEmpty)
import Data.List.NonEmpty qualified as NE
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import EventChain.Crypto.Types (LineHash)
import EventChain.Verify (Verdict (..), verifiedEntry, verifiedLineHash, verifiedPosition)
import EventChain.Verify.Types (Attestation (..), ChainPosition, Entry (..), EntryKind (..))

{- | What the join established.

@minted@ maps each attested Entry's position to the positions of the Mints
that attest it — one Entry may accrue several Attestations, and a report that
collapsed them would lose who vouched. Entries absent from the map are
unminted, which is a status and not a fault: ADR-0001's produce phase exists
precisely so an Entry can stand anchored before any human attests it.
-}
data MintedReport = MintedReport
    { minted :: Map ChainPosition (NonEmpty ChainPosition)
    , orphans :: [OrphanMint]
    }
    deriving stock (Eq, Show)

{- | A sound Mint whose target this file does not establish before it: the
named hash belongs to no Sound Entry at an earlier position.

Carries the claimed hash because "orphan at line 5000" sends a reader back to
the file with nothing to look for — the hash is what to search other files,
or later positions, for.
-}
data OrphanMint = OrphanMint
    { position :: ChainPosition
    , target :: LineHash
    }
    deriving stock (Eq, Show)

{- | Join each Sound Mint to the Sound Entry its target hash names.

One forward pass, carrying the hashes seen so far. The lookup happens before
the current entry is added, so a Mint naming its own hash — representable,
since the hash covers the line that carries the claim — is an orphan rather
than self-attesting.
-}
mintedStatus :: [Verdict] -> MintedReport
mintedStatus = go Map.empty MintedReport{minted = Map.empty, orphans = []}
  where
    go _ report [] = report{orphans = reverse report.orphans}
    go seen report (verdict : rest) = case verdict of
        Sound v ->
            let report' = case (verifiedEntry v).kind of
                    LifecycleEntry -> report
                    MintEntry a -> credit (verifiedPosition v) a.target seen report
             in go (Map.insert (verifiedLineHash v) (verifiedPosition v) seen) report' rest
        Malformed _ -> go seen report rest
        Unsound _ _ -> go seen report rest
        Undecided _ _ -> go seen report rest

    -- @flip@ keeps a target's Mints in file order: `insertWith` applies its
    -- function as @f new old@, and the new Mint belongs after the ones that
    -- preceded it.
    credit mintPos targetHash seen report = case Map.lookup targetHash seen of
        Just targetPos ->
            report
                { minted =
                    Map.insertWith (flip (<>)) targetPos (NE.singleton mintPos) report.minted
                }
        Nothing -> report{orphans = OrphanMint{position = mintPos, target = targetHash} : report.orphans}
