{- | The Entry model: what an Entry claims, what Kind it is, and where it
sits in the chain.

Everything here is the claim tier. An Entry decoded from a line asserts a
predecessor, a payload commitment and a Producer; none of that is
believed until "EventChain.Verify" discharges it, and only that module
can build the verified-fact types that say so.
-}
module EventChain.Verify.Types.Internal.Entry
    ( EntryId (..)
    , entryId
    , entryIdText
    , PayloadRef (..)
    , payloadRef
    , payloadRefText
    , ProducedProof (..)
    , EntryKind (..)
    , Entry (..)
    , DecodedEntry (..)
    , decodedLine
    , decodedEntry
    , ChainPosition (..)
    , chainPosition
    , chainPositionIndex
    ) where

import Data.Text (Text)
import Data.Word (Word64)
import EventChain.Crypto.Types (ClaimedKey, LineBytes, LineHash, PayloadHash, Sig)
import EventChain.Verify.Types.Internal.Attestation (Attestation)

{- | A producer-chosen label for an Entry, e.g. @evt-042@.

Carries no security weight and is not required to be unique: the entry
hash is the only reference the protocol trusts. Any text is a valid
label, so there is nothing to validate.
-}
newtype EntryId = EntryId Text
    deriving stock (Eq, Ord, Show)

-- | Label some text as t'EntryId'.
entryId :: Text -> EntryId
entryId = EntryId

-- | The label's text.
entryIdText :: EntryId -> Text
entryIdText (EntryId t) = t

{- | An index key into external payload storage — where the Hub keeps the
content this Entry commits to by hash.

Like t'EntryId', an opaque label with no security weight: resolving it is
the caller's business and a wrong answer is caught by the payload
commitment, not by this type.
-}
newtype PayloadRef = PayloadRef Text
    deriving stock (Eq, Ord, Show)

-- | Label some text as t'PayloadRef'.
payloadRef :: Text -> PayloadRef
payloadRef = PayloadRef

-- | The reference's text.
payloadRefText :: PayloadRef -> Text
payloadRefText (PayloadRef t) = t

{- | The Produced Proof every Entry carries: this event happened, at this
chain position, originating from this Producer.

The Producer signs the entry's canonical bytes at append time — a device
for its own measurements, an ingesting service for an external stream, a
client carrying a human's passkey. Whatever emits the event signs it, with
its own key; the Hub holds no key and signs nothing, so no part of an Entry
rests on the Hub having behaved.

That the signed bytes include @prev_hash@ is what makes that true of chain
/position/ too, and not only of content: a Hub cannot relocate an Entry
within a chain, or move it to another chain, without invalidating a
signature it cannot forge (ADR-0002 §2, @docs/paper-amendments.md@ PA-08).
-}
data ProducedProof = ProducedProof
    { publicKey :: ClaimedKey
    , signature :: Sig
    }
    deriving stock (Eq, Show)

{- | The taxonomy of Entries, and the content each Kind adds.

A Mint carries its 'Attestation', which carries the target: a Mint
without a target cannot be represented. New Kinds extend the protocol
without touching existing ones.
-}
data EntryKind
    = -- | Records a business event. The absent @kind@ member on the wire.
      LifecycleEntry
    | -- | Attests an earlier Entry. Never mutates its target.
      MintEntry Attestation
    deriving stock (Eq, Show)

{- | An immutable, signed record in the AOF.

The constructor is not exported: an Entry only comes into being by decoding
a line ("EventChain.Verify.Wire"), and there is no second door. An earlier
draft of this docstring named the Producer's @Produce@ as the other one; it
never was, and since ADR-0005 it could not be — the Producer is a package
that cannot name this type. What it takes instead is a @ChainedEvent@, and
what it emits is a line. Constructing an Entry is what /reading/ one does.

Fields are readable — a claim is not a secret, and any claim at all can be
fabricated by writing a file and decoding it.
-}
data Entry = Entry
    { entryId :: EntryId
    , payloadHash :: PayloadHash
    , payloadRef :: PayloadRef
    , prevHash :: LineHash
    , producedProof :: ProducedProof
    , kind :: EntryKind
    }
    deriving stock (Eq, Show)

{- | A line's bytes together with the Entry parsed from them.

Fully opaque, and the pairing is the reason: the chain commits to line
bytes, so verification must hash the bytes an Entry was actually read
from. A pair whose two halves disagree would let a line say one thing
while the parsed view says another, and verification would bless it.
"EventChain.Verify.Wire" is the only place a pair is made, and nothing can
take one apart and put a different one back together.
-}
data DecodedEntry = DecodedEntry
    { line :: LineBytes
    , entry :: Entry
    }
    deriving stock (Eq, Show)

-- | The bytes this Entry was read from — what the chain commits to.
decodedLine :: DecodedEntry -> LineBytes
decodedLine (DecodedEntry ln _) = ln

-- | The Entry parsed from the line.
decodedEntry :: DecodedEntry -> Entry
decodedEntry (DecodedEntry _ e) = e

{- | An Entry's ordinal in the AOF, counted from zero at the genesis entry.

Where a failure happened, not how far along it is: the chain's order is
established by the hash links, and this only names a position in the file
so a report can point at one.
-}
newtype ChainPosition = ChainPosition Word64
    deriving stock (Eq, Ord, Show)

-- | Name the ordinal of a line. "EventChain.Verify" counts them as it folds.
chainPosition :: Word64 -> ChainPosition
chainPosition = ChainPosition

-- | The ordinal, counted from zero.
chainPositionIndex :: ChainPosition -> Word64
chainPositionIndex (ChainPosition n) = n
