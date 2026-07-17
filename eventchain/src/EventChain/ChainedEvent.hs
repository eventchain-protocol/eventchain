{- | What a Producer is handed: a business event's commitment plus its chain
linkage. Unsigned, and not yet an Entry.

An Entry carries a Produced Proof; a t'ChainedEvent' is what exists before there
is one, so the two are not the same type and no function taking this one may
assume a signature. Making that proof is "EventChain.Produce"'s, and it is the
only thing that turns one of these into a line.

/Event/ here is the business occurrence — the thing that happened — as
@CONTEXT.md@ reserves the word. The Entry is the record of it.

== Why these types live here and not in the shared package

t'EntryId' and t'PayloadRef' are written on this side and written again,
separately, on the Verifier's (ADR-0005, and @docs/plan.md@'s type table says
"each, separately"). They will read almost identically to their counterparts,
and that is the expected outcome rather than a smell: the split is what makes
the golden vectors evidence, not a claim that two independent readings of the
same document must come out different. Where a difference /does/ appear, one
side is wrong about the format and the vectors are what say so.

The decision-free types these sit beside — t'EventChain.Crypto.Types.LineHash',
t'EventChain.Crypto.Types.PayloadHash' — go the other way and are shared,
because a digest's length is not a judgment two implementations could reach
differently.
-}
module EventChain.ChainedEvent
    ( -- * Labels
      EntryId
    , entryId
    , entryIdText
    , PayloadRef
    , payloadRef
    , payloadRefText

      -- * The Producer's input
    , ChainedEvent (..)

      -- * Chain linkage
    , genesisHash
    ) where

import Data.ByteString qualified as BS
import Data.Text (Text)
import EventChain.Crypto.Types
    ( LineHash
    , PayloadHash
    , lineHashFromBytes
    , sha256Length
    )

{- | A producer-chosen label for an Entry, e.g. @evt-042@.

Carries no security weight and is not required to be unique: the entry hash is
the only reference the protocol trusts. Any text is a valid label, so there is
nothing to validate and this newtype buys labelling and no more — it is not the
kind whose constructor proves a check ran, because there is no check.

The paper calls it "Unique entry identifier" and names no scope for the
uniqueness and no point that would enforce it; @docs/paper-amendments.md@ PA-09
records our reading and leaves the paper's open rather than guessing.
-}
newtype EntryId = EntryId Text
    deriving stock (Eq, Ord, Show)

-- | Label some text as an t'EntryId'.
entryId :: Text -> EntryId
entryId = EntryId

-- | The label's text, for the wire.
entryIdText :: EntryId -> Text
entryIdText (EntryId t) = t

{- | An index key into external payload storage — where the Hub keeps the
content this event commits to by hash.

Like t'EntryId', an opaque label with no security weight and nothing to
validate: resolving it is the caller's business, and a wrong answer is caught
by the payload commitment rather than by this type. @docs/paper-amendments.md@
PA-03 records that both labels are opaque strings and carry no encoding
requirement.
-}
newtype PayloadRef = PayloadRef Text
    deriving stock (Eq, Ord, Show)

-- | Label some text as a t'PayloadRef'.
payloadRef :: Text -> PayloadRef
payloadRef = PayloadRef

-- | The reference's text, for the wire.
payloadRefText :: PayloadRef -> Text
payloadRefText (PayloadRef t) = t

{- | An event's commitment, plus where in the chain it goes.

The constructor is exported, and that is not an oversight. Every field is
already a type that proved its own shape on the way in — a t'PayloadHash' is 32
bytes because nothing else can be one — so there is no check left for a smart
constructor to run and nothing it could refuse. A door that validates nothing
is a door that lies about what holding the value proves.

@prevHash@ is the predecessor's entry hash: the digest of its line bytes, which
"EventChain.Produce" hands back for exactly this purpose. The first event of an
AOF takes 'genesisHash'.
-}
data ChainedEvent = ChainedEvent
    { entryId :: EntryId
    , payloadHash :: PayloadHash
    , payloadRef :: PayloadRef
    , prevHash :: LineHash
    }
    deriving stock (Eq, Show)

{- | The @prev_hash@ the first event of an AOF carries: 32 zero bytes.

A sentinel, and a deliberately false claim — 32 zero bytes are not the digest
of any line, and no producer could arrange for them to be. The claim tier
admits it because t'EventChain.Crypto.Types.LineHash' is 32 bytes /asserted/ to
be a digest and cannot check the assertion; that same latitude is what lets a
verifier read a claimed @prev_hash@ off a line it has not checked yet.

Why a constant rather than a @Genesis | Follows LineHash@ sum: this side never
branches on it. The member is rendered identically either way, so the sum would
buy a distinction nobody here consumes, and a type-level feature earns its place
by preventing a bug (ADR-0003). A verifier /does/ branch — it must reject a
first entry carrying anything else, per @docs/paper-amendments.md@ PA-05 — and
that is its type to choose, on its own side of the split.

The paper does not define this. Its chain loop guards with @IF i > 0@ and so
never examines the first entry's @prev_hash@ at all; PA-05 carries the
correction for submission upstream.
-}
genesisHash :: LineHash
genesisHash = case lineHashFromBytes (BS.replicate sha256Length 0) of
    Right h -> h
    -- Unreachable: `BS.replicate sha256Length` is `sha256Length` bytes, which is
    -- the only thing `lineHashFromBytes` checks.
    Left e -> error ("EventChain.ChainedEvent.genesisHash: " <> show e)
