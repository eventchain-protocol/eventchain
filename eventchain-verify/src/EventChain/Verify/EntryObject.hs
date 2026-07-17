{-# LANGUAGE OverloadedStrings #-}

{- | The AOF's JSON shape, as the Verifier expects to read it: the member name
vocabulary and the flat, string-valued object a line decodes to.

Re-derived from @docs/protocol.md@'s field table and ADR-0002 §4, not from the
Producer's source (ADR-0005). If this vocabulary and the Producer's ever
disagree, one of them is wrong about the format and the vectors say which —
that is the gate working. Sharing them to settle a disagreement would pass
every test and destroy the evidence.

The object is flat and every value is a string. That is not a simplification of
a richer model: @docs/protocol.md@'s six fields are two opaque labels
(@entry_id@, @payload_ref@) and four binary quantities, and ADR-0002 §4 puts
every binary field in base64url precisely so a line stays plain text. A member
carrying a number, an object or a null is therefore a malformed line rather
than a shape to accommodate.

What this module does /not/ own: what a member's text means. @prev_hash@ is 32
bytes of base64url here and a claim about a predecessor in
"EventChain.Verify.Wire". The split is deliberate — "EventChain.Verify.Canonical"
needs the names and the text and must never need the meaning, because the
signing message is derived from what the line said rather than from what we
made of it.
-}
module EventChain.Verify.EntryObject
    ( Member (..)
    , memberName
    , memberFromName
    , allMembers
    , EntryObject (..)
    , entryObjectMembers
    ) where

import Data.Text (Text)

{- | The members a v0 lifecycle line carries, and the only names this Verifier
will accept.

Declaration order is @docs/protocol.md@'s table order, which is the paper's.
Nothing derives from it: the Verifier reads members by name, and
"EventChain.Verify.Canonical" sorts them itself because RFC 8785 says to. A
producer may write them in any order it likes (@docs/paper-amendments.md@
PA-01), so an implementation that depended on this order would reject legal
files.

The addendum's @kind@ and @target_hash@ are absent, and their absence is
load-bearing at M3: a line carrying @kind@ is rejected as an unknown member
rather than quietly read as a lifecycle event. Mint arrives at M4 and adds them
here.
-}
data Member
    = EntryId
    | PayloadHash
    | PayloadRef
    | PrevHash
    | PublicKey
    | Signature
    deriving stock (Eq, Ord, Show, Enum, Bounded)

{- | The member's name as it appears on a line.

The wire names are the format's, and this function is the only place this
package writes them down.
-}
memberName :: Member -> Text
memberName = \case
    EntryId -> "entry_id"
    PayloadHash -> "payload_hash"
    PayloadRef -> "payload_ref"
    PrevHash -> "prev_hash"
    PublicKey -> "public_key"
    Signature -> "signature"

{- | The member a name denotes, or nothing if the format has no such member.

'Nothing' is a rejection, not a gap to fill in. An unknown member is a hard
error with a line number ("EventChain.Verify.Wire"): a line saying something
this Verifier cannot account for is a line whose signature might cover a
meaning we did not read.
-}
memberFromName :: Text -> Maybe Member
memberFromName t = lookup t [(memberName m, m) | m <- allMembers]

-- | Every member of the vocabulary.
allMembers :: [Member]
allMembers = [minBound .. maxBound]

{- | A line's members and their text, with every one of them present.

Total by construction: six fields rather than a map, so a value of this type is
a complete object and no consumer has a missing-member case to handle.
"EventChain.Verify.Wire" is where an incomplete line is rejected, which is where
the line number is.

The text is the /parsed/ string — escapes resolved, as JSON means them. Not the
bytes as they sat on the line: two lines escaping the same label differently
are the same object, they simply hash differently, and keeping the distinction
straight is what ADR-0002 §1 and §2 are each about.
-}
data EntryObject = EntryObject
    { entryId :: Text
    , payloadHash :: Text
    , payloadRef :: Text
    , prevHash :: Text
    , publicKey :: Text
    , signature :: Text
    }
    deriving stock (Eq, Show)

{- | The object as name-and-text pairs, in vocabulary order.

For "EventChain.Verify.Canonical", which drops one member and sorts the rest.
Pairs rather than the record because canonicalization is about names and text
and must not be able to see which field is which — the moment it can, it can
treat one specially, and the signing message stops being a function of what the
line said.
-}
entryObjectMembers :: EntryObject -> [(Member, Text)]
entryObjectMembers o =
    [ (EntryId, o.entryId)
    , (PayloadHash, o.payloadHash)
    , (PayloadRef, o.payloadRef)
    , (PrevHash, o.prevHash)
    , (PublicKey, o.publicKey)
    , (Signature, o.signature)
    ]
