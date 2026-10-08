{-# LANGUAGE OverloadedStrings #-}

{- | The AOF's JSON shape, as the Verifier expects to read it: the member name
vocabulary, the Revision that selects how much of it a line may use, and the
flat, string-valued object a line decodes to.

Re-derived from @docs/protocol.md@'s field table, ADR-0002 §4, ADR-0006 and
ADR-0007, not from the Producer's source (ADR-0005). If this vocabulary and
the Producer's ever disagree, one of them is wrong about the format and the
vectors say which — that is the gate working. Sharing them to settle a
disagreement would pass every test and destroy the evidence.

The object is flat and every value is a string. That is not a simplification of
a richer model: the paper's six fields are two opaque labels
(@entry_id@, @payload_ref@) and four binary quantities, ADR-0002 §4 puts
every binary field in base64url precisely so a line stays plain text, and the
addendum's members follow the same rule — the envelope's blobs travel as
base64url and @v@ is a label. A member carrying a number, an object or a null
is therefore a malformed line rather than a shape to accommodate. (The JSON
/inside/ a decoded @client_data_json@ is another document with its own reading
rules; the Verifier's WebAuthn checks own them, and nothing here does.)

What this module does /not/ own: what a member's text means. @prev_hash@ is 32
bytes of base64url here and a claim about a predecessor in
"EventChain.Verify.Wire". The split is deliberate — "EventChain.Verify.Canonical"
needs the names and the text and must never need the meaning, because the
signing message is derived from what the line said rather than from what we
made of it.
-}
module EventChain.Verify.EntryObject
    ( -- * The vocabulary
      Member (..)
    , memberName
    , memberFromName
    , allMembers

      -- * Revisions
    , Revision (..)
    , revisionFromLabel
    , memberInRevision

      -- * The object
    , EntryObject (..)
    , MintMembers (..)
    , entryObjectMembers
    ) where

import Data.Text (Text)

{- | Every member name the format defines across all revisions, and the only
names this Verifier will ever accept.

Declaration order is @docs/protocol.md@'s table order for the paper's six,
with the addendum's after them in @docs/plan.md@'s listing order and @v@
last. Nothing derives from it: the Verifier reads members by name, and
"EventChain.Verify.Canonical" sorts them itself because RFC 8785 says to. A
producer may write them in any order it likes (@docs/paper-amendments.md@
PA-01), so an implementation that depended on this order would reject legal
files.

Knowing a name is not admitting it. Which of these a given line may carry is
the line's own 'Revision' declaration to say (ADR-0006), and
"EventChain.Verify.Wire" rejects a member outside the declared vocabulary
exactly as it rejects a name outside this one — the declaration selects which
vocabulary the closed-vocabulary rule closes over.
-}
data Member
    = EntryId
    | PayloadHash
    | PayloadRef
    | PrevHash
    | PublicKey
    | Signature
    | Kind
    | TargetHash
    | AttesterKey
    | AssertionSig
    | AuthenticatorData
    | ClientDataJson
    | V
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
    Kind -> "kind"
    TargetHash -> "target_hash"
    AttesterKey -> "attester_key"
    AssertionSig -> "assertion_sig"
    AuthenticatorData -> "authenticator_data"
    ClientDataJson -> "client_data_json"
    V -> "v"

{- | The member a name denotes, or nothing if no revision of the format has
such a member.

'Nothing' is a rejection, not a gap to fill in. An unknown member is a hard
error with a line number ("EventChain.Verify.Wire"): a line saying something
this Verifier cannot account for is a line whose signature might cover a
meaning we did not read.
-}
memberFromName :: Text -> Maybe Member
memberFromName t = lookup t [(memberName m, m) | m <- allMembers]

-- | Every member of every revision's vocabulary.
allMembers :: [Member]
allMembers = [minBound .. maxBound]

{- | The member vocabulary an entry declares itself against (ADR-0006).

A closed set, compared by equality only: the @v@ member's label either names
one of these or the line is rejected with its line number — never read
"approximately", never ordered, never matched by prefix. Absence of @v@ is
itself a declaration, of 'Base'.
-}
data Revision
    = {- | The paper's six members, exactly: the absent @v@ member. What a
      paper-only implementation writes and reads.
      -}
      Base
    | {- | Label @\"1\"@: the ADR-0001 addendum — the six, plus @kind@,
      @target_hash@, the four envelope members, plus @v@ itself.
      -}
      Addendum
    deriving stock (Eq, Show)

{- | The revision a label declares, or nothing if this Verifier knows no such
revision.

'Nothing' is PA-11's obligation running in our own house: a verifier rejects
what it cannot read rather than misreading it. The label is compared whole —
@\"1.0\"@ is not @\"1\"@ and is not in the set.
-}
revisionFromLabel :: Text -> Maybe Revision
revisionFromLabel = \case
    "1" -> Just Addendum
    _ -> Nothing

{- | Whether a revision's vocabulary admits a member.

Admitting the /name/ is all this answers. A revision-@\"1\"@ lifecycle line
may carry @v@ and nothing else beyond the six — the label admits the
vocabulary, it does not mandate exercising it (ADR-0006) — while which members
a declared /Kind/ then requires is "EventChain.Verify.Wire"'s completeness
question, one tier up.
-}
memberInRevision :: Revision -> Member -> Bool
memberInRevision r m = case r of
    Addendum -> True
    Base -> case m of
        EntryId -> True
        PayloadHash -> True
        PayloadRef -> True
        PrevHash -> True
        PublicKey -> True
        Signature -> True
        Kind -> False
        TargetHash -> False
        AttesterKey -> False
        AssertionSig -> False
        AuthenticatorData -> False
        ClientDataJson -> False
        V -> False

{- | A line's members and their text, with every required one present.

Total by construction where the format is total: the six the paper requires
are plain fields, so no consumer has a missing-member case to handle. What a
line may add — the declaration, the Mint members — is optional in the format
and 'Maybe' here, grouped as the format groups it: 'MintMembers' exists whole
or not at all, because "EventChain.Verify.Wire" refuses a line carrying part
of a Kind's members. A @v@ without Mint members is representable on purpose —
ADR-0006 makes the bare declaration valid input.

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
    , v :: Maybe Text
    , mint :: Maybe MintMembers
    }
    deriving stock (Eq, Show)

{- | The members a Mint carries beyond the six, as the line's text.

@kind@ is here as written — any value the line carried, not only @\"mint\"@ —
because this is the object tier and meaning has not happened yet: the signing
message must be derivable from a line whose @kind@ says something we cannot
read, or the reading rules could never reject that line /as/ an entry with a
position. Judging the value is "EventChain.Verify.Wire"'s.
-}
data MintMembers = MintMembers
    { kind :: Text
    , targetHash :: Text
    , attesterKey :: Text
    , assertionSig :: Text
    , authenticatorData :: Text
    , clientDataJson :: Text
    }
    deriving stock (Eq, Show)

{- | The object as name-and-text pairs, present members only, in vocabulary
order.

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
        <> foldMap mintPairs o.mint
        <> foldMap (\label -> [(V, label)]) o.v
  where
    mintPairs m =
        [ (Kind, m.kind)
        , (TargetHash, m.targetHash)
        , (AttesterKey, m.attesterKey)
        , (AssertionSig, m.assertionSig)
        , (AuthenticatorData, m.authenticatorData)
        , (ClientDataJson, m.clientDataJson)
        ]
