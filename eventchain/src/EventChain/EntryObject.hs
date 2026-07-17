{-# LANGUAGE OverloadedStrings #-}

{- | An Entry in the shape a line carries it: a flat JSON object, string
values, each member named once.

Member names come from three places, and 'Member' is where the three meet.
They are a closed vocabulary because a member name is a domain quantity,
and domain quantities are not text a caller invents (ADR-0003).

This is the shape the two halves of the format meet at. @EventChain.Wire@
(M2) renders a @ChainedEvent@ into one of these and then into line bytes,
owning the domain types and base64url; "EventChain.Canonical" turns one into
the bytes a signature covers, owning RFC 8785. Neither needs the other, and
the vocabulary is owned by neither — it belongs to the format both serve.

One direction only. An earlier draft said Wire maps an @Entry@ "to and from"
one of these; the Producer never parses JSON, so there is no @from@, and
since ADR-0005 there is no @Entry@ on this side of the split either — that
type is the Verifier's, and this package cannot name it. The Verifier's
member vocabulary is written separately and their agreement is the gate.
-}
module EventChain.EntryObject
    ( -- * The member vocabulary
      Member (..)
    , memberName
    , MemberValue
    , memberValue
    , memberValueText

      -- * Objects
    , ObjectError (..)
    , EntryObject
    , entryObject
    , entryObjectMembers
    , lookupMember
    ) where

import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Text (Text)

{- | Every member name an AOF entry may carry, and no others.

Provenance differs by group, and it matters, because a name nobody published
is a name no other implementation can guess:

* @entry_id@ @payload_hash@ @payload_ref@ @prev_hash@ @public_key@
  @signature@ — the upstream protocol's, per @docs/protocol.md@.
* @kind@, @target_hash@ — the ADR-0001 addendum's, named in @docs/plan.md@.
  Additive, so upstream six-member files stay parseable.
* @attester_key@ @assertion_sig@ @authenticator_data@ @client_data_json@ —
  __chosen here, and not yet recorded anywhere else__. ADR-0002 fixes that a
  Mint carries the WebAuthn envelope but names none of its members. These
  four are this module's invention until @docs/wire-format.md@ (M4) makes
  them normative, and until then they are the weakest thing in the format.

Every name is ASCII, and "EventChain.Canonical" leans on that: RFC 8785
orders members by UTF-16 code unit, which a plain sort agrees with only
while names stay ASCII. A name outside that range would oblige the
canonicalizer to grow the UTF-16 ordering it currently does without.

Constructors collide with the domain types on purpose — a 'PayloadHash'
member is the format's name for a payload hash, not the hash. Import
qualified.
-}
data Member
    = -- | Producer-chosen label. No security weight.
      EntryId
    | -- | SHA-256 of the payload content, base64url.
      PayloadHash
    | -- | Index key into external payload storage.
      PayloadRef
    | -- | SHA-256 of the previous line's bytes, base64url.
      PrevHash
    | -- | The Producer's compressed P-256 point, base64url.
      PublicKey
    | -- | The Produced Proof's raw @r‖s@ signature, base64url.
      Signature
    | -- | Absent for a lifecycle Entry; @"mint"@ for a Mint.
      Kind
    | -- | The Mint's target: the attested Entry's hash, base64url.
      TargetHash
    | -- | The attester's compressed P-256 point, base64url.
      AttesterKey
    | -- | The WebAuthn assertion's raw @r‖s@ signature, base64url.
      AssertionSig
    | -- | The authenticator's signed data, base64url.
      AuthenticatorData
    | -- | The client data the authenticator hashed, base64url.
      ClientDataJson
    deriving stock (Eq, Ord, Enum, Bounded, Show)

-- | The member's name as it appears on the wire.
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

{- | A member's value: a JSON string, always.

Every binary field is base64url and every label is text (ADR-0002), so the
AOF needs no other JSON type and nothing downstream implements one. Any
text is a valid JSON string, so there is nothing to validate — what the
text /means/ belongs to the type it was rendered from.
-}
newtype MemberValue = MemberValue Text
    deriving stock (Eq, Ord, Show)

-- | Carry some text as a member's value.
memberValue :: Text -> MemberValue
memberValue = MemberValue

-- | The value's text, for decoding back to the type it came from.
memberValueText :: MemberValue -> Text
memberValueText (MemberValue t) = t

-- | Every way a list of members can fail to be an object.
newtype ObjectError
    = -- | A member was supplied twice.
      DuplicateMember Member
    deriving stock (Eq, Show)

-- | An Entry's members: each name at most once, each value a string.
newtype EntryObject = EntryObject (Map Member MemberValue)
    deriving stock (Eq, Show)

{- | Collect members into an object, refusing a name given twice.

Last-wins is the tempting default and the wrong one: which of two @prev_hash@
members the signature covered is exactly the question it discards. Nothing
downstream can answer it either, so the answer is no object.
-}
entryObject :: [(Member, MemberValue)] -> Either ObjectError EntryObject
entryObject = fmap EntryObject . foldr insert (Right Map.empty)
  where
    insert (m, v) acc = do
        ms <- acc
        if Map.member m ms
            then Left (DuplicateMember m)
            else Right (Map.insert m v ms)

{- | The object's members.

Order is unspecified and carries no meaning — a JSON object is unordered,
and the only order that matters to this protocol is RFC 8785's, which is
"EventChain.Canonical"'s to impose. Do not depend on what comes out.
-}
entryObjectMembers :: EntryObject -> [(Member, MemberValue)]
entryObjectMembers (EntryObject ms) = Map.toList ms

-- | The value of one member, if the object carries it.
lookupMember :: Member -> EntryObject -> Maybe MemberValue
lookupMember m (EntryObject ms) = Map.lookup m ms
