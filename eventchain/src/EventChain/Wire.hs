{-# LANGUAGE OverloadedStrings #-}

{- | The line codec, encode direction: a t'EventChain.ChainedEvent.ChainedEvent'
into the AOF's JSON shape, and that shape into the bytes of a line.

One direction only, and the absence is the point. The Producer emits JSON and
never reads it, so there is no decoder here, no JSON parser in this package, and
no JSON-accepting attack surface. The Verifier's codec decodes, because reading
bytes someone else wrote is inherently its job; it is written separately and
this package cannot name it (ADR-0005).

This module owns two things the format leaves to it: base64url, and the order
members are written in.

== The exact-bytes invariant starts here

ADR-0002 makes line bytes load-bearing — @prev_hash@ covers them, and a Mint
names its target by their digest. On this side the invariant needs no pairing to
enforce it: 'encodeLine' builds the line, so the bytes signed and chained are
the bytes written and there is no claim to check. A verifier has the harder job,
because it is handed bytes and must not hash a re-serialization of what it
parsed out of them.

== Member order

The format leaves it free. @docs/paper-amendments.md@ PA-01: "the order in which
a producer writes members on the line does not affect @entry.data()@, and
producers are free to choose it" — RFC 8785 sorts the /signing message/, so what
a line does is the producer's business.

We write the vocabulary's own declaration order, which is @docs/protocol.md@'s
table order for the six members the paper defines, with the addendum's after
them. A line reads as the paper's entry with our additions bolted on the end.

The order is derived from the 'Bounded' and 'Enum' instances of t'Member' rather
than written out as a list here, and the reason is the same one "EventChain.Canonical" gives
for excluding rather than including: a hand-written list is a second enumeration
of the vocabulary that no warning checks, so a t'Member' added later and
forgotten here would vanish from the line while 'EventChain.Canonical.signingMessage'
— which drops only @signature@ — went on signing it. Walking 'Bounded' cannot
forget.

== A coincidence, not a rule

The six members the paper defines sort to their own declaration order, so a
lifecycle line is byte-identical to the RFC 8785 serialization of its entry.
That is arithmetic about six names, not a property of the format, and @kind@
breaks it as soon as Mint arrives — RFC 8785 puts @kind@ second where this
module puts it seventh.

Nothing may be built on the coincidence. The chain covers the line's bytes as
written (ADR-0002 §1), never @SHA256(JCS(entry))@; a verifier that
recanonicalizes before hashing would agree with every line this module currently
emits and then fail on the first legal file written by anyone else.
-}
module EventChain.Wire
    ( -- * The AOF's JSON shape
      unsignedObject
    , signedObject

      -- * Line bytes
    , encodeLine
    ) where

import Data.Base64.Types (extractBase64)
import Data.ByteString (ByteString)
import Data.ByteString.Base64.URL qualified as Base64Url
import Data.Text (Text)
import EventChain.ChainedEvent
    ( Attestation (..)
    , ChainedEvent (..)
    , EventKind (..)
    , entryIdText
    , payloadRefText
    )
import EventChain.Crypto.Types
    ( ClaimedKey
    , LineBytes
    , Sig
    , authenticatorBytesRaw
    , claimedKeyRaw
    , clientDataBytesRaw
    , lineBytes
    , lineHashRaw
    , payloadHashRaw
    , sigRaw
    )
import EventChain.EntryObject
    ( EntryObject
    , Member (..)
    , MemberValue
    , entryObject
    , lookupMember
    , memberValue
    )
import EventChain.Internal.Json (renderObject)

{- | The entry as it stands before it is signed: everything but @signature@.

This is what "EventChain.Canonical" turns into the signing message. It is not a
line and must never be written as one — an entry without its Produced Proof is
not an Entry, and a file of these would carry no attribution at all.
-}
unsignedObject :: ClaimedKey -> ChainedEvent -> EntryObject
unsignedObject key event = build (commonMembers key event)

{- | The complete entry: the unsigned members, plus the Produced Proof's
signature over their canonical form.

Nothing here checks that the signature covers these members — it cannot, and no
type in this package could. That relation is discharged by a verifier
recomputing the signing message from the line, which is the only place it can
be discharged from bytes alone.
-}
signedObject :: ClaimedKey -> ChainedEvent -> Sig -> EntryObject
signedObject key event sig =
    build (commonMembers key event <> [(Signature, base64url (sigRaw sig))])

{- | The event's members before signing, in any order — 'encodeLine' imposes
the order and 'EventChain.Canonical.signingMessage' imposes its own.

@entry_id@ and @payload_ref@ travel as the text they are; the rest are binary
and travel as base64url (ADR-0002 §4). A Mint adds its Kind's members and,
with them, the revision declaration they oblige.
-}
commonMembers :: ClaimedKey -> ChainedEvent -> [(Member, MemberValue)]
commonMembers key event =
    [ (EntryId, memberValue (entryIdText event.entryId))
    , (PayloadHash, base64url (payloadHashRaw event.payloadHash))
    , (PayloadRef, memberValue (payloadRefText event.payloadRef))
    , (PrevHash, base64url (lineHashRaw event.prevHash))
    , (PublicKey, base64url (claimedKeyRaw key))
    ]
        <> kindMembers event.kind

{- | What the Kind adds to the line: nothing for a lifecycle event, the
addendum's members for a Mint.

The declaration goes on Mint lines and on no others, and both halves are
ADR-0006's. Emitting @v@ here keeps a lifecycle line byte-identical to what a
paper-only implementation writes; withholding it would emit members a reader
cannot account for under the vocabulary the line declares — the unread-claim
failure ADR-0002 §5 exists to refuse, on our own output.
-}
kindMembers :: EventKind -> [(Member, MemberValue)]
kindMembers = \case
    Lifecycle -> []
    Mint a ->
        [ (Kind, memberValue "mint")
        , (TargetHash, base64url (lineHashRaw a.target))
        , (AttesterKey, base64url (claimedKeyRaw a.attesterKey))
        , (AssertionSig, base64url (sigRaw a.assertionSig))
        , (AuthenticatorData, base64url (authenticatorBytesRaw a.authenticatorData))
        , (ClientDataJson, base64url (clientDataBytesRaw a.clientDataJson))
        , (V, memberValue addendumRevision)
        ]

{- | The revision label the addendum's members declare: ADR-0006's @\"1\"@.

A closed label from a closed set, compared by equality only — never parsed,
never ordered. It is data this module writes, not text a caller chooses,
which is what keeps "an entry declares the revision it conforms to" a rule
the codec enforces rather than a convention callers follow.
-}
addendumRevision :: Text
addendumRevision = "1"

{- | The bytes of one AOF line: the object, minified, in the vocabulary's
declaration order.

The terminator is not here. JSON Lines §3 puts the @0x0a@ in the file between
lines, and t'EventChain.Crypto.Types.LineBytes' is a line's /content/ — every
byte before it. Writing it is the caller's, at the same moment it decides the
line is worth keeping.
-}
encodeLine :: EntryObject -> LineBytes
encodeLine object =
    case lineBytes (renderObject (present object)) of
        Right ln -> ln
        -- Unreachable, and each clause of `lineBytes` is refused by construction:
        -- an object always renders at least `{}`, so it is not empty; escaping
        -- turns a `0x0a` in a label into the two characters `\n`, so no raw
        -- terminator survives into the output; and `Text` rendered by
        -- `Data.Text.Encoding` is UTF-8 by definition.
        Left e -> error ("EventChain.Wire.encodeLine: " <> show e)

{- | The object's members in declaration order, absent ones skipped.

Walking the whole vocabulary is what makes this total against a t'Member' added
later: a new one is written by default rather than by someone remembering this
function exists.
-}
present :: EntryObject -> [(Member, MemberValue)]
present object =
    [(m, v) | m <- [minBound .. maxBound], Just v <- [lookupMember m object]]

-- | Some binary field, base64url and unpadded, per ADR-0002 §4.
base64url :: ByteString -> MemberValue
base64url = memberValue . extractBase64 . Base64Url.encodeBase64Unpadded

{- | Collect members into an object.

The rejection is unreachable from this module: every caller passes a literal
list of distinct t'Member' constructors, which is the only thing
'EventChain.EntryObject.entryObject' refuses. It is an @error@ rather than a
constructor on some exported sum because a caller cannot act on it — there is no
input they could supply that would cause it, and none they could change to fix
it.
-}
build :: [(Member, MemberValue)] -> EntryObject
build ms = case entryObject ms of
    Right o -> o
    Left e -> error ("EventChain.Wire: " <> show e)
