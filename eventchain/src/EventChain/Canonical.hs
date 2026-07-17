{- | The signing message: an entry object minus its @signature@ member,
serialized per RFC 8785 (JSON Canonicalization Scheme).

A Produced Proof signs the Entry it travels in, so the signed bytes cannot
include the signature. ADR-0002 fixes what remains: the entry with its
@signature@ member removed, re-serialized per RFC 8785 — members sorted,
minified, no whitespace. A producer's field order on the line therefore
stays free without weakening the chain rule, which covers
t'EventChain.Crypto.Types.LineBytes' exactly as written.

Canonicalization exists /only/ here. Producer and verifier must derive the
same bytes from the same Entry or every signature drifts apart, so the
type t'CanonicalBytes' is defined in this module with its constructor
unexported: holding one is proof this module made it, and the compiler is
what says so rather than a comment asking nicely.

== The subset

RFC 8785's two hard parts are number serialization (ECMA-262
@NumberToString@) and UTF-16 member ordering. An "EventChain.EntryObject"
has neither: every value is a string, and every 'Member' name is ASCII, so
'Data.List.sortOn' over the names /is/ UTF-16 order. Both of those are
properties of the input type rather than promises this module keeps — if
'Member' ever admits a non-ASCII name, the sort below is wrong and needs
UTF-16 code units, as @aeson@'s canonicalizer does for arbitrary keys.

What is left to this module is a sort and an exclusion, which is why RFC 8785
is an encoder here rather than a dependency. Writing the object out is JSON
syntax rather than canonicalization, and belongs to the Producer's JSON
renderer, which "EventChain.Wire" also writes lines with — deliberately, so
that the bytes a signature covers and the bytes a line carries cannot be
escaped two different ways.

== Divergence from @Data.Aeson.RFC8785@

The conformance gate compares against @aeson@'s canonicalizer, which
serializes U+0008 and U+000C as @\\u0008@ and @\\u000c@. RFC 8785 §3.2.2.2
requires @\\b@ and @\\f@. We follow the RFC; the tests pin those two code
points against the RFC's table rather than against the oracle.
-}
module EventChain.Canonical
    ( CanonicalBytes
    , canonicalBytesRaw
    , signingMessage
    ) where

import Data.ByteString (ByteString)
import Data.List (sortOn)
import EventChain.EntryObject
    ( EntryObject
    , Member (Signature)
    , entryObjectMembers
    , memberName
    )
import EventChain.Internal.Json (renderObject)

{- | The RFC 8785 serialization of an entry minus its @signature@ member:
the exact message a Produced Proof signs.

Canonicalization lives only inside signing, so a producer's field order stays
free without weakening the chain rule that covers
t'EventChain.Crypto.Types.LineBytes'.

The constructor is unexported and 'signingMessage' is the only thing in
scope to build one, so a value of this type cannot be anything but what this
module produced. That matters for the verifier: fabricating these bytes is
checking a signature against a message of your choosing.
-}
newtype CanonicalBytes = CanonicalBytes ByteString
    deriving stock (Eq, Show)

-- | The signing message's bytes, for the crypto edge.
canonicalBytesRaw :: CanonicalBytes -> ByteString
canonicalBytesRaw (CanonicalBytes bs) = bs

{- | The bytes a Produced Proof signs — the paper's @entry.data()@.

The paper names @entry.data()@ in its @VerifyAttribution@ pseudocode and
defines it nowhere; @docs/paper-amendments.md@ PA-01 carries the definition
this function implements, for submission upstream. Every member except
@signature@ is covered, including any this vocabulary gains later: removal is
by exclusion, so a new member is signed by default rather than by remembering
to add it.

That @prev_hash@ is among them is load-bearing, not incidental. The producer
signs its own chain position, so no Hub can relocate an entry or move it to
another chain without invalidating a signature it cannot forge — ordering
rests on the producer's key rather than on the Hub behaving. Filtering more
than @Signature@ here would hand that guarantee back to the Hub silently, and
every test would still pass (ADR-0002 §2, PA-08).

Total in both directions of use. A producer canonicalizes an object with no
signature in it yet; a verifier canonicalizes one read off a line, where the
signature is present and must come out. Dropping a member that isn't there
is not an error — it is the producer's case.

Uniform across Kinds. A Mint's WebAuthn envelope (@assertion_sig@,
@authenticator_data@, @client_data_json@, @attester_key@) are ordinary
members, so the Producer's signature covers them and the attestation is bound
to its chain position. The envelope's own signature is a WebAuthn assertion
over @authenticatorData || SHA-256(clientDataJSON)@ and is checked elsewhere —
it never covers these bytes, which is why the paper's single @VerifyAttribution@
cannot verify a passkey (PA-07).
-}
signingMessage :: EntryObject -> CanonicalBytes
signingMessage =
    CanonicalBytes
        . renderObject
        . sortOn (memberName . fst)
        . filter ((/= Signature) . fst)
        . entryObjectMembers
