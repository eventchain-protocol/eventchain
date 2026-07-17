{- | EventChain, the Producer: a signed AOF line out.

An append-only JSON-Lines file (the AOF) of hash-chained, identity-signed
Entries that any holder can verify offline. This package writes them. It does
not read them and it does not verify them — that is @eventchain-verify@, a
separate package that shares no format logic with this one (ADR-0005). The two
sides agreeing is what the golden vectors are evidence /of/, and code they
shared could not produce that evidence.

__This package never parses JSON.__ It emits JSON. There is no JSON parser
here and no JSON-accepting attack surface, and that absence is a security
property rather than an oversight or a gap waiting to be filled.

What a Producer is: whatever emits the event, signing with its own key — a
device signing its own measurements, a service ingesting an external stream, a
client carrying a human's passkey. The Hub holds no key and signs nothing.

The front door. "EventChain.Canonical" is re-exported whole: the signing
message, and the type whose existence is the claim that RFC 8785 produced it.
That is this package's public surface today. "EventChain.EntryObject" sits
beside it and is imported qualified — its member constructors collide with the
domain types on purpose, because a @PayloadHash@ member is the format's /name/
for a payload hash and not the hash.

Still to come (M2): @ChainedEvent@ — a business event's commitment plus its
chain linkage, which is the Producer's whole input — then @Wire@ and
@Produce@.

See @docs/protocol.md@ for the protocol summary, @CONTEXT.md@ for the
vocabulary, and <https://eventchain.heliosapp.run/> for the specification.
-}
module EventChain
    ( module EventChain.Canonical
    ) where

import EventChain.Canonical
