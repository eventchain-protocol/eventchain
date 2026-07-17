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

The front door, and it holds what appending an entry takes:
"EventChain.ChainedEvent" for what a Producer is handed,
'EventChain.Produce.produce' for turning one into a line, and
"EventChain.Canonical" for the signing message and the type whose existence is
the claim that RFC 8785 produced it.

Two modules sit beside it rather than in it, and are imported qualified.
"EventChain.EntryObject" is the member vocabulary, whose constructors collide
with the domain types on purpose — a @PayloadHash@ member is the format's
/name/ for a payload hash and not the hash. "EventChain.Wire" is the codec
underneath 'EventChain.Produce.produce', and a caller who only wants to append
an entry does not need it.

== Appending, end to end

The first event of a chain takes 'EventChain.ChainedEvent.genesisHash' as its
@prevHash@; every one after it takes the @lineHash@ of the line before. Write
the @line@ to the file, then a @0x0a@ — JSON Lines §3 puts the terminator
between lines, so it is never among the bytes the chain covers.

See @docs/protocol.md@ for the protocol summary, @CONTEXT.md@ for the
vocabulary, and <https://eventchain.heliosapp.run/> for the specification.
-}
module EventChain
    ( module EventChain.ChainedEvent
    , module EventChain.Produce
    , module EventChain.Canonical
    ) where

import EventChain.Canonical
import EventChain.ChainedEvent
import EventChain.Produce
