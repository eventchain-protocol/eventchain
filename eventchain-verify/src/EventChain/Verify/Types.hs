{- | The claim tier: what a line asserts, before anything has been discharged.

An Entry decoded from a line asserts a predecessor, a payload commitment and a
Producer. None of it is believed here. Whether a claimed @prev_hash@ equals
SHA-256 of the previous line's bytes, or a signature verifies, is a relation
between values that only the verification machinery settles — and only
"EventChain.Verify" can build the fact types that say it ran.

/Why the claim tier lives in the Verifier and not in the Producer./ A claim is
what reading bytes someone else wrote produces. The Producer /computes/ a
hash, /holds/ a key and /makes/ a signature; it never claims any of them, and
it never decodes a line. So there is no Entry on that side of the split to
share — the Producer takes a @ChainedEvent@ and emits a line, and this
vocabulary would be dead weight there.

/Why it is written separately anyway./ These member names, and the model they
describe, are re-derived from the normative wire-format document rather than
from the Producer's source (ADR-0005). If this model and the Producer's ever
disagree, one of them is wrong about the format and the golden vectors are
what say so. That is the gate working; sharing the model to make a divergence
go away would pass every test and destroy the evidence the tests are for.

Constructors are unexported throughout. Fields are readable — a claim is not a
secret, and any claim at all can be fabricated by writing a file and decoding
it — but an Entry comes into being only in "EventChain.Verify.Wire".

The pairing of a line's bytes with what was parsed from them is /not/ here: it
lives in "EventChain.Verify.Wire" with the code that makes it, per rule 8 of
@docs/plan.md@. A type whose meaning is "this pair was built from one line by
the codec" has to have its constructor unexported from the module that reads the
line, or "sole constructor" is a convention rather than a guarantee. M0 parked it
here because the codec did not exist yet.

Note the omission: no @ToJSON@ or @FromJSON@ instances. A derived instance
would be a second serialization path silently bypassing the exact-bytes
invariant the chain rests on (ADR-0003).
-}
module EventChain.Verify.Types
    ( -- * Entries
      EntryId
    , entryId
    , entryIdText
    , PayloadRef
    , payloadRef
    , payloadRefText
    , ProducedProof (publicKey, signature)
    , EntryKind (..)
    , Entry (entryId, payloadHash, payloadRef, prevHash, producedProof, kind)
    , ChainPosition
    , chainPositionIndex

      -- * Attestations
    , Attestation (target, attesterKey, assertionSig, envelope)
    , WebAuthnEnvelope (authenticatorData, clientDataJson)
    ) where

import EventChain.Verify.Types.Internal.Attestation
import EventChain.Verify.Types.Internal.Entry
