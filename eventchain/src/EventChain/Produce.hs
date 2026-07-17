{- | The Producer's whole job: a t'EventChain.ChainedEvent.ChainedEvent' and a
key in, a signed AOF line out.

Pure. Signing is a function because the nonce is deterministic (RFC 6979,
ADR-0004), and hashing always was, so nothing in the path to a line needs 'IO'.
The caller opens the file, appends the bytes, writes the @0x0a@, and decides
what to do when the disk says no — none of which this module can do better than
the caller can.

== Where the Producer's state lives

The chain has exactly one piece of carried state: the hash of the last line
written. It is not held here. It arrives as the @prevHash@ of the next
t'EventChain.ChainedEvent.ChainedEvent', because a producer that crashed and
restarted must be able to recover it from the file rather than from this
process's memory.

What lives here is the /rule/ for advancing it: the next @prev_hash@ is the
digest of the line you actually wrote, which is why 'produce' hands the digest
back rather than leaving the caller to compute it. Hashing anything else — a
re-encoding of the same event, the object before it was rendered — produces a
number that is not this line's identity, and the chain would break at the next
entry with nothing to say why.
-}
module EventChain.Produce
    ( ProducedLine (..)
    , produce
    ) where

import EventChain.Canonical (canonicalBytesRaw, signingMessage)
import EventChain.ChainedEvent (ChainedEvent)
import EventChain.Crypto
    ( CryptoError
    , PrivateKey
    , hashLines
    , privateKeyPublic
    , sign
    )
import EventChain.Crypto.Types (LineBytes, LineHash, signedBytes)
import EventChain.Wire (encodeLine, signedObject, unsignedObject)

{- | A line, and the digest the next event will name it by.

The digest is the whole reason this is a pair rather than a t'LineBytes'. It is
of these exact bytes — the ones about to be written — so a caller that appends
@line@ and carries @lineHash@ into the next event's @prevHash@ has chained
correctly by construction, and one that recomputes a digest from anything else
has not.
-}
data ProducedLine = ProducedLine
    { line :: LineBytes
    , lineHash :: LineHash
    }
    deriving stock (Eq, Show)

{- | Build the next signed line of an AOF.

Four steps, in the only order they can happen: render the event's members
without a signature, canonicalize them into the signing message (RFC 8785, minus
@signature@ — which is not there yet, and 'EventChain.Canonical.signingMessage'
is total about that), sign, then render the line with the signature among the
members.

The public key on the line is derived from the private one rather than accepted
alongside it. A Produced Proof attributes the entry to whoever signed it, so a
caller able to pass a key that did not make the signature could produce a line
attributing its event to someone else, and every signature check would fail
somewhere far away from the mistake.

== One hash per line is forced

ADR-0004 requires batching, and this calls 'hashLines' with a single line, which
looks like exactly what it warns against. It is not, and there is no batch to
form: line N+1's @prev_hash@ is inside the bytes line N+1 signs, so it must be
known before line N+1 exists. The chain is sequential by construction and no
amount of API shape changes that.

It also costs almost nothing here. A ~300-byte digest is ~150ns against a ~34µs
signature at M1's measured 29.5k/s — under half a percent of a produce. The
batching that ADR-0004 is about is the /Verifier's/, which has a whole file at
once and nothing forcing it to go one at a time.

'Left' means libcrypto refused to sign with a key it had already accepted, which
is a malfunction rather than a mistake a caller made. It stays in the type
because it is the one place in this path that talks to the seam.
-}
produce :: PrivateKey -> ChainedEvent -> Either CryptoError ProducedLine
produce key event = do
    sig <- sign key message
    let written = encodeLine (signedObject claimed event sig)
    pure ProducedLine{line = written, lineHash = digestOf written}
  where
    claimed = privateKeyPublic key

    message =
        signedBytes
            . canonicalBytesRaw
            . signingMessage
            $ unsignedObject claimed event

    digestOf ln = case hashLines [ln] of
        [h] -> h
        -- Unreachable: `hashLines` is one digest per line, and there is one line.
        hs -> error ("EventChain.Produce.produce: " <> show (length hs) <> " digests for one line")
