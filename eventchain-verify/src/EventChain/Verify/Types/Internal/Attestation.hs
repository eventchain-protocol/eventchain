{- | The Attestation a Mint Entry carries: a named human vouching for an
earlier Entry, with a hardware-held key.

A WebAuthn authenticator cannot sign arbitrary bytes — it signs
@authenticatorData ‖ SHA256(clientDataJSON)@ with the challenge embedded
in the client data (ADR-0002). So a Mint carries the envelope those bytes
are rebuilt from, and the rule that binds it to its target is
@challenge == target entry hash@.

The types here are structure only, and every leaf is a shared crypto type —
byte blobs and claims whose shapes no two implementations could read
differently. Parsing the envelope, extracting the challenge and checking the
binding rule are the Verifier's WebAuthn checks' job, hand-written on the
shared kernels per ADR-0007; nothing here runs one.
-}
module EventChain.Verify.Types.Internal.Attestation
    ( WebAuthnEnvelope (..)
    , Attestation (..)
    ) where

import EventChain.Crypto.Types (AuthenticatorBytes, ClaimedKey, ClientDataBytes, LineHash, Sig)

{- | The two byte strings a WebAuthn assertion's signed message is rebuilt
from, exactly as transmitted.

Both stay bytes for the chain's own reason: the signature covers these exact
bytes, so re-serializing either would break it precisely as re-serializing a
line breaks the chain.
-}
data WebAuthnEnvelope = WebAuthnEnvelope
    { authenticatorData :: AuthenticatorBytes
    , clientDataJson :: ClientDataBytes
    }
    deriving stock (Eq, Show)

{- | A human's claim that the target Entry is true.

The attester's key travels with the Attestation because attribution must
hold offline from the AOF alone — the file carries public keys and
nothing that names a person; the organisational directory maps key to
human, elsewhere. It is a t'ClaimedKey' for the same reason the Producer's
is: promoting it to a 'EventChain.Crypto.Types.PublicKey' is curve
arithmetic, and that happens behind the crypto seam, in batches.
-}
data Attestation = Attestation
    { target :: LineHash
    , attesterKey :: ClaimedKey
    , assertionSig :: Sig
    , envelope :: WebAuthnEnvelope
    }
    deriving stock (Eq, Show)
