{- | The Attestation a Mint Entry carries: a named human vouching for an
earlier Entry, with a hardware-held key.

A WebAuthn authenticator cannot sign arbitrary bytes — it signs
@authenticatorData ‖ SHA256(clientDataJSON)@ with the challenge embedded
in the client data (ADR-0002). So a Mint carries the envelope those bytes
are rebuilt from, and the rule that binds it to its target is
@challenge == target entry hash@.

The types here are structure only. Parsing the envelope, extracting the
challenge and checking that rule are "EventChain.Verify.WebAuthn"'s job — a
distinct protocol, quarantined from the hot path.
-}
module EventChain.Verify.Types.Internal.Attestation
    ( AuthenticatorData (..)
    , authenticatorDataRaw
    , ClientDataJson (..)
    , clientDataJsonRaw
    , WebAuthnEnvelope (..)
    , Attestation (..)
    ) where

import Data.ByteString (ByteString)
import EventChain.Crypto.Types (ClaimedKey, LineHash, Sig)

{- | The authenticator's own attested data: RP ID hash, flags, signature
counter. Opaque bytes here; "EventChain.Verify.WebAuthn" gives them structure.
-}
newtype AuthenticatorData = AuthenticatorData ByteString
    deriving stock (Eq, Show)

-- | The authenticator data's bytes, as they were signed.
authenticatorDataRaw :: AuthenticatorData -> ByteString
authenticatorDataRaw (AuthenticatorData bs) = bs

{- | The client data the authenticator hashed into its signed message: JSON
text carrying the challenge, origin and type.

Kept as bytes on purpose — the client data is signed as it was
transmitted, so re-serializing it would break the signature exactly as
re-serializing a line breaks the chain.
-}
newtype ClientDataJson = ClientDataJson ByteString
    deriving stock (Eq, Show)

-- | The client data's bytes, as they were hashed.
clientDataJsonRaw :: ClientDataJson -> ByteString
clientDataJsonRaw (ClientDataJson bs) = bs

-- | The two byte strings a WebAuthn assertion's signed message is rebuilt from.
data WebAuthnEnvelope = WebAuthnEnvelope
    { authenticatorData :: AuthenticatorData
    , clientDataJson :: ClientDataJson
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
