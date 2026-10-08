# One-time generator for envelope.json: a WebAuthn assertion over the sound
# vector's target hash, produced by an implementation that shares nothing with
# this repository — soft-webauthn's SoftWebauthnDevice, built on python-fido2's
# primitives (ADR-0007). The output is committed; the device's key is random,
# so rerunning writes a different-but-equally-valid fixture and every
# downstream vector is rebuilt from whatever is committed.
#
# Usage: python generate.py <repo-root>   (needs: pip install soft-webauthn)

import json
import sys
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from soft_webauthn import SoftWebauthnDevice

root = Path(sys.argv[1])

# The challenge is the target entry's line hash: the text the mint line's
# target_hash member carries, decoded. Read from the committed sound vector so
# the two stay one value.
mint_line = json.loads(root.joinpath("vectors/mint/sound.jsonl").read_bytes().splitlines()[1])
target_text = mint_line["target_hash"]
challenge = urlsafe_b64decode(target_text + "=" * (-len(target_text) % 4))
assert len(challenge) == 32

device = SoftWebauthnDevice()
device.cred_init("eventchain.test", b"eventchain-cross-check")
assertion = device.get(
    {"publicKey": {"rpId": "eventchain.test", "challenge": challenge}},
    "https://eventchain.test",
)

client_data = assertion["response"]["clientDataJSON"]
auth_data = assertion["response"]["authenticatorData"]
der_sig = assertion["response"]["signature"]

# The wire rule: DER never appears on a line; the signature is normalized to
# raw r||s at the source (docs/plan.md, wire-format list).
r, s = utils.decode_dss_signature(der_sig)
raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

public = device.private_key.public_key()
attester_key = public.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

# Self-checks before anything is written: the challenge text binds the target,
# and the signature verifies over authData || SHA256(clientDataJSON).
assert json.loads(client_data)["challenge"] == target_text
public.verify(der_sig, auth_data + __import__("hashlib").sha256(client_data).digest(), ec.ECDSA(SHA256()))

b64 = lambda bs: urlsafe_b64encode(bs).decode("ascii").rstrip("=")
envelope = {
    "attester_key": b64(attester_key),
    "assertion_sig": b64(raw_sig),
    "authenticator_data": b64(auth_data),
    "client_data_json": b64(client_data),
}
out = root / "vectors/mint/cross/envelope.json"
out.write_text(json.dumps(envelope, separators=(",", ":")))
print(f"wrote {out}")
