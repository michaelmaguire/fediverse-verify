"""The signed copy as a W3C Verifiable Credential with a Data Integrity proof.

Format (see docs/alignment.md in the super repo):
- W3C Verifiable Credentials Data Model 2.0: issuer = the verifier's ActivityPub
  actor, credentialSubject = the account and its claims, evidence = how they were
  checked.
- Signed with a DataIntegrityProof using the eddsa-jcs-2022 cryptosuite
  (W3C VC Data Integrity EdDSA), the same format Mastodon already verifies for
  FEP-8b32 Object Integrity Proofs (app/lib/activitypub/object_integrity_proof.rb).
- The key is an Ed25519 Multikey listed under the verifier actor's assertionMethod
  (FEP-521a), so Mastodon can fetch and check it with its existing code.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CREDENTIALS_V2 = "https://www.w3.org/ns/credentials/v2"
# Term namespace for our claims; to be registered at w3id.org with the FEP.
VOCAB = "https://w3id.org/fediverse-verified#"
CONTEXT = [CREDENTIALS_V2, {"@vocab": VOCAB}]
CREDENTIAL_TYPE = "FediverseVerifiedCredential"

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_PUB = b"\xed\x01"          # multicodec prefix for an Ed25519 public key


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def multikey(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "z" + b58encode(_ED25519_PUB + raw)


def public_key_from_multikey(value: str) -> Ed25519PublicKey:
    if not value.startswith("z"):
        raise ValueError("expected base58btc multibase")
    raw = b58decode(value[1:])
    if not raw.startswith(_ED25519_PUB) or len(raw) != 34:
        raise ValueError("not an Ed25519 Multikey")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def _hash_input(document: dict, proof_options: dict) -> bytes:
    """eddsa-jcs-2022: SHA-256(JCS(proof options)) || SHA-256(JCS(document without proof))."""
    unsecured = {k: v for k, v in document.items() if k != "proof"}
    options = {k: v for k, v in proof_options.items() if k != "proofValue"}
    return hashlib.sha256(rfc8785.dumps(options)).digest() + hashlib.sha256(rfc8785.dumps(unsecured)).digest()


class ActorKey:
    """The verifier actor's Ed25519 key (FEP-521a Multikey, used for eddsa-jcs-2022)."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        self.public_multibase = multikey(private_key.public_key())

    @classmethod
    def load_or_create(cls, path: Path) -> "ActorKey":
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            key = Ed25519PrivateKey.generate()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
            path.chmod(0o600)
        assert isinstance(key, Ed25519PrivateKey)
        return cls(key)

    def sign(self, document: dict, verification_method: str, created: datetime | None = None) -> dict:
        """Return a copy of `document` with a DataIntegrityProof (eddsa-jcs-2022)."""
        unsecured = {k: v for k, v in document.items() if k != "proof"}
        proof = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": _iso(created or datetime.now(timezone.utc)),
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod",
        }
        if "@context" in unsecured:
            proof["@context"] = unsecured["@context"]
        signature = self._key.sign(_hash_input(unsecured, proof))
        return {**unsecured, "proof": {**proof, "proofValue": "z" + b58encode(signature)}}


def verify(document: dict, public_key: Ed25519PublicKey) -> bool:
    """Check an eddsa-jcs-2022 DataIntegrityProof, following the same steps as Mastodon."""
    proof = document.get("proof")
    if not isinstance(proof, dict) or proof.get("type") != "DataIntegrityProof" \
            or proof.get("cryptosuite") != "eddsa-jcs-2022" or not str(proof.get("proofValue", "")).startswith("z"):
        return False
    unsecured = {k: v for k, v in document.items() if k != "proof"}
    if "@context" in proof and unsecured.get("@context") != proof["@context"]:
        return False
    try:
        public_key.verify(b58decode(proof["proofValue"][1:]), _hash_input(unsecured, proof))
        return True
    except (InvalidSignature, ValueError):
        return False


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_credential(*, proof_url: str, issuer: str, claims: dict[str, Any]) -> dict:
    """The unsigned credential for a proof, from the same claims as the JWT signed copy."""
    subject = {"id": claims["sub"], "account_profile_url": claims["account_profile_url"],
               "verification_level": claims["verification_level"]}
    for key in ("name", "issuing_country", "issuing_authority", "age_over_18"):
        if key in claims:
            subject[key] = claims[key]
    return {
        "@context": CONTEXT,
        "id": proof_url,
        "type": ["VerifiableCredential", CREDENTIAL_TYPE],
        "issuer": issuer,
        "validFrom": _iso(datetime.fromtimestamp(claims["iat"], timezone.utc)),
        "credentialSubject": subject,
        "evidence": [{
            "type": "FediverseVerifiedEvidence",
            "identity_check_method": claims["identity_check_method"],
            "account_ownership_check": claims["account_ownership_check"],
        }],
    }
