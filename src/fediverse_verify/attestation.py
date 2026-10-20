"""Signed attestations: a compact JWS (ES256) that readers verify with our JWKS."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

ATTESTATION_TYP = "identity-attestation+jwt"
LEVELS = ("person", "legal_name")


class Signer:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._key = private_key
        public_jwk = json.loads(ECAlgorithm.to_jwk(private_key.public_key()))
        self.kid = _thumbprint(public_jwk)
        self.public_jwk = {**public_jwk, "kid": self.kid, "use": "sig", "alg": "ES256"}

    @classmethod
    def load_or_create(cls, path: Path) -> "Signer":
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            path.chmod(0o600)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        return cls(key)

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.public_jwk]}

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self._key, algorithm="ES256", headers={"kid": self.kid, "typ": ATTESTATION_TYP})

    def verify(self, token: str, issuer: str) -> dict[str, Any]:
        return jwt.decode(token, self._key.public_key(), algorithms=["ES256"], issuer=issuer,
                          options={"require": ["iss", "sub", "iat", "jti"]})


def build_claims(*, issuer: str, proof_id: str, subject_uri: str, profile_url: str,
                 level: str, method: str, name: str | None = None,
                 binding: str = "mastodon-oauth", issuing_country: str | None = None,
                 issuing_authority: str | None = None) -> dict[str, Any]:
    """No `exp`: proofs stay valid until revoked (see docs/overview.md#decided)."""
    if level not in LEVELS:
        raise ValueError(f"unknown level {level!r}")
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject_uri,
        "jti": proof_id,
        "iat": int(time.time()),
        "profile_url": profile_url,
        "level": level,
        "method": method,
        "binding": binding,       # how control of the account was proven
    }
    if issuing_country:
        claims["issuing_country"] = issuing_country
    if issuing_authority:
        claims["issuing_authority"] = issuing_authority
    if level == "legal_name":
        if not name:
            raise ValueError("legal_name level requires a name")
        claims["name"] = name
    return claims


def _thumbprint(jwk: dict[str, Any]) -> str:
    # RFC 7638 thumbprint for an EC key.
    import base64
    import hashlib

    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()
