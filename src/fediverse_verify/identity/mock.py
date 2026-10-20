"""Test wallets (development only). Proofs they produce are marked "mock".

They follow the shape of a real wallet flow, so the verifier's pages are the same as
in production: the verifier publishes a request at a request link; a separate
test-wallet app (test-wallets/ in this repo) fetches it, shows a consent
screen, and posts back the claims of a pre-issued test identity, or a refusal.

Unlike a real wallet, nothing is signed: the test identities are plain test data.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import quote

from . import IdentityError, IdentityResult, WalletRequest

REQUEST_TTL = 30 * 60
ALLOWED_CLAIMS = {"given_name", "family_name", "issuing_country", "issuing_authority", "age_over_18"}


@dataclass
class PendingRequest:
    level: str
    include_age: bool
    nonce: str
    claims: list[str]
    created: float = field(default_factory=time.time)
    response: dict | None = None        # {"decision": "share" | "decline", "claims": {...}}


def requested_claims(level: str, include_age: bool) -> list[str]:
    claims = ["given_name", "family_name"] if level == "legal_name" else []
    claims += ["issuing_country", "issuing_authority"]
    return claims + (["age_over_18"] if include_age else [])


class MockProvider:
    def __init__(self, name: str, system: str, verifier_url: str, test_wallet_url: str,
                 issuing_countries: tuple[str, ...]) -> None:
        self.name = name                    # e.g. "mock" (EU-style) or "mock-ch" (Swiss-style)
        self.system = system                # "eu" or "ch": which test apps can open the request
        self._verifier_url = verifier_url.rstrip("/")
        self._test_wallet_url = test_wallet_url.rstrip("/")
        self._countries = issuing_countries
        self._requests: dict[str, PendingRequest] = {}

    # ---- IdentityProvider ----
    async def begin(self, level: str, include_age: bool = False) -> WalletRequest:
        now = time.time()
        for key in [k for k, r in self._requests.items() if now - r.created > REQUEST_TTL]:
            self._requests.pop(key, None)
        request_id = secrets.token_urlsafe(16)
        self._requests[request_id] = PendingRequest(level, include_age, secrets.token_urlsafe(16),
                                                 requested_claims(level, include_age))
        request_uri = f"{self._verifier_url}/test-wallet-api/requests/{request_id}"
        wallet_url = f"{self._test_wallet_url}/{self.system}/present?request_uri={quote(request_uri, safe='')}"
        return WalletRequest(kind="qr", wallet_url=wallet_url, handle=request_id)

    async def result(self, request: WalletRequest) -> IdentityResult | None:
        pending = self._requests.get(request.handle)
        if pending is None:
            raise IdentityError("This request has expired. Please start again.")
        if pending.response is None:
            return None
        self._requests.pop(request.handle, None)
        if pending.response["decision"] != "share":
            raise IdentityError("You declined in your wallet app. Nothing was shared.")
        claims = pending.response["claims"]
        legal = pending.level == "legal_name"
        return IdentityResult(method="mock",
                              issuing_country=claims.get("issuing_country"),
                              issuing_authority=claims.get("issuing_authority"),
                              given_name=claims.get("given_name") if legal else None,
                              family_name=claims.get("family_name") if legal else None,
                              age_over_18=True if (pending.include_age and claims.get("age_over_18") is True) else None)

    def close(self, request: WalletRequest) -> None:
        """Stop accepting answers to a request (another wallet answered first)."""
        self._requests.pop(request.handle, None)

    # ---- the test-wallet side (HTTP endpoints in app.py) ----
    def request_object(self, request_id: str) -> PendingRequest | None:
        return self._requests.get(request_id)

    def respond(self, request_id: str, nonce: str, decision: str, claims: dict) -> None:
        pending = self._requests.get(request_id)
        if pending is None:
            raise LookupError("unknown or expired request")
        if pending.response is not None:
            raise ValueError("this request has already been answered")
        if not secrets.compare_digest(nonce, pending.nonce):
            raise ValueError("nonce mismatch")
        if decision not in ("share", "decline"):
            raise ValueError("decision must be share or decline")
        if decision == "share":
            extra = set(claims) - set(pending.claims)
            if extra or not set(claims) <= ALLOWED_CLAIMS:
                raise ValueError(f"claims not requested: {', '.join(sorted(extra))}")
            if self._countries and claims.get("issuing_country") not in self._countries:
                raise ValueError("this wallet system doesn't issue IDs from that country")
        pending.response = {"decision": decision, "claims": claims if decision == "share" else {}}
