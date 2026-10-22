"""Identity providers: obtain a verified government credential presentation.

A provider receives the chosen level, asks the wallet only for the claims that
level needs, and returns an IdentityResult. Nothing else leaves the provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


# Methods that check no real identity: our test wallets, and the swiyu Beta-ID (the
# person types in any details they like). Proofs made with them are marked as test
# proofs ("test": true in the signed evidence) and must never earn a badge.
TEST_METHODS = frozenset({"mock", "swiyu-beta-id"})


def is_test_method(method: str) -> bool:
    return method in TEST_METHODS


@dataclass(frozen=True)
class IdentityResult:
    method: str                 # e.g. "eudi-pid", "swiyu-eid", or a TEST_METHODS value; published
    issuing_country: str | None = None      # ISO 3166-1 alpha-2, mandatory PID metadata; published
    issuing_authority: str | None = None    # mandatory PID metadata; published
    given_name: str | None = None
    family_name: str | None = None
    # True only if the wallet proved the person is 18 or over (EU Proof of Age attestation,
    # or computed from the PID birth date, which is then discarded). Never "under 18".
    age_over_18: bool | None = None

    @property
    def full_name(self) -> str | None:
        parts = [p for p in (self.given_name, self.family_name) if p]
        return " ".join(parts) or None


@dataclass(frozen=True)
class WalletRequest:
    kind: str                   # "form" (mock) or "qr" (real wallet)
    wallet_url: str = ""        # deep link / QR payload for real wallets
    handle: str = ""            # provider-specific id to poll with


class IdentityProvider(Protocol):
    name: str

    async def begin(self, level: str, include_age: bool = False) -> WalletRequest: ...

    async def result(self, request: WalletRequest) -> IdentityResult | None:
        """None while the user hasn't finished; raises on failure."""
        ...


class IdentityError(Exception):
    pass
