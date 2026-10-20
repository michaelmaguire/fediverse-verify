"""The wallet types this verifier can offer, and how to build each."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..config import Settings
from . import IdentityProvider
from .eudi import EudiProvider
from .mock import MockProvider
from .swiyu import SwiyuProvider


@dataclass(frozen=True)
class WalletType:
    name: str
    label: str            # shown on the start page
    wallet_app: str       # shown on the wallet page ("Scan with your …")
    countries: str        # who can use it
    test_only: bool = False


WALLET_TYPES = {
    "eudi": WalletType("eudi", "EU Digital Identity Wallet", "EU Digital Identity wallet", "EU member states"),
    "swiyu": WalletType("swiyu", "Swiss e-ID (swiyu)", "swiyu wallet", "Switzerland"),
    "mock": WalletType("mock", "Test wallet (EU-style)", "test wallet", "test mode", test_only=True),
    "mock-ch": WalletType("mock-ch", "Test wallet (Swiss-style)", "test wallet", "test mode", test_only=True),
}


def build_providers(settings: Settings, http: httpx.AsyncClient) -> dict[str, IdentityProvider]:
    names = settings.identity_providers or ("mock",)
    unknown = [n for n in names if n not in WALLET_TYPES]
    if unknown:
        raise ValueError(f"unknown identity provider(s): {', '.join(unknown)}")
    if len({WALLET_TYPES[n].test_only for n in names}) > 1:
        raise ValueError("test (mock) and real identity providers can't be enabled together")
    providers: dict[str, IdentityProvider] = {}
    for name in names:
        if name == "eudi":
            providers[name] = EudiProvider(http, settings.eudi_endpoint, settings.eudi_wallet_scheme)
        elif name == "swiyu":
            providers[name] = SwiyuProvider(http, settings.swiyu_endpoint, settings.swiyu_issuer_dids)
        elif name == "mock":
            providers[name] = MockProvider("mock", "IT")
        elif name == "mock-ch":
            providers[name] = MockProvider("mock-ch", "CH")
    return providers
