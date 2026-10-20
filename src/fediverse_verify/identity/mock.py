"""Development-only provider: a form stands in for the wallet. Proofs say method=mock."""

from __future__ import annotations

import secrets

from . import IdentityResult, WalletRequest


class MockProvider:
    name = "mock"

    def __init__(self) -> None:
        self._results: dict[str, IdentityResult] = {}

    async def begin(self, level: str) -> WalletRequest:
        return WalletRequest(kind="form", handle=secrets.token_urlsafe(16))

    def submit(self, handle: str, given_name: str | None, family_name: str | None,
               issuing_country: str | None = "IT", issuing_authority: str | None = None) -> None:
        self._results[handle] = IdentityResult(method="mock", given_name=given_name or None,
                                               family_name=family_name or None,
                                               issuing_country=(issuing_country or "IT").upper(),
                                               issuing_authority=issuing_authority or None)

    async def result(self, request: WalletRequest) -> IdentityResult | None:
        return self._results.pop(request.handle, None)
