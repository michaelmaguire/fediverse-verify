"""Client for the Swiss e-ID (swiyu) generic verifier's management API.

The swiyu verifier (github.com/swiyu-admin-ch/swiyu-verifier) does the cryptography
and trust checks (DIDs in the swiyu identifier and trust registries, OpenID4VP 1.0,
SD-JWT VC). We create a verification with a DCQL query asking only for the claims
the chosen options need, show its deeplink as a QR code, and read the decoded
claims (`credential_subject_data`) once the wallet has answered.

The Swiss e-ID uses the same attribute names as the EU PID (given_name,
family_name, issuing_country, issuing_authority) and carries age_over_18 directly,
so "18+" never needs a birth date here.

Status: written against the swiyu-verifier openapi.yaml and the swiyu cookbooks
(Oct 2026); not yet tested with a real swiyu wallet. Using it in production needs a
verifier DID registered in the swiyu identifier registry and onboarding on the
swiyu portals.
"""

from __future__ import annotations

import httpx

from . import IdentityError, IdentityResult, WalletRequest

CREDENTIAL_ID = "eid"
# The Beta ID's type is changing; the roadmap asks verifiers to accept both values.
DEFAULT_VCT_VALUES = ("betaid-sdjwt", "urn:vct:ch.admin.bcs.betaid")

ISSUER_CLAIMS = [["issuing_country"], ["issuing_authority"]]
CLAIMS_FOR_LEVEL = {
    "person": ISSUER_CLAIMS,
    "legal_name": [["given_name"], ["family_name"], *ISSUER_CLAIMS],
}

PURPOSES = {
    "person": ("fediverse-verified person", "Confirm that a real person controls your Fediverse account. Only the issuing country and authority are published."),
    "legal_name": ("fediverse-verified name", "Confirm that you control your Fediverse account and publish your legal name on your proof page."),
}


def dcql_for(level: str, include_age: bool = False, vct_values: tuple[str, ...] = DEFAULT_VCT_VALUES) -> dict:
    claims = list(CLAIMS_FOR_LEVEL[level]) + ([["age_over_18"]] if include_age else [])
    return {"credentials": [{
        "id": CREDENTIAL_ID,
        "format": "dc+sd-jwt",
        "meta": {"vct_values": list(vct_values)},
        "claims": [{"path": p} for p in claims],
        "require_cryptographic_holder_binding": True,
    }]}


class SwiyuProvider:
    name = "swiyu"

    def __init__(self, http: httpx.AsyncClient, endpoint: str, accepted_issuer_dids: tuple[str, ...],
                 vct_values: tuple[str, ...] = DEFAULT_VCT_VALUES, purpose_scope: str = "org.fediverse-verify"):
        if not endpoint:
            raise ValueError("VERIFIER_SWIYU_ENDPOINT is required for the swiyu provider")
        if not accepted_issuer_dids:
            raise ValueError("VERIFIER_SWIYU_ISSUER_DIDS is required for the swiyu provider")
        self._http = http
        self._endpoint = endpoint
        self._issuers = list(accepted_issuer_dids)
        self._vct_values = vct_values
        self._scope = purpose_scope
        self._requests: dict[str, tuple[str, bool]] = {}

    async def begin(self, level: str, include_age: bool = False) -> WalletRequest:
        name, description = PURPOSES[level]
        if include_age:
            name, description = f"{name} · 18+", description + " Also confirm that you are 18 or over."
        resp = await self._http.post(f"{self._endpoint}/management/api/verifications", json={
            "accepted_issuer_dids": self._issuers,
            "jwt_secured_authorization_request": True,
            "response_mode": "direct_post",
            "verification_purpose": {
                "scope": f"{self._scope}.{level}{'.age18' if include_age else ''}",
                "purpose_name": {"default": name},
                "purpose_description": {"default": description},
            },
            "dcql_query": dcql_for(level, include_age, self._vct_values),
        })
        if resp.status_code != 200:
            raise IdentityError(f"swiyu verifier returned {resp.status_code}")
        body = resp.json()
        self._requests[body["id"]] = (level, include_age)
        return WalletRequest(kind="qr", wallet_url=body["verification_deeplink"], handle=body["id"])

    async def result(self, request: WalletRequest) -> IdentityResult | None:
        resp = await self._http.get(f"{self._endpoint}/management/api/verifications/{request.handle}")
        if resp.status_code != 200:
            raise IdentityError(f"verification unavailable ({resp.status_code})")
        body = resp.json()
        state = body.get("state")
        if state == "PENDING":
            return None
        level, include_age = self._requests.pop(request.handle, ("person", False))
        if state != "SUCCESS":
            detail = (body.get("wallet_response") or {}).get("error_description") or "the wallet response was rejected"
            raise IdentityError(f"Swiss e-ID check failed: {detail}")
        claims = ((body.get("wallet_response") or {}).get("credential_subject_data") or {}).get(CREDENTIAL_ID) or {}
        if level == "legal_name" and not (claims.get("given_name") and claims.get("family_name")):
            raise IdentityError("wallet did not disclose a name")
        return IdentityResult(method="swiyu-eid",
                              issuing_country=claims.get("issuing_country"),
                              issuing_authority=claims.get("issuing_authority"),
                              given_name=claims.get("given_name") if level == "legal_name" else None,
                              family_name=claims.get("family_name") if level == "legal_name" else None,
                              age_over_18=True if (include_age and claims.get("age_over_18") is True) else None)
