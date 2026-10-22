"""Client for the Swiss e-ID (swiyu) generic verifier's management API.

The swiyu verifier (github.com/swiyu-admin-ch/swiyu-verifier) does the cryptography
and trust checks (DIDs in the swiyu identifier and trust registries, OpenID4VP 1.0,
SD-JWT VC). We create a verification with a DCQL query asking only for the claims
the chosen options need, show its deeplink as a QR code, and read the decoded
claims (`credential_subject_data`) once the wallet has answered.

The Swiss e-ID uses the same attribute names as the EU PID (given_name,
family_name, issuing_country, issuing_authority) and carries age_over_18 directly,
so "18+" never needs a birth date here.

The swiyu Sandbox (Public Beta) only has the Beta-ID, whose holder chooses its
values freely: it's "not a proof of identification". Results from it are labelled
"swiyu-beta-id", a test method, so they never count as a real identity check. Set
VERIFIER_SWIYU_VCT_VALUES to the real e-ID's credential type once it launches.

Status: written against the swiyu-verifier openapi.yaml and the swiyu cookbooks
(Oct 2026); not yet tested with a real swiyu wallet. Using it in production needs a
verifier DID registered in the swiyu identifier registry and onboarding on the
swiyu portals.
"""

from __future__ import annotations

import httpx

from ..binding.webfinger import json_object
from . import IdentityError, IdentityResult, WalletRequest

CREDENTIAL_ID = "eid"
# The Beta-ID's type is changing; the roadmap asks verifiers to accept both values.
BETA_ID_VCT_VALUES = ("betaid-sdjwt", "urn:vct:ch.admin.bcs.betaid")
DEFAULT_VCT_VALUES = BETA_ID_VCT_VALUES

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


def purpose(level: str, include_age: bool, scope_prefix: str = "org.fediverse-verify") -> tuple[str, str, str]:
    """The scope, purpose name and description shown to the wallet for one query."""
    name, description = PURPOSES[level]
    if include_age:
        name, description = f"{name} · 18+", description + " Also confirm that you are 18 or over."
    return f"{scope_prefix}.{level}{'.age18' if include_age else ''}", name, description


def vqps_submissions(verifier_did: str, vct_values: tuple[str, ...] = DEFAULT_VCT_VALUES,
                     scope_prefix: str = "org.fediverse-verify") -> list[dict]:
    """Verification Query Public Statements for the swiyu trust registry: one per query we
    send (each level, with and without 18+), built from the same code as the queries."""
    submissions = []
    for level in ("person", "legal_name"):
        for include_age in (False, True):
            scope, name, description = purpose(level, include_age, scope_prefix)
            submissions.append({"waitForPublication": True, "sub": verifier_did, "scope": scope,
                                "purpose_name": {"default": name}, "purpose_description": {"default": description},
                                "query": dcql_for(level, include_age, vct_values)})
    return submissions


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

    def _is_beta_id(self, claims: dict) -> bool:
        """A Beta-ID, judged by the credential's type when the verifier passes it on;
        otherwise assume the worst if any Beta-ID type was accepted."""
        vct = claims.get("vct")
        if vct:
            return vct in BETA_ID_VCT_VALUES
        return any(v in BETA_ID_VCT_VALUES for v in self._vct_values)

    async def begin(self, level: str, include_age: bool = False) -> WalletRequest:
        scope, name, description = purpose(level, include_age, self._scope)
        resp = await self._http.post(f"{self._endpoint}/management/api/verifications", json={
            "accepted_issuer_dids": self._issuers,
            "jwt_secured_authorization_request": True,
            "response_mode": "direct_post",
            "verification_purpose": {
                "scope": scope,
                "purpose_name": {"default": name},
                "purpose_description": {"default": description},
            },
            "dcql_query": dcql_for(level, include_age, self._vct_values),
        })
        if resp.status_code != 200:
            raise IdentityError(f"swiyu verifier returned {resp.status_code}")
        body = json_object(resp, "the Swiss verifier", IdentityError)
        self._requests[body["id"]] = (level, include_age)
        return WalletRequest(kind="qr", wallet_url=body["verification_deeplink"], handle=body["id"])

    async def result(self, request: WalletRequest) -> IdentityResult | None:
        resp = await self._http.get(f"{self._endpoint}/management/api/verifications/{request.handle}")
        if resp.status_code != 200:
            raise IdentityError(f"verification unavailable ({resp.status_code})")
        body = json_object(resp, "the Swiss verifier", IdentityError)
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
        return IdentityResult(method="swiyu-beta-id" if self._is_beta_id(claims) else "swiyu-eid",
                              issuing_country=claims.get("issuing_country"),
                              issuing_authority=claims.get("issuing_authority"),
                              given_name=claims.get("given_name") if level == "legal_name" else None,
                              family_name=claims.get("family_name") if level == "legal_name" else None,
                              age_over_18=True if (include_age and claims.get("age_over_18") is True) else None)


if __name__ == "__main__":
    # Print the vqPS submissions for the swiyu trust registry, one JSON object per line:
    #   python -m fediverse_verify.identity.swiyu <verifier DID> [comma-separated vct values]
    import json
    import sys

    if len(sys.argv) < 2:
        sys.exit("usage: python -m fediverse_verify.identity.swiyu <verifier DID> [vct,vct...]")
    vcts = tuple(v for v in sys.argv[2].split(",") if v) if len(sys.argv) > 2 else DEFAULT_VCT_VALUES
    for submission in vqps_submissions(sys.argv[1], vcts):
        print(json.dumps(submission, ensure_ascii=False))
