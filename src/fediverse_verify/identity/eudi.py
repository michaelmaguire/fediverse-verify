"""Client for the EUDI reference verifier endpoint (OpenID4VP).

The endpoint does the cryptography: request signing, wallet response validation,
issuer trust and key binding. We send a DCQL query asking only for the claims the
chosen level needs, then read those claims from the SD-JWT disclosures.

Status: written against the endpoint's README (POST /ui/presentations, GET
/ui/presentations/{id}); not yet tested with a real wallet.
"""

from __future__ import annotations

import base64
import json
import secrets
from urllib.parse import quote

import httpx

from . import IdentityError, IdentityResult, WalletRequest

PID_VCT = "urn:eudi:pid:1"
QUERY_ID = "pid"

ISSUER_CLAIMS = [["issuing_country"], ["issuing_authority"]]   # mandatory PID metadata, published
CLAIMS_FOR_LEVEL = {
    "person": ISSUER_CLAIMS,
    "legal_name": [["given_name"], ["family_name"], *ISSUER_CLAIMS],
}
# TODO(real wallets): national PIDs may use extended types such as urn:eudi:pid:de:1;
# check how the endpoint matches vct_values against those.


def dcql_for(level: str) -> dict:
    return {
        "credentials": [{
            "id": QUERY_ID,
            "format": "dc+sd-jwt",
            "meta": {"vct_values": [PID_VCT]},
            "claims": [{"path": p} for p in CLAIMS_FOR_LEVEL[level]],
        }],
    }


def disclosed_claims(sd_jwt: str) -> dict:
    """Claims of an (already validated) SD-JWT: issuer-jwt~d1~d2~...~kb-jwt.

    Plain claims from the issuer-signed payload plus selectively disclosed ones; an
    issuer may put metadata such as issuing_country in either place.
    """
    claims: dict = {}
    payload = sd_jwt.split("~")[0].split(".")
    if len(payload) == 3:
        try:
            body = json.loads(base64.urlsafe_b64decode(payload[1] + "=" * (-len(payload[1]) % 4)))
            claims.update({k: v for k, v in body.items() if isinstance(k, str) and not k.startswith("_")})
        except (ValueError, json.JSONDecodeError):
            pass
    for part in sd_jwt.split("~")[1:]:
        if not part or part.count(".") == 2:      # skip empty tail and the key-binding JWT
            continue
        padded = part + "=" * (-len(part) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        if len(decoded) == 3:                     # [salt, name, value]; array elements have 2
            claims[decoded[1]] = decoded[2]
    return claims


class EudiProvider:
    name = "eudi"

    def __init__(self, http: httpx.AsyncClient, endpoint: str, wallet_scheme: str = "openid4vp://"):
        if not endpoint:
            raise ValueError("VERIFIER_EUDI_ENDPOINT is required for the eudi provider")
        self._http = http
        self._endpoint = endpoint
        self._scheme = wallet_scheme
        self._levels: dict[str, str] = {}

    async def begin(self, level: str) -> WalletRequest:
        resp = await self._http.post(f"{self._endpoint}/ui/presentations", json={
            "dcql_query": dcql_for(level),
            "nonce": secrets.token_urlsafe(24),
            "jar_mode": "by_reference",
            "request_uri_method": "get",
        })
        if resp.status_code != 200:
            raise IdentityError(f"verifier endpoint returned {resp.status_code}")
        tx = resp.json()
        wallet_url = (f"{self._scheme}?client_id={quote(tx['client_id'], safe='')}"
                      f"&request_uri={quote(tx['request_uri'], safe='')}")
        self._levels[tx["transaction_id"]] = level
        return WalletRequest(kind="qr", wallet_url=wallet_url, handle=tx["transaction_id"])

    async def result(self, request: WalletRequest) -> IdentityResult | None:
        resp = await self._http.get(f"{self._endpoint}/ui/presentations/{request.handle}")
        if resp.status_code == 400 and "PresentationNotSubmitted" in resp.text:
            return None
        if resp.status_code != 200:
            raise IdentityError(f"wallet response unavailable ({resp.status_code})")
        tokens = resp.json().get("vp_token", {}).get(QUERY_ID) or []
        if not tokens:
            raise IdentityError("wallet returned no PID")
        claims = disclosed_claims(tokens[0])
        level = self._levels.pop(request.handle, "person")
        if level == "legal_name" and not (claims.get("given_name") and claims.get("family_name")):
            raise IdentityError("wallet did not disclose a name")
        return IdentityResult(method="eudi-pid",
                              issuing_country=claims.get("issuing_country"),
                              issuing_authority=claims.get("issuing_authority"),
                              given_name=claims.get("given_name") if level == "legal_name" else None,
                              family_name=claims.get("family_name") if level == "legal_name" else None)
