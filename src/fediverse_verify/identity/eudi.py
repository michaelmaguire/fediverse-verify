"""Client for the EUDI reference verifier endpoint (OpenID4VP).

The endpoint does the cryptography: request signing, wallet response validation,
issuer trust and key binding. We send a DCQL query asking only for the claims the
chosen options need, then read those claims from the validated presentation.

Credentials used:
- PID (SD-JWT VC, vct urn:eudi:pid:1): issuer metadata, plus the name for the
  fediverse-verified name level.
- EU Proof of Age attestation (ISO mdoc, doctype eu.europa.ec.av.1) for "18+": it
  contains only age_over_18 / age_over_NN, nothing else (AV profile, Annex A).
- Fallback for the name level only: the PID birth date, used once to compute
  "18 or over" and then discarded; never stored or published.

Status: written against the endpoint's README (POST /ui/presentations, GET
/ui/presentations/{id}) and the AV profile; not yet tested with a real wallet.
Known gaps: the AV profile's OpenID4VP transport (no JAR, redirect_uri client id)
differs from this endpoint's defaults, and requesting the PID and Proof of Age
together in one presentation is untested. The AV profile prefers zero-knowledge
proofs (Longfellow ZK over the W3C Digital Credentials API), not supported here yet.
"""

from __future__ import annotations

import base64
import json
import secrets
from datetime import date, datetime, timezone
from urllib.parse import quote

import cbor2
import httpx

from ..binding.webfinger import json_object
from . import IdentityError, IdentityResult, WalletRequest

PID_VCT = "urn:eudi:pid:1"
AGE_DOCTYPE = "eu.europa.ec.av.1"
PID_QUERY, PID_WITH_BIRTHDATE_QUERY, AGE_QUERY = "pid", "pid_bd", "age"

ISSUER_CLAIMS = [["issuing_country"], ["issuing_authority"]]   # mandatory PID metadata, published
CLAIMS_FOR_LEVEL = {
    "person": ISSUER_CLAIMS,
    "legal_name": [["given_name"], ["family_name"], *ISSUER_CLAIMS],
}
# TODO(real wallets): national PIDs may use extended types such as urn:eudi:pid:de:1;
# check how the endpoint matches vct_values against those.


def _pid_query(query_id: str, claims: list[list[str]]) -> dict:
    return {"id": query_id, "format": "dc+sd-jwt", "meta": {"vct_values": [PID_VCT]},
            "claims": [{"path": p} for p in claims]}


def dcql_for(level: str, include_age: bool = False) -> dict:
    pid = _pid_query(PID_QUERY, CLAIMS_FOR_LEVEL[level])
    if not include_age:
        return {"credentials": [pid]}
    age = {"id": AGE_QUERY, "format": "mso_mdoc", "meta": {"doctype_value": AGE_DOCTYPE},
           "claims": [{"path": [AGE_DOCTYPE, "age_over_18"]}]}
    credentials, options = [pid, age], [[PID_QUERY, AGE_QUERY]]
    if level == "legal_name":
        # The name is disclosed anyway at this level, so the birth date is an acceptable fallback.
        credentials.append(_pid_query(PID_WITH_BIRTHDATE_QUERY, CLAIMS_FOR_LEVEL[level] + [["birthdate"]]))
        options.append([PID_WITH_BIRTHDATE_QUERY])
    return {"credentials": credentials,
            "credential_sets": [{"options": options, "purpose": "Show that you are 18 or over"}]}


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


def mdoc_claims(device_response_b64: str, namespace: str) -> dict:
    """Disclosed elements of one namespace in an (already validated) ISO mdoc DeviceResponse."""
    raw = base64.urlsafe_b64decode(device_response_b64 + "=" * (-len(device_response_b64) % 4))
    response = cbor2.loads(raw)
    claims: dict = {}
    for document in response.get("documents", []):
        for item in document.get("issuerSigned", {}).get("nameSpaces", {}).get(namespace, []):
            signed_item = cbor2.loads(item.value if isinstance(item, cbor2.CBORTag) else item)
            claims[signed_item["elementIdentifier"]] = signed_item["elementValue"]
    return claims


def is_adult(birthdate: str, today: date | None = None) -> bool:
    """18 or over on `today`, from an ISO YYYY-MM-DD birth date (which the caller then discards)."""
    born = date.fromisoformat(str(birthdate)[:10])
    today = today or datetime.now(timezone.utc).date()
    return (today.year - born.year - ((today.month, today.day) < (born.month, born.day))) >= 18


class EudiProvider:
    name = "eudi"

    def __init__(self, http: httpx.AsyncClient, endpoint: str, wallet_scheme: str = "openid4vp://"):
        if not endpoint:
            raise ValueError("VERIFIER_EUDI_ENDPOINT is required for the eudi provider")
        self._http = http
        self._endpoint = endpoint
        self._scheme = wallet_scheme
        self._requests: dict[str, tuple[str, bool]] = {}

    async def begin(self, level: str, include_age: bool = False) -> WalletRequest:
        resp = await self._http.post(f"{self._endpoint}/ui/presentations", json={
            "dcql_query": dcql_for(level, include_age),
            "nonce": secrets.token_urlsafe(24),
            "jar_mode": "by_reference",
            "request_uri_method": "get",
        })
        if resp.status_code != 200:
            raise IdentityError(f"verifier endpoint returned {resp.status_code}")
        tx = json_object(resp, "the EU verifier endpoint", IdentityError)
        wallet_url = (f"{self._scheme}?client_id={quote(tx['client_id'], safe='')}"
                      f"&request_uri={quote(tx['request_uri'], safe='')}")
        self._requests[tx["transaction_id"]] = (level, include_age)
        return WalletRequest(kind="qr", wallet_url=wallet_url, handle=tx["transaction_id"])

    async def result(self, request: WalletRequest) -> IdentityResult | None:
        resp = await self._http.get(f"{self._endpoint}/ui/presentations/{request.handle}")
        if resp.status_code == 400 and "PresentationNotSubmitted" in resp.text:
            return None
        if resp.status_code != 200:
            raise IdentityError(f"wallet response unavailable ({resp.status_code})")
        level, include_age = self._requests.pop(request.handle, ("person", False))
        vp_token = json_object(resp, "the EU verifier endpoint", IdentityError).get("vp_token") or {}
        pid_tokens = vp_token.get(PID_QUERY) or vp_token.get(PID_WITH_BIRTHDATE_QUERY) or []
        if not pid_tokens:
            raise IdentityError("wallet returned no PID")
        claims = disclosed_claims(pid_tokens[0])
        if level == "legal_name" and not (claims.get("given_name") and claims.get("family_name")):
            raise IdentityError("wallet did not disclose a name")

        age_over_18 = None
        if include_age:
            if vp_token.get(AGE_QUERY):
                age_over_18 = mdoc_claims(vp_token[AGE_QUERY][0], AGE_DOCTYPE).get("age_over_18") is True
            elif level == "legal_name" and claims.get("birthdate"):
                age_over_18 = is_adult(claims["birthdate"])
        claims.pop("birthdate", None)            # never kept beyond this point

        return IdentityResult(method="eudi-pid",
                              issuing_country=claims.get("issuing_country"),
                              issuing_authority=claims.get("issuing_authority"),
                              given_name=claims.get("given_name") if level == "legal_name" else None,
                              family_name=claims.get("family_name") if level == "legal_name" else None,
                              age_over_18=True if age_over_18 else None)
