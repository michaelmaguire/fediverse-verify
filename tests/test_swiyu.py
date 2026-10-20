from __future__ import annotations

import html
import json
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from fediverse_verify.app import create_app
from fediverse_verify.config import Settings
from fediverse_verify.identity import IdentityError
from fediverse_verify.identity.registry import build_providers
from fediverse_verify.identity.swiyu import DEFAULT_VCT_VALUES, SwiyuProvider, dcql_for

from .conftest import HOST, csrf_from

ISSUER = "did:webvh:example:issuer"


# ---- query ----

def test_dcql_asks_only_for_needed_claims():
    person = dcql_for("person")["credentials"][0]
    assert person["meta"]["vct_values"] == list(DEFAULT_VCT_VALUES)      # old and new Beta ID types
    assert person["require_cryptographic_holder_binding"] is True
    assert {tuple(c["path"]) for c in person["claims"]} == {("issuing_country",), ("issuing_authority",)}
    named = {tuple(c["path"]) for c in dcql_for("legal_name", include_age=True)["credentials"][0]["claims"]}
    assert named == {("given_name",), ("family_name",), ("issuing_country",), ("issuing_authority",), ("age_over_18",)}
    assert not any("birth" in p[0] for p in named)


# ---- talking to the swiyu verifier ----

class FakeSwiyu:
    def __init__(self, state="SUCCESS", claims=None, error=None):
        self.state, self.claims, self.error = state, claims or {}, error
        self.created: dict | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/management/api/verifications":
            self.created = json.loads(request.content)
            return httpx.Response(200, json={"id": "v1", "state": "PENDING",
                                             "verification_deeplink": "swiyu-verify://?client_id=did%3Ax&request_uri=y"})
        if request.url.path == "/management/api/verifications/v1":
            body = {"id": "v1", "state": self.state}
            if self.state == "SUCCESS":
                body["wallet_response"] = {"credential_subject_data": {"eid": self.claims}}
            elif self.state == "FAILED":
                body["wallet_response"] = {"error_description": self.error}
            return httpx.Response(200, json=body)
        return httpx.Response(404)


async def run(fake, level="legal_name", include_age=False):
    provider = SwiyuProvider(httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
                             "https://swiyu.internal", (ISSUER,))
    request = await provider.begin(level, include_age)
    return provider, request, await provider.result(request)


@pytest.mark.anyio
async def test_begin_sends_purpose_issuers_and_returns_deeplink():
    fake = FakeSwiyu(state="PENDING")
    _, request, result = await run(fake, "person", include_age=True)
    assert result is None                                           # still waiting for the wallet
    assert request.wallet_url.startswith("swiyu-verify://")
    assert fake.created["accepted_issuer_dids"] == [ISSUER]
    assert fake.created["verification_purpose"]["scope"] == "org.fediverse-verify.person.age18"
    assert "18 or over" in fake.created["verification_purpose"]["purpose_description"]["default"]


@pytest.mark.anyio
async def test_success_maps_claims():
    fake = FakeSwiyu(claims={"given_name": "Heidi", "family_name": "Muster", "issuing_country": "CH",
                             "issuing_authority": "fedpol", "age_over_18": True})
    _, _, result = await run(fake, "legal_name", include_age=True)
    assert (result.method, result.full_name, result.issuing_country, result.issuing_authority, result.age_over_18) == \
        ("swiyu-eid", "Heidi Muster", "CH", "fedpol", True)


@pytest.mark.anyio
async def test_age_ignored_unless_asked_and_name_dropped_for_person_level():
    fake = FakeSwiyu(claims={"given_name": "Heidi", "family_name": "Muster", "issuing_country": "CH", "age_over_18": True})
    _, _, result = await run(fake, "person", include_age=False)
    assert result.age_over_18 is None and result.full_name is None


@pytest.mark.anyio
async def test_failed_verification_raises():
    with pytest.raises(IdentityError, match="credential revoked"):
        await run(FakeSwiyu(state="FAILED", error="credential revoked"))


@pytest.mark.anyio
async def test_missing_country_is_not_invented():
    _, _, result = await run(FakeSwiyu(claims={"given_name": "A", "family_name": "B"}))
    assert result.issuing_country is None


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---- registry safety checks ----

def test_registry_rejects_unknown_and_mixed_providers(tmp_path):
    base = Settings(public_url="https://v.test", data_dir=tmp_path, session_secret="s")
    http = httpx.AsyncClient()
    with pytest.raises(ValueError, match="unknown"):
        build_providers(replace(base, identity_providers=("nope",)), http)
    with pytest.raises(ValueError, match="can't be enabled together"):
        build_providers(replace(base, identity_providers=("mock", "swiyu"), swiyu_endpoint="x",
                                swiyu_issuer_dids=(ISSUER,)), http)
    with pytest.raises(ValueError, match="VERIFIER_SWIYU_ENDPOINT"):
        build_providers(replace(base, identity_providers=("swiyu",)), http)
    providers = build_providers(replace(base, identity_providers=("eudi", "swiyu"), eudi_endpoint="e",
                                        swiyu_endpoint="s", swiyu_issuer_dids=(ISSUER,)), http)
    assert list(providers) == ["eudi", "swiyu"]


# ---- the app with two wallet types ----

@pytest.fixture
def two_wallet_client(settings, mastodon):
    app = create_app(replace(settings, identity_providers=("mock", "mock-ch")),
                     http=httpx.AsyncClient(transport=httpx.MockTransport(mastodon.handler)))
    with TestClient(app, base_url="https://verify.test", follow_redirects=False) as c:
        yield c


def test_start_page_offers_a_choice_only_with_several_wallets(client, two_wallet_client):
    assert "Your digital ID" not in client.get("/").text
    page = two_wallet_client.get("/").text
    assert "Your digital ID" in page and 'value="mock-ch"' in page


def test_swiss_style_flow_says_switzerland(two_wallet_client):
    from .conftest import sign_in
    c = two_wallet_client
    r = sign_in(c, "/verify", {"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-sign-in",
                               "wallet": "mock-ch"})
    assert r.headers["location"] == "/wallet"
    page = c.get("/wallet").text
    assert '<option value="CH" selected>' in page and "Swiss-style" in page
    r = c.post("/wallet/mock", data={"csrf": csrf_from(page), "issuing_country": "CH"})
    c.get(r.headers["location"])
    url = c.get("/issued").text.split("<code data-proof-url>")[1].split("</code>")[0]
    assert "issued by <strong>Switzerland</strong>" in html.unescape(c.get(url.removeprefix("https://verify.test")).text)
    assert c.post("/verify", data={"handle": f"@alice@{HOST}", "level": "person", "wallet": "eudi"}).status_code == 400
