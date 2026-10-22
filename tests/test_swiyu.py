from __future__ import annotations

import html
import json
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from fediverse_verify.app import create_app
from fediverse_verify.config import Settings
from fediverse_verify.identity import IdentityError, is_test_method
from fediverse_verify.identity.registry import build_providers
from fediverse_verify.identity.swiyu import (BETA_ID_VCT_VALUES, DEFAULT_VCT_VALUES, SwiyuProvider, dcql_for,
                                            vqps_submissions)

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


REAL_EID_VCT = "urn:vct:ch.admin.fedpol.eid"     # placeholder until the real e-ID type is published


async def run(fake, level="legal_name", include_age=False, vct_values=(REAL_EID_VCT,)):
    provider = SwiyuProvider(httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
                             "https://swiyu.internal", (ISSUER,), vct_values)
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
async def test_beta_id_is_a_test_method():
    claims = {"given_name": "Heidi", "family_name": "Muster", "issuing_country": "CH"}
    _, _, result = await run(FakeSwiyu(claims=claims), vct_values=BETA_ID_VCT_VALUES)
    assert result.method == "swiyu-beta-id" and is_test_method(result.method)


@pytest.mark.anyio
async def test_beta_id_recognised_by_its_type_even_when_real_types_also_accepted():
    claims = {"vct": "betaid-sdjwt", "issuing_country": "CH"}
    _, _, result = await run(FakeSwiyu(claims=claims), "person", vct_values=(REAL_EID_VCT, *BETA_ID_VCT_VALUES))
    assert result.method == "swiyu-beta-id"
    _, _, result = await run(FakeSwiyu(claims={"vct": REAL_EID_VCT, "issuing_country": "CH"}), "person",
                             vct_values=(REAL_EID_VCT, *BETA_ID_VCT_VALUES))
    assert result.method == "swiyu-eid" and not is_test_method(result.method)


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


def test_start_page_never_asks_which_system(client, two_wallet_client):
    for c in (client, two_wallet_client):
        page = c.get("/").text
        assert "Your digital ID" not in page and 'name="wallet"' not in page


def signed_in(c, level="person", show_age=False):
    from .conftest import sign_in
    form = {"handle": f"@alice@{HOST}", "level": level, "binding": "mastodon-sign-in"}
    if show_age:
        form["show_age"] = "yes"
    r = sign_in(c, "/verify", form)
    assert r.headers["location"] == "/wallet"
    return c.get("/wallet").text


def choose(c, page, wallet):
    r = c.post("/wallet/choose", data={"csrf": csrf_from(page), "wallet": wallet})
    assert r.status_code == 303, r.text[:300]
    return c.get("/wallet").text


def test_one_system_goes_straight_to_its_qr_code(client):
    page = signed_in(client)
    assert "Which ID app do you have?" not in page and "/present?request_uri=" in page
    assert "Use a different ID app" not in page


def test_several_systems_ask_which_app_then_open_only_that_one(two_wallet_client):
    c = two_wallet_client
    page = signed_in(c)
    assert "Which ID app do you have?" in page and "/present?request_uri=" not in page   # nothing opened yet
    page = choose(c, page, "mock-ch")
    assert "Swiss e-ID (test)" in page and "/ch/present?request_uri=" in page and "/eu/present" not in page


def test_switching_apps_closes_the_first_request(two_wallet_client):
    import re
    from urllib.parse import parse_qs, urlparse
    c = two_wallet_client
    eu_page = choose(c, signed_in(c), "mock")
    href = html.unescape(re.search(r'href="([^"]*/present\?request_uri=[^"]*)"', eu_page).group(1))
    request_path = urlparse(parse_qs(urlparse(href).query)["request_uri"][0]).path
    assert c.get(request_path).status_code == 200
    c.post("/wallet/change", data={"csrf": csrf_from(eu_page)})
    assert c.get(request_path).status_code == 404                                  # closed
    assert c.post(request_path + "/response", json={"nonce": "x", "decision": "share", "claims": {}}).status_code == 404
    assert "Which ID app do you have?" in c.get("/wallet").text


def test_swiss_test_identity_says_switzerland(two_wallet_client):
    from .conftest import wallet_answer
    c = two_wallet_client
    page = choose(c, signed_in(c), "mock-ch")
    heidi = {"issuing_country": "CH", "issuing_authority": "fedpol"}
    assert wallet_answer(c, page, heidi).status_code == 200
    c.get("/wallet/done")
    url = c.get("/issued").text.split("<code data-proof-url>")[1].split("</code>")[0]
    assert "issued by <strong>Switzerland (fedpol)</strong>" in html.unescape(c.get(url.removeprefix("https://verify.test")).text)


def test_eu_request_refuses_a_swiss_identity(two_wallet_client):
    from .conftest import wallet_answer
    c = two_wallet_client
    page = choose(c, signed_in(c), "mock")
    assert wallet_answer(c, page, {"issuing_country": "CH", "issuing_authority": "fedpol"}).status_code == 400


# ---- real EU + Swiss providers together ----

class FakeBoth:
    def __init__(self, swiyu_up=True):
        self.swiyu = FakeSwiyu(claims={"issuing_country": "CH", "issuing_authority": "fedpol"})
        self.swiyu_up = swiyu_up
        self.eudi_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "swiyu.internal":
            if not self.swiyu_up:
                raise httpx.ConnectError("down")
            return self.swiyu.handler(request)
        if request.url.host == "eudi.internal":
            self.eudi_calls += 1
            return httpx.Response(200, json={"transaction_id": "tx", "client_id": "x509_san_dns:v",
                                             "request_uri": "https://v/r"})
        return MASTODON.handler(request)


MASTODON = None


@pytest.fixture
def real_both(settings, mastodon):
    global MASTODON
    MASTODON = mastodon
    def make(**kw):
        fake = FakeBoth(**kw)
        app = create_app(replace(settings, identity_providers=("eudi", "swiyu"), eudi_endpoint="https://eudi.internal",
                                 swiyu_endpoint="https://swiyu.internal", swiyu_issuer_dids=(ISSUER,)),
                         http=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)))
        return fake, TestClient(app, base_url="https://verify.test", follow_redirects=False)
    return make


def test_choosing_swiss_contacts_only_the_swiss_verifier(real_both):
    import jwt
    fake, c = real_both()
    with c:
        page = choose(c, signed_in(c), "swiyu")
        assert "swiyu-verify://" in page and fake.eudi_calls == 0                    # EU endpoint never asked
        assert c.get("/wallet/status").json()["state"] == "done"
        url = c.get("/issued").text.split("<code data-proof-url>")[1].split("</code>")[0]
        claims = jwt.decode(c.get(url.removeprefix("https://verify.test") + ".jwt").text,
                            options={"verify_signature": False})
        # No real e-ID type configured, so this is the Sandbox Beta-ID: a test proof.
        assert claims["identity_check_method"] == "swiyu-beta-id" and claims["issuing_country"] == "CH"
        path = url.removeprefix("https://verify.test")
        assert "TEST PROOF" in c.get(path).text
        assert c.get(path + ".json").json()["evidence"][0]["test"] is True


def test_unreachable_system_says_so(real_both):
    _, c = real_both(swiyu_up=False)
    with c:
        page = signed_in(c)
        r = c.post("/wallet/choose", data={"csrf": csrf_from(page), "wallet": "swiyu"})
        assert r.status_code == 502 and "can&#39;t be reached" in r.text


# ---- trust registry statements (vqPS) ----

def test_vqps_covers_every_query_we_send_within_swiyu_limits():
    subs = vqps_submissions("did:webvh:x", (REAL_EID_VCT,))
    assert [s["scope"] for s in subs] == ["org.fediverse-verify.person", "org.fediverse-verify.person.age18",
                                          "org.fediverse-verify.legal_name", "org.fediverse-verify.legal_name.age18"]
    for s in subs:
        assert s["sub"] == "did:webvh:x"
        assert len(s["purpose_name"]["default"]) <= 40           # swiyu limit
        assert len(s["purpose_description"]["default"]) <= 1000  # swiyu limit
    assert subs[3]["query"] == dcql_for("legal_name", True, (REAL_EID_VCT,))


@pytest.mark.anyio
async def test_vqps_matches_what_begin_sends():
    fake = FakeSwiyu(state="PENDING")
    await run(fake, "legal_name", include_age=True)
    sent = fake.created
    statement = vqps_submissions("did:webvh:x", (REAL_EID_VCT,))[3]
    assert sent["verification_purpose"]["scope"] == statement["scope"]
    assert sent["verification_purpose"]["purpose_name"] == statement["purpose_name"]
    assert sent["verification_purpose"]["purpose_description"] == statement["purpose_description"]
    assert sent["dcql_query"] == statement["query"]
