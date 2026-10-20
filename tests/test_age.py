from __future__ import annotations

import base64
import html
from datetime import date

import cbor2
import httpx
import jwt
import pytest

from fediverse_verify.identity import WalletRequest
from fediverse_verify.identity.eudi import (AGE_DOCTYPE, EudiProvider, dcql_for, is_adult, mdoc_claims)

from .conftest import verify


def path_of(url: str) -> str:
    return url.removeprefix("https://verify.test")


def claims_of(client, url):
    return jwt.decode(client.get(path_of(url) + ".jwt").text, options={"verify_signature": False})


# ---- the four combinations ----

@pytest.mark.parametrize("level,label", [("legal_name", "Verified name · 18+"), ("person", "Verified person · 18+")])
def test_18_plus_is_shown_and_signed(client, level, label):
    url, _ = verify(client, level, show_age=True)
    page = html.unescape(client.get(path_of(url)).text)
    assert f"<h1>{label}</h1>" in page and "18 or over" in page
    assert claims_of(client, url)["age_over_18"] is True


def test_age_not_mentioned_unless_asked(client):
    url, _ = verify(client, "legal_name", show_age=False, over_18=True)
    assert "age_over_18" not in claims_of(client, url)
    assert "18+" not in client.get(path_of(url)).text


def test_unconfirmed_age_issues_proof_without_age(client):
    r = client.post("/verify", data={"handle": "@alice@social.example", "level": "person", "binding": "link-back",
                                     "show_age": "yes"})
    from .conftest import MARIO, wallet_answer
    page = client.get("/wallet").text
    assert "18 or over" in page
    wallet_answer(client, page, {**MARIO, "age_over_18": False})              # an under-18 test identity
    client.get("/wallet/done")
    issued = html.unescape(client.get("/issued").text)
    assert "didn't confirm that you're 18 or over" in issued
    url = issued.split("<code data-proof-url>")[1].split("</code>")[0]
    proof_page = client.get(path_of(url)).text                                # pending page, no age shown
    assert "18+" not in proof_page and "18 or over" not in proof_page


# ---- wallet queries ----

def test_dcql_without_age_is_unchanged():
    q = dcql_for("person")
    assert [c["id"] for c in q["credentials"]] == ["pid"] and "credential_sets" not in q


def test_dcql_person_with_age_uses_proof_of_age_only():
    q = dcql_for("person", include_age=True)
    ids = {c["id"]: c for c in q["credentials"]}
    assert ids["age"]["format"] == "mso_mdoc" and ids["age"]["meta"]["doctype_value"] == AGE_DOCTYPE
    assert q["credential_sets"][0]["options"] == [["pid", "age"]]
    assert all(["birthdate"] not in [c["path"] for c in cred["claims"]] for cred in q["credentials"])


def test_dcql_name_with_age_falls_back_to_birthdate():
    q = dcql_for("legal_name", include_age=True)
    assert q["credential_sets"][0]["options"] == [["pid", "age"], ["pid_bd"]]
    pid_bd = next(c for c in q["credentials"] if c["id"] == "pid_bd")
    assert {"path": ["birthdate"]} in pid_bd["claims"]


# ---- parsing ----

def device_response(age_over_18: bool) -> str:
    item = cbor2.dumps({"digestID": 0, "random": b"x" * 16, "elementIdentifier": "age_over_18",
                        "elementValue": age_over_18})
    doc = {"docType": AGE_DOCTYPE, "issuerSigned": {"nameSpaces": {AGE_DOCTYPE: [cbor2.CBORTag(24, item)]}}}
    return base64.urlsafe_b64encode(cbor2.dumps({"version": "1.0", "documents": [doc], "status": 0})).rstrip(b"=").decode()


def test_mdoc_claims_reads_age_over_18():
    assert mdoc_claims(device_response(True), AGE_DOCTYPE) == {"age_over_18": True}
    assert mdoc_claims(device_response(False), AGE_DOCTYPE) == {"age_over_18": False}


@pytest.mark.parametrize("born,adult", [("2008-10-20", True), ("2008-10-21", False), ("1980-01-01", True)])
def test_is_adult_on_birthday_boundary(born, adult):
    assert is_adult(born, today=date(2026, 10, 20)) is adult


# ---- EUDI provider end to end (fake endpoint) ----

def sd_jwt(**disclosed) -> str:
    def b64(obj):
        import json
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    head = b64({"alg": "ES256"}) + "." + b64({"vct": "urn:eudi:pid:1", "issuing_country": "IT"}) + ".c2ln"
    return head + "~" + "~".join(b64(["s", k, v]) for k, v in disclosed.items()) + "~"


async def run_provider(level, include_age, vp_token):
    def handler(request: httpx.Request):
        if request.method == "POST":
            return httpx.Response(200, json={"transaction_id": "tx", "client_id": "x509_san_dns:verify.test",
                                             "request_uri": "https://verify.test/r"})
        return httpx.Response(200, json={"vp_token": vp_token})
    provider = EudiProvider(httpx.AsyncClient(transport=httpx.MockTransport(handler)), "https://endpoint.test")
    req = await provider.begin(level, include_age)
    return await provider.result(req)


@pytest.mark.anyio
async def test_provider_uses_proof_of_age_credential():
    result = await run_provider("person", True, {"pid": [sd_jwt()], "age": [device_response(True)]})
    assert result.age_over_18 is True and result.given_name is None


@pytest.mark.anyio
async def test_provider_birthdate_fallback_and_discard():
    token = sd_jwt(given_name="Mario", family_name="Rossi", birthdate="1980-05-23")
    result = await run_provider("legal_name", True, {"pid_bd": [token]})
    assert result.age_over_18 is True and result.full_name == "Mario Rossi"
    assert "1980" not in repr(result)                                  # birth date not carried forward


@pytest.mark.anyio
async def test_provider_minor_gets_no_age_claim():
    result = await run_provider("person", True, {"pid": [sd_jwt()], "age": [device_response(False)]})
    assert result.age_over_18 is None


@pytest.fixture
def anyio_backend():
    return "asyncio"
