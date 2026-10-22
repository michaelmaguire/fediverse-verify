from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from fediverse_verify.app import create_app
from fediverse_verify.config import Settings

HOST = "social.example"
PROFILE_URL = f"https://{HOST}/@alice"
ACTOR_URI = f"https://{HOST}/users/alice"


class FakeMastodon:
    """Just enough of the Mastodon API for the sign-in flow."""

    def __init__(self) -> None:
        self.revoked: list[str] = []
        self.apps = 0
        self.fields: list[dict] = []          # alice's profile fields (name/value HTML)
        self.authorized_fetch = False         # True: refuse unsigned actor fetches, like secure mode
        self.stale_actor_fields: list[dict] | None = None   # set: actor shows these (cache), lookup shows fields
        self.revoke_fails = False             # True: /oauth/revoke errors
        self.app_scopes: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        assert url.host == HOST, f"unexpected request to {url}"
        if url.path == "/api/v1/apps":
            self.apps += 1
            self.app_scopes.append(parse_qs(request.content.decode())["scopes"][0])
            return httpx.Response(200, json={"client_id": "cid", "client_secret": "csecret"})
        if url.path == "/oauth/token":
            form = parse_qs(request.content.decode())
            assert form["code"] == ["good-code"] and form["code_verifier"]
            return httpx.Response(200, json={"access_token": "tok"})
        if url.path == "/api/v1/accounts/verify_credentials":
            assert request.headers["Authorization"] == "Bearer tok"
            return httpx.Response(200, json={"username": "alice", "acct": "alice", "url": PROFILE_URL})
        if url.path == "/.well-known/webfinger":
            return httpx.Response(200, json={"subject": f"acct:alice@{HOST}", "links": [
                {"rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": PROFILE_URL},
                {"rel": "self", "type": "application/activity+json", "href": ACTOR_URI}]})
        if url.path == "/users/alice":
            if self.authorized_fetch:
                return httpx.Response(401)
            shown = self.fields if self.stale_actor_fields is None else self.stale_actor_fields
            return httpx.Response(200, json={"id": ACTOR_URI, "type": "Person", "url": PROFILE_URL, "attachment": [
                {"type": "PropertyValue", "name": f["name"], "value": f["value"]} for f in shown]})
        if url.path == "/api/v1/accounts/lookup":
            return httpx.Response(200, json={"username": "alice", "url": PROFILE_URL, "fields": self.fields})
        if url.path == "/oauth/revoke":
            if self.revoke_fails:
                return httpx.Response(503)
            self.revoked.append(parse_qs(request.content.decode())["token"][0])
            return httpx.Response(200, json={})
        return httpx.Response(404)


@pytest.fixture
def mastodon() -> FakeMastodon:
    return FakeMastodon()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(public_url="https://verify.test", data_dir=tmp_path, session_secret="test-secret",
                    identity_providers=("mock",), allow_private_hosts=True)


@pytest.fixture
def client(settings, mastodon):
    http = httpx.AsyncClient(transport=httpx.MockTransport(mastodon.handler))
    app = create_app(settings, http=http)
    with TestClient(app, base_url="https://verify.test", follow_redirects=False) as c:
        yield c


def sign_in(client: TestClient, path: str, data: dict) -> httpx.Response:
    """Submit a sign-in form, check the OAuth redirect, and come back with a code."""
    r = client.post(path, data=data)
    assert r.status_code == 303, r.text
    auth = urlparse(r.headers["location"])
    assert auth.netloc == HOST and auth.path == "/oauth/authorize"
    q = parse_qs(auth.query)
    assert q["code_challenge_method"] == ["S256"] and q["scope"] == ["read:accounts"]
    return client.get("/auth/mastodon/callback", params={"code": "good-code", "state": q["state"][0]})


def csrf_from(html: str) -> str:
    marker = 'name="csrf" value="'
    start = html.index(marker) + len(marker)
    return html[start:html.index('"', start)]


def link_field(url: str) -> dict:
    """A profile field as Mastodon renders it: HTML with a rel=me link."""
    return {"name": "fediverse-verified name", "value": f'<a href="{url}" rel="me nofollow noopener" target="_blank">{url}</a>'}


MARIO = {"given_name": "Mario", "family_name": "Rossi", "issuing_country": "IT",
         "issuing_authority": "Ministero dell'Interno", "age_over_18": True}


def wallet_answer(client: TestClient, page: str, persona: dict | None = None,
                  decision: str = "share") -> httpx.Response:
    """Act like a test wallet app: open the request link shown on the wallet page and answer it."""
    import html as html_mod
    import re
    href = html_mod.unescape(re.search(r'href="([^"]*/present\?request_uri=[^"]*)"', page).group(1))
    request_uri = parse_qs(urlparse(href).query)["request_uri"][0]
    req = client.get(urlparse(request_uri).path).json()
    claims = {k: v for k, v in (persona or MARIO).items() if k in req["requested_claims"]}
    return client.post(urlparse(req["response_uri"]).path,
                       json={"nonce": req["nonce"], "decision": decision, "claims": claims})


def verify(client: TestClient, level: str, given: str = "Mario", family: str = "Rossi",
           binding: str = "mastodon-sign-in", show_age: bool = False, over_18: bool = True,
           persona: dict | None = None) -> tuple[str, str]:
    """Run the whole verify flow with a test wallet; returns (proof_url, removal_code)."""
    form = {"handle": f"@alice@{HOST}", "level": level, "binding": binding}
    if show_age:
        form["show_age"] = "yes"
    if binding == "mastodon-sign-in":
        r = sign_in(client, "/verify", form)
    else:
        r = client.post("/verify", data=form)
    assert r.headers["location"] == "/wallet"
    page = client.get("/wallet").text
    persona = persona or {**MARIO, "given_name": given, "family_name": family, "age_over_18": over_18}
    assert wallet_answer(client, page, persona).status_code == 200
    r = client.get("/wallet/done")
    assert r.headers["location"] == "/issued", r.text[:300]
    html = client.get("/issued").text
    url = html.split("<code data-proof-url>")[1].split("</code>")[0]
    code = html.split('<span class="code">')[1].split("</span>")[0]
    return url, code
