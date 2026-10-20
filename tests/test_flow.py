from __future__ import annotations

import base64
import json
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

import jwt
import pytest

from fediverse_verify.binding.mastodon import BindingError, parse_handle
from fediverse_verify.identity.eudi import dcql_for, disclosed_claims

from .conftest import ACTOR_URI, HOST, PROFILE_URL, csrf_from, link_field, sign_in, verify


class RelMe(HTMLParser):
    """Collects rel=me hrefs the way Mastodon's VerifyLinkService does (a and link tags)."""

    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link") and "me" in (a.get("rel") or "").split():
            self.hrefs.append(a.get("href"))


def path_of(url: str) -> str:
    return url.removeprefix("https://verify.test")


# ---- issuing ----

def test_legal_name_proof_page(client, mastodon):
    url, _ = verify(client, "legal_name")
    assert "/n/" in url
    r = client.get(path_of(url))
    assert r.status_code == 200
    parser = RelMe(); parser.feed(r.text)
    assert PROFILE_URL in parser.hrefs                       # what Mastodon checks
    assert "Mario Rossi" in r.text and "TEST PROOF" in r.text
    assert "noindex" in r.headers["x-robots-tag"]
    assert mastodon.revoked == ["tok"]                       # sign-in token discarded


def test_person_proof_publishes_no_name(client):
    url, _ = verify(client, "person", given="Mario", family="Rossi")
    assert "/u/" in url
    page = client.get(path_of(url)).text
    assert "Rossi" not in page
    claims = jwt.decode(client.get(path_of(url) + ".jwt").text, options={"verify_signature": False})
    assert claims["level"] == "person" and "name" not in claims


def test_attestation_verifies_with_published_jwks(client):
    url, _ = verify(client, "legal_name")
    token = client.get(path_of(url) + ".jwt").text
    jwks = client.get("/.well-known/jwks.json").json()
    key = jwt.PyJWKSet.from_dict(jwks).keys[0]
    header = jwt.get_unverified_header(token)
    assert header["kid"] == key.key_id and header["typ"] == "identity-attestation+jwt"
    claims = jwt.decode(token, key.key, algorithms=["ES256"], issuer="https://verify.test")
    assert claims["sub"] == ACTOR_URI
    assert claims["profile_url"] == PROFILE_URL
    assert claims["name"] == "Mario Rossi"
    assert claims["method"] == "mock"
    assert "exp" not in claims                               # proofs don't expire


def test_wrong_level_prefix_is_404(client):
    url, _ = verify(client, "legal_name")
    assert client.get(path_of(url).replace("/n/", "/u/")).status_code == 404


def test_issued_page_shows_code_only_once(client):
    verify(client, "person")
    assert client.get("/issued").status_code == 303


def test_one_app_registration_per_server(client, mastodon):
    verify(client, "person")
    verify(client, "legal_name")
    assert mastodon.apps == 1


def test_callback_rejects_wrong_state(client):
    r = client.post("/verify", data={"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-oauth"})
    assert r.status_code == 303
    r = client.get("/auth/mastodon/callback", params={"code": "good-code", "state": "forged"})
    assert "cancelled" in r.text


def test_mock_form_requires_csrf(client):
    sign_in(client, "/verify", {"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-oauth"})
    assert client.post("/wallet/mock", data={"csrf": "wrong"}).status_code == 400


# ---- revocation ----

def test_revoke_with_code(client):
    url, code = verify(client, "legal_name")
    r = client.post("/revoke/code", data={"code": code.lower().replace("-", " ")})   # forgiving input
    assert r.status_code == 200 and "Removed" in r.text
    assert client.get(path_of(url)).status_code == 404
    assert client.get(path_of(url) + ".jwt").status_code == 404
    assert client.post("/revoke/code", data={"code": code}).status_code == 404


def test_revoke_by_signing_in_removes_all_proofs_for_account(client):
    url1, _ = verify(client, "legal_name")
    url2, _ = verify(client, "person")
    r = sign_in(client, "/revoke/sign-in", {"handle": f"@alice@{HOST}"})
    assert r.headers["location"] == "/revoke/account"
    page = client.get("/revoke/account").text
    assert "Remove all 2 proof(s)" in page
    r = client.post("/revoke/account", data={"csrf": csrf_from(page)})
    assert "2 proof(s)" in r.text
    assert client.get(path_of(url1)).status_code == 404
    assert client.get(path_of(url2)).status_code == 404


# ---- units ----

@pytest.mark.parametrize("text", ["@alice@social.example", "alice@social.example", "https://social.example/@alice"])
def test_parse_handle(text):
    assert parse_handle(text) == ("alice", "social.example")


def test_parse_handle_rejects_garbage():
    with pytest.raises(BindingError):
        parse_handle("alice")


def test_private_hosts_refused_by_default(tmp_path, mastodon):
    import httpx
    from fastapi.testclient import TestClient
    from fediverse_verify.app import create_app
    from fediverse_verify.config import Settings

    settings = Settings(public_url="https://verify.test", data_dir=tmp_path, session_secret="s")
    app = create_app(settings, http=httpx.AsyncClient(transport=httpx.MockTransport(mastodon.handler)))
    with TestClient(app, base_url="https://verify.test", follow_redirects=False) as c:
        r = c.post("/verify", data={"handle": "@alice@localhost", "level": "person"})
    assert r.status_code == 400 and "non-public" in r.text


def test_dcql_asks_only_for_needed_claims():
    person = {tuple(c["path"]) for c in dcql_for("person")["credentials"][0]["claims"]}
    named = {tuple(c["path"]) for c in dcql_for("legal_name")["credentials"][0]["claims"]}
    issuer = {("issuing_country",), ("issuing_authority",)}
    assert person == issuer
    assert named == {("given_name",), ("family_name",)} | issuer


def test_disclosed_claims_decodes_sd_jwt():
    def disc(*items):
        return base64.urlsafe_b64encode(json.dumps(list(items)).encode()).rstrip(b"=").decode()
    token = "eyJh.eyJi.c2ln~" + disc("salt1", "given_name", "Mario") + "~" + disc("salt2", "family_name", "Rossi") + "~eyJh.eyJi.a2I"
    assert disclosed_claims(token) == {"given_name": "Mario", "family_name": "Rossi"}


# ---- link-back binding ----

def test_link_back_proof_is_pending_until_profile_links(client, mastodon):
    url, _ = verify(client, "legal_name", binding="link-back")
    assert mastodon.apps == 0                                # no sign-in, no OAuth app
    page = client.get(path_of(url))
    parser = RelMe(); parser.feed(page.text)
    assert PROFILE_URL in parser.hrefs                       # Mastodon can verify it already
    assert "Verification pending" in page.text
    assert "Rossi" not in page.text and "identity-attestation" not in page.text
    assert client.get(path_of(url) + ".jwt").status_code == 404

    proof_id = url.rsplit("/", 1)[1]
    assert client.post(f"/check/{proof_id}", headers={"Accept": "application/json"}).json() == {"status": "pending"}

    mastodon.fields = [link_field(url)]
    from fediverse_verify import app as app_module
    app_module.CHECK_INTERVAL = 0                           # checks are rate-limited per proof
    try:
        assert client.post(f"/check/{proof_id}", headers={"Accept": "application/json"}).json() == {"status": "active"}
    finally:
        app_module.CHECK_INTERVAL = 5
    page = client.get(path_of(url)).text
    assert "Mario Rossi" in page and "identity-attestation" in page
    claims = jwt.decode(client.get(path_of(url) + ".jwt").text, options={"verify_signature": False})
    assert claims["binding"] == "link-back" and claims["sub"] == ACTOR_URI


def test_link_back_falls_back_to_lookup_api_under_authorized_fetch(client, mastodon, monkeypatch):
    from fediverse_verify import app as app_module
    monkeypatch.setattr(app_module, "CHECK_INTERVAL", 0)
    url, _ = verify(client, "person", binding="link-back")
    mastodon.authorized_fetch = True
    mastodon.fields = [link_field(url)]
    proof_id = url.rsplit("/", 1)[1]
    assert client.post(f"/check/{proof_id}", headers={"Accept": "application/json"}).json() == {"status": "active"}


def test_link_to_a_different_url_does_not_count(client, mastodon, monkeypatch):
    from fediverse_verify import app as app_module
    monkeypatch.setattr(app_module, "CHECK_INTERVAL", 0)
    url, _ = verify(client, "person", binding="link-back")
    mastodon.fields = [link_field(url + "x"), link_field("https://verify.test/u/other")]
    proof_id = url.rsplit("/", 1)[1]
    assert client.post(f"/check/{proof_id}", headers={"Accept": "application/json"}).json() == {"status": "pending"}


def test_unconfirmed_proofs_expire(client, monkeypatch):
    from fediverse_verify import app as app_module
    url, _ = verify(client, "legal_name", binding="link-back")
    real_time = app_module.time.time
    monkeypatch.setattr("fediverse_verify.store.time.time", lambda: real_time() + 25 * 3600)
    assert client.get(path_of(url)).status_code == 404


def test_pending_proof_can_be_revoked_with_code(client):
    url, code = verify(client, "legal_name", binding="link-back")
    assert client.post("/revoke/code", data={"code": code}).status_code == 200
    assert client.get(path_of(url)).status_code == 404


def test_issued_page_shows_the_real_label_and_link(client):
    r = client.post("/verify", data={"handle": f"@alice@{HOST}", "level": "person", "binding": "link-back"})
    page = client.get("/wallet").text
    r = client.post("/wallet/mock", data={"csrf": csrf_from(page)})
    client.get(r.headers["location"])
    html = client.get("/issued").text
    url = html.split("<code data-proof-url>")[1].split("</code>")[0]
    form = html.split('<div class="mshot"')[1].split('<div class="mshot__actions">')[0]
    assert 'class="shot__badge">Example<' in html          # framed as an illustration
    assert "Verified person" in form and url in form
    assert f"{len(url)}/40 recommended characters" in form
    assert ("limit exceeded" in form) == (len(url) > 40)


def test_about_page_and_footer(client):
    r = client.get("/about")
    assert r.status_code == 200
    for spec in ("openid-4-verifiable-presentations-1_0", "rfc9901", "rfc7033", "activitypub", "2024/1183"):
        assert spec in r.text
    assert 'href="https://github.com/michaelmaguire/fediverse-verify"' in r.text
    assert 'href="/about"' in client.get("/").text


def test_footer_links_exact_commit_only_when_clean(client, monkeypatch, settings):
    from fediverse_verify import buildinfo
    sha = "0123456789abcdef0123456789abcdef01234567"
    monkeypatch.setenv("VERIFIER_GIT_COMMIT", sha)
    info = buildinfo.detect(settings.source_url)
    assert info.commit_url == f"https://github.com/michaelmaguire/fediverse-verify/tree/{sha}"
    monkeypatch.setenv("VERIFIER_GIT_COMMIT", sha + "-dirty")
    info = buildinfo.detect(settings.source_url)
    assert info.commit == sha and info.dirty and info.commit_url is None
    monkeypatch.setenv("VERIFIER_GIT_COMMIT", "unknown")
    monkeypatch.setattr(buildinfo, "_from_git", lambda url: buildinfo.BuildInfo(url, None, False))
    assert buildinfo.detect(settings.source_url).commit is None


def test_both_levels_show_issuing_country_and_authority(client):
    for level in ("legal_name", "person"):
        r = client.post("/verify", data={"handle": f"@alice@{HOST}", "level": level, "binding": "mastodon-oauth"})
        auth = parse_qs(urlparse(r.headers["location"]).query)
        client.get("/auth/mastodon/callback", params={"code": "good-code", "state": auth["state"][0]})
        page = client.get("/wallet").text
        r = client.post("/wallet/mock", data={"csrf": csrf_from(page), "given_name": "Mario", "family_name": "Rossi",
                                              "issuing_country": "IT", "issuing_authority": "Ministero dell'Interno"})
        client.get(r.headers["location"])
        url = client.get("/issued").text.split("<code data-proof-url>")[1].split("</code>")[0]
        proof = client.get(path_of(url)).text
        assert "issued by <strong>Italy (Ministero dell&#39;Interno)</strong>" in proof
        claims = jwt.decode(client.get(path_of(url) + ".jwt").text, options={"verify_signature": False})
        assert claims["issuing_country"] == "IT" and claims["issuing_authority"] == "Ministero dell'Interno"


def test_issuer_label_hides_redundant_authority():
    from fediverse_verify.countries import issuer_label
    assert issuer_label("DE", "DE") == "Germany"
    assert issuer_label("nl", "Rijksdienst voor Identiteitsgegevens") == "Netherlands (Rijksdienst voor Identiteitsgegevens)"
    assert issuer_label("XX", None) == "XX"


def test_disclosed_claims_reads_plain_payload_claims_too():
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    issuer_jwt = b64({"alg": "ES256"}) + "." + b64({"vct": "urn:eudi:pid:1", "issuing_country": "IT",
                                                     "_sd": ["x"], "_sd_alg": "sha-256"}) + ".c2ln"
    token = issuer_jwt + "~" + b64(["salt", "given_name", "Mario"]) + "~"
    claims = disclosed_claims(token)
    assert claims["issuing_country"] == "IT" and claims["given_name"] == "Mario" and "_sd" not in claims


def test_dcql_always_asks_for_issuer():
    for level in ("person", "legal_name"):
        paths = {tuple(c["path"]) for c in dcql_for(level)["credentials"][0]["claims"]}
        assert {("issuing_country",), ("issuing_authority",)} <= paths


def test_link_back_sees_through_cached_actor(client, mastodon, monkeypatch):
    """Mastodon caches actor JSON for minutes; the lookup API reflects a just-saved profile."""
    from fediverse_verify import app as app_module
    monkeypatch.setattr(app_module, "CHECK_INTERVAL", 0)
    url, _ = verify(client, "person", binding="link-back")
    mastodon.stale_actor_fields = [link_field("https://verify.test/u/an-older-proof")]
    mastodon.fields = [link_field(url)]
    proof_id = url.rsplit("/", 1)[1]
    assert client.post(f"/check/{proof_id}", headers={"Accept": "application/json"}).json() == {"status": "active"}


def test_about_documents_every_stored_column(client, settings):
    """Adding a column without describing it on /about fails this test."""
    import sqlite3
    page = client.get("/about").text
    db = sqlite3.connect(settings.data_dir / "verifier.sqlite3")
    for table in ("proofs", "oauth_clients"):
        for (_, column, *_rest) in db.execute(f"PRAGMA table_info({table})"):
            assert f"<code>{column}</code>" in page, f"{table}.{column} is not described on /about"


def test_about_links_to_the_code_that_stores_data(client):
    import re
    page = client.get("/about").text
    # Pinned to the running commit when known, else main; either way a line-anchored link.
    assert re.search(r"/blob/[0-9a-f]{40}|/blob/main", page)
    assert re.search(r"/src/fediverse_verify/store\.py#L\d+-L\d+", page)
    assert "Saving a proof" in page and "Deleting a proof" in page
    assert "CREATE TABLE IF NOT EXISTS proofs" in page          # schema shown verbatim


def test_link_ranges_point_at_the_right_code():
    from pathlib import Path
    from fediverse_verify import transparency
    from fediverse_verify.buildinfo import BuildInfo
    links = transparency.build_links(BuildInfo("https://example.org/repo", None, False))
    root = Path(transparency.PACKAGE_DIR)
    for key, needle in (("add_proof", "def add_proof"), ("delete", "def delete_proof"), ("schema", "SCHEMA = ")):
        rel, anchor = links[key].url.split("/src/fediverse_verify/")[1].split("#L")
        first = int(anchor.split("-")[0])
        assert (root / rel).read_text().splitlines()[first - 1].strip().startswith(needle)


def test_secure_delete_is_on(settings):
    from fediverse_verify.store import Store
    store = Store(settings.data_dir / "x.sqlite3")
    assert store._db.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_about_states_disk_encryption_truthfully(tmp_path, mastodon):
    import httpx
    from dataclasses import replace
    from fastapi.testclient import TestClient
    from fediverse_verify.app import create_app
    from fediverse_verify.config import Settings
    base = Settings(public_url="https://verify.test", data_dir=tmp_path, session_secret="s")
    for encrypted, expected in ((False, "not on an encrypted disk"), (True, "on an encrypted disk whose passphrase")):
        app = create_app(replace(base, storage_encrypted=encrypted),
                         http=httpx.AsyncClient(transport=httpx.MockTransport(mastodon.handler)))
        with TestClient(app, base_url="https://verify.test") as c:
            assert expected in c.get("/about").text
