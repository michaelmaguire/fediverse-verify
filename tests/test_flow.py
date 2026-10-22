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
    assert claims["verification_level"] == "person" and "name" not in claims


def test_attestation_verifies_with_published_jwks(client):
    url, _ = verify(client, "legal_name")
    token = client.get(path_of(url) + ".jwt").text
    jwks = client.get("/.well-known/jwks.json").json()
    key = jwt.PyJWKSet.from_dict(jwks).keys[0]
    header = jwt.get_unverified_header(token)
    assert header["kid"] == key.key_id and header["typ"] == "identity-attestation+jwt"
    claims = jwt.decode(token, key.key, algorithms=["ES256"], issuer="https://verify.test")
    assert claims["sub"] == ACTOR_URI
    assert claims["account_profile_url"] == PROFILE_URL
    assert claims["name"] == "Mario Rossi"
    assert claims["identity_check_method"] == "mock"
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
    r = client.post("/verify", data={"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-sign-in"})
    assert r.status_code == 303
    r = client.get("/auth/mastodon/callback", params={"code": "good-code", "state": "forged"})
    assert "cancelled" in r.text


def test_wallet_response_needs_the_nonce_and_only_requested_claims(client):
    from urllib.parse import urlparse
    sign_in(client, "/verify", {"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-sign-in"})
    page = client.get("/wallet").text
    import html as h, re
    from urllib.parse import parse_qs
    href = h.unescape(re.search(r'href="([^"]*/present\?request_uri=[^"]*)"', page).group(1))
    path = urlparse(parse_qs(urlparse(href).query)["request_uri"][0]).path
    req = client.get(path).json()
    assert req["requested_claims"] == ["issuing_country", "issuing_authority"]       # person level: no name
    respond = lambda body: client.post(path + "/response", json=body)
    assert respond({"nonce": "wrong", "decision": "share", "claims": {"issuing_country": "IT"}}).status_code == 400
    assert respond({"nonce": req["nonce"], "decision": "share",
                    "claims": {"issuing_country": "IT", "given_name": "Mario"}}).status_code == 400   # not requested
    assert respond({"nonce": req["nonce"], "decision": "share", "claims": {"issuing_country": "IT"}}).status_code == 200
    assert respond({"nonce": req["nonce"], "decision": "share", "claims": {"issuing_country": "IT"}}).status_code == 400   # once


def test_declining_in_the_wallet_issues_nothing(client):
    from .conftest import wallet_answer
    sign_in(client, "/verify", {"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-sign-in"})
    assert wallet_answer(client, client.get("/wallet").text, decision="decline").status_code == 200
    assert "declined" in client.get("/wallet/done").text


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
    assert claims["account_ownership_check"] == "link-back" and claims["sub"] == ACTOR_URI


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
    from .conftest import wallet_answer
    client.post("/verify", data={"handle": f"@alice@{HOST}", "level": "person", "binding": "link-back"})
    wallet_answer(client, client.get("/wallet").text)
    client.get("/wallet/done")
    html = client.get("/issued").text
    url = html.split("<code data-proof-url>")[1].split("</code>")[0]
    form = html.split('<div class="mshot"')[1].split('<div class="mshot__actions">')[0]
    assert 'class="shot__badge">Example<' in html          # framed as an illustration
    assert "fediverse-verified person" in form and url in form
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
        r = client.post("/verify", data={"handle": f"@alice@{HOST}", "level": level, "binding": "mastodon-sign-in"})
        auth = parse_qs(urlparse(r.headers["location"]).query)
        client.get("/auth/mastodon/callback", params={"code": "good-code", "state": auth["state"][0]})
        from .conftest import wallet_answer
        wallet_answer(client, client.get("/wallet").text)
        client.get("/wallet/done")
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


def test_proof_page_shows_signed_copy_contents(client):
    url, _ = verify(client, "legal_name")
    import html
    page = html.unescape(client.get(path_of(url)).text)
    shown = page.split("What's in the signed copy?")[1].split("</details>")[0]
    token = client.get(path_of(url) + ".jwt").text
    for key, value in jwt.decode(token, options={"verify_signature": False}).items():
        assert f'"{key}"' in shown and str(value) in shown


def test_about_example_lists_every_signed_field(client):
    from fediverse_verify.attestation import build_claims
    import html
    example = html.unescape(client.get("/about").text).split('id="signed-copy"')[1].split("</pre>")[0]
    claims = build_claims(issuer="i", proof_id="p", subject_uri="s", profile_url="u", level="legal_name",
                          method="m", name="n", binding="b", issuing_country="IT", issuing_authority="a")
    for key in claims:
        assert f'"{key}"' in example, f"{key} missing from the /about example"


def test_app_registration_requests_only_read_accounts(client, mastodon):
    verify(client, "person")
    assert mastodon.app_scopes == ["read:accounts"]


def test_failed_token_cancellation_is_reported(client, mastodon):
    mastodon.revoke_fails = True
    r = sign_in(client, "/verify", {"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-sign-in"})
    page = client.get("/wallet").text
    assert "couldn&#39;t confirm" in page or "couldn't confirm" in page
    assert f"https://{HOST}/oauth/authorized_applications" in page


def test_no_warning_when_token_is_cancelled(client, mastodon):
    sign_in(client, "/verify", {"handle": f"@alice@{HOST}", "level": "person", "binding": "mastodon-sign-in"})
    assert "authorized_applications" not in client.get("/wallet").text
    assert mastodon.revoked == ["tok"]


def test_old_databases_are_migrated(tmp_path):
    """A database from before the 2026-10-20 renames opens with data intact."""
    import sqlite3
    from fediverse_verify.store import Store, hash_removal_code
    db = sqlite3.connect(tmp_path / "old.sqlite3")
    db.executescript("""
        CREATE TABLE proofs (id TEXT PRIMARY KEY, level TEXT NOT NULL CHECK (level IN ('person','legal_name')),
            subject_uri TEXT NOT NULL, profile_url TEXT NOT NULL, handle TEXT NOT NULL, name TEXT,
            method TEXT NOT NULL, attestation TEXT NOT NULL, revocation_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active', binding TEXT NOT NULL,
            expires_at INTEGER);
    """)
    db.execute("INSERT INTO proofs VALUES ('p1','legal_name','s','u','@a@x','Mario','mock','tok',?,1,'active','mastodon-oauth',NULL)",
               (hash_removal_code("ABCD-EFGH"),))
    db.commit(); db.close()
    store = Store(tmp_path / "old.sqlite3")
    proof = store.get_proof("p1")
    assert proof.verification_level == "legal_name" and proof.account_profile_url == "u"
    assert proof.identity_check_method == "mock" and proof.account_ownership_check == "mastodon-sign-in"
    assert proof.issuing_country is None
    assert store.delete_by_removal_code("abcd efgh").id == "p1"


def test_about_explains_keys_and_registration_status(tmp_path, mastodon):
    import httpx
    from dataclasses import replace
    from fastapi.testclient import TestClient
    from fediverse_verify.app import create_app
    from fediverse_verify.config import Settings
    base = Settings(public_url="https://verify.test", data_dir=tmp_path, session_secret="s")
    for settings, expected in ((base, "not registered with any EU member state yet"),
                               (replace(base, rp_registrar="AgID (Italy)", rp_register_url="https://register.example/rp/42"),
                                'href="https://register.example/rp/42"')):
        app = create_app(settings, http=httpx.AsyncClient(transport=httpx.MockTransport(mastodon.handler)))
        with TestClient(app, base_url="https://verify.test") as c:
            page = c.get("/about").text
            assert expected in page
            kid = c.get("/.well-known/jwks.json").json()["keys"][0]["kid"]
            assert f"<code>{kid}</code>" in page          # the key ID shown matches the published key


def test_wallet_page_after_finishing_says_already_done(client):
    verify(client, "person")
    r = client.get("/wallet")                       # e.g. the wallet's "back" link, in a second tab
    assert r.status_code == 200 and "Already done" in r.text and "expired" not in r.text


def test_wallet_page_without_any_flow_still_says_expired(client):
    assert "expired" in client.get("/wallet").text
