from __future__ import annotations

import base64
import hashlib
import json

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fediverse_verify.credential import (ActorKey, b58decode, b58encode, build_credential,
                                         public_key_from_multikey, verify)

from .conftest import ACTOR_URI, PROFILE_URL, verify as run_verify


def path_of(url: str) -> str:
    return url.removeprefix("https://verify.test")


def mastodon_verify_eddsa_jcs_2022(document: dict, public_key) -> bool:
    """A line-by-line port of Mastodon's ActivityPub::ObjectIntegrityProof.verify_eddsa_jcs_2022."""
    unsecured = {k: v for k, v in document.items() if k != "proof"}
    proof_options = {k: v for k, v in document["proof"].items() if k != "proofValue"}
    proof_bytes = b58decode(document["proof"]["proofValue"][1:])
    if proof_options.get("@context"):
        assert isinstance(unsecured["@context"], list)
        assert unsecured["@context"][: len(proof_options["@context"])] == proof_options["@context"]
        unsecured["@context"] = proof_options["@context"]
    to_be_verified = hashlib.sha256(rfc8785.dumps(proof_options)).digest() + hashlib.sha256(rfc8785.dumps(unsecured)).digest()
    try:
        public_key.verify(proof_bytes, to_be_verified)
        return True
    except Exception:
        return False


def test_base58_round_trip():
    for data in (b"", b"\0\0abc", bytes(range(64))):
        assert b58decode(b58encode(data)) == data


def test_proof_publishes_a_signed_w3c_credential(client):
    url, _ = run_verify(client, "legal_name", show_age=True)
    vc = client.get(path_of(url) + ".json").json()
    assert vc["type"] == ["VerifiableCredential", "FediverseVerifiedCredential"]
    assert vc["issuer"] == "https://verify.test/actor" and vc["id"] == url
    subject = vc["credentialSubject"]
    assert subject["id"] == ACTOR_URI and subject["account_profile_url"] == PROFILE_URL
    assert subject["verification_level"] == "legal_name" and subject["name"] == "Mario Rossi"
    assert subject["age_over_18"] is True
    assert vc["evidence"][0]["identity_check_method"] == "mock"
    assert vc["evidence"][0]["test"] is True                  # test proofs say so in the signed evidence
    assert vc["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert 'id="fediverse-verified-credential"' in client.get(path_of(url)).text


def test_credential_verifies_with_the_published_actor_key_like_mastodon(client):
    url, _ = run_verify(client, "person")
    vc = client.get(path_of(url) + ".json").json()
    actor = client.get("/actor").json()
    key = next(k for k in actor["assertionMethod"] if k["id"] == vc["proof"]["verificationMethod"])
    assert key["type"] == "Multikey" and key["controller"] == actor["id"] == vc["issuer"]
    public_key = public_key_from_multikey(key["publicKeyMultibase"])
    assert mastodon_verify_eddsa_jcs_2022(vc, public_key)
    assert verify(vc, public_key)
    tampered = {**vc, "credentialSubject": {**vc["credentialSubject"], "verification_level": "legal_name"}}
    assert not mastodon_verify_eddsa_jcs_2022(tampered, public_key) and not verify(tampered, public_key)


def test_actor_is_discoverable_by_webfinger(client):
    r = client.get("/.well-known/webfinger", params={"resource": "acct:verify@verify.test"})
    assert r.json()["links"][0]["href"] == "https://verify.test/actor"
    assert client.get("/.well-known/webfinger", params={"resource": "acct:someone@verify.test"}).status_code == 404
    assert client.get("/actor").headers["content-type"].startswith("application/activity+json")


def test_pending_proofs_have_no_credential_yet(client):
    url, _ = run_verify(client, "person", binding="link-back")
    assert client.get(path_of(url) + ".json").status_code == 404


def test_webfinger_answers_the_handle_without_a_port(tmp_path):
    import httpx
    from fastapi.testclient import TestClient
    from fediverse_verify.app import create_app
    from fediverse_verify.config import Settings
    app = create_app(Settings(public_url="https://verify.localhost:8443", data_dir=tmp_path, session_secret="s"),
                     http=httpx.AsyncClient())
    with TestClient(app, base_url="https://verify.localhost:8443") as c:
        for resource in ("acct:verify@verify.localhost", "acct:verify@verify.localhost:8443"):
            r = c.get("/.well-known/webfinger", params={"resource": resource})
            assert r.status_code == 200 and r.json()["subject"] == resource
            assert r.json()["links"][0]["href"] == "https://verify.localhost:8443/actor"


def test_real_identity_checks_carry_no_test_marker():
    claims = {"sub": ACTOR_URI, "account_profile_url": PROFILE_URL, "verification_level": "person", "iat": 0,
              "identity_check_method": "eudi-pid", "account_ownership_check": "link-back"}
    vc = build_credential(proof_url="https://verify.test/u/x", issuer="https://verify.test/actor", claims=claims)
    assert "test" not in vc["evidence"][0]
