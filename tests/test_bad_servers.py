"""A server that doesn't answer like Mastodon (e.g. a proxy's empty page) gets a message, never a crash."""
from __future__ import annotations

import html

import pytest


@pytest.mark.parametrize("binding", ["mastodon-sign-in", "link-back"])
def test_empty_answers_explain_instead_of_crashing(client, mastodon, binding):
    mastodon.empty_answers = True
    r = client.post("/verify", data={"handle": "@alice@social.example", "level": "legal_name", "binding": binding})
    assert r.status_code == 400
    assert "didn't answer like a Fediverse server" in html.unescape(r.text)
