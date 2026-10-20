"""Account binding: proving the user controls an account before a proof is issued.

Mastodon OAuth is the first provider; others (IndieAuth, posted challenge) can follow.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BoundAccount:
    subject_uri: str   # what the attestation's `sub` names (ActivityPub actor id for Mastodon)
    profile_url: str   # the URL the proof page's rel="me" must point at
    handle: str        # human-readable, e.g. @alice@example.social
