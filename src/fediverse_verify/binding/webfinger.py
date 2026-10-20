"""WebFinger lookup: handle -> ActivityPub actor and profile page. Works for any Fediverse software."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

ACTIVITY_JSON = ("application/activity+json", 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"')
PROFILE_PAGE_REL = "http://webfinger.net/rel/profile-page"


class WebFingerError(Exception):
    pass


@dataclass(frozen=True)
class Finger:
    actor_uri: str
    profile_url: str | None
    handle_domain: str


async def finger(http: httpx.AsyncClient, host: str, username: str) -> Finger:
    resp = await http.get(f"https://{host}/.well-known/webfinger",
                          params={"resource": f"acct:{username}@{host}"},
                          headers={"Accept": "application/jrd+json, application/json"})
    if resp.status_code != 200:
        raise WebFingerError(f"{host} doesn't know @{username} (WebFinger returned {resp.status_code})")
    data = resp.json()
    actor = profile = None
    for link in data.get("links", []):
        if link.get("rel") == "self" and link.get("type") in ACTIVITY_JSON:
            actor = link.get("href")
        elif link.get("rel") == PROFILE_PAGE_REL:
            profile = link.get("href")
    if not actor:
        raise WebFingerError("could not find the account's ActivityPub actor")
    handle_domain = data.get("subject", "").rpartition("@")[2] or host
    return Finger(actor_uri=actor, profile_url=profile, handle_domain=handle_domain)
