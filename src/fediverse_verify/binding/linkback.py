"""Link-back binding: the account proves control by linking to its proof from its own profile.

Works with any software that publishes profile fields on its ActivityPub actor
(Mastodon, GoToSocial, Akkoma, Misskey, ...). No sign-in or permissions needed.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

from ..net import ensure_public_host
from . import BoundAccount
from .mastodon import BindingError, parse_handle
from .webfinger import ACTIVITY_JSON, WebFingerError, finger


class _Hrefs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


def links_in(value: str) -> set[str]:
    """Links in a profile field value, which may be HTML or a bare URL."""
    parser = _Hrefs()
    parser.feed(value or "")
    found = set(parser.hrefs)
    if value and value.strip().startswith(("https://", "http://")) and " " not in value.strip():
        found.add(value.strip())
    return found


def _same_url(a: str, b: str) -> bool:
    return a.rstrip("/") == b.rstrip("/")


class LinkBackBinding:
    def __init__(self, http: httpx.AsyncClient, *, allow_private_hosts: bool):
        self._http = http
        self._allow_private = allow_private_hosts

    async def resolve(self, handle: str) -> BoundAccount:
        """Look the account up (no proof of control yet)."""
        username, host = parse_handle(handle)
        await ensure_public_host(host, self._allow_private)
        try:
            found = await finger(self._http, host, username)
        except WebFingerError as e:
            raise BindingError(str(e)) from e
        profile_url = found.profile_url or (await self._actor(found.actor_uri) or {}).get("url")
        if not isinstance(profile_url, str):
            raise BindingError("could not find the account's profile page")
        return BoundAccount(subject_uri=found.actor_uri, profile_url=profile_url,
                            handle=f"@{username}@{found.handle_domain}")

    async def links_to(self, account: BoundAccount, url: str) -> bool:
        """Does the account's public profile currently contain a link to `url`?"""
        actor = await self._actor(account.subject_uri)
        if actor is not None:
            for item in actor.get("attachment") or []:
                if isinstance(item, dict) and item.get("type") == "PropertyValue":
                    if any(_same_url(href, url) for href in links_in(item.get("value", ""))):
                        return True
        # Not found on the actor. Mastodon caches actor documents for up to 3 minutes,
        # and servers with "authorized fetch" refuse unsigned actor requests, so also
        # ask the public Mastodon-compatible lookup API, which is always current.
        return await self._mastodon_lookup_links_to(account, url)

    async def _actor(self, actor_uri: str) -> dict | None:
        host = urlparse(actor_uri).netloc
        await ensure_public_host(host, self._allow_private)
        resp = await self._http.get(actor_uri, headers={"Accept": ACTIVITY_JSON[0]})
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    async def _mastodon_lookup_links_to(self, account: BoundAccount, url: str) -> bool:
        username, _ = parse_handle(account.handle)
        resp = await self._http.get(f"https://{urlparse(account.subject_uri).netloc}/api/v1/accounts/lookup",
                                    params={"acct": username})
        if resp.status_code != 200:
            return False
        try:
            data = resp.json()
        except ValueError:
            return False
        for field in (data.get("fields") if isinstance(data, dict) else None) or []:
            if any(_same_url(href, url) for href in links_in(field.get("value", ""))):
                return True
        return False
