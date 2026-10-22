"""Sign in with Mastodon (or any server implementing the Mastodon OAuth API)."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from ..net import ensure_public_host, normalize_host
from ..store import OAuthClient, Store
from . import BoundAccount
from .webfinger import WebFingerError, finger, json_object

SCOPES = "read:accounts"


class BindingError(Exception):
    pass


@dataclass(frozen=True)
class Authorization:
    url: str            # where to send the browser
    host: str
    state: str
    code_verifier: str


def parse_handle(text: str) -> tuple[str, str]:
    """'@alice@example.social', 'alice@example.social' or 'https://example.social/@alice' -> (user, host)."""
    text = text.strip()
    if text.startswith(("https://", "http://")):
        rest = text.split("://", 1)[1]
        host, _, path = rest.partition("/")
        user = path.lstrip("@").split("/")[0]
    else:
        user, sep, host = text.lstrip("@").partition("@")
        if not sep:
            raise BindingError("Enter your handle as @name@server")
    if not user or not host:
        raise BindingError("Enter your handle as @name@server")
    return user, normalize_host(host)


class MastodonBinding:
    def __init__(self, http: httpx.AsyncClient, store: Store, *, app_name: str, website: str,
                 redirect_uri: str, allow_private_hosts: bool):
        self._http = http
        self._store = store
        self._app_name = app_name
        self._website = website
        self._redirect_uri = redirect_uri
        self._allow_private = allow_private_hosts

    async def authorize(self, handle: str, *, scopes: str = SCOPES) -> Authorization:
        _user, host = parse_handle(handle)
        await ensure_public_host(host, self._allow_private)
        client = await self._client_for(host)
        state = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query = urlencode({
            "response_type": "code",
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uri,
            "scope": scopes,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        return Authorization(url=f"https://{host}/oauth/authorize?{query}", host=host, state=state,
                             code_verifier=verifier)

    async def complete(self, host: str, code: str, code_verifier: str) -> BoundAccount:
        client = self._store.get_client(host, self._redirect_uri)
        if client is None:
            raise BindingError("unknown server; start again")
        # The access token (scope read:accounts only) lives in this local variable for this
        # one request: it is never written to disk, the database or logs, and is revoked below.
        token = await self._exchange(client, code, code_verifier)
        revoked = False
        try:
            account = await self._get_json(host, "/api/v1/accounts/verify_credentials", token=token)
            username, profile_url = account["username"], account["url"]
            try:
                found = await finger(self._http, host, username)
            except WebFingerError as e:
                raise BindingError(str(e)) from e
            subject_uri, handle_domain = found.actor_uri, found.handle_domain
        finally:
            revoked = await self._revoke(client, token)   # we only needed the token once
            del token
        return BoundAccount(subject_uri=subject_uri, profile_url=profile_url,
                            handle=f"@{username}@{handle_domain}", token_revoked=revoked, server=host)

    # ---- internals ----
    async def _client_for(self, host: str) -> OAuthClient:
        client = self._store.get_client(host, self._redirect_uri)
        if client:
            return client
        resp = await self._http.post(f"https://{host}/api/v1/apps", data={
            "client_name": self._app_name,
            "redirect_uris": self._redirect_uri,
            "scopes": SCOPES,              # read:accounts only; nothing more is ever requested
            "website": self._website,
        })
        if resp.status_code != 200:
            raise BindingError(f"{host} refused app registration ({resp.status_code})")
        body = json_object(resp, host, BindingError)
        if not body.get("client_id") or not body.get("client_secret"):
            raise BindingError(f"{host} didn't register this verifier as an app")
        client = OAuthClient(host=host, client_id=body["client_id"], client_secret=body["client_secret"],
                             redirect_uri=self._redirect_uri)
        self._store.put_client(client)
        return client

    async def _exchange(self, client: OAuthClient, code: str, code_verifier: str) -> str:
        resp = await self._http.post(f"https://{client.host}/oauth/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uri": client.redirect_uri,
            "code_verifier": code_verifier,
        })
        if resp.status_code != 200:
            raise BindingError("sign-in failed; please try again")
        token = json_object(resp, client.host, BindingError).get("access_token")
        if not token:
            raise BindingError("sign-in failed; please try again")
        return token

    async def _revoke(self, client: OAuthClient, token: str) -> bool:
        """Cancel the access token on the user's server (RFC 7009). True if the server confirmed."""
        try:
            resp = await self._http.post(f"https://{client.host}/oauth/revoke", data={
                "client_id": client.client_id, "client_secret": client.client_secret, "token": token,
            })
        except httpx.HTTPError:
            return False
        return resp.status_code == 200

    async def _get_json(self, host: str, path: str, *, token: str | None = None, params=None) -> dict:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        resp = await self._http.get(f"https://{host}{path}", headers=headers, params=params)
        if resp.status_code != 200:
            raise BindingError(f"{host} returned {resp.status_code} for {path}")
        return json_object(resp, host, BindingError)
