"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Settings:
    public_url: str                      # e.g. https://verify.example.org (no trailing slash)
    data_dir: Path                       # SQLite database + signing key
    session_secret: str                  # signs the browser session cookie
    identity_provider: str = "mock"      # "mock" (development only) or "eudi"
    eudi_endpoint: str = ""              # base URL of the EUDI verifier endpoint, for "eudi"
    eudi_wallet_scheme: str = "openid4vp://"
    allow_private_hosts: bool = False    # let instance hosts resolve to private IPs (local testing only)
    app_name: str = "Fediverse Verify"     # site name; also shown on Mastodon's sign-in consent screen
    source_url: str = "https://github.com/michaelmaguire/fediverse-verify"
    operator_contact: str = ""            # shown on /about for removal requests (email or URL)
    storage_encrypted: bool = False        # set by deployments that keep the data folder on an encrypted disk

    @classmethod
    def from_env(cls) -> "Settings":
        public_url = os.environ.get("VERIFIER_PUBLIC_URL", "http://localhost:8000").rstrip("/")
        secret = os.environ.get("VERIFIER_SESSION_SECRET", "")
        if not secret:
            raise RuntimeError("VERIFIER_SESSION_SECRET must be set")
        return cls(
            public_url=public_url,
            data_dir=Path(os.environ.get("VERIFIER_DATA_DIR", "./data")),
            session_secret=secret,
            identity_provider=os.environ.get("VERIFIER_IDENTITY_PROVIDER", "mock"),
            eudi_endpoint=os.environ.get("VERIFIER_EUDI_ENDPOINT", "").rstrip("/"),
            eudi_wallet_scheme=os.environ.get("VERIFIER_EUDI_WALLET_SCHEME", "openid4vp://"),
            allow_private_hosts=_bool("VERIFIER_ALLOW_PRIVATE_HOSTS"),
            app_name=os.environ.get("VERIFIER_APP_NAME", "Fediverse Verify"),
            source_url=os.environ.get("VERIFIER_SOURCE_URL", "https://github.com/michaelmaguire/fediverse-verify"),
            operator_contact=os.environ.get("VERIFIER_OPERATOR_CONTACT", ""),
            storage_encrypted=_bool("VERIFIER_STORAGE_ENCRYPTED"),
        )
