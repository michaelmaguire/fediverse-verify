"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _list(value: str | None) -> tuple[str, ...]:
    return tuple(item.strip() for item in (value or "").split(",") if item.strip())


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Settings:
    public_url: str                      # e.g. https://verify.example.org (no trailing slash)
    data_dir: Path                       # SQLite database + signing key
    session_secret: str                  # signs the browser session cookie
    # Wallet types offered: "eudi" (EU Digital Identity Wallets), "swiyu" (Swiss e-ID),
    # or, for development only, "mock" / "mock-ch". Several may be enabled; users choose.
    identity_providers: tuple[str, ...] = ("mock",)
    eudi_endpoint: str = ""              # base URL of the EUDI verifier endpoint, for "eudi"
    eudi_wallet_scheme: str = "openid4vp://"
    swiyu_endpoint: str = ""             # base URL of the swiyu verifier's management API, for "swiyu"
    swiyu_issuer_dids: tuple[str, ...] = ()   # issuer DIDs whose Swiss e-IDs are accepted
    swiyu_vct_values: tuple[str, ...] = ()    # credential types to ask for; empty = the Beta-ID (test only)
    test_wallet_url: str = "http://localhost:8001"   # the test-wallet apps, for "mock" / "mock-ch"
    allow_private_hosts: bool = False    # let instance hosts resolve to private IPs (local testing only)
    app_name: str = "Fediverse Verify"     # site name; also shown on Mastodon's sign-in consent screen
    source_url: str = "https://github.com/michaelmaguire/fediverse-verify"
    operator_contact: str = ""            # shown on /about for removal requests (email or URL)
    storage_encrypted: bool = False        # set by deployments that keep the data folder on an encrypted disk
    rp_registrar: str = ""                 # e.g. "AgID (Italy)": who registered us as a wallet relying party
    rp_register_url: str = ""              # link to our entry in that registrar's public register

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
            identity_providers=_list(os.environ.get("VERIFIER_IDENTITY_PROVIDERS")
                                     or os.environ.get("VERIFIER_IDENTITY_PROVIDER", "mock")),
            eudi_endpoint=os.environ.get("VERIFIER_EUDI_ENDPOINT", "").rstrip("/"),
            eudi_wallet_scheme=os.environ.get("VERIFIER_EUDI_WALLET_SCHEME", "openid4vp://"),
            swiyu_endpoint=os.environ.get("VERIFIER_SWIYU_ENDPOINT", "").rstrip("/"),
            swiyu_issuer_dids=_list(os.environ.get("VERIFIER_SWIYU_ISSUER_DIDS", "")),
            swiyu_vct_values=_list(os.environ.get("VERIFIER_SWIYU_VCT_VALUES", "")),
            test_wallet_url=os.environ.get("VERIFIER_TEST_WALLET_URL", "http://localhost:8001").rstrip("/"),
            allow_private_hosts=_bool("VERIFIER_ALLOW_PRIVATE_HOSTS"),
            app_name=os.environ.get("VERIFIER_APP_NAME", "Fediverse Verify"),
            source_url=os.environ.get("VERIFIER_SOURCE_URL", "https://github.com/michaelmaguire/fediverse-verify"),
            operator_contact=os.environ.get("VERIFIER_OPERATOR_CONTACT", ""),
            storage_encrypted=_bool("VERIFIER_STORAGE_ENCRYPTED"),
            rp_registrar=os.environ.get("VERIFIER_RP_REGISTRAR", ""),
            rp_register_url=os.environ.get("VERIFIER_RP_REGISTER_URL", ""),
        )
