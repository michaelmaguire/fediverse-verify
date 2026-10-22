"""SQLite storage. Holds proofs and OAuth client registrations, nothing else.

Deliberately absent: any identifier that links two proofs to the same person.
Column names match the signed copy's field names where both exist.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_clients (
    host          TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proofs (
    id                      TEXT PRIMARY KEY,
    verification_level      TEXT NOT NULL CHECK (verification_level IN ('person', 'legal_name')),
    subject_uri             TEXT NOT NULL,
    account_profile_url     TEXT NOT NULL,
    handle                  TEXT NOT NULL,
    name                    TEXT,
    identity_check_method   TEXT NOT NULL,
    attestation             TEXT NOT NULL,
    removal_code_hash       TEXT NOT NULL UNIQUE,
    created_at              INTEGER NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active')),
    account_ownership_check TEXT NOT NULL DEFAULT 'mastodon-sign-in',
    expires_at              INTEGER,         -- only for pending proofs
    issuing_country         TEXT,
    issuing_authority       TEXT,
    age_over_18             INTEGER,         -- 1 if shown as 18+; otherwise NULL (never "under 18")
    credential              TEXT             -- the signed copy as a W3C credential (JSON); empty while pending
);
CREATE INDEX IF NOT EXISTS proofs_subject ON proofs (subject_uri);
"""

PROOF_COLUMNS = (
    "id, verification_level, subject_uri, account_profile_url, handle, name, identity_check_method, "
    "attestation, created_at, status, account_ownership_check, expires_at, issuing_country, issuing_authority, "
    "age_over_18, credential"
)


@dataclass(frozen=True)
class Proof:
    id: str
    verification_level: str            # "legal_name" or "person"
    subject_uri: str
    account_profile_url: str
    handle: str
    name: str | None
    identity_check_method: str         # "eudi-pid" or "mock"
    attestation: str                   # the signed copy; empty while pending
    created_at: int
    status: str = "active"             # "pending" until the account links back, then "active"
    account_ownership_check: str = "mastodon-sign-in"   # or "link-back"
    expires_at: int | None = None
    issuing_country: str | None = None
    issuing_authority: str | None = None
    age_over_18: bool | None = None
    credential: str = ""                 # W3C Verifiable Credential (eddsa-jcs-2022); empty while pending


@dataclass(frozen=True)
class OAuthClient:
    host: str
    client_id: str
    client_secret: str
    redirect_uri: str


def _proof(row: sqlite3.Row) -> Proof:
    values = dict(row)
    values["age_over_18"] = True if values.get("age_over_18") else None
    values["credential"] = values.get("credential") or ""
    return Proof(**values)


def hash_removal_code(code: str) -> str:
    normalized = code.replace("-", "").replace(" ", "").upper()
    return hashlib.sha256(normalized.encode()).hexdigest()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        # Overwrite deleted content with zeros, so removed proofs don't linger in the file.
        self._db.execute("PRAGMA secure_delete = ON")
        self._db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Bring databases created by earlier versions up to the current schema."""
        columns = {row["name"] for row in self._db.execute("PRAGMA table_info(proofs)")}
        # 2026-10-20: columns renamed to match the signed copy's field names.
        for old, new in (("level", "verification_level"), ("profile_url", "account_profile_url"),
                         ("method", "identity_check_method"), ("binding", "account_ownership_check"),
                         ("revocation_hash", "removal_code_hash")):
            if old in columns and new not in columns:
                self._db.execute(f"ALTER TABLE proofs RENAME COLUMN {old} TO {new}")
                columns = (columns - {old}) | {new}
        for name, ddl in (("status", "TEXT NOT NULL DEFAULT 'active'"),
                          ("account_ownership_check", "TEXT NOT NULL DEFAULT 'mastodon-sign-in'"),
                          ("expires_at", "INTEGER"),
                          ("issuing_country", "TEXT"),
                          ("issuing_authority", "TEXT"),
                          ("age_over_18", "INTEGER"),
                          ("credential", "TEXT")):
            if name not in columns:
                self._db.execute(f"ALTER TABLE proofs ADD COLUMN {name} {ddl}")
        # 2026-10-20: value renamed for clarity.
        self._db.execute("UPDATE proofs SET account_ownership_check = 'mastodon-sign-in' "
                         "WHERE account_ownership_check = 'mastodon-oauth'")

    # ---- OAuth clients (one app registration per Mastodon instance) ----
    def get_client(self, host: str, redirect_uri: str) -> OAuthClient | None:
        row = self._db.execute(
            "SELECT host, client_id, client_secret, redirect_uri FROM oauth_clients WHERE host = ? AND redirect_uri = ?",
            (host, redirect_uri),
        ).fetchone()
        return OAuthClient(**row) if row else None

    def put_client(self, client: OAuthClient) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO oauth_clients VALUES (?, ?, ?, ?, ?)",
            (client.host, client.client_id, client.client_secret, client.redirect_uri, int(time.time())),
        )

    # ---- Proofs ----
    def add_proof(self, proof: Proof, removal_code: str) -> None:
        self._db.execute(
            f"INSERT INTO proofs ({PROOF_COLUMNS}, removal_code_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (proof.id, proof.verification_level, proof.subject_uri, proof.account_profile_url, proof.handle,
             proof.name, proof.identity_check_method, proof.attestation, proof.created_at, proof.status,
             proof.account_ownership_check, proof.expires_at, proof.issuing_country, proof.issuing_authority,
             1 if proof.age_over_18 else None, proof.credential or None, hash_removal_code(removal_code)),
        )

    def activate(self, proof_id: str, attestation: str, issued_at: int, credential: str = "") -> None:
        self._db.execute(
            "UPDATE proofs SET status = 'active', attestation = ?, credential = ?, created_at = ?, expires_at = NULL "
            "WHERE id = ? AND status = 'pending'", (attestation, credential or None, issued_at, proof_id))

    def purge_expired(self, now: int | None = None) -> int:
        """Delete pending proofs whose account never linked back."""
        return self._db.execute("DELETE FROM proofs WHERE status = 'pending' AND expires_at < ?",
                                (now or int(time.time()),)).rowcount

    def get_proof(self, proof_id: str) -> Proof | None:
        self.purge_expired()
        row = self._db.execute(f"SELECT {PROOF_COLUMNS} FROM proofs WHERE id = ?", (proof_id,)).fetchone()
        return _proof(row) if row else None

    def proofs_for_subject(self, subject_uri: str) -> list[Proof]:
        rows = self._db.execute(
            f"SELECT {PROOF_COLUMNS} FROM proofs WHERE subject_uri = ? ORDER BY created_at", (subject_uri,)
        ).fetchall()
        return [_proof(r) for r in rows]

    def delete_proof(self, proof_id: str) -> bool:
        return self._db.execute("DELETE FROM proofs WHERE id = ?", (proof_id,)).rowcount > 0

    def delete_by_removal_code(self, code: str) -> Proof | None:
        row = self._db.execute(
            "SELECT id FROM proofs WHERE removal_code_hash = ?", (hash_removal_code(code),)
        ).fetchone()
        if not row:
            return None
        proof = self.get_proof(row["id"])
        self.delete_proof(row["id"])
        return proof
