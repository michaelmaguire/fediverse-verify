"""SQLite storage. Holds proofs and OAuth client registrations, nothing else.

Deliberately absent: any identifier that links two proofs to the same person.
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
    id              TEXT PRIMARY KEY,
    level           TEXT NOT NULL CHECK (level IN ('person', 'legal_name')),
    subject_uri     TEXT NOT NULL,
    profile_url     TEXT NOT NULL,
    handle          TEXT NOT NULL,
    name            TEXT,
    method          TEXT NOT NULL,
    attestation     TEXT NOT NULL,
    revocation_hash TEXT NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active')),
    binding         TEXT NOT NULL DEFAULT 'mastodon-oauth',
    expires_at      INTEGER,         -- only for pending proofs
    issuing_country   TEXT,
    issuing_authority TEXT
);
CREATE INDEX IF NOT EXISTS proofs_subject ON proofs (subject_uri);
"""


@dataclass(frozen=True)
class Proof:
    id: str
    level: str
    subject_uri: str
    profile_url: str
    handle: str
    name: str | None
    method: str
    attestation: str          # empty while pending
    created_at: int
    status: str = "active"    # "pending" until the account links back, then "active"
    binding: str = "mastodon-oauth"
    expires_at: int | None = None
    issuing_country: str | None = None
    issuing_authority: str | None = None


@dataclass(frozen=True)
class OAuthClient:
    host: str
    client_id: str
    client_secret: str
    redirect_uri: str


def hash_revocation_code(code: str) -> str:
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
        columns = {row["name"] for row in self._db.execute("PRAGMA table_info(proofs)")}
        for name, ddl in (("status", "TEXT NOT NULL DEFAULT 'active'"),
                          ("binding", "TEXT NOT NULL DEFAULT 'mastodon-oauth'"),
                          ("expires_at", "INTEGER"),
                          ("issuing_country", "TEXT"),
                          ("issuing_authority", "TEXT")):
            if name not in columns:
                self._db.execute(f"ALTER TABLE proofs ADD COLUMN {name} {ddl}")

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
    def add_proof(self, proof: Proof, revocation_code: str) -> None:
        self._db.execute(
            "INSERT INTO proofs (id, level, subject_uri, profile_url, handle, name, method, attestation, "
            "revocation_hash, created_at, status, binding, expires_at, issuing_country, issuing_authority) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (proof.id, proof.level, proof.subject_uri, proof.profile_url, proof.handle, proof.name,
             proof.method, proof.attestation, hash_revocation_code(revocation_code), proof.created_at,
             proof.status, proof.binding, proof.expires_at, proof.issuing_country, proof.issuing_authority),
        )

    def activate(self, proof_id: str, attestation: str, issued_at: int) -> None:
        self._db.execute(
            "UPDATE proofs SET status = 'active', attestation = ?, created_at = ?, expires_at = NULL "
            "WHERE id = ? AND status = 'pending'", (attestation, issued_at, proof_id))

    def purge_expired(self, now: int | None = None) -> int:
        """Delete pending proofs whose account never linked back."""
        return self._db.execute("DELETE FROM proofs WHERE status = 'pending' AND expires_at < ?",
                                (now or int(time.time()),)).rowcount

    def get_proof(self, proof_id: str) -> Proof | None:
        self.purge_expired()
        row = self._db.execute(
            "SELECT id, level, subject_uri, profile_url, handle, name, method, attestation, created_at, "
            "status, binding, expires_at, issuing_country, issuing_authority "
            "FROM proofs WHERE id = ?", (proof_id,)
        ).fetchone()
        return Proof(**row) if row else None

    def proofs_for_subject(self, subject_uri: str) -> list[Proof]:
        rows = self._db.execute(
            "SELECT id, level, subject_uri, profile_url, handle, name, method, attestation, created_at, "
            "status, binding, expires_at, issuing_country, issuing_authority "
            "FROM proofs WHERE subject_uri = ? ORDER BY created_at", (subject_uri,)
        ).fetchall()
        return [Proof(**r) for r in rows]

    def delete_proof(self, proof_id: str) -> bool:
        return self._db.execute("DELETE FROM proofs WHERE id = ?", (proof_id,)).rowcount > 0

    def delete_by_revocation_code(self, code: str) -> Proof | None:
        row = self._db.execute(
            "SELECT id FROM proofs WHERE revocation_hash = ?", (hash_revocation_code(code),)
        ).fetchone()
        if not row:
            return None
        proof = self.get_proof(row["id"])
        self.delete_proof(row["id"])
        return proof
