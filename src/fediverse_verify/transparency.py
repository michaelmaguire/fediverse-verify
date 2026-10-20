"""Links from the About page to the exact code that stores, reads and deletes data.

Line ranges are computed from the running code, and links are pinned to the commit
it was built from, so they stay accurate as the code changes.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import dataclass
from pathlib import Path

from . import app as _app_module
from . import attestation, store
from .buildinfo import BuildInfo
from .identity import eudi

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_PREFIX = "src/fediverse_verify"


@dataclass(frozen=True)
class CodeLink:
    label: str
    url: str
    where: str          # e.g. "store.py lines 84–92"


def _lines_of(obj) -> tuple[Path, int, int]:
    source, start = inspect.getsourcelines(obj)
    return Path(inspect.getsourcefile(obj)).resolve(), start, start + len(source) - 1


def _lines_of_assignment(module, name: str) -> tuple[Path, int, int]:
    """Line range of a module-level `NAME = ...` statement."""
    path = Path(inspect.getsourcefile(module)).resolve()
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return path, node.lineno, node.end_lineno or node.lineno
    raise LookupError(f"{name} not found in {path}")


def build_links(build: BuildInfo) -> dict[str, CodeLink]:
    ref = build.commit if build.commit else "main"
    base = build.source_url.rstrip("/")

    def link(label: str, located: tuple[Path, int, int]) -> CodeLink:
        path, start, end = located
        rel = f"{REPO_PREFIX}/{path.relative_to(PACKAGE_DIR).as_posix()}"
        return CodeLink(label, f"{base}/blob/{ref}/{rel}#L{start}-L{end}",
                        f"{path.name} lines {start}–{end}")

    S = store.Store
    return {
        "schema": link("Database tables", _lines_of_assignment(store, "SCHEMA")),
        "open": link("Opening the database (secure delete on)", _lines_of(S.__init__)),
        "add_proof": link("Saving a proof", _lines_of(S.add_proof)),
        "hash": link("Hashing the removal code", _lines_of(store.hash_removal_code)),
        "activate": link("Activating a confirmed proof", _lines_of(S.activate)),
        "get_proof": link("Reading a proof", _lines_of(S.get_proof)),
        "for_subject": link("Listing an account's proofs", _lines_of(S.proofs_for_subject)),
        "delete": link("Deleting a proof", _lines_of(S.delete_proof)),
        "delete_code": link("Deleting with the removal code", _lines_of(S.delete_by_removal_code)),
        "purge": link("Deleting unconfirmed proofs after 24 hours", _lines_of(S.purge_expired)),
        "clients": link("Saving app registrations", _lines_of(S.put_client)),
        "key": link("Creating/loading the signing key", _lines_of(attestation.Signer.load_or_create)),
        "claims": link("What goes into the signed statement", _lines_of(attestation.build_claims)),
        "wallet": link("Reading only the requested claims from the wallet", _lines_of(eudi.EudiProvider.result)),
        "app": link("Sessions, cookies and in-memory state", _lines_of(_app_module.create_app)),
    }
