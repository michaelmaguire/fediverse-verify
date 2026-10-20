"""Which source the running code was built from, for the footer's transparency links."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

_SHA = re.compile(r"^[0-9a-f]{7,40}$")


@dataclass(frozen=True)
class BuildInfo:
    source_url: str
    commit: str | None      # full SHA, or None if unknown
    dirty: bool             # built from uncommitted changes

    @property
    def short(self) -> str | None:
        return self.commit[:12] if self.commit else None

    @property
    def commit_url(self) -> str | None:
        """Only link a commit when the running code matches it exactly."""
        if self.commit and not self.dirty:
            return f"{self.source_url.rstrip('/')}/tree/{self.commit}"
        return None


def detect(source_url: str) -> BuildInfo:
    """VERIFIER_GIT_COMMIT (set at image build time, '-dirty' suffix allowed) or a local git checkout."""
    value = os.environ.get("VERIFIER_GIT_COMMIT", "").strip().lower()
    if value and value != "unknown":
        sha, _, suffix = value.partition("-")
        return BuildInfo(source_url, sha if _SHA.match(sha) else None, suffix == "dirty")
    return _from_git(source_url)


def _from_git(source_url: str) -> BuildInfo:
    here = Path(__file__).resolve().parent
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=here, capture_output=True, text=True,
                             timeout=5, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "."], cwd=here,
                                    capture_output=True, text=True, timeout=5, check=True).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return BuildInfo(source_url, None, False)
    return BuildInfo(source_url, sha if _SHA.match(sha) else None, dirty)


def describe_for_build(path: Path) -> str:
    """Helper for build scripts: '<sha>' or '<sha>-dirty' for the checkout at `path`, else 'unknown'."""
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True,
                             check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=path, capture_output=True, text=True,
                               check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return f"{sha}-dirty" if dirty else sha
