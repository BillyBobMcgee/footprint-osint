"""Registered-account discovery via holehe (keyless email → accounts).

holehe checks whether an email is *registered* on 120+ sites by probing their
password-reset / signup flows — no API key, and the target receives no email.
This is the same technique the standalone `holehe` tool uses; footprint shells
out to it so its async stack stays isolated.

holehe is an optional dependency: `pip install holehe` (or `pip install
"footprint-osint[holehe]"`). If it isn't installed, this source is skipped.
"""

from __future__ import annotations

import csv
import glob
import io
import os
import shutil
import subprocess
import sys
import tempfile

from footprint.config import Config
from footprint.models import RegisteredAccount
from footprint.sources.base import SourceError


def _holehe_path() -> str | None:
    """Locate the holehe CLI on PATH or beside the running interpreter."""
    found = shutil.which("holehe")
    if found:
        return found
    scripts_dir = os.path.dirname(sys.executable)
    for name in ("holehe", "holehe.exe"):
        candidate = os.path.join(scripts_dir, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def available() -> bool:
    """True if the holehe CLI can be found."""
    return _holehe_path() is not None


def _parse_csv(text: str) -> list[RegisteredAccount]:
    """Parse holehe's CSV output into the accounts where the email exists."""
    reader = csv.DictReader(io.StringIO(text))
    accounts: list[RegisteredAccount] = []
    for row in reader:
        if str(row.get("exists", "")).strip().lower() == "true":
            accounts.append(
                RegisteredAccount(
                    site=(row.get("name") or "").strip(),
                    domain=(row.get("domain") or "").strip(),
                    email_recovery=(row.get("emailrecovery") or "").strip() or None,
                    phone=(row.get("phoneNumber") or "").strip() or None,
                )
            )
    accounts.sort(key=lambda a: a.site.lower())
    return accounts


def scan(email: str, config: Config) -> list[RegisteredAccount]:
    """Run holehe for an email and return the sites where it's registered."""
    holehe_bin = _holehe_path()
    if not holehe_bin:
        raise SourceError(
            "holehe not installed — run `pip install holehe` to enable "
            "registered-account discovery."
        )

    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(
                [holehe_bin, "--no-color", "-C", email],
                cwd=tmp,
                capture_output=True,
                timeout=max(config.timeout * 8, 120),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SourceError("holehe timed out") from exc
        except OSError as exc:  # pragma: no cover - PATH race
            raise SourceError(f"could not run holehe: {exc}") from exc

        csv_files = glob.glob(os.path.join(tmp, "*.csv"))
        if not csv_files:
            return []
        with open(csv_files[0], encoding="utf-8", errors="replace") as fh:
            text = fh.read()

    return _parse_csv(text)
