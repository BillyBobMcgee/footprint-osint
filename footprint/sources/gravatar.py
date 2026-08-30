"""Gravatar existence + public profile enrichment for an email.

Gravatar profiles are public by design. This reveals whether an email has a
public avatar/profile and surfaces any self-published profile fields — useful
context when assessing an account's public footprint.
"""

from __future__ import annotations

import hashlib
from typing import Any

from footprint.config import Config
from footprint.sources.base import fetch

AVATAR_URL = "https://www.gravatar.com/avatar/{hash}?d=404"
PROFILE_URL = "https://gravatar.com/{hash}.json"


def email_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()  # noqa: S324


def lookup(email: str, config: Config) -> dict[str, Any] | None:
    """Return a small dict of public profile info, or None if no Gravatar."""
    h = email_hash(email)

    avatar = fetch(config, AVATAR_URL.format(hash=h), source="Gravatar")
    if avatar.status_code != 200:
        return None

    result: dict[str, Any] = {
        "has_avatar": True,
        "avatar_url": f"https://www.gravatar.com/avatar/{h}",
    }

    try:
        profile = fetch(config, PROFILE_URL.format(hash=h), source="Gravatar")
        if profile.status_code == 200:
            data = profile.json() or {}
            entries = data.get("entry") or []
            if entries:
                entry = entries[0]
                result.update(
                    {
                        "username": entry.get("preferredUsername"),
                        "display_name": entry.get("displayName"),
                        "location": entry.get("currentLocation"),
                        "profile_url": entry.get("profileUrl"),
                        "accounts": [
                            a.get("url") for a in entry.get("accounts", []) if a.get("url")
                        ],
                    }
                )
    except Exception:  # noqa: BLE001 - profile JSON is best-effort enrichment
        pass

    return result
