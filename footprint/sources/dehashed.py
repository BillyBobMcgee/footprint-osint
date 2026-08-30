"""DeHashed credential-leak index integration (secrets redacted).

DeHashed's API returns full leaked records, including plaintext passwords and
hashes. footprint deliberately DISCARDS those secret values and reports only
their *presence*, plus non-secret identifiers, so the tool assesses exposure
without redistributing third-party credentials.

Requires a DeHashed account email + API key.
"""

from __future__ import annotations

from urllib.parse import quote

from footprint.config import Config
from footprint.models import LeakRecord
from footprint.sources.base import SourceError, build_session, fetch

API_URL = "https://api.dehashed.com/search?query={query}&size=100"

# Field -> label shown to the user. Secret fields are marked but never printed.
_FIELD_LABELS = {
    "email": "email",
    "username": "username",
    "name": "name",
    "password": "password [REDACTED]",
    "hashed_password": "hash [REDACTED]",
    "phone": "phone",
    "address": "address",
    "ip_address": "ip",
    "vin": "vin",
}


def _auth(config: Config):
    if not (config.dehashed_email and config.dehashed_api_key):
        raise SourceError(
            "DeHashed needs an account email + API key (set them in Settings)."
        )
    return config.dehashed_email, config.dehashed_api_key


def search_email(email: str, config: Config) -> list[LeakRecord]:
    """Return redacted leak records referencing an email."""
    return _search(f"email:{email}", config)


def search_username(username: str, config: Config) -> list[LeakRecord]:
    return _search(f"username:{username}", config)


def _search(query: str, config: Config) -> list[LeakRecord]:
    acct_email, api_key = _auth(config)
    session = build_session(config)
    session.auth = (acct_email, api_key)
    session.headers.update({"Accept": "application/json"})

    url = API_URL.format(query=quote(query, safe=":"))
    result = fetch(config, url, session=session, source="DeHashed")
    session.close()

    if result.status_code == 401:
        raise SourceError("DeHashed rejected the credentials (HTTP 401).")
    if result.status_code != 200:
        raise SourceError(f"DeHashed returned HTTP {result.status_code}")

    data = result.json() or {}
    entries = data.get("entries") or []
    records: list[LeakRecord] = []
    for entry in entries:
        present = [
            _FIELD_LABELS[k]
            for k in _FIELD_LABELS
            if entry.get(k) not in (None, "", [])
        ]
        records.append(
            LeakRecord(
                database=entry.get("database_name", "unknown"),
                fields_present=present,
                # Non-secret identifiers are kept; password/hash values are not.
                username=entry.get("username") or None,
                name=entry.get("name") or None,
                email=entry.get("email") or None,
            )
        )
    return records
