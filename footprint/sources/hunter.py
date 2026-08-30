"""Hunter.io domain-search: email naming pattern + known addresses.

Useful for authorized domain assessments — reveals the organization's email
format (e.g. {first}.{last}@corp.com) and publicly known addresses.

Requires a Hunter.io API key.
"""

from __future__ import annotations

from urllib.parse import quote

from footprint.config import Config
from footprint.sources.base import SourceError, fetch

API_URL = "https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}&limit=50"


def domain_emails(domain: str, config: Config) -> tuple[str | None, list[str]]:
    """Return (email_pattern, known_emails) for a domain."""
    if not config.hunter_api_key:
        raise SourceError("Hunter.io needs an API key (set it in Settings).")

    url = API_URL.format(domain=quote(domain, safe=""), key=config.hunter_api_key)
    result = fetch(config, url, source="Hunter.io")
    if result.status_code == 401:
        raise SourceError("Hunter.io rejected the API key (HTTP 401).")
    if result.status_code != 200:
        raise SourceError(f"Hunter.io returned HTTP {result.status_code}")

    data = (result.json() or {}).get("data", {}) or {}
    pattern = data.get("pattern")
    emails = [e.get("value") for e in data.get("emails", []) if e.get("value")]
    return pattern, emails
