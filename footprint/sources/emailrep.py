"""EmailRep.io reputation lookup for an email address.

Returns a risk summary (reputation, whether the address looks suspicious,
and whether it's been seen in credential leaks / breaches). Works without a
key at a low rate limit; a key raises the limit.
"""

from __future__ import annotations

from urllib.parse import quote

from footprint.config import Config
from footprint.models import ReputationReport
from footprint.sources.base import SourceError, fetch

API_URL = "https://emailrep.io/{email}"


def lookup(email: str, config: Config) -> ReputationReport:
    headers = {"Accept": "application/json"}
    if config.emailrep_api_key:
        headers["Key"] = config.emailrep_api_key

    result = fetch(
        config, API_URL.format(email=quote(email, safe="")),
        headers=headers, source="EmailRep",
    )
    if result.status_code == 401:
        raise SourceError("EmailRep rejected the API key (HTTP 401).")
    if result.status_code != 200:
        raise SourceError(f"EmailRep returned HTTP {result.status_code}")

    data = result.json() or {}
    details = data.get("details", {}) or {}
    return ReputationReport(
        email=email,
        reputation=data.get("reputation", "none"),
        suspicious=bool(data.get("suspicious", False)),
        references=int(data.get("references", 0)),
        blacklisted=bool(details.get("blacklisted", False)),
        credentials_leaked=bool(details.get("credentials_leaked", False)),
        data_breach=bool(details.get("data_breach", False)),
        malicious_activity=bool(details.get("malicious_activity", False)),
        profiles=list(details.get("profiles", []) or []),
    )
