"""Intelligence X (intelx.io) dark-web / leak *index* integration.

This queries an index that has already crawled leak sites, pastes, and
dark-web sources, and reports which entries *reference* a search term. It
returns catalog metadata only (source bucket, date, item name), so footprint
never downloads or displays the leaked file contents.

Requires an Intelligence X API key.
"""

from __future__ import annotations

from footprint.config import Config
from footprint.models import DarkWebMatch
from footprint.sources.base import SourceError, fetch

BASE = "https://2.intelx.io"
SEARCH_URL = f"{BASE}/intelligent/search"
RESULT_URL = f"{BASE}/intelligent/search/result"

# Numeric media-type codes IntelX uses; enough for a readable label.
_MEDIA = {
    0: "unknown", 1: "paste", 2: "paste-user", 15: "leak", 16: "url",
    18: "pdf", 23: "leak", 24: "leak",
}


def _headers(config: Config) -> dict[str, str]:
    if not config.intelx_api_key:
        raise SourceError("Intelligence X needs an API key (set it in Settings).")
    return {"x-key": config.intelx_api_key}


def search(term: str, config: Config, max_results: int = 50) -> list[DarkWebMatch]:
    """Search the IntelX index for a term (email, domain, etc.)."""
    headers = _headers(config)

    start = fetch(
        config,
        SEARCH_URL,
        method="POST",
        headers=headers,
        json_body={
            "term": term,
            "maxresults": max_results,
            "media": 0,
            "sort": 2,  # newest first
            "terminate": [],
        },
        source="IntelX",
    )
    if start.status_code == 401:
        raise SourceError("Intelligence X rejected the API key (HTTP 401).")
    if start.status_code != 200:
        raise SourceError(f"IntelX search returned HTTP {start.status_code}")

    search_id = (start.json() or {}).get("id")
    if not search_id:
        return []

    result = fetch(
        config,
        f"{RESULT_URL}?id={search_id}&limit={max_results}",
        headers=headers,
        source="IntelX",
    )
    if result.status_code != 200:
        raise SourceError(f"IntelX result returned HTTP {result.status_code}")

    records = (result.json() or {}).get("records") or []
    matches: list[DarkWebMatch] = []
    for rec in records:
        matches.append(
            DarkWebMatch(
                name=rec.get("name") or "(unnamed)",
                bucket=rec.get("bucket") or "?",
                date=rec.get("date"),
                media_type=_MEDIA.get(rec.get("media", 0), "unknown"),
                system_id=rec.get("systemid"),
            )
        )
    return matches
