"""Have I Been Pwned v3 API integration.

- Breach/paste lookups for an *account* require an HIBP API key.
- Domain breach listing and the full breach catalog are public (no key).

The account endpoints deliberately return breach *metadata* (which service,
when, what categories of data), never plaintext credentials.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from footprint.config import Config
from footprint.models import Breach, Paste
from footprint.sources.base import HttpResult, SourceError, fetch

API_ROOT = "https://haveibeenpwned.com/api/v3"
# HIBP asks clients to rate-limit; keep a polite gap between account calls.
MIN_INTERVAL = 1.6


def _auth_headers(config: Config) -> dict[str, str]:
    if not config.hibp_api_key:
        raise SourceError(
            "This lookup needs an HIBP API key. Set HIBP_API_KEY or configure it "
            "in Settings. Get one at https://haveibeenpwned.com/API/Key"
        )
    return {"hibp-api-key": config.hibp_api_key}


def _check(result: HttpResult, endpoint: str) -> None:
    if result.status_code == 401:
        raise SourceError("HIBP rejected the API key (HTTP 401).")
    if result.status_code == 403:
        raise SourceError("HIBP forbade the request (HTTP 403); check User-Agent.")
    if result.status_code not in (200, 404):
        raise SourceError(f"HIBP {endpoint} returned HTTP {result.status_code}")


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


def _parse_breach(item: dict) -> Breach:
    return Breach(
        name=item.get("Name", ""),
        title=item.get("Title", item.get("Name", "")),
        domain=item.get("Domain", ""),
        breach_date=item.get("BreachDate"),
        added_date=item.get("AddedDate"),
        pwn_count=item.get("PwnCount", 0),
        data_classes=item.get("DataClasses", []) or [],
        is_verified=item.get("IsVerified", False),
        is_sensitive=item.get("IsSensitive", False),
        is_fabricated=item.get("IsFabricated", False),
        description=_strip_html(item.get("Description", "")),
    )


def breached_account(account: str, config: Config) -> list[Breach]:
    """Breaches an email/account appears in (requires API key)."""
    url = f"{API_ROOT}/breachedaccount/{quote(account, safe='')}?truncateResponse=false"
    result = fetch(
        config, url, headers=_auth_headers(config),
        min_interval=MIN_INTERVAL, source="HIBP",
    )
    _check(result, "breachedaccount")
    if result.status_code == 404:
        return []
    return [_parse_breach(item) for item in result.json()]


def pasted_account(account: str, config: Config) -> list[Paste]:
    """Pastes an email/account appears in (requires API key)."""
    url = f"{API_ROOT}/pasteaccount/{quote(account, safe='')}"
    result = fetch(
        config, url, headers=_auth_headers(config),
        min_interval=MIN_INTERVAL, source="HIBP",
    )
    _check(result, "pasteaccount")
    if result.status_code == 404:
        return []
    return [
        Paste(
            source=item.get("Source", ""),
            paste_id=item.get("Id", ""),
            title=item.get("Title"),
            date=item.get("Date"),
            email_count=item.get("EmailCount", 0),
        )
        for item in result.json()
    ]


def breaches_for_domain(domain: str, config: Config) -> list[Breach]:
    """All catalogued breaches affecting a domain (public, no key needed)."""
    url = f"{API_ROOT}/breaches?domain={quote(domain, safe='')}"
    result = fetch(config, url, source="HIBP")
    if result.status_code != 200:
        raise SourceError(f"HIBP breaches returned HTTP {result.status_code}")
    return [_parse_breach(item) for item in result.json()]


def all_breaches(config: Config) -> list[Breach]:
    """The full public breach catalog."""
    result = fetch(config, f"{API_ROOT}/breaches", source="HIBP")
    if result.status_code != 200:
        raise SourceError(f"HIBP breaches returned HTTP {result.status_code}")
    return [_parse_breach(item) for item in result.json()]
