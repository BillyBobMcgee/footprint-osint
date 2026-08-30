"""XposedOrNot — a free, keyless breach-by-email index.

Unlike HIBP (which charges for account lookups), XposedOrNot's email breach
and analytics endpoints require no API key, so footprint can report breach
exposure with zero credentials configured. Returns breach *metadata* only.

Docs: https://xposedornot.com/api_doc
"""

from __future__ import annotations

from urllib.parse import quote

from footprint.config import Config
from footprint.models import Breach
from footprint.sources.base import SourceError, fetch

ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email={email}"
CATALOG_URL = "https://api.xposedornot.com/v1/breaches"
MIN_INTERVAL = 0.5  # API allows ~2 requests/sec


def _parse_breach(item: dict) -> Breach:
    data = item.get("xposed_data") or ""
    return Breach(
        name=item.get("breach", ""),
        title=item.get("breach", ""),
        domain=item.get("domain", ""),
        breach_date=str(item.get("xposed_date") or "") or None,
        added_date=item.get("added"),
        pwn_count=int(item.get("xposed_records") or 0),
        data_classes=[d.strip() for d in data.split(";") if d.strip()],
        is_verified=str(item.get("verified", "")).lower() == "yes",
        description=item.get("details", ""),
    )


def analytics(email: str, config: Config) -> tuple[list[Breach], dict]:
    """Return (breaches, risk) for an email. Keyless.

    `risk` is {"label": str, "score": int} when available, else {}.
    """
    url = ANALYTICS_URL.format(email=quote(email, safe=""))
    result = fetch(config, url, min_interval=MIN_INTERVAL, source="XposedOrNot")
    if result.status_code == 404:
        return [], {}
    if result.status_code != 200:
        raise SourceError(f"XposedOrNot returned HTTP {result.status_code}")

    data = result.json() or {}
    if isinstance(data, dict) and data.get("Error"):
        return [], {}  # "Not found" — email is clean

    details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
    breaches = [_parse_breach(item) for item in details]

    risk: dict = {}
    risk_list = (data.get("BreachMetrics") or {}).get("risk") or []
    if risk_list:
        risk = {
            "label": risk_list[0].get("risk_label"),
            "score": risk_list[0].get("risk_score"),
        }
    return breaches, risk


def catalog(config: Config) -> list[Breach]:
    """The full public breach catalog (keyless alternative to HIBP's)."""
    result = fetch(config, CATALOG_URL, source="XposedOrNot")
    if result.status_code != 200:
        raise SourceError(f"XposedOrNot catalog returned HTTP {result.status_code}")
    data = result.json() or {}
    exposed = data.get("exposedBreaches") or data.get("breaches") or []
    return [_parse_breach(item) for item in exposed]
