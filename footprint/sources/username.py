"""Username presence checks across public platforms.

By default this loads the community-maintained WhatsMyName dataset (~600
sites), cached locally for a week. If the dataset can't be fetched, it falls
back to a small built-in list so the feature still works offline. Only public
profile pages are requested.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from footprint.config import Config, config_dir
from footprint.models import SiteHit
from footprint.sources.base import build_session

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_DATASET_TTL = 7 * 24 * 3600  # a week


@dataclass(frozen=True)
class SiteRule:
    name: str
    uri: str  # format string with {account}
    category: str = "other"
    e_code: int = 200
    e_string: str = ""  # must be present in body for a positive match
    m_string: str = ""  # if present in body, treat as a negative match


# Small offline fallback set.
_FALLBACK: tuple[SiteRule, ...] = (
    SiteRule("GitHub", "https://github.com/{account}", "coding"),
    SiteRule("GitLab", "https://gitlab.com/{account}", "coding"),
    SiteRule("Reddit", "https://www.reddit.com/user/{account}/about.json", "social"),
    SiteRule("Instagram", "https://www.instagram.com/{account}/", "social"),
    SiteRule("Twitter/X", "https://x.com/{account}", "social"),
    SiteRule("Keybase", "https://keybase.io/{account}", "coding"),
    SiteRule("Telegram", "https://t.me/{account}", "social", m_string="tgme_page_extra"),
    SiteRule("Pastebin", "https://pastebin.com/u/{account}", "misc"),
    SiteRule("HackerNews", "https://news.ycombinator.com/user?id={account}", "news",
             m_string="No such user."),
    SiteRule("Steam", "https://steamcommunity.com/id/{account}", "gaming",
             m_string="The specified profile could not be found"),
    SiteRule("Dev.to", "https://dev.to/{account}", "coding"),
    SiteRule("Medium", "https://medium.com/@{account}", "blog"),
)


def _dataset_path():
    return config_dir() / "wmn-data.json"


def load_sites(config: Config, refresh: bool = False) -> list[SiteRule]:
    """Load the WhatsMyName dataset (cached), or the built-in fallback."""
    path = _dataset_path()
    fresh = path.exists() and (time.time() - path.stat().st_mtime) < _DATASET_TTL

    if refresh or not fresh:
        try:
            session = build_session(config)
            resp = session.get(WMN_URL, timeout=config.timeout)
            session.close()
            if resp.status_code == 200 and resp.json().get("sites"):
                path.write_text(resp.text, encoding="utf-8")
        except Exception:  # noqa: BLE001 - fall back to cache / built-in list
            pass

    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            sites = [
                SiteRule(
                    name=s.get("name", "?"),
                    uri=s.get("uri_check", ""),
                    category=s.get("cat", "other"),
                    e_code=int(s.get("e_code", 200)),
                    e_string=s.get("e_string", "") or "",
                    m_string=s.get("m_string", "") or "",
                )
                for s in data.get("sites", [])
                if "{account}" in s.get("uri_check", "")
            ]
            if sites:
                return sites
        except (json.JSONDecodeError, OSError):
            pass

    return list(_FALLBACK)


def _check_one(rule: SiteRule, account: str, config: Config) -> SiteHit:
    session = build_session(config)
    url = rule.uri.format(account=account)
    try:
        resp = session.get(url, timeout=config.timeout, allow_redirects=True)
        body = resp.text
        exists = resp.status_code == rule.e_code
        if exists and rule.e_string and rule.e_string not in body:
            exists = False
        if exists and rule.m_string and rule.m_string in body:
            exists = False
    except Exception:  # noqa: BLE001 - one flaky site must not abort the sweep
        exists = False
    finally:
        session.close()
    return SiteHit(site=rule.name, url=url, exists=exists)


def check_username(
    username: str,
    config: Config,
    *,
    category: str | None = None,
    workers: int = 20,
    refresh: bool = False,
) -> list[SiteHit]:
    """Check `username` across the dataset, optionally filtered by category."""
    sites = load_sites(config, refresh=refresh)
    if category:
        sites = [s for s in sites if s.category.lower() == category.lower()]

    results: list[SiteHit] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_check_one, rule, username, config): rule for rule in sites
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda h: (not h.exists, h.site.lower()))
    return results


def categories(config: Config) -> list[str]:
    return sorted({s.category for s in load_sites(config)})
