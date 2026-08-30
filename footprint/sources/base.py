"""Shared HTTP plumbing: retries, Tor routing, rate limiting, and caching."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from footprint import cache
from footprint.config import Config


class SourceError(RuntimeError):
    """Raised when a source cannot complete a lookup (network, auth, quota)."""


class RateLimitError(SourceError):
    """Raised specifically when a source reports HTTP 429."""


@dataclass
class HttpResult:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        return json.loads(self.text) if self.text else None


# Per-host last-call timestamps so we can honor minimum intervals politely.
_last_call: dict[str, float] = {}
_rate_lock = threading.Lock()


def build_session(config: Config) -> requests.Session:
    """A session with retry/backoff and optional Tor proxying."""
    session = requests.Session()
    retry = Retry(
        total=config.max_retries,
        connect=config.max_retries,
        read=config.max_retries,
        backoff_factor=0.6,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": config.user_agent})
    if config.proxies:
        session.proxies.update(config.proxies)
    return session


def _respect_rate(host: str, min_interval: float) -> None:
    if min_interval <= 0:
        return
    with _rate_lock:
        last = _last_call.get(host, 0.0)
        wait = min_interval - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        _last_call[host] = time.time()


def _cache_key(method: str, url: str, headers: dict | None, body: str | None) -> str:
    # API keys live in headers; hash them into the key so cached entries don't
    # bleed across credentials, but the raw key is never stored.
    material = json.dumps(
        {"m": method, "u": url, "h": headers or {}, "b": body or ""}, sort_keys=True
    )
    return hashlib.sha256(material.encode()).hexdigest()


def fetch(
    config: Config,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
    cache_ttl: int | None = None,
    min_interval: float = 0.0,
    session: requests.Session | None = None,
    source: str = "source",
    timeout: float | None = None,
    data: dict[str, str] | None = None,
    files: dict[str, tuple] | None = None,
) -> HttpResult:
    """Perform an HTTP request with caching, rate limiting, and error mapping.

    `timeout` overrides the default for one call; some public endpoints (crt.sh
    especially) are slow enough that the default cuts them off.

    `data`/`files` send multipart instead of JSON, which is how Discord takes a
    file alongside an embed. Multipart requests are never cached.
    """
    method = method.upper()
    ttl = config.cache_ttl if cache_ttl is None else cache_ttl
    body_str = json.dumps(json_body, sort_keys=True) if json_body is not None else None
    can_cache = (config.cache_enabled and method == "GET" and ttl > 0
                 and files is None)
    key = _cache_key(method, url, headers, body_str)

    if can_cache:
        cached = cache.get(key, ttl)
        if cached is not None:
            return HttpResult(status_code=200, text=cached, headers={"x-cache": "hit"})

    own_session = session is None
    sess = session or build_session(config)
    host = urlsplit(url).netloc
    _respect_rate(host, min_interval)

    try:
        resp = sess.request(
            method,
            url,
            headers=headers or {},
            json=json_body if files is None and data is None else None,
            data=data,
            files=files,
            timeout=config.timeout if timeout is None else timeout,
        )
    except requests.RequestException as exc:  # pragma: no cover - network
        raise SourceError(f"{source} request failed: {exc}") from exc
    finally:
        if own_session:
            sess.close()

    if resp.status_code == 429:
        retry_after = resp.headers.get("retry-after", "?")
        raise RateLimitError(f"{source} rate limit hit; retry after {retry_after}s.")

    result = HttpResult(
        status_code=resp.status_code,
        text=resp.text,
        headers=dict(resp.headers),
    )
    if can_cache and resp.status_code == 200:
        cache.set(key, resp.text)
    return result
