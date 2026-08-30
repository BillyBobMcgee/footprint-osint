"""Pwned Passwords lookup via the k-anonymity range API.

This is the safe, privacy-preserving way to check whether a password has
appeared in a breach corpus. Only the first 5 characters of the password's
SHA-1 hash ever leave the machine; the full password is never transmitted.
No API key is required.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

from footprint.config import Config
from footprint.models import PasswordExposure
from footprint.sources.base import SourceError, fetch

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_password(password: str, config: Config) -> PasswordExposure:
    """Return how many times `password` appears in the Pwned Passwords set."""
    if not password:
        raise ValueError("password must not be empty")

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    prefix, suffix = digest[:5], digest[5:]

    result = fetch(
        config,
        RANGE_URL.format(prefix=prefix),
        headers={"Add-Padding": "true"},  # blunts traffic analysis
        source="Pwned Passwords",
    )
    if result.status_code != 200:
        raise SourceError(f"Pwned Passwords returned HTTP {result.status_code}")

    for line in result.text.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix.strip().upper() == suffix:
            try:
                n = int(count.strip())
            except ValueError:
                n = 0
            if n > 0:  # padding entries have count 0
                return PasswordExposure(exposed=True, count=n)

    return PasswordExposure(exposed=False, count=0)


def sha1_hex(password: str) -> str:
    """The uppercase SHA-1 hex digest used as the lookup key everywhere."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324


def _range(prefix: str, config: Config) -> dict[str, int]:
    """Fetch one hash-prefix range as {suffix: count}."""
    result = fetch(
        config,
        RANGE_URL.format(prefix=prefix),
        headers={"Add-Padding": "true"},
        source="Pwned Passwords",
    )
    if result.status_code != 200:
        raise SourceError(f"Pwned Passwords returned HTTP {result.status_code}")

    out: dict[str, int] = {}
    for line in result.text.splitlines():
        suffix, _, count = line.partition(":")
        try:
            n = int(count.strip())
        except ValueError:
            continue
        if n > 0:  # padding entries have count 0
            out[suffix.strip().upper()] = n
    return out


def check_many(
    passwords: list[str], config: Config, *, workers: int = 8
) -> dict[str, PasswordExposure]:
    """Check many passwords at once, keyed by SHA-1 digest.

    Passwords sharing a 5-character hash prefix need one request between them,
    so a vault export costs far fewer round-trips than one lookup each.

    The result is keyed by digest, never by password, so nothing downstream can
    leak a secret into a report.
    """
    digests = {sha1_hex(p) for p in passwords if p}
    prefixes = sorted({d[:5] for d in digests})
    if not prefixes:
        return {}

    ranges: dict[str, dict[str, int]] = {}
    with ThreadPoolExecutor(max_workers=min(len(prefixes), workers)) as pool:
        futures = {pool.submit(_range, p, config): p for p in prefixes}
        for future in as_completed(futures):
            prefix = futures[future]
            try:
                ranges[prefix] = future.result()
            except SourceError:
                ranges[prefix] = {}  # one bad range must not sink the batch

    out: dict[str, PasswordExposure] = {}
    for digest in digests:
        count = ranges.get(digest[:5], {}).get(digest[5:], 0)
        out[digest] = PasswordExposure(exposed=count > 0, count=count)
    return out
