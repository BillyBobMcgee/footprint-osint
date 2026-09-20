"""Bulk scanning: run any check over a file of subjects.

One subject per line, one code path for emails, domains, usernames, and
passwords, so --save, --notify, exit codes, and reports behave the same
throughout. Lines are auto-classified unless you force a kind.

Passwords get special handling: a password list is the most sensitive file
anyone will hand this tool. A password is never a subject, never written to a
report, and never sent to a webhook. Entries are labelled by line number and
looked up by hash.
"""

from __future__ import annotations

import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from footprint import aggregate, scoring
from footprint.config import Config
from footprint.sources import pwned_passwords
from footprint.sources import username as username_src
from footprint.sources.base import SourceError

KINDS = ("email", "domain", "username", "password")

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


@dataclass
class BulkResult:
    """One subject's outcome, uniform across every kind."""

    label: str                       # display name; never a password
    kind: str
    score: int = 0
    risk: str = "Minimal"
    exposed: bool = False
    detail: str = ""
    payload: dict[str, Any] | None = None   # None when there is no report
    error: str | None = None
    # Password runs only. Deliberately absent from to_dict(), so it reaches a
    # webhook message and nothing else.
    secret: str | None = None


@dataclass
class BulkRun:
    kind: str
    results: list[BulkResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def exposed(self) -> list[BulkResult]:
        return [r for r in self.results if r.exposed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": f"{len(self.results)} {self.kind}(s)",
            "kind": f"bulk-{self.kind}",
            "sections": {"bulk": [
                {"label": r.label, "score": r.score, "risk": r.risk,
                 "exposed": r.exposed, "detail": r.detail, "error": r.error}
                for r in self.results
            ]},
            "timeline": [],
            "notes": self.notes,
        }


# --- detection

def detect_kind(value: str) -> str:
    """Classify one line. Passwords are never guessed; they must be forced."""
    value = value.strip()
    if _EMAIL.match(value):
        return "email"
    if _DOMAIN.match(value):
        return "domain"
    return "username"


# --- input

def parse_subjects(text: str, kind: str) -> list[tuple[str, str]]:
    """Split raw text into (label, value) pairs: one subject per line.

    For passwords the label is the line number, never the secret. Shared by the
    CLI, the interactive menu, and the GUI so all three behave identically.
    """
    if kind == "password":
        # Comments would be indistinguishable from a password starting with #,
        # so every non-blank line counts.
        return [
            (f"line {i}", line.rstrip("\n"))
            for i, line in enumerate(text.splitlines(), 1)
            if line.strip()
        ]

    values = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return [(v, v) for v in values]


def load_subjects(path: Path, kind: str) -> list[tuple[str, str]]:
    """Read a file into (label, value) pairs."""
    return parse_subjects(path.read_text(encoding="utf-8", errors="replace"), kind)


def detect_kind_for(rows: list[tuple[str, str]]) -> str:
    """Classify a whole file by majority, so one odd line does not decide it."""
    votes = Counter(detect_kind(value) for _, value in rows)
    return max(votes, key=lambda k: (votes[k], k)) if votes else "email"


# --- running

def _scan_one(label: str, value: str, kind: str, config: Config) -> BulkResult:
    try:
        if kind == "email":
            profile = aggregate.email_profile(value, config)
        elif kind == "domain":
            profile = aggregate.domain_profile(value, config)
        elif kind == "username":
            hits = username_src.check_username(value, config)
            found = [h for h in hits if h.exists]
            assessment = scoring.assess_username(hits)
            return BulkResult(
                label=label, kind=kind, score=assessment.score, risk=assessment.label,
                exposed=bool(found),
                detail=f"{len(found)} of {len(hits)} sites",
                payload={
                    "subject": value, "kind": "username",
                    "sections": {"sites": [h.to_dict() for h in hits],
                                 "risk": assessment.to_dict()},
                    "timeline": [], "notes": [],
                },
            )
        else:
            raise SourceError(f"unknown kind: {kind}")
    except SourceError as exc:
        return BulkResult(label=label, kind=kind, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - one bad subject must not stop the run
        return BulkResult(label=label, kind=kind, error=f"unexpected error: {exc}")

    if profile.failed:
        return BulkResult(label=label, kind=kind, error=profile.failed)

    risk = profile.sections.get("risk")
    score = getattr(risk, "score", 0)
    counts = len(profile.sections.get("breaches") or []) + \
        len(profile.sections.get("xon_breaches") or [])
    return BulkResult(
        label=label, kind=kind, score=score, risk=getattr(risk, "label", "?"),
        exposed=score >= 20 or counts > 0,
        detail=f"{counts} breach(es)",
        payload=profile.to_dict(),
    )


def _run_passwords(rows: list[tuple[str, str]], config: Config) -> BulkRun:
    """Check every password at once, then report by label only."""
    run = BulkRun(kind="password")
    secrets = [value for _, value in rows]
    exposures = pwned_passwords.check_many(secrets, config)

    # Reuse is a local computation and costs nothing extra to surface.
    digests = [pwned_passwords.sha1_hex(value) for _, value in rows]
    seen: dict[str, list[str]] = {}
    for (label, _), digest in zip(rows, digests):
        seen.setdefault(digest, []).append(label)

    for (label, value), digest in zip(rows, digests):
        exposure = exposures.get(digest)
        reused = len(seen.get(digest, [])) > 1
        count = exposure.count if exposure else 0

        score = scoring.password_score(count, reused)
        if count:
            detail = f"seen {count:,}x" + (" · reused" if reused else "")
        else:
            detail = "reused across entries" if reused else "not found"

        run.results.append(BulkResult(
            label=label, kind="password", score=score,
            risk=scoring.label_for(score), exposed=bool(count) or reused,
            detail=detail, secret=value,
        ))

    dupes = sum(1 for v in seen.values() if len(v) > 1)
    if dupes:
        run.notes.append(f"{dupes} password(s) are reused across multiple entries")
    return run


def run(
    rows: list[tuple[str, str]],
    kind: str,
    config: Config,
    *,
    workers: int = 4,
    on_start: Callable[[str], None] | None = None,
    on_result: Callable[[BulkResult], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> BulkRun:
    """Scan every subject. Returns results in input order.

    `on_start` fires with a label as its scan begins and `on_result` when it
    finishes, so a caller can show what is in flight rather than only what is
    already done.
    """
    if kind == "password":
        # Passwords are checked in one batched call, so they all start together.
        if on_start:
            for label, _ in rows:
                on_start(label)
        run_ = _run_passwords(rows, config)
        if on_result:
            for r in run_.results:
                on_result(r)
        return run_

    def scan(label: str, value: str) -> BulkResult:
        # Everything is queued up front, so a stop is honoured by the subjects
        # that have not started yet.
        if should_stop and should_stop():
            return BulkResult(label=label, kind=kind, error="stopped")
        if on_start:
            on_start(label)
        return _scan_one(label, value, kind, config)

    run_ = BulkRun(kind=kind)
    # Each subject already fans out internally, so keep outer concurrency low
    # rather than opening a hundred sockets against the same APIs.
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(scan, label, value) for label, value in rows]
        for future in futures:
            result = future.result()
            run_.results.append(result)
            if on_result:
                on_result(result)
    return run_
