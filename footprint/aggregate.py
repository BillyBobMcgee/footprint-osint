"""Combines multiple sources into one profile and exposure timeline.

Each source runs in isolation: a missing key or an error becomes a note and the
rest still run.

Sources run concurrently — they are independent calls to different hosts, so a
profile costs roughly one round-trip instead of eight. Results are assembled in
a fixed order so output stays deterministic, and base.fetch keeps its own
per-host rate limiting so this never turns into hammering one API.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable

from footprint import scoring
from footprint.config import Config
from footprint.models import TimelineEvent
from footprint.sources import (
    dehashed,
    dns_recon,
    emailrep,
    gravatar,
    hibp,
    holehe_scan,
    hunter,
    intelx,
    xposedornot,
)
from footprint.sources.base import SourceError

# Called as progress(label, status) where status is "start" | "ok" | "skip".
Progress = Callable[[str, str], None]


@dataclass
class Profile:
    subject: str
    kind: str
    sections: dict[str, Any] = field(default_factory=dict)
    timeline: list[TimelineEvent] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        def conv(v):
            if isinstance(v, list):
                return [conv(x) for x in v]
            if isinstance(v, dict):
                return {k: conv(x) for k, x in v.items()}
            return v.to_dict() if hasattr(v, "to_dict") else v

        return {
            "subject": self.subject,
            "kind": self.kind,
            "sections": {k: conv(v) for k, v in self.sections.items()},
            "timeline": [e.to_dict() for e in self.timeline],
            "notes": self.notes,
        }


class _Runner:
    """Runs labelled tasks in parallel, turning failures into profile notes."""

    def __init__(self, profile: Profile, progress: Progress | None = None):
        self.profile = profile
        self.progress = progress
        self._lock = Lock()

    def _note(self, message: str) -> None:
        with self._lock:
            self.profile.notes.append(message)

    def _emit(self, label: str, status: str) -> None:
        if self.progress:
            try:
                self.progress(label, status)
            except Exception:  # noqa: BLE001 - a bad UI hook must not fail a scan
                pass

    def _one(self, label: str, fn: Callable[[], Any]) -> Any:
        self._emit(label, "start")
        try:
            value = fn()
        except SourceError as exc:
            self._note(f"{label}: {exc}")
            self._emit(label, "skip")
            return None
        except Exception as exc:  # noqa: BLE001 - never let one source kill the profile
            self._note(f"{label}: unexpected error ({exc})")
            self._emit(label, "skip")
            return None
        self._emit(label, "ok")
        return value

    def run_all(self, tasks: dict[str, Callable[[], Any]]) -> dict[str, Any]:
        """Run every task concurrently; returns {label: result-or-None}."""
        if not tasks:
            return {}
        labels = list(tasks)
        with ThreadPoolExecutor(max_workers=min(len(labels), 10)) as pool:
            values = pool.map(lambda lb: self._one(lb, tasks[lb]), labels)
        return dict(zip(labels, values))


def email_profile(
    email: str, config: Config, *, progress: Progress | None = None
) -> Profile:
    """Run every email-capable source concurrently and build a timeline."""
    p = Profile(subject=email, kind="email")
    runner = _Runner(p, progress)

    tasks: dict[str, Callable[[], Any]] = {
        "HIBP breaches": lambda: hibp.breached_account(email, config),
        "HIBP pastes": lambda: hibp.pasted_account(email, config),
        # XposedOrNot is keyless, so breaches show up even with no keys set.
        "XposedOrNot": lambda: xposedornot.analytics(email, config),
        "EmailRep": lambda: emailrep.lookup(email, config),
        "DeHashed": lambda: dehashed.search_email(email, config),
        "IntelX": lambda: intelx.search(email, config),
        "Gravatar": lambda: gravatar.lookup(email, config),
    }
    # Registered-account discovery (keyless), only if holehe is installed.
    if holehe_scan.available():
        tasks["holehe"] = lambda: holehe_scan.scan(email, config)

    got = runner.run_all(tasks)

    if not holehe_scan.available():
        p.notes.append(
            "holehe not installed — `pip install holehe` to discover "
            "registered accounts (keyless)."
        )

    # Assemble in a fixed order so output stays deterministic.
    breaches = got.get("HIBP breaches")
    if breaches is not None:
        p.sections["breaches"] = breaches
        for b in breaches:
            p.timeline.append(TimelineEvent(b.breach_date, "breach", b.title, "HIBP"))

    pastes = got.get("HIBP pastes")
    if pastes is not None:
        p.sections["pastes"] = pastes
        for paste in pastes:
            p.timeline.append(TimelineEvent(paste.date, "paste", paste.source, "HIBP"))

    xon = got.get("XposedOrNot")
    if xon is not None:
        xon_breaches, risk = xon
        if xon_breaches:
            p.sections["xon_breaches"] = xon_breaches
            for b in xon_breaches:
                p.timeline.append(
                    TimelineEvent(b.breach_date, "breach", b.title, "XposedOrNot")
                )
        if risk:
            p.sections["xon_risk"] = risk

    for label, key in (
        ("EmailRep", "reputation"),
        ("DeHashed", "leaks"),
        ("Gravatar", "gravatar"),
        ("holehe", "accounts"),
    ):
        value = got.get(label)
        if value is not None:
            p.sections[key] = value

    dark = got.get("IntelX")
    if dark is not None:
        p.sections["darkweb"] = dark
        for m in dark:
            p.timeline.append(TimelineEvent(m.date, "darkweb", m.name, "IntelX"))

    p.timeline.sort(key=lambda e: e.date or "", reverse=True)
    p.sections["risk"] = scoring.assess_email(p.sections)
    return p


def domain_profile(
    domain: str, config: Config, *, deep: bool = True, progress: Progress | None = None
) -> Profile:
    """DNS posture + subdomains + Hunter email pattern + HIBP domain breaches."""
    p = Profile(subject=domain, kind="domain")
    runner = _Runner(p, progress)

    got = runner.run_all({
        "DNS recon": lambda: dns_recon.recon(domain, config, deep=deep),
        "Hunter.io": lambda: hunter.domain_emails(domain, config),
        "HIBP domain": lambda: hibp.breaches_for_domain(domain, config),
    })

    recon = got.get("DNS recon")
    if recon is not None:
        hunter_data = got.get("Hunter.io")
        if hunter_data is not None:
            recon.email_pattern, recon.known_emails = hunter_data
        p.sections["recon"] = recon
        # A failed subdomain sweep is not a clean result, so say so.
        if recon.subdomain_error:
            p.notes.append(f"crt.sh: {recon.subdomain_error}")

    breaches = got.get("HIBP domain")
    if breaches is not None:
        p.sections["breaches"] = breaches
        for b in breaches:
            p.timeline.append(TimelineEvent(b.breach_date, "breach", b.title, "HIBP"))

    p.timeline.sort(key=lambda e: e.date or "", reverse=True)
    p.sections["risk"] = scoring.assess_domain(p.sections)
    return p
