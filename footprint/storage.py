"""Persistent state for watch/monitor mode.

Records a fingerprint of each finding per subject so re-runs can report only
what is *new* since last time. Backed by SQLite in the config directory.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

from footprint.config import config_dir


def _db_path() -> Path:
    return config_dir() / "watch.sqlite3"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.execute(
        "CREATE TABLE IF NOT EXISTS seen ("
        "subject TEXT NOT NULL, fingerprint TEXT NOT NULL, label TEXT, "
        "first_seen REAL NOT NULL, PRIMARY KEY (subject, fingerprint))"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS watchlist ("
        "subject TEXT PRIMARY KEY, kind TEXT NOT NULL, added REAL NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, "
        "kind TEXT NOT NULL, score INTEGER, label TEXT, created REAL NOT NULL, "
        "payload TEXT NOT NULL)"
    )
    return conn


# --- scan history

HISTORY_LIMIT = 200


def record_scan(subject: str, kind: str, payload: dict) -> int | None:
    """Save a finished scan so the GUI can reopen it without re-running it."""
    risk = (payload.get("sections") or {}).get("risk") or {}
    try:
        with _connect() as conn:
            cur = conn.execute(
                "INSERT INTO history (subject, kind, score, label, created, payload) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (subject, kind, int(risk.get("score", 0) or 0),
                 str(risk.get("label", "") or ""), time.time(),
                 json.dumps(payload, default=str)),
            )
            conn.execute(
                "DELETE FROM history WHERE id NOT IN "
                "(SELECT id FROM history ORDER BY id DESC LIMIT ?)",
                (HISTORY_LIMIT,),
            )
            return cur.lastrowid
    except (sqlite3.Error, TypeError, ValueError):
        return None


def history(limit: int = 30) -> list[dict]:
    """Recent scans, newest first, without their payloads."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, subject, kind, score, label, created FROM history "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    except sqlite3.Error:
        return []
    return [{"id": r[0], "subject": r[1], "kind": r[2], "score": r[3],
             "label": r[4], "created": r[5]} for r in rows]


def history_payload(entry_id: int) -> dict | None:
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT payload FROM history WHERE id = ?", (entry_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None
    except (sqlite3.Error, json.JSONDecodeError):
        return None


def clear_history() -> int:
    try:
        with _connect() as conn:
            n = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
            conn.execute("DELETE FROM history")
            return int(n)
    except sqlite3.Error:
        return 0


def add_to_watchlist(subject: str, kind: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO watchlist (subject, kind, added) VALUES (?, ?, ?)",
            (subject, kind, time.time()),
        )


def remove_from_watchlist(subject: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM watchlist WHERE subject = ?", (subject,))
        conn.execute("DELETE FROM seen WHERE subject = ?", (subject,))


def watchlist() -> list[tuple[str, str]]:
    with _connect() as conn:
        return [
            (row[0], row[1])
            for row in conn.execute(
                "SELECT subject, kind FROM watchlist ORDER BY added"
            ).fetchall()
        ]


def diff_new(subject: str, findings: dict[str, str]) -> dict[str, str]:
    """Given {fingerprint: label}, return only the fingerprints not seen before.

    Newly seen fingerprints are recorded so the next run won't re-report them.
    """
    new: dict[str, str] = {}
    with _connect() as conn:
        known = {
            row[0]
            for row in conn.execute(
                "SELECT fingerprint FROM seen WHERE subject = ?", (subject,)
            ).fetchall()
        }
        now = time.time()
        for fp, label in findings.items():
            if fp not in known:
                new[fp] = label
                conn.execute(
                    "INSERT OR IGNORE INTO seen "
                    "(subject, fingerprint, label, first_seen) VALUES (?, ?, ?, ?)",
                    (subject, fp, label, now),
                )
    return new


def _fp(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()  # noqa: S324


def fingerprints(profile) -> dict[str, str]:
    """Map each finding on a profile to a stable fingerprint for diffing.

    Ignores volatile fields (counts, descriptions) so a breach that just gets
    re-described upstream does not re-alert.
    """
    out: dict[str, str] = {}
    all_breaches = (profile.sections.get("breaches", [])
                    + profile.sections.get("xon_breaches", []))
    for b in all_breaches:
        out[_fp("breach", b.name)] = f"breach: {b.title} ({b.breach_date})"
    for a in profile.sections.get("accounts", []) or []:
        out[_fp("account", a.site)] = f"registered account: {a.site}"
    for p in profile.sections.get("pastes", []) or []:
        out[_fp("paste", p.paste_id)] = f"paste: {p.source}"
    for r in profile.sections.get("leaks", []) or []:
        out[_fp("leak", r.database, ",".join(r.fields_present))] = f"leak: {r.database}"
    for m in profile.sections.get("darkweb", []) or []:
        out[_fp("dark", m.system_id or m.name)] = f"dark-web: {m.name} ({m.bucket})"

    # Domain findings. Without these a watched domain only alerts on HIBP
    # breaches, and a new takeover or a weakened DMARC passes silently.
    recon = profile.sections.get("recon")
    if recon is not None:
        for t in getattr(recon, "takeovers", None) or []:
            host = t.get("host", "?")
            out[_fp("takeover", host, t.get("target", ""))] = (
                f"SUBDOMAIN TAKEOVER: {host} -> {t.get('service', '?')} (unclaimed)"
            )
        # Fingerprint posture by value, so a regression (reject -> none, or a
        # record vanishing) reads as a new finding.
        policy = (getattr(recon, "dmarc_policy", None) or "none"
                  if getattr(recon, "dmarc", None) else "missing")
        if policy in ("missing", "none"):
            out[_fp("dmarc", policy)] = f"DMARC not enforcing (p={policy})"
        if not getattr(recon, "spf", None):
            out[_fp("spf", "missing")] = "SPF record missing"
        if not getattr(recon, "dnssec", False):
            out[_fp("dnssec", "off")] = "DNSSEC not enabled"
    return out
