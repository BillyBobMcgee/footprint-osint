"""A small SQLite response cache to avoid burning API quota on repeat runs."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from footprint.config import config_dir


def _db_path() -> Path:
    return config_dir() / "cache.sqlite3"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache ("
        "key TEXT PRIMARY KEY, value TEXT NOT NULL, created REAL NOT NULL)"
    )
    return conn


def get(key: str, ttl: int) -> str | None:
    """Return a cached value if present and younger than `ttl` seconds."""
    if ttl <= 0:
        return None
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT value, created FROM cache WHERE key = ?", (key,)
            ).fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    value, created = row
    if time.time() - created > ttl:
        return None
    return value


def set(key: str, value: str) -> None:  # noqa: A001 - deliberate cache verb
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, created) VALUES (?, ?, ?)",
                (key, value, time.time()),
            )
    except sqlite3.Error:
        pass  # Cache failures must never break a lookup.


def clear() -> int:
    """Drop all cached entries; returns how many were removed."""
    try:
        with _connect() as conn:
            n = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            conn.execute("DELETE FROM cache")
            return int(n)
    except sqlite3.Error:
        return 0
