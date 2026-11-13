import os

import pytest

from footprint.config import Config
from footprint.sources import holehe_scan
from footprint.sources.base import SourceError, Unreachable

SAMPLE_CSV = (
    "name,domain,rateLimit,exists,emailrecovery,phoneNumber,others\n"
    "github,github.com,False,True,,,\n"
    "spotify,spotify.com,False,True,ab***@gmail.com,,\n"
    "instagram,instagram.com,False,False,,,\n"
    "twitter,twitter.com,True,False,,,\n"
)


def test_parse_csv_keeps_only_existing_accounts():
    accounts = holehe_scan._parse_csv(SAMPLE_CSV)
    sites = [a.site for a in accounts]
    assert sites == ["github", "spotify"]  # sorted, only exists==True


def test_parse_csv_captures_recovery_hint():
    accounts = holehe_scan._parse_csv(SAMPLE_CSV)
    spotify = next(a for a in accounts if a.site == "spotify")
    assert spotify.email_recovery == "ab***@gmail.com"
    assert spotify.domain == "spotify.com"


def test_parse_csv_empty():
    assert holehe_scan._parse_csv("name,domain,rateLimit,exists\n") == []


OFFLINE_CSV = (
    "name,domain,rateLimit,exists,emailrecovery,phoneNumber,others\n"
    "github,github.com,True,False,,,\n"
    "spotify,spotify.com,True,False,,,\n"
)


def fake_holehe(monkeypatch, csv_text):
    """Stand in for the holehe CLI: write csv_text where it would, or nothing."""
    monkeypatch.setattr(holehe_scan, "_holehe_path", lambda: "holehe")

    def run(cmd, cwd, **kwargs):
        if csv_text is not None:
            with open(os.path.join(cwd, "holehe_results.csv"), "w") as fh:
                fh.write(csv_text)

    monkeypatch.setattr(holehe_scan.subprocess, "run", run)


def test_scan_returns_the_accounts_holehe_found(monkeypatch):
    fake_holehe(monkeypatch, SAMPLE_CSV)
    accounts = holehe_scan.scan("a@example.com", Config())
    assert [a.site for a in accounts] == ["github", "spotify"]


def test_scan_with_no_network_is_not_a_clean_result(monkeypatch):
    fake_holehe(monkeypatch, OFFLINE_CSV)
    with pytest.raises(Unreachable):
        holehe_scan.scan("a@example.com", Config())


def test_scan_fails_when_holehe_writes_nothing(monkeypatch):
    fake_holehe(monkeypatch, None)
    with pytest.raises(SourceError):
        holehe_scan.scan("a@example.com", Config())
