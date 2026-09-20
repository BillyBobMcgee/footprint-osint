"""Typed result objects shared across sources and output formatters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Breach:
    """A single breach an account or domain was found in."""

    name: str
    title: str
    domain: str
    breach_date: str | None
    added_date: str | None
    pwn_count: int
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = False
    is_sensitive: bool = False
    is_fabricated: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Paste:
    """A paste (e.g. Pastebin dump) an account appeared in."""

    source: str
    paste_id: str
    title: str | None
    date: str | None
    email_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SiteHit:
    """A username found on a given site."""

    site: str
    url: str
    exists: bool
    category: str = "other"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PasswordExposure:
    """Result of a k-anonymity Pwned Passwords lookup."""

    exposed: bool
    count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LeakRecord:
    """A record found in a credential-leak index (DeHashed).

    Secret values (password, hash) are deliberately NOT stored, only whether
    each field type was present. This keeps footprint an exposure-assessment
    tool rather than a credential-dumper.
    """

    database: str
    fields_present: list[str] = field(default_factory=list)
    username: str | None = None
    name: str | None = None
    email: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DarkWebMatch:
    """A match in a dark-web / leak *index* (Intelligence X).

    Only the catalog metadata is kept, never the leaked file contents.
    """

    name: str
    bucket: str
    date: str | None
    media_type: str | None = None
    system_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReputationReport:
    """Email reputation summary (EmailRep)."""

    email: str
    reputation: str
    suspicious: bool
    references: int
    blacklisted: bool = False
    credentials_leaked: bool = False
    data_breach: bool = False
    malicious_activity: bool = False
    profiles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DomainRecon:
    """DNS / email-security posture and discovered subdomains for a domain."""

    domain: str
    mx: list[str] = field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    dmarc_policy: str | None = None
    subdomains: list[str] = field(default_factory=list)
    email_pattern: str | None = None
    known_emails: list[str] = field(default_factory=list)

    # Deeper posture checks (populated by the "deep" recon path).
    dnssec: bool = False
    dkim_selectors: list[str] = field(default_factory=list)
    mta_sts: str | None = None
    tls_rpt: str | None = None
    bimi: str | None = None
    # Each entry: {"host", "target", "service"} for a dangling CNAME.
    takeovers: list[dict[str, str]] = field(default_factory=list)
    # Set when subdomain enumeration could not run. Distinguishes "this domain
    # has no subdomains" from "we never got to look", which also means takeover
    # detection did not run.
    subdomain_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RegisteredAccount:
    """An account discovered to exist for an email via signup/reset probes.

    Produced by the holehe-style registration checker. No key is required and
    the target is not notified, only the existence signal is recorded.
    """

    site: str
    domain: str = ""
    email_recovery: str | None = None
    phone: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    """A single dated event on a subject's exposure timeline."""

    date: str | None
    kind: str
    label: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
