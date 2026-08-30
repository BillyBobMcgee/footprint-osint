"""Exposure scoring and remediation advice, computed locally.

No network calls and no key: this works from data the sources already returned
and turns it into a 0-100 score plus concrete steps.

The score is additive and explainable rather than a black box — `factors`
always accounts for every point.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from typing import Any

# --------------------------------------------------------------- data classes

# Breach "data classes" are free text and vary by source ("Passwords" from
# HIBP, "passwords" from XposedOrNot, "Password hashes"...), so match on
# lowercased substrings and keep the highest tier that hits.
_CRITICAL = (
    "password", "hash", "social security", "ssn", "credit card", "bank",
    "financial", "payment", "passport", "government id", "national id",
    "driver", "security question", "security answer", "private key",
    "auth token", "access token", "session token", "biometric", "tax",
    "maiden name",
)
_HIGH = (
    "physical address", "home address", "mailing address", "street address",
    "postal", "phone", "date of birth", "dob", "geographic location",
    "geolocation", "health", "medical", "income", "salary", "employer",
    "employment", "family", "spouse",
)

# "Email addresses" and "IP addresses" contain "address" but are nowhere near
# as sensitive as a home address, so check these first.
_NOT_PHYSICAL = ("email", "ip address", "e-mail")
_MEDIUM = (
    "email", "username", "name", "ip address", "gender", "job title",
    "device", "browser", "avatar", "profile photo", "social media profile",
)

SEVERITY = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def classify_data(label: str) -> str:
    """Bucket one breach data-class label into critical/high/medium/low."""
    text = label.strip().lower()
    for needle in _CRITICAL:
        if needle in text:
            return "critical"
    if any(n in text for n in _NOT_PHYSICAL):
        return "medium"
    for needle in _HIGH:
        if needle in text:
            return "high"
    for needle in _MEDIUM:
        if needle in text:
            return "medium"
    return "low"


# ------------------------------------------------------------------- results

@dataclass
class Factor:
    """One scored contribution, with the human reason behind it."""

    points: int
    reason: str
    weight: str = "info"  # info | caution | severe

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Action:
    """A remediation step. Lower ``priority`` sorts first."""

    priority: int
    title: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Assessment:
    score: int = 0
    label: str = "Minimal"
    factors: list[Factor] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    exposed_data: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "label": self.label,
            "factors": [f.to_dict() for f in self.factors],
            "actions": [a.to_dict() for a in self.actions],
            "exposed_data": self.exposed_data,
        }


def label_for(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Moderate"
    if score >= 20:
        return "Low"
    return "Minimal"


# -------------------------------------------------------------------- helpers

def _parse_year(value: str | None) -> int | None:
    """Pull a year out of the many date shapes the sources return."""
    if not value:
        return None
    match = re.search(r"(19|20)\d{2}", str(value))
    return int(match.group(0)) if match else None


def _years_since(value: str | None, today: date | None = None) -> float | None:
    """Age of a date in years, tolerant of YYYY, YYYY-MM, and full timestamps."""
    if not value:
        return None
    text = str(value).strip()
    now = today or datetime.now().date()
    for fmt, width in (("%Y-%m-%d", 10), ("%Y-%m", 7), ("%Y", 4)):
        try:
            when = datetime.strptime(text[:width], fmt).date()
            return (now - when).days / 365.25
        except ValueError:
            continue
    year = _parse_year(text)
    return None if year is None else float(now.year - year)


def _all_breaches(sections: dict) -> list:
    """HIBP and XposedOrNot overlap heavily — merge and de-duplicate by name."""
    merged: dict[str, Any] = {}
    for key in ("breaches", "xon_breaches"):
        for b in sections.get(key) or []:
            name = (getattr(b, "name", "") or getattr(b, "title", "")).strip().lower()
            if name and name not in merged:
                merged[name] = b
    return list(merged.values())


def _data_classes(breaches: Iterable) -> list[str]:
    seen: list[str] = []
    for b in breaches:
        for dc in getattr(b, "data_classes", None) or []:
            if dc not in seen:
                seen.append(dc)
    return seen


# --------------------------------------------------------------------- assess

def assess_email(sections: dict, today: date | None = None) -> Assessment:
    """Score an email profile and produce remediation steps.

    `sections` is Profile.sections, holding live dataclass objects.
    """
    a = Assessment()
    breaches = _all_breaches(sections)
    leaks = sections.get("leaks") or []
    dark = sections.get("darkweb") or []
    pastes = sections.get("pastes") or []
    accounts = sections.get("accounts") or []
    rep = sections.get("reputation")

    # Bucket the leaked data classes by severity; both the score and the
    # advice below work off these.
    buckets: dict[str, list[str]] = {}
    for dc in _data_classes(breaches):
        buckets.setdefault(classify_data(dc), []).append(dc)
    a.exposed_data = {k: sorted(v) for k, v in buckets.items() if k != "low"}

    # -- breach volume ------------------------------------------------------
    if breaches:
        pts = min(6 + 3 * (len(breaches) - 1), 24)
        a.factors.append(Factor(
            pts,
            f"appears in {len(breaches)} known breach"
            f"{'es' if len(breaches) != 1 else ''}",
            "severe" if len(breaches) >= 5 else "caution",
        ))

    # -- what actually leaked ----------------------------------------------
    if buckets.get("critical"):
        names = sorted(buckets["critical"])
        pts = min(10 + 4 * (len(names) - 1), 26)
        a.factors.append(Factor(
            pts, f"critical data exposed: {', '.join(names[:4])}", "severe"
        ))
    if buckets.get("high"):
        names = sorted(buckets["high"])
        pts = min(5 + 2 * (len(names) - 1), 14)
        a.factors.append(Factor(
            pts, f"identity data exposed: {', '.join(names[:4])}", "caution"
        ))

    # -- recency: a 2012 breach you already dealt with matters less ---------
    ages = [y for y in (_years_since(getattr(b, "breach_date", None), today)
                        for b in breaches) if y is not None]
    if ages:
        newest = min(ages)
        if newest <= 1:
            a.factors.append(Factor(12, "a breach occurred within the last year", "severe"))
        elif newest <= 3:
            a.factors.append(Factor(
                6, f"most recent breach is ~{newest:.0f} years old", "caution"
            ))

    # -- corroborating indexes ---------------------------------------------
    if leaks:
        a.factors.append(Factor(
            min(6 + 2 * (len(leaks) - 1), 14),
            f"{len(leaks)} credential-leak record(s) indexed (DeHashed)",
            "severe",
        ))
    if dark:
        a.factors.append(Factor(
            min(4 + 2 * (len(dark) - 1), 10),
            f"{len(dark)} dark-web index match(es)", "severe",
        ))
    if pastes:
        a.factors.append(Factor(
            min(3 + len(pastes), 8), f"{len(pastes)} public paste(s)", "caution"
        ))

    # -- attack surface: how many places is this address actually used? -----
    if accounts:
        a.factors.append(Factor(
            min(2 + len(accounts) // 3, 8),
            f"{len(accounts)} registered account(s) discoverable from this address",
            "caution" if len(accounts) >= 8 else "info",
        ))

    if rep is not None:
        flags = [n for n, on in (
            ("blacklisted", getattr(rep, "blacklisted", False)),
            ("credentials leaked", getattr(rep, "credentials_leaked", False)),
            ("malicious activity", getattr(rep, "malicious_activity", False)),
        ) if on]
        if flags:
            a.factors.append(Factor(
                4 * len(flags), f"reputation flags: {', '.join(flags)}", "severe"
            ))

    a.score = min(sum(f.points for f in a.factors), 100)
    a.label = label_for(a.score)
    a.actions = _email_actions(buckets, breaches, accounts, leaks, pastes)
    return a


def _email_actions(buckets, breaches, accounts, leaks, pastes) -> list[Action]:
    """Turn what leaked into ordered, concrete steps."""
    actions: list[Action] = []
    critical = " ".join(buckets.get("critical", [])).lower()
    high = " ".join(buckets.get("high", [])).lower()
    names = [getattr(b, "title", "") or getattr(b, "name", "") for b in breaches]

    if "password" in critical or "hash" in critical:
        where = ", ".join(n for n in names[:3] if n) or "the affected sites"
        actions.append(Action(
            1, "Rotate the exposed passwords",
            f"A password or password hash leaked in {where}. Change it there, and "
            "anywhere you reused it — cracked hashes get replayed against other "
            "sites first. A password manager makes each one unique.",
        ))
    if "private key" in critical or "token" in critical:
        actions.append(Action(
            2, "Revoke exposed keys and tokens",
            "Assume any leaked key or session token is live. Revoke and reissue it; "
            "rotating without revoking leaves the old one working.",
        ))
    if accounts:
        actions.append(Action(
            2, f"Turn on 2FA across {len(accounts)} confirmed account(s)",
            "These sites are confirmed to have an account on this address, so they "
            "are the exact list an attacker would work through first. App-based or "
            "hardware 2FA blocks a working password.",
        ))
    if any(k in critical for k in ("social security", "ssn", "tax", "national id",
                                   "passport", "government id", "driver")):
        actions.append(Action(
            3, "Freeze your credit",
            "Government identifiers were in a breach. A credit freeze at each bureau "
            "is free and reversible, and stops new accounts being opened in your name.",
        ))
    if any(k in critical for k in ("credit card", "bank", "financial", "payment")):
        actions.append(Action(
            3, "Replace the affected card or account number",
            "Financial data was exposed. Turn on transaction alerts and ask the "
            "issuer for a new number rather than waiting for fraud to show up.",
        ))
    if "security question" in critical or "security answer" in critical or \
            "maiden name" in critical:
        actions.append(Action(
            4, "Reset your security questions",
            "Answers leaked in plaintext, and unlike a password they are facts you "
            "cannot change. Replace them with random strings kept in your password "
            "manager.",
        ))
    if "phone" in high:
        actions.append(Action(
            5, "Add a port-out PIN with your carrier",
            "Your number leaked, which is the first ingredient in a SIM swap. A "
            "carrier PIN blocks the transfer, and moving off SMS 2FA removes the prize.",
        ))
    if any(k in high for k in ("address", "date of birth", "dob")):
        actions.append(Action(
            6, "Treat identity-verification questions as compromised",
            "Address and date of birth are exactly what call-centre identity checks "
            "ask for, and they are now public. Prefer providers that verify with a "
            "PIN or an app instead.",
        ))
    if leaks or pastes:
        actions.append(Action(
            7, "Expect targeted phishing, not generic spam",
            "This address appears in leak indexes or public pastes, so it is already "
            "circulating in aggregated lists — expect mail that quotes real details "
            "back at you to establish trust.",
        ))
    if not actions and breaches:
        actions.append(Action(
            5, "Rotate credentials as a precaution",
            "The breaches found did not name a specific sensitive field, but this "
            "address is confirmed in a leaked dataset. Rotating is cheap.",
        ))
    if not breaches and not leaks:
        actions.append(Action(
            9, "Nothing to remediate — keep it that way",
            "No exposure surfaced in the sources that ran. Absence of evidence is "
            "not proof: add this address to the watchlist so new breaches surface "
            "on their own.",
        ))
    actions.sort(key=lambda x: x.priority)
    return actions


# -------------------------------------------------------------------- domains

def assess_domain(sections: dict, today: date | None = None) -> Assessment:
    """Score a domain's email-security posture and exposed surface."""
    a = Assessment()
    recon = sections.get("recon")
    breaches = sections.get("breaches") or []

    if recon is not None:
        spf = getattr(recon, "spf", None)
        if not spf:
            a.factors.append(Factor(
                14, "no SPF record — anyone may spoof this domain", "severe"
            ))
        elif "+all" in spf:
            a.factors.append(Factor(
                14, "SPF ends in +all, which authorizes every sender on the internet",
                "severe",
            ))

        policy = (getattr(recon, "dmarc_policy", None) or "").lower()
        if not getattr(recon, "dmarc", None):
            a.factors.append(Factor(
                16, "no DMARC record — spoofed mail is not rejected", "severe"
            ))
        elif policy == "none":
            a.factors.append(Factor(
                9, "DMARC is p=none (monitor only, nothing enforced)", "caution"
            ))
        elif policy == "quarantine":
            a.factors.append(Factor(3, "DMARC is p=quarantine, not p=reject", "info"))

        if not getattr(recon, "dnssec", False):
            a.factors.append(Factor(5, "DNSSEC not enabled", "caution"))
        if not getattr(recon, "mta_sts", None):
            a.factors.append(Factor(
                4, "no MTA-STS policy — SMTP can be downgraded in transit", "caution"
            ))
        if getattr(recon, "mx", None) and not getattr(recon, "dkim_selectors", None):
            a.factors.append(Factor(
                4, "no DKIM key found at the common selector names", "caution"
            ))

        takeovers = getattr(recon, "takeovers", None) or []
        if takeovers:
            a.factors.append(Factor(
                min(12 * len(takeovers), 30),
                f"{len(takeovers)} subdomain(s) point at an unclaimed service",
                "severe",
            ))
        subs = getattr(recon, "subdomains", None) or []
        if len(subs) > 50:
            a.factors.append(Factor(
                4, f"{len(subs)} subdomains are public in certificate transparency",
                "info",
            ))

    if breaches:
        a.factors.append(Factor(
            min(4 + 2 * (len(breaches) - 1), 12),
            f"{len(breaches)} breach(es) affect addresses at this domain", "caution",
        ))

    a.score = min(sum(f.points for f in a.factors), 100)
    a.label = label_for(a.score)
    a.actions = _domain_actions(recon)
    return a


def _domain_actions(recon) -> list[Action]:
    actions: list[Action] = []
    if recon is None:
        return actions

    takeovers = getattr(recon, "takeovers", None) or []
    if takeovers:
        hosts = ", ".join(t.get("host", "?") for t in takeovers[:4])
        actions.append(Action(
            1, f"Remove {len(takeovers)} dangling DNS record(s)",
            f"These names resolve to a service that no longer claims them: {hosts}. "
            "Anyone can register the target and serve content on your domain. Delete "
            "the record, or re-claim the resource.",
        ))
    if not getattr(recon, "spf", None):
        actions.append(Action(
            2, "Publish an SPF record",
            "Without SPF a receiving server has no way to tell your mail from a "
            "forgery. List your real senders and end the record in -all.",
        ))
    policy = (getattr(recon, "dmarc_policy", None) or "").lower()
    if not getattr(recon, "dmarc", None):
        actions.append(Action(
            2, "Publish a DMARC record",
            "Start at p=none with an rua= address to collect reports, then move to "
            "quarantine and finally reject once the reports look clean.",
        ))
    elif policy in ("none", "quarantine"):
        actions.append(Action(
            3, f"Tighten DMARC from p={policy} to p=reject",
            "The record exists but is not enforcing, so spoofed mail still lands. "
            "Reject is the only policy that actually stops delivery.",
        ))
    if not getattr(recon, "mta_sts", None):
        actions.append(Action(
            5, "Add MTA-STS and TLS-RPT",
            "Without a policy an attacker in the network path can strip STARTTLS and "
            "read mail in transit. MTA-STS pins TLS for senders that honour it.",
        ))
    if not getattr(recon, "dnssec", False):
        actions.append(Action(
            6, "Enable DNSSEC",
            "Signed responses stop a resolver being poisoned into pointing your "
            "domain somewhere else.",
        ))
    actions.sort(key=lambda x: x.priority)
    return actions


# ------------------------------------------------------------------ usernames

# Sites where a hit says more than a plain profile does, either because the
# account is sensitive or because it ties the handle to a real identity.
_SENSITIVE_SITES = (
    "adult", "porn", "escort", "fetlife", "ashley", "onlyfans", "grindr",
    "tinder", "okcupid", "match", "gambl", "casino", "poker", "bet",
)
_IDENTITY_SITES = (
    "linkedin", "facebook", "github", "gitlab", "instagram", "venmo",
    "paypal", "cash", "strava", "untappd", "spotify", "goodreads",
)


def assess_username(hits, today: date | None = None) -> Assessment:
    """Score how much a handle exposes by being reused across sites.

    Not a breach score — nothing here is a compromise. This measures
    linkability: one handle used everywhere lets anyone assemble a profile from
    public pages alone.
    """
    a = Assessment()
    found = [h for h in hits if getattr(h, "exists", False)]
    if not found:
        a.label = label_for(0)
        a.actions.append(Action(
            9, "Nothing to do — this handle is not widely reused",
            "The handle did not turn up on the sites checked, so there is no "
            "obvious cross-site trail tied to it.",
        ))
        return a

    names = [getattr(h, "site", "") for h in found]
    lowered = " ".join(names).lower()

    a.factors.append(Factor(
        min(4 + 2 * len(found), 30),
        f"handle found on {len(found)} public site(s)",
        "caution" if len(found) >= 10 else "info",
    ))

    sensitive = [n for n in names if any(k in n.lower() for k in _SENSITIVE_SITES)]
    if sensitive:
        a.factors.append(Factor(
            min(10 * len(sensitive), 25),
            f"present on sensitive site(s): {', '.join(sorted(sensitive)[:3])}",
            "severe",
        ))

    identity = [k for k in _IDENTITY_SITES if k in lowered]
    if len(identity) >= 2:
        a.factors.append(Factor(
            min(5 * len(identity), 20),
            f"appears on {len(identity)} identity-linked site(s)", "caution",
        ))

    a.score = min(sum(f.points for f in a.factors), 100)
    a.label = label_for(a.score)

    a.actions.append(Action(
        2, "Use a different handle where you want separation",
        "A single handle is the easiest way to link accounts across sites. "
        "Reusing it means anyone can walk from one profile to all the others.",
    ))
    if sensitive:
        a.actions.append(Action(
            1, "Rename the accounts you would not want linked",
            "This handle appears on sites most people keep separate from their "
            f"public identity ({', '.join(sorted(sensitive)[:3])}). Renaming "
            "breaks the link that makes them findable together.",
        ))
    if len(found) >= 10:
        a.actions.append(Action(
            3, "Prune the accounts you no longer use",
            "Dormant profiles keep leaking old photos, bios, and contacts long "
            "after you have stopped thinking about them. Deleting is the only "
            "durable fix.",
        ))
    a.actions.sort(key=lambda x: x.priority)
    return a
