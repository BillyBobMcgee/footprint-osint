"""Exposure scoring and remediation advice, computed locally.

No network calls and no key: this works from data the sources already returned
and turns it into a 0-100 score plus concrete steps.

The score is additive: `factors` accounts for every point.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from typing import Any

# --- data classes

# Breach "data classes" are free text and vary by source ("Passwords" from
# HIBP, "passwords" from XposedOrNot, "Password hashes"...). Keywords match at
# a word start, so "password" catches "Passwords" without "pin" catching
# "shipping".
_CRITICAL = {
    # Points for this class on its own. A leaked password is the whole game;
    # a leaked maiden name is one answer in a reset flow.
    "password": 32, "hash": 32, "mnemonic": 32, "seed phrase": 32,
    "private key": 28,
    "social security": 26, "ssn": 26, "national insurance": 26,
    "bank account": 24, "credit card": 24, "cvv": 24, "payment method": 24,
    "passport": 22, "government": 22, "national id": 22, "biometric": 22,
    "encrypted key": 22, "auth token": 22, "access token": 22,
    "session token": 22, "api key": 22,
    "pin": 20, "driver": 20,
    "account balance": 18, "security question": 18, "security answer": 18,
    "tax": 16, "maiden name": 12,
}
_HIGH = {
    # health
    "hiv": 14, "health": 14, "medical": 14, "disabilit": 12,
    "drug habit": 8, "smoking habit": 8, "drinking habit": 8,
    # who you are
    "sexual orientation": 14, "sexual fetish": 14, "religio": 12,
    "political": 12, "ethnic": 12, "race": 12, "nationalit": 10,
    "citizenship": 10, "birth": 11,
    "marital status": 7, "relationship status": 7, "spouse": 7, "family": 7,
    "parenting": 7,
    # private content
    "private message": 11, "sms message": 11, "chat log": 11,
    "audio recording": 11, "browsing histor": 8, "login histor": 8,
    # where you live and how to reach you
    "physical address": 10, "home address": 10, "mailing address": 10,
    "street address": 10, "postal": 7, "latitude": 10,
    "geographic location": 10, "geolocation": 10, "travel plan": 8,
    "phone": 9, "telecommunications carrier": 6, "address book": 8,
    "social connection": 8,
    # money and work
    "cryptocurrency": 12, "credit score": 9, "credit status": 9,
    "financial": 9, "net worth": 9, "income": 9, "earning": 9, "salary": 9,
    "loan": 9, "socioeconomic": 9, "living cost": 7, "payment histor": 9,
    "utility bill": 7, "employer": 6, "employment": 6, "occupation": 6,
    "military service": 6, "academic record": 5, "school grade": 5,
    # identifiers that follow you offline
    "imei": 6, "imsi": 6, "mac address": 6, "licence plate": 6,
    "license plate": 6, "registration plate": 6, "vehicle identification": 6,
    "vin": 6,
}
_MEDIUM = (
    "email", "username", "name", "ip address", "gender", "job title",
    "device", "browser", "avatar", "photo", "social media profile", "bio",
    "age", "time zone", "spoken language", "education level", "homepage url",
    "personal interest", "nickname", "instant messenger", "physical attribute",
    "personal description",
)

SEVERITY = {"critical": 3, "high": 2, "medium": 1, "low": 0}

_TIERS = tuple(
    (tier, re.compile(r"\b(?:" + "|".join(words) + r")"))
    for tier, words in (("critical", _CRITICAL), ("high", _HIGH), ("medium", _MEDIUM))
)
_WEIGHTED = tuple(
    (re.compile(r"\b(?:" + needle + r")"), points)
    for table in (_CRITICAL, _HIGH)
    for needle, points in table.items()
)


def classify_data(label: str) -> str:
    """Bucket one breach data-class label into critical/high/medium/low."""
    text = label.strip().lower()
    for tier, pattern in _TIERS:
        if pattern.search(text):
            return tier
    return "low"


def data_weight(label: str) -> int:
    """What one leaked class is worth, by the damage it actually enables.

    A label can match more than one keyword ("Password hashes"), so the worst
    match wins.
    """
    text = label.strip().lower()
    return max((pts for rx, pts in _WEIGHTED if rx.search(text)), default=0)


# --- results

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


def password_score(count: int, reused: bool = False) -> int:
    """Score one password. Anything in the corpus is burned, but a top-1000
    password is a different class of problem."""
    if count:
        return 95 if count >= 10000 else 80 if count >= 100 else 65
    return 25 if reused else 0


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


# --- helpers

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
            # A future date is bad upstream data, not a fresher breach.
            return max((now - when).days / 365.25, 0.0)
        except ValueError:
            continue
    year = _parse_year(text)
    return None if year is None else float(max(now.year - year, 0))


def _all_breaches(sections: dict) -> list:
    """HIBP and XposedOrNot overlap, so merge and de-duplicate by name."""
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


# --- assess

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
    # The worst class sets the level and the rest adds on top, so one leaked
    # password outweighs a long list of email addresses.
    if buckets.get("critical"):
        names = sorted(buckets["critical"], key=data_weight, reverse=True)
        pts = min(data_weight(names[0]) + 4 * (len(names) - 1), 44)
        a.factors.append(Factor(
            pts, f"critical data exposed: {', '.join(names[:4])}", "severe"
        ))
    if buckets.get("high"):
        names = sorted(buckets["high"], key=data_weight, reverse=True)
        pts = min(data_weight(names[0]) + 2 * (len(names) - 1), 22)
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

    if "password" in critical or "hash" in critical:
        # Name the breaches that actually leaked one, not the first three found.
        leaked_here = [
            getattr(b, "title", "") or getattr(b, "name", "")
            for b in breaches
            if any("password" in c.lower() or "hash" in c.lower()
                   for c in (getattr(b, "data_classes", None) or []))
        ]
        where = ", ".join(n for n in leaked_here[:3] if n) or "the affected sites"
        actions.append(Action(
            1, "Rotate the exposed passwords",
            f"Leaked in {where}. Change it there and anywhere you reused it.",
        ))
    if "mnemonic" in critical or "seed phrase" in critical:
        actions.append(Action(
            1, "Move your crypto to a new wallet",
            "A leaked seed phrase gives away every key derived from it.",
        ))
    if any(k in critical for k in ("private key", "encrypted key", "token")):
        actions.append(Action(
            2, "Revoke exposed keys and tokens",
            "Revoke, don't just rotate. The old one still works otherwise.",
        ))
    if accounts:
        actions.append(Action(
            2, f"Turn on 2FA across {len(accounts)} confirmed account(s)",
            "These are the accounts an attacker would try first.",
        ))
    if any(k in critical for k in ("social security", "ssn", "tax", "national id",
                                   "passport", "government", "driver")):
        actions.append(Action(
            3, "Freeze your credit",
            "Government IDs leaked. A freeze is free and blocks new accounts.",
        ))
    if any(k in critical for k in ("credit card", "bank", "financial", "payment")):
        actions.append(Action(
            3, "Replace the affected card or account number",
            "Ask the issuer for a new number; don't wait for fraud.",
        ))
    if "security question" in critical or "security answer" in critical or \
            "maiden name" in critical:
        actions.append(Action(
            4, "Reset your security questions",
            "Answers leaked. Replace them with random strings.",
        ))
    if "phone" in high:
        actions.append(Action(
            5, "Add a port-out PIN with your carrier",
            "Your number leaked, that's step one of a SIM swap.",
        ))
    if any(k in high for k in ("address", "birth")):
        actions.append(Action(
            6, "Treat identity checks as compromised",
            "Your address and date of birth are what call centres ask for.",
        ))
    if leaks or pastes:
        actions.append(Action(
            7, "Expect targeted phishing, not generic spam",
            "This address is circulating in aggregated lists.",
        ))
    if not actions and breaches:
        actions.append(Action(
            5, "Rotate credentials as a precaution",
            "No specific field was named, but the address is in a leaked set.",
        ))
    if not breaches and not leaks:
        actions.append(Action(
            9, "Nothing",
            "Add it to the watchlist to catch anything new.",
        ))
    actions.sort(key=lambda x: x.priority)
    return actions


# --- domains

def assess_domain(sections: dict, today: date | None = None) -> Assessment:
    """Score a domain's email-security posture and exposed surface."""
    a = Assessment()
    recon = sections.get("recon")
    breaches = sections.get("breaches") or []

    if recon is not None:
        spf = getattr(recon, "spf", None)
        if not spf:
            a.factors.append(Factor(
                14, "no SPF record, anyone may spoof this domain", "severe"
            ))
        elif "+all" in spf:
            a.factors.append(Factor(
                14, "SPF ends in +all, which authorizes every sender on the internet",
                "severe",
            ))

        policy = (getattr(recon, "dmarc_policy", None) or "").lower()
        if not getattr(recon, "dmarc", None):
            a.factors.append(Factor(
                16, "no DMARC record, spoofed mail is not rejected", "severe"
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
                4, "no MTA-STS policy, SMTP can be downgraded in transit", "caution"
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
            f"Anyone could claim {hosts} and serve content on your domain.",
        ))
    if not getattr(recon, "spf", None):
        actions.append(Action(
            2, "Publish an SPF record",
            "List your real senders and end it in -all.",
        ))
    policy = (getattr(recon, "dmarc_policy", None) or "").lower()
    if not getattr(recon, "dmarc", None):
        actions.append(Action(
            2, "Publish a DMARC record",
            "Start at p=none with rua=, then tighten once reports look clean.",
        ))
    elif policy in ("none", "quarantine"):
        actions.append(Action(
            3, f"Tighten DMARC from p={policy} to p=reject",
            "Not enforcing, so spoofed mail still lands.",
        ))
    if not getattr(recon, "mta_sts", None):
        actions.append(Action(
            5, "Add MTA-STS and TLS-RPT",
            "Otherwise STARTTLS can be stripped in transit.",
        ))
    if not getattr(recon, "dnssec", False):
        actions.append(Action(
            6, "Enable DNSSEC",
            "Stops a resolver being poisoned to point elsewhere.",
        ))
    actions.sort(key=lambda x: x.priority)
    return actions


# --- usernames

# WhatsMyName tags every site with a category. A hit in one of these says more
# than a plain profile does: the first group is sensitive, the second usually
# carries a real name.
_SENSITIVE_CATS = ("xx nsfw xx", "dating", "health", "political")
_IDENTITY_CATS = ("finance", "business")


def _in_cats(hits, cats: tuple[str, ...]) -> list:
    return [h for h in hits if getattr(h, "category", "").strip().lower() in cats]


def assess_username(hits, today: date | None = None) -> Assessment:
    """Score how much a handle exposes by being reused across sites.

    Not a breach score, nothing here is a compromise. It measures linkability:
    one handle used everywhere lets anyone assemble a profile from public pages
    alone.
    """
    a = Assessment()
    found = [h for h in hits if getattr(h, "exists", False)]
    if not found:
        a.label = label_for(0)
        a.actions.append(Action(
            9, "Nothing",
            "This handle didn't turn up on the sites checked.",
        ))
        return a

    a.factors.append(Factor(
        min(4 + 2 * len(found), 30),
        f"handle found on {len(found)} public site(s)",
        "caution" if len(found) >= 10 else "info",
    ))

    sensitive = sorted(getattr(h, "site", "?") for h in _in_cats(found, _SENSITIVE_CATS))
    if sensitive:
        a.factors.append(Factor(
            min(10 * len(sensitive), 25),
            f"present on sensitive site(s): {', '.join(sensitive[:3])}",
            "severe",
        ))

    identity = _in_cats(found, _IDENTITY_CATS)
    if len(identity) >= 2:
        a.factors.append(Factor(
            min(5 * len(identity), 20),
            f"appears on {len(identity)} identity-linked site(s)", "caution",
        ))

    a.score = min(sum(f.points for f in a.factors), 100)
    a.label = label_for(a.score)

    a.actions.append(Action(
        2, "Use a different handle where you want separation",
        "One handle lets anyone walk from one profile to all the others.",
    ))
    if sensitive:
        a.actions.append(Action(
            1, "Rename the accounts you would not want linked",
            f"Found on {', '.join(sensitive[:3])}.",
        ))
    if len(found) >= 10:
        a.actions.append(Action(
            3, "Prune the accounts you no longer use",
            "Dormant profiles keep leaking old photos, bios, and contacts.",
        ))
    a.actions.sort(key=lambda x: x.priority)
    return a
