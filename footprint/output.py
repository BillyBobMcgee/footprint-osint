"""Rendering of results as human-readable tables or machine-readable JSON."""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console
from rich.table import Table

_console = Console()
_err_console = Console(stderr=True)


def _encodable(sample: str) -> bool:
    """Whether this console can actually print `sample`.

    The legacy Windows console is cp1252 and raises on box-drawing glyphs (rich
    does not shield you from this), so decorative characters need a fallback.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        sample.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


_FANCY = _encodable("█░▲→")
BAR_FULL, BAR_EMPTY = ("█", "░") if _FANCY else ("#", "-")
MARK, ARROW = ("▲", "→") if _FANCY else ("!", "->")


def emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def info(message: str) -> None:
    _console.print(message)


def warn(message: str) -> None:
    _err_console.print(f"[yellow]![/yellow] {message}")


def error(message: str) -> None:
    _err_console.print(f"[bold red]error:[/bold red] {message}")


def rule(title: str) -> None:
    _console.rule(f"[bold cyan]{title}")


def render_breaches(breaches: list, subject: str) -> None:
    if not breaches:
        _console.print(f"[green]No breaches found for[/green] [bold]{subject}[/bold].")
        return

    _console.print(
        f"[bold red]{len(breaches)}[/bold red] breach(es) found for "
        f"[bold]{subject}[/bold]:\n"
    )
    table = Table(show_lines=False, header_style="bold magenta")
    table.add_column("Breach")
    table.add_column("Date", no_wrap=True)
    table.add_column("Accounts", justify="right")
    table.add_column("Exposed data")
    for b in sorted(breaches, key=lambda x: x.breach_date or "", reverse=True):
        flags = []
        if b.is_sensitive:
            flags.append("[red]sensitive[/red]")
        if not b.is_verified:
            flags.append("[dim]unverified[/dim]")
        title = b.title + (" " + " ".join(flags) if flags else "")
        table.add_row(
            title,
            b.breach_date or "?",
            f"{b.pwn_count:,}" if b.pwn_count else "?",
            ", ".join(b.data_classes[:6]) + ("…" if len(b.data_classes) > 6 else ""),
        )
    _console.print(table)


def render_pastes(pastes: list) -> None:
    if not pastes:
        return
    _console.print(f"\n[bold]{len(pastes)}[/bold] paste(s):")
    for p in pastes:
        title = p.title or "(untitled)"
        _console.print(f"  • [cyan]{p.source}[/cyan] {title} — {p.date or '?'}")


def render_gravatar(profile: dict | None) -> None:
    _console.print("\n[bold]Gravatar[/bold]")
    if not profile:
        _console.print("  [dim]No public Gravatar profile.[/dim]")
        return
    _console.print(f"  avatar: {profile.get('avatar_url')}")
    for key in ("username", "display_name", "location", "profile_url"):
        if profile.get(key):
            _console.print(f"  {key}: {profile[key]}")
    if profile.get("accounts"):
        _console.print("  linked accounts:")
        for url in profile["accounts"]:
            _console.print(f"    - {url}")


def render_password(exposure) -> None:
    if exposure.exposed:
        _console.print(
            f"[bold red]COMPROMISED[/bold red] — this password appears "
            f"[bold]{exposure.count:,}[/bold] time(s) in breach corpora. "
            "Do not use it."
        )
    else:
        _console.print(
            "[green]Not found[/green] in the Pwned Passwords set. "
            "(Absence is not proof of safety.)"
        )


def render_username(hits: list) -> None:
    found = [h for h in hits if h.exists]
    _console.print(
        f"Checked [bold]{len(hits)}[/bold] sites — "
        f"[bold green]{len(found)}[/bold green] hit(s):\n"
    )
    table = Table(header_style="bold magenta")
    table.add_column("Site")
    table.add_column("Status", no_wrap=True)
    table.add_column("URL")
    for h in hits:
        status = "[green]found[/green]" if h.exists else "[dim]-[/dim]"
        table.add_row(h.site, status, h.url if h.exists else f"[dim]{h.url}[/dim]")
    _console.print(table)


def render_reputation(rep) -> None:
    _console.print("\n[bold]Reputation (EmailRep)[/bold]")
    color = "red" if rep.suspicious else "green"
    _console.print(f"  reputation: [{color}]{rep.reputation}[/{color}]"
                   f"  suspicious: {rep.suspicious}  references: {rep.references}")
    flags = [
        name for name, on in (
            ("blacklisted", rep.blacklisted),
            ("credentials leaked", rep.credentials_leaked),
            ("in data breach", rep.data_breach),
            ("malicious activity", rep.malicious_activity),
        ) if on
    ]
    if flags:
        _console.print(f"  [red]flags:[/red] {', '.join(flags)}")
    if rep.profiles:
        _console.print(f"  profiles: {', '.join(rep.profiles)}")


def render_leaks(records) -> None:
    _console.print(f"\n[bold]Credential leaks (DeHashed)[/bold] — "
                   f"{len(records)} record(s) [dim](secrets redacted)[/dim]")
    if not records:
        return
    table = Table(header_style="bold magenta")
    table.add_column("Database")
    table.add_column("Fields present")
    table.add_column("Username")
    for r in records[:50]:
        table.add_row(r.database, ", ".join(r.fields_present), r.username or "")
    _console.print(table)


def render_darkweb(matches) -> None:
    _console.print(f"\n[bold]Dark-web index (IntelX)[/bold] — {len(matches)} match(es) "
                   "[dim](metadata only)[/dim]")
    if not matches:
        return
    table = Table(header_style="bold magenta")
    table.add_column("Date", no_wrap=True)
    table.add_column("Bucket")
    table.add_column("Type")
    table.add_column("Name")
    for m in matches[:50]:
        table.add_row(m.date or "?", m.bucket, m.media_type or "?", m.name)
    _console.print(table)


def render_domain(recon) -> None:
    _console.print(f"\n[bold]DNS / email posture[/bold] for [bold]{recon.domain}[/bold]")
    _console.print(f"  MX: {', '.join(recon.mx) if recon.mx else '[dim]none[/dim]'}")
    spf_c = "green" if recon.spf else "red"
    _console.print(f"  SPF: [{spf_c}]{recon.spf or 'missing'}[/{spf_c}]")
    if recon.dmarc:
        pol = recon.dmarc_policy or "?"
        pol_c = "green" if pol in ("quarantine", "reject") else "yellow"
        _console.print(f"  DMARC: present, policy [{pol_c}]p={pol}[/{pol_c}]")
    else:
        _console.print("  DMARC: [red]missing[/red]")

    def flag(name: str, value, good: str = "present", bad: str = "missing") -> None:
        color = "green" if value else "red"
        _console.print(f"  {name}: [{color}]{good if value else bad}[/{color}]")

    flag("DNSSEC", recon.dnssec, "enabled", "not enabled")
    flag("MTA-STS", recon.mta_sts)
    flag("TLS-RPT", recon.tls_rpt)
    if recon.dkim_selectors:
        _console.print(f"  DKIM: [green]{', '.join(recon.dkim_selectors)}[/green]")
    elif recon.mx:
        _console.print("  DKIM: [red]no key at the common selectors[/red]")
    if recon.bimi:
        _console.print("  BIMI: [green]present[/green]")

    if recon.takeovers:
        _console.print(f"\n  [bold red]SUBDOMAIN TAKEOVER[/bold red] — "
                       f"{len(recon.takeovers)} dangling record(s):")
        for t in recon.takeovers:
            _console.print(f"    [red]![/red] {t['host']} {ARROW} {t['target']} "
                           f"[dim]({t['service']}, unclaimed)[/dim]")

    if recon.email_pattern:
        _console.print(f"  email pattern: {recon.email_pattern}")
    if recon.known_emails:
        _console.print(f"  known emails: {len(recon.known_emails)} "
                       f"(e.g. {', '.join(recon.known_emails[:3])})")
    if recon.subdomain_error:
        _console.print(f"  subdomains: [yellow]unavailable[/yellow] "
                       f"[dim]({recon.subdomain_error})[/dim]")
        return
    _console.print(f"  subdomains: [bold]{len(recon.subdomains)}[/bold] found")
    for s in recon.subdomains[:25]:
        _console.print(f"    • {s}")
    if len(recon.subdomains) > 25:
        _console.print(f"    [dim]… and {len(recon.subdomains) - 25} more[/dim]")


def render_timeline(events) -> None:
    if not events:
        return
    _console.print("\n[bold]Exposure timeline[/bold]")
    for e in events:
        _console.print(f"  [cyan]{e.date or '????-??-??'}[/cyan]  "
                       f"[dim]{e.kind}[/dim]  {e.label}  [dim]({e.source})[/dim]")


def render_notes(notes) -> None:
    if not notes:
        return
    _console.print("\n[dim]Skipped / notes:[/dim]")
    for n in notes:
        _console.print(f"  [yellow]-[/yellow] {n}")


_RISK_COLORS = {
    "Critical": "bright_red",
    "High": "red",
    "Moderate": "yellow",
    "Medium": "yellow",
    "Low": "green",
    "Minimal": "green",
}


def render_xon_risk(risk) -> None:
    """XposedOrNot's own risk label, shown alongside our score."""
    if not risk:
        return
    label = risk.get("label", "?")
    score = risk.get("score", "?")
    color = _RISK_COLORS.get(label, "cyan")
    _console.print(f"[dim]XposedOrNot rates this[/dim] [{color}]{label}[/{color}] "
                   f"[dim]({score}/100)[/dim]")


def render_assessment(assessment) -> None:
    """The locally-computed score, with the reasons behind it."""
    if assessment is None:
        return
    score = getattr(assessment, "score", 0)
    label = getattr(assessment, "label", "?")
    color = _RISK_COLORS.get(label, "cyan")

    filled = round(score / 5)
    bar = BAR_FULL * filled + BAR_EMPTY * (20 - filled)
    _console.print(f"\n[bold]Exposure score[/bold]  [{color}]{bar}[/{color}]  "
                   f"[bold {color}]{score}/100 - {label}[/bold {color}]")

    for f in getattr(assessment, "factors", []):
        mark = {"severe": f"[red]{MARK}[/red]",
                "caution": f"[yellow]{MARK}[/yellow]"}.get(f.weight, "[dim]·[/dim]")
        _console.print(f"  {mark} [dim]+{f.points:>2}[/dim]  {f.reason}")


def render_actions(assessment) -> None:
    actions = getattr(assessment, "actions", None)
    if not actions:
        return
    _console.print("\n[bold]What to do now[/bold]")
    _console.print("  [dim][yellow]proof of concept[/yellow] - advice may be "
                   "inaccurate[/dim]")
    for i, a in enumerate(actions, 1):
        _console.print(f"  [bold cyan]{i}.[/bold cyan] [bold]{a.title}[/bold]")
        _console.print(f"     [dim]{a.detail}[/dim]")


def render_registered_accounts(accounts) -> None:
    _console.print(f"\n[bold]Registered accounts[/bold] (holehe) — "
                   f"{len(accounts)} site(s) where this email is in use")
    if not accounts:
        return
    table = Table(header_style="bold magenta")
    table.add_column("Site")
    table.add_column("Domain")
    table.add_column("Recovery hint")
    for a in accounts:
        table.add_row(a.site, a.domain, a.email_recovery or a.phone or "")
    _console.print(table)


def render_profile(profile) -> None:
    rule(f"{profile.kind.title()}: {profile.subject}")
    if profile.kind == "domain":
        _console.print("[yellow]proof of concept[/yellow] [dim]- the domain "
                       "checker is a test of a concept and may not be accurate[/dim]")
    s = profile.sections
    if "risk" in s:
        render_assessment(s["risk"])
    if "xon_risk" in s:
        render_xon_risk(s["xon_risk"])
    if "breaches" in s:
        render_breaches(s["breaches"], f"{profile.subject} (HIBP)")
    if "xon_breaches" in s:
        render_breaches(s["xon_breaches"], f"{profile.subject} (XposedOrNot)")
    if "accounts" in s:
        render_registered_accounts(s["accounts"])
    if s.get("pastes"):
        render_pastes(s["pastes"])
    if "reputation" in s:
        render_reputation(s["reputation"])
    if "leaks" in s:
        render_leaks(s["leaks"])
    if "darkweb" in s:
        render_darkweb(s["darkweb"])
    if "recon" in s:
        render_domain(s["recon"])
    if "gravatar" in s:
        render_gravatar(s["gravatar"])
    render_timeline(profile.timeline)
    render_notes(profile.notes)
    if "risk" in s:
        render_actions(s["risk"])
