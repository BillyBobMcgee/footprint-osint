"""Interactive, menu-driven front end for footprint.

Launched when `footprint` is run with no subcommand. Prompts for everything,
so users never need to remember flags.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt

from footprint import __version__, aggregate, bulk, output, reports, scoring, storage
from footprint.config import Config
from footprint.sources import pwned_passwords
from footprint.sources import username as username_src
from footprint.sources.base import SourceError

console = Console()

BANNER = (
    f"[bold cyan]footprint[/bold cyan] [dim]v{__version__}[/dim]\n"
    "defensive OSINT exposure checker\n"
    "[yellow]Use only against accounts/domains you are authorized to assess.[/yellow]"
)

MENU = """[bold]Choose an action:[/bold]
  [cyan]1[/cyan]  Email exposure (full profile)
  [cyan]2[/cyan]  Password check (safe, k-anonymity)
  [cyan]3[/cyan]  Domain recon (DNS, subdomains, breaches)
  [cyan]4[/cyan]  Username search (across public sites)
  [cyan]5[/cyan]  Bulk scan (emails, domains, usernames, or passwords)
  [cyan]6[/cyan]  Watch / monitor (alert on new exposure)
  [cyan]7[/cyan]  Open the web GUI
  [cyan]8[/cyan]  Settings (API keys, cache)
  [cyan]9[/cyan]  Quit"""


def run(config: Config) -> int:
    console.print(Panel(BANNER, expand=False))
    while True:
        console.print()
        console.print(MENU)
        choice = Prompt.ask(
            "[bold]>[/bold]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
            default="1",
        )
        try:
            if choice == "1":
                _do_email(config)
            elif choice == "2":
                _do_password(config)
            elif choice == "3":
                _do_domain(config)
            elif choice == "4":
                _do_username(config)
            elif choice == "5":
                _do_batch(config)
            elif choice == "6":
                _do_watch(config)
            elif choice == "7":
                from footprint.gui import serve

                serve(config)
            elif choice == "8":
                config = _do_settings(config)
            elif choice == "9":
                console.print("bye.")
                return 0
        except SourceError as exc:
            output.error(str(exc))
        except KeyboardInterrupt:
            console.print("\n[dim](cancelled)[/dim]")


# --- actions
def _do_email(config: Config) -> None:
    email = Prompt.ask("Email address").strip()
    if not email:
        return
    with console.status("Querying sources…"):
        profile = aggregate.email_profile(email, config)
    output.render_profile(profile)
    _offer_report(profile.to_dict())


def _do_password(config: Config) -> None:
    from getpass import getpass

    pw = getpass("Password (hidden): ")
    if not pw:
        return
    exposure = pwned_passwords.check_password(pw, config)
    output.render_password(exposure)


def _do_domain(config: Config) -> None:
    domain = Prompt.ask("Domain (e.g. example.com)").strip()
    if not domain:
        return
    with console.status("Running DNS + breach recon…"):
        profile = aggregate.domain_profile(domain, config)
    output.render_profile(profile)
    _offer_report(profile.to_dict())


def _do_username(config: Config) -> None:
    handle = Prompt.ask("Username / handle").strip()
    if not handle:
        return
    cats = username_src.categories(config)
    console.print(f"[dim]categories: {', '.join(cats)}[/dim]")
    category = Prompt.ask("Filter by category (blank = all)", default="").strip() or None
    with console.status("Checking sites…"):
        hits = username_src.check_username(handle, config, category=category)
    assessment = scoring.assess_username(hits)
    output.render_assessment(assessment)
    output.render_username(hits)
    output.render_actions(assessment)
    _offer_report({
        "subject": handle, "kind": "username",
        "sections": {"sites": [h.to_dict() for h in hits],
                     "risk": assessment.to_dict()},
    })


def _do_batch(config: Config) -> None:
    path = Prompt.ask("Path to a file (one subject per line)").strip().strip('"')
    p = Path(path)
    if not p.exists():
        output.error(f"file not found: {path}")
        return

    kind = Prompt.ask(
        "What does it contain?",
        choices=["auto", *bulk.KINDS],
        default="auto",
    )
    rows = bulk.load_subjects(p, kind)
    if not rows:
        output.error("no subjects in that file")
        return
    if kind == "auto":
        kind = bulk.detect_kind_for(rows)
        console.print(f"[dim]detected {kind}s[/dim]")

    console.print(f"Scanning [bold]{len(rows)}[/bold] {kind}(s)…")

    def show(result: bulk.BulkResult) -> None:
        if result.error:
            output.warn(f"{result.label}: {result.error}")
            return
        color = {"Critical": "bright_red", "High": "red",
                 "Moderate": "yellow"}.get(result.risk, "green")
        console.print(f"  [{color}]{result.score:>3}[/{color}] "
                      f"[dim]{result.risk:<8}[/dim] {result.label}  "
                      f"[dim]{result.detail}[/dim]")

    with console.status("Scanning…"):
        run = bulk.run(rows, kind, config, on_result=show)

    for note in run.notes:
        output.warn(note)
    console.print(f"\n[bold]{len(run.exposed)}[/bold] of "
                  f"[bold]{len(run.results)}[/bold] exposed")
    _offer_report(run.to_dict())


def _do_watch(config: Config) -> None:
    action = Prompt.ask(
        "Watch: [cyan]a[/cyan]dd, [cyan]r[/cyan]emove, [cyan]l[/cyan]ist, "
        "[cyan]c[/cyan]heck now",
        choices=["a", "r", "l", "c"],
        default="c",
    )
    if action == "a":
        subject = Prompt.ask("Email to watch").strip()
        if subject:
            storage.add_to_watchlist(subject, "email")
            console.print(f"[green]added[/green] {subject}")
            console.print("[dim]the first check sets the baseline[/dim]")
    elif action == "r":
        subject = Prompt.ask("Email to stop watching").strip()
        if subject:
            storage.remove_from_watchlist(subject)
            console.print(f"[yellow]removed[/yellow] {subject}")
    elif action == "l":
        items = storage.watchlist()
        if not items:
            console.print("[dim]watchlist is empty[/dim]")
        for subject, kind in items:
            console.print(f"  • {subject} [dim]({kind})[/dim]")
    elif action == "c":
        _run_watch_check(config)


def _run_watch_check(config: Config) -> None:
    items = storage.watchlist()
    if not items:
        console.print("[dim]watchlist is empty, add someone first[/dim]")
        return
    any_new = False
    for subject, kind in items:
        with console.status(f"[cyan]{subject}[/cyan]…"):
            profile = (aggregate.domain_profile(subject, config) if kind == "domain"
                       else aggregate.email_profile(subject, config))
        findings = storage.fingerprints(profile)
        new = storage.diff_new(subject, findings)
        if new:
            any_new = True
            console.print(f"[bold red]NEW exposure[/bold red] for {subject}:")
            for label in new.values():
                console.print(f"    • {label}")
        else:
            console.print(f"[green]no change[/green]  {subject}")
    if not any_new:
        console.print("[dim]nothing new across the watchlist[/dim]")


# --- settings
def _do_settings(config: Config) -> Config:
    masked = config.masked()
    console.print(Panel.fit(
        "\n".join(f"{k}: {v}" for k, v in masked.items() if "key" in k or k in
                  ("cache_enabled", "profile")),
        title="current settings",
    ))
    field = Prompt.ask(
        "Set: [cyan]hibp[/cyan], [cyan]dehashed[/cyan], [cyan]intelx[/cyan], "
        "[cyan]hunter[/cyan], [cyan]emailrep[/cyan], [cyan]cache[/cyan], "
        "[cyan]back[/cyan]",
        choices=["hibp", "dehashed", "intelx", "hunter", "emailrep", "cache", "back"],
        default="back",
    )
    if field == "back":
        return config
    if field == "hibp":
        config.hibp_api_key = Prompt.ask("HIBP API key", password=True).strip() or None
    elif field == "dehashed":
        config.dehashed_email = Prompt.ask("DeHashed account email").strip() or None
        config.dehashed_api_key = Prompt.ask("DeHashed API key", password=True).strip() or None
    elif field == "intelx":
        config.intelx_api_key = Prompt.ask("IntelX API key", password=True).strip() or None
    elif field == "hunter":
        config.hunter_api_key = Prompt.ask("Hunter.io API key", password=True).strip() or None
    elif field == "emailrep":
        config.emailrep_api_key = Prompt.ask("EmailRep API key", password=True).strip() or None
    elif field == "cache":
        config.cache_enabled = Confirm.ask("Enable response cache?", default=config.cache_enabled)
        if config.cache_enabled:
            config.cache_ttl = IntPrompt.ask("Cache TTL (seconds)", default=config.cache_ttl)

    if Confirm.ask("Save to config file?", default=True):
        path = config.save_profile()
        console.print(f"[green]saved[/green] → {path}")
    return config


# --- helpers
def _offer_report(payload: dict) -> None:
    if not Confirm.ask("Save a report?", default=False):
        return
    default_name = f"footprint-{payload.get('subject', 'report')}.html".replace("@", "_at_")
    path = Prompt.ask("Output path", default=default_name)
    try:
        reports.save(payload, path)
        console.print(f"[green]wrote[/green] {path}")
    except (OSError, ValueError) as exc:
        output.error(str(exc))
