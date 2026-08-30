"""Command-line interface for footprint.

Run with no subcommand to launch the interactive menu. Subcommands remain
available for scripting and automation.

Exit codes:
    0  ran successfully, nothing exposed / no hits
    1  ran successfully, exposure or hits were found
    2  a source/network/auth error occurred
    3  usage error
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from footprint import (
    __version__,
    aggregate,
    bulk,
    cache,
    notify,
    output,
    reports,
    scoring,
    storage,
)
from footprint.config import Config, Webhook
from footprint.sources import hibp, pwned_passwords
from footprint.sources import username as username_src
from footprint.sources.base import RateLimitError, SourceError

EXIT_OK = 0
EXIT_FOUND = 1
EXIT_SOURCE_ERROR = 2
EXIT_USAGE = 3

BANNER = (
    "footprint — defensive OSINT exposure checker\n"
    "Run with no arguments for the interactive menu.\n"
    "Use only against accounts/domains you own or are authorized to assess."
)


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit JSON instead of tables")
    parser.add_argument("--api-key", help="HIBP API key (overrides HIBP_API_KEY)")
    parser.add_argument("--profile", help="config-file profile to use")
    parser.add_argument("--timeout", type=float, default=15.0, help="per-request timeout (s)")
    parser.add_argument("--tor", action="store_true", default=None,
                        help="route traffic through Tor (SOCKS5)")
    parser.add_argument("--cache", action="store_true", default=None,
                        help="enable the response cache")
    parser.add_argument("--no-cache", action="store_false", dest="cache",
                        help="disable the response cache")


def _add_report(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--save", action="store_true", help="write an HTML report")
    parser.add_argument("--out", help="report output path (with --save)")
    parser.add_argument("--notify", action="store_true",
                        help="(default) push the result to enabled webhook(s)")
    parser.add_argument("--no-notify", action="store_true",
                        help="don't push this result to any webhook")
    parser.add_argument("--fail-on", type=int, metavar="SCORE",
                        help="exit 1 only when the exposure score reaches SCORE "
                             "(default: exit 1 on any finding)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="footprint",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"footprint {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_int = sub.add_parser("interactive", help="launch the interactive menu (default)")
    _add_common(p_int)

    p_email = sub.add_parser("email", help="full email exposure profile")
    p_email.add_argument("address")
    _add_common(p_email)
    _add_report(p_email)

    p_pw = sub.add_parser("password", help="check a password via k-anonymity (safe)")
    p_pw.add_argument("value", nargs="?", help="password (omit to be prompted securely)")
    p_pw.add_argument("--no-notify", action="store_true",
                      help="don't push this result to any webhook")
    _add_common(p_pw)

    p_domain = sub.add_parser("domain", help="DNS/subdomain/breach recon for a domain")
    p_domain.add_argument("name")
    _add_common(p_domain)
    _add_report(p_domain)

    p_user = sub.add_parser("username", help="check a username across public sites")
    p_user.add_argument("handle")
    p_user.add_argument("--category", help="limit to one site category")
    p_user.add_argument("--refresh", action="store_true", help="refresh the site dataset")
    _add_common(p_user)
    _add_report(p_user)

    p_batch = sub.add_parser(
        "batch", help="bulk-scan a file of emails, domains, usernames, or passwords")
    p_batch.add_argument("file", help="one subject per line")
    p_batch.add_argument("--kind", default="auto",
                         choices=["auto", *bulk.KINDS],
                         help="what the file contains (default: detect per line; "
                              "'password' must always be given explicitly)")
    p_batch.add_argument("--save", action="store_true",
                         help="also write an HTML report per subject")
    p_batch.add_argument("--out-dir", default=".",
                         help="directory for --save reports (default: .)")
    p_batch.add_argument("--notify", action="store_true",
                         help="(default) push exposed subjects to enabled webhook(s)")
    p_batch.add_argument("--no-notify", action="store_true",
                         help="don't push this run to any webhook")
    p_batch.add_argument("--fail-on", type=int, metavar="SCORE",
                         help="exit 1 only when a subject reaches SCORE")
    _add_common(p_batch)

    p_watch = sub.add_parser("watch", help="track subjects and alert only on new exposure")
    watch_sub = p_watch.add_subparsers(dest="watch_action")
    w_add = watch_sub.add_parser("add", help="add a subject to the watchlist")
    w_add.add_argument("subject")
    w_add.add_argument("--kind", default="email", choices=["email", "domain"])
    w_rm = watch_sub.add_parser("remove", help="stop watching a subject")
    w_rm.add_argument("subject")
    watch_sub.add_parser("list", help="show the watchlist")
    w_check = watch_sub.add_parser("check", help="re-scan the watchlist")
    w_check.add_argument("--quiet", action="store_true",
                         help="print only new findings (for cron)")
    w_check.add_argument("--no-notify", action="store_true",
                         help="don't push new findings to the webhook(s)")
    for p in (w_add, w_rm, w_check):
        _add_common(p)
    _add_common(p_watch)

    p_gui = sub.add_parser("gui", help="open the local web interface")
    p_gui.add_argument("--port", type=int, default=8731, help="port to bind (default 8731)")
    p_gui.add_argument("--no-browser", action="store_true",
                       help="don't open a browser automatically")
    _add_common(p_gui)

    p_hook = sub.add_parser("webhook", help="manage webhooks results are pushed to")
    hook_sub = p_hook.add_subparsers(dest="webhook_action")
    h_add = hook_sub.add_parser("add", help="add a webhook URL (Discord or any JSON endpoint)")
    h_add.add_argument("url")
    h_rm = hook_sub.add_parser("remove", help="remove a webhook URL")
    h_rm.add_argument("url")
    hook_sub.add_parser("list", help="show configured webhooks (redacted)")
    hook_sub.add_parser("test", help="send a test message to every enabled webhook")
    h_on = hook_sub.add_parser("enable", help="switch a webhook back on")
    h_on.add_argument("target", help="its number from `webhook list`, or its URL")
    h_off = hook_sub.add_parser("disable", help="stop sending to a webhook")
    h_off.add_argument("target", help="its number from `webhook list`, or its URL")
    for p in (h_add, h_rm, h_on, h_off):
        _add_common(p)
    _add_common(p_hook)

    p_breaches = sub.add_parser("breaches", help="show the full public breach catalog")
    _add_common(p_breaches)

    sub.add_parser("clear-cache", help="empty the response cache")

    return parser


def _config_from_args(args: argparse.Namespace) -> Config:
    return Config.resolve(
        profile=getattr(args, "profile", None),
        api_key=getattr(args, "api_key", None),
        timeout=getattr(args, "timeout", None),
        tor=getattr(args, "tor", None),
        cache=getattr(args, "cache", None),
    )


def _maybe_save(args, payload: dict) -> None:
    if getattr(args, "save", False):
        path = args.out or f"footprint-{payload.get('subject', 'report')}.html"
        path = path.replace("@", "_at_")
        reports.save(payload, path)
        output.info(f"[green]wrote[/green] {path}")


def _deliver(config, embed: dict, raw: dict | None = None,
             attachments: list | None = None, quiet: bool = False) -> None:
    """Push to every configured webhook, reporting failures without raising.

    A delivery problem is a warning, not an error — the scan itself succeeded,
    and failing here would break `watch check` in cron whenever Discord is down.
    """
    if not config.webhooks:
        if not quiet:
            output.warn("no webhooks configured — `footprint webhook add <url>`")
        return
    if not config.active_webhooks:
        if not quiet:
            output.warn("every webhook is disabled — `footprint webhook enable <n>`")
        return
    for url, error in notify.send(config, embed, raw, attachments=attachments):
        if error:
            output.warn(f"webhook {notify.redact(url)}: {error}")
        else:
            output.info(f"[green]sent[/green] {output.ARROW} {notify.redact(url)}")


def _verdict(args, score: int, found: bool) -> int:
    """Decide the exit code.

    By default any finding exits 1, which for a long-lived address is always
    true and useless for gating. --fail-on N switches to a score threshold.
    """
    threshold = getattr(args, "fail_on", None)
    if threshold is not None:
        return EXIT_FOUND if score >= threshold else EXIT_OK
    return EXIT_FOUND if found else EXIT_OK


def _wants_delivery(args, config) -> bool:
    """Every result goes to the enabled webhooks unless suppressed.

    The per-webhook on/off switch is the control, so there is no separate flag
    to remember -- if a webhook is enabled, it receives results.
    """
    if getattr(args, "no_notify", False):
        return False
    return bool(config.active_webhooks)


def _maybe_notify(args, config, payload: dict) -> None:
    if _wants_delivery(args, config):
        _deliver(config, notify.profile_embed(payload), payload, quiet=True)


def _cmd_email(args, config) -> int:
    profile = aggregate.email_profile(args.address, config)
    payload = profile.to_dict()
    if args.json:
        output.emit_json(payload)
    else:
        output.render_profile(profile)
    _maybe_save(args, payload)
    _maybe_notify(args, config, payload)
    exposed = bool(
        profile.sections.get("breaches")
        or profile.sections.get("xon_breaches")
        or profile.sections.get("leaks")
        or profile.sections.get("pastes")
    )
    return _verdict(args, getattr(profile.sections.get("risk"), "score", 0), exposed)


def _cmd_password(args, config) -> int:
    value = args.value or getpass.getpass("Password (hidden): ")
    if not value:
        output.error("no password provided")
        return EXIT_USAGE
    exposure = pwned_passwords.check_password(value, config)
    if args.json:
        output.emit_json(exposure.to_dict())
    else:
        output.render_password(exposure)
    if _wants_delivery(args, config):
        _deliver(config, notify.password_embed(exposure), quiet=True)
    return EXIT_FOUND if exposure.exposed else EXIT_OK


def _cmd_domain(args, config) -> int:
    profile = aggregate.domain_profile(args.name, config)
    payload = profile.to_dict()
    if args.json:
        output.emit_json(payload)
    else:
        output.render_profile(profile)
    _maybe_save(args, payload)
    _maybe_notify(args, config, payload)
    recon = profile.sections.get("recon")
    at_risk = bool(profile.sections.get("breaches")) or bool(
        getattr(recon, "takeovers", None)
    )
    return _verdict(args, getattr(profile.sections.get("risk"), "score", 0), at_risk)


def _cmd_username(args, config) -> int:
    hits = username_src.check_username(
        args.handle, config, category=args.category, refresh=args.refresh
    )
    assessment = scoring.assess_username(hits)
    payload = {
        "subject": args.handle,
        "kind": "username",
        "sections": {"sites": [h.to_dict() for h in hits],
                     "risk": assessment.to_dict()},
    }
    if args.json:
        output.emit_json(payload)
    else:
        output.rule(f"Username: {args.handle}")
        output.render_assessment(assessment)
        output.render_username(hits)
        output.render_actions(assessment)
    _maybe_save(args, payload)
    _maybe_notify(args, config, payload)
    return _verdict(args, assessment.score, any(h.exists for h in hits))


def _cmd_breaches(args, config) -> int:
    breaches = hibp.all_breaches(config)
    if args.json:
        output.emit_json({"breaches": [b.to_dict() for b in breaches]})
    else:
        output.info(f"[bold]{len(breaches)}[/bold] breaches in the public catalog:")
        for b in sorted(breaches, key=lambda x: x.breach_date or "", reverse=True):
            output.info(f"  {b.breach_date or '?'}  {b.title} ({b.domain})")
    return EXIT_OK


def _cmd_clear_cache(args, config) -> int:
    n = cache.clear()
    output.info(f"cleared {n} cached entr{'y' if n == 1 else 'ies'}")
    return EXIT_OK


def _cmd_batch(args, config) -> int:
    """Bulk-scan a file of subjects. Exits 1 if any are exposed."""
    path = Path(args.file)
    if not path.exists():
        output.error(f"file not found: {args.file}")
        return EXIT_USAGE

    kind = args.kind
    if kind == "auto":
        peek = bulk.load_subjects(path, "email")
        if not peek:
            output.error("no subjects in that file")
            return EXIT_USAGE
        kind = bulk.detect_kind_for(peek)
        output.info(f"[dim]detected {kind}s[/dim]")

    try:
        rows = bulk.load_subjects(path, kind)
    except OSError as exc:
        output.error(str(exc))
        return EXIT_USAGE
    if not rows:
        output.error("no subjects in that file")
        return EXIT_USAGE

    out_dir = Path(args.out_dir)
    if args.save:
        out_dir.mkdir(parents=True, exist_ok=True)

    def show(result: bulk.BulkResult) -> None:
        if args.json:
            return
        if result.error:
            output.warn(f"{result.label}: {result.error}")
            return
        color = {"Critical": "bright_red", "High": "red",
                 "Moderate": "yellow"}.get(result.risk, "green")
        output.info(f"  [{color}]{result.score:>3}[/{color}] "
                    f"[dim]{result.risk:<8}[/dim] {result.label}  "
                    f"[dim]{result.detail}[/dim]")

    if not args.json:
        output.info(f"Scanning [bold]{len(rows)}[/bold] {kind}(s)…")
    run = bulk.run(rows, kind, config, on_result=show)

    saved: list[tuple[str, bytes]] = []
    if args.save:
        for result in run.results:
            if result.payload is None:
                continue  # passwords never produce a per-subject report
            name = f"footprint-{result.label}.html".replace("@", "_at_")
            name = "".join(c for c in name if c.isalnum() or c in "-_.")
            reports.save(result.payload, str(out_dir / name))
        output.info(f"[green]wrote[/green] {len(run.results)} report(s) to {out_dir}")

    payload = run.to_dict()
    if args.json:
        output.emit_json(payload)
    else:
        for note in run.notes:
            output.warn(note)
        output.info("")
        output.info(f"[bold]{len(run.exposed)}[/bold] of "
                    f"[bold]{len(run.results)}[/bold] exposed")

    if _wants_delivery(args, config):
        # One summary message with each exposed subject's report attached.
        for result in run.exposed:
            if result.payload is not None and len(saved) < notify.MAX_FILES:
                attachment = notify.report_attachment(result.payload)
                if attachment:
                    saved.append(attachment)
        _deliver(config, notify.bulk_embed(run), payload, attachments=saved,
                 quiet=True)

    top = max((r.score for r in run.results), default=0)
    return _verdict(args, top, bool(run.exposed))


def _cmd_watch(args, config) -> int:
    action = getattr(args, "watch_action", None) or "check"

    if action == "add":
        storage.add_to_watchlist(args.subject, args.kind)
        output.info(f"[green]watching[/green] {args.subject}")
        return EXIT_OK

    if action == "remove":
        storage.remove_from_watchlist(args.subject)
        output.info(f"[yellow]stopped watching[/yellow] {args.subject}")
        return EXIT_OK

    if action == "list":
        items = storage.watchlist()
        if not items:
            output.info("[dim]watchlist is empty[/dim]")
        for subject, kind in items:
            output.info(f"  • {subject} [dim]({kind})[/dim]")
        return EXIT_OK

    # check
    items = storage.watchlist()
    if not items:
        output.error("watchlist is empty — `footprint watch add <email>` first")
        return EXIT_USAGE

    quiet = getattr(args, "quiet", False)
    found: dict[str, list[str]] = {}
    for subject, kind in items:
        profile = (aggregate.domain_profile(subject, config) if kind == "domain"
                   else aggregate.email_profile(subject, config))
        new = storage.diff_new(subject, storage.fingerprints(profile))
        if new:
            found[subject] = list(new.values())
        elif not quiet:
            output.info(f"[green]no change[/green]  {subject}")

    # Watch runs unattended, so deliver automatically rather than needing a
    # flag that is easy to forget in a cron line.
    if found and config.active_webhooks and not getattr(args, "no_notify", False):
        _deliver(config, notify.watch_embed(found))

    if getattr(args, "json", False):
        output.emit_json({"new": found})
    else:
        for subject, labels in found.items():
            output.info(f"[bold red]NEW exposure[/bold red] for {subject}:")
            for label in labels:
                output.info(f"    • {label}")
        if not found and not quiet:
            output.info("[dim]nothing new across the watchlist[/dim]")
    return EXIT_FOUND if found else EXIT_OK


def _find_webhook(config, target: str):
    """Resolve a webhook by its listing number or by (part of) its URL."""
    if target.isdigit():
        index = int(target) - 1
        if 0 <= index < len(config.webhooks):
            return config.webhooks[index]
        # Fall through rather than fail: a Discord webhook ID is all digits, so
        # an out-of-range number is far more likely a URL fragment.
    return next((w for w in config.webhooks if w.url == target or target in w.url), None)


def _cmd_webhook(args, config) -> int:
    action = getattr(args, "webhook_action", None) or "list"

    if action == "list":
        if not config.webhooks:
            output.info("[dim]no webhooks configured[/dim]")
        for i, hook in enumerate(config.webhooks, 1):
            kind = "Discord" if notify.is_discord(hook.url) else "generic"
            state = ("[green]on[/green]" if hook.enabled
                     else "[dim]off[/dim]")
            output.info(f"  [cyan]{i}[/cyan]  {state}  {notify.redact(hook.url)} "
                        f"[dim]({kind})[/dim]")
        return EXIT_OK

    if action in ("enable", "disable"):
        hook = _find_webhook(config, args.target.strip())
        if hook is None:
            output.error(f"no webhook matching {args.target!r} — see `webhook list`")
            return EXIT_USAGE
        hook.enabled = action == "enable"
        config.save_profile()
        word = "enabled" if hook.enabled else "disabled"
        color = "green" if hook.enabled else "yellow"
        output.info(f"[{color}]{word}[/{color}] {notify.redact(hook.url)}")
        return EXIT_OK

    if action == "test":
        _deliver(config, notify.test_embed())
        return EXIT_OK

    url = args.url.strip()
    if action == "add":
        if not url.startswith(("http://", "https://")):
            output.error("a webhook URL must start with http:// or https://")
            return EXIT_USAGE
        if any(w.url == url for w in config.webhooks):
            output.warn("that webhook is already configured")
            return EXIT_OK
        config.webhooks.append(Webhook(url=url))
        path = config.save_profile()
        output.info(f"[green]added[/green] {notify.redact(url)} [dim]{output.ARROW} "
                    f"{path}[/dim]")
        return EXIT_OK

    if action == "remove":
        hook = _find_webhook(config, url)
        if hook is None:
            output.error("no such webhook configured")
            return EXIT_USAGE
        config.webhooks.remove(hook)
        config.save_profile()
        output.info(f"[yellow]removed[/yellow] {notify.redact(url)}")
        return EXIT_OK

    return EXIT_USAGE


def _cmd_gui(args, config) -> int:
    from footprint.gui import serve

    return serve(config, port=args.port, open_browser=not args.no_browser)


_DISPATCH = {
    "email": _cmd_email,
    "password": _cmd_password,
    "domain": _cmd_domain,
    "username": _cmd_username,
    "batch": _cmd_batch,
    "watch": _cmd_watch,
    "gui": _cmd_gui,
    "webhook": _cmd_webhook,
    "breaches": _cmd_breaches,
    "clear-cache": _cmd_clear_cache,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # No subcommand (or "interactive") → launch the menu.
    if args.command in (None, "interactive"):
        from footprint import interactive

        config = _config_from_args(args) if args.command else Config.resolve()
        try:
            return interactive.run(config)
        except KeyboardInterrupt:  # pragma: no cover
            return EXIT_OK

    config = _config_from_args(args)
    handler = _DISPATCH[args.command]
    try:
        return handler(args, config)
    except (RateLimitError, SourceError) as exc:
        output.error(str(exc))
        return EXIT_SOURCE_ERROR
    except KeyboardInterrupt:  # pragma: no cover
        output.warn("interrupted")
        return EXIT_SOURCE_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
