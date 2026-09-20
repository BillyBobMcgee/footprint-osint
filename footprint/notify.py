"""Push results to user-configured webhooks.

Discord URLs get a formatted embed; anything else gets the plain result JSON,
which suits ntfy/Zapier/n8n endpoints.

Nothing is sent unless the user configures a webhook. Payloads carry the same
redacted data as every other output, but they do include the subject being
scanned, hence opt-in.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from footprint import reports
from footprint.config import Config
from footprint.scoring import label_for
from footprint.sources.base import SourceError, fetch

# Discord's limits. Exceeding any of them is a 400, and a badly exposed
# address can carry 200+ breaches, so everything is truncated to fit.
MAX_TITLE = 256
MAX_DESC = 4096
MAX_FIELD_NAME = 256
MAX_FIELD_VALUE = 1024
MAX_FIELDS = 25
MAX_CONTENT = 2000
# Upload limit for a non-boosted server.
MAX_ATTACHMENT = 8 * 1024 * 1024
# Discord accepts at most 10 files in one message.
MAX_FILES = 10

# One colour per severity band, red through green.
COLORS = {
    "Critical": 0xDC2626,
    "High": 0xEA580C,
    "Moderate": 0xD97706,
    "Medium": 0xD97706,
    "Low": 0x65A30D,
    "Minimal": 0x16A34A,
}
# The embed's colour bar is thin, so severity gets a dot as well.
DOTS = {
    "Critical": "🔴",
    "High": "🟠",
    "Moderate": "🟡",
    "Medium": "🟡",
    "Low": "🟢",
    "Minimal": "🟢",
}
NEW_FINDING_COLOR = 0xDC2626
DEFAULT_COLOR = 0x5865F2

# Shown in every embed footer.
PROJECT_URL = "github.com/BillyBobMcgee/footprint"


def is_discord(url: str) -> bool:
    return "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url


def _clip(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bullets(lines: list[str], limit: int = MAX_FIELD_VALUE, sep: str = "\n") -> str:
    """Join lines into one field value, dropping any that would overflow."""
    out: list[str] = []
    used = 0
    for line in lines:
        line = _clip(line, 200)
        if used + len(line) + 1 > limit - 20:
            out.append(f"…and {len(lines) - len(out)} more")
            break
        out.append(line)
        used += len(line) + 1
    return sep.join(out) or "-"


# --- styling

def _meter(score: int, width: int = 12) -> str:
    """A score bar, fenced so it renders monospaced and every embed lines up."""
    filled = max(0, min(width, round(score / 100 * width)))
    return f"`{'█' * filled}{'░' * (width - filled)}`"


def _verdict(score: int, label: str, prefix: str = "") -> str:
    dot = DOTS.get(label, "")
    return f"{dot} {_meter(score)} **{prefix}{score}/100 {label}**".strip()


def _note(text: str) -> str:
    """Discord subtext: small grey text, for caveats."""
    return f"-# {text}"


def _stat(name: str, n: int) -> dict:
    """One count as its own column. Discord packs three of these per row."""
    return {"name": name, "value": f"**{n}**", "inline": True}


def _embed(title: str, description: str, color: int,
           fields: list[dict] | None = None) -> dict:
    """The shape every embed shares: footer, timestamp, capped fields."""
    return {
        "title": _clip(title, MAX_TITLE),
        "description": _clip(description, MAX_DESC),
        "color": color,
        "fields": (fields or [])[:MAX_FIELDS],
        "footer": {"text": PROJECT_URL},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# --- payloads

def profile_embed(payload: dict[str, Any]) -> dict:
    """A Discord embed summarising a finished scan."""
    subject = payload.get("subject", "?")
    kind = payload.get("kind", "result")
    sections = payload.get("sections") or {}
    risk = sections.get("risk") or {}
    score = risk.get("score", 0)
    label = risk.get("label", "Minimal")

    # A domain scan is flagged as a whole, so its advice isn't flagged twice.
    poc = kind.endswith("domain")
    fields: list[dict] = []

    breaches = len(sections.get("breaches") or []) + len(sections.get("xon_breaches") or [])
    for name, n in (
        ("Breaches", breaches),
        ("Accounts", len(sections.get("accounts") or [])),
        ("Leaks", len(sections.get("leaks") or [])),
        ("Dark web", len(sections.get("darkweb") or [])),
        ("Pastes", len(sections.get("pastes") or [])),
    ):
        if n:
            fields.append(_stat(name, n))

    if risk.get("factors"):
        fields.append({
            "name": "Why",
            # Padded inside the fence so the points column stays straight.
            "value": _bullets([f"`{'+' + str(f.get('points')):>4}` {f.get('reason')}"
                               for f in risk["factors"]]),
            "inline": False,
        })

    if risk.get("actions"):
        caveat = "" if poc else "\n" + _note("Proof of concept, may be inaccurate.")
        fields.append({
            "name": "What to do now",
            "value": _bullets([f"{i}. {a.get('title')}"
                               for i, a in enumerate(risk["actions"][:6], 1)],
                              limit=MAX_FIELD_VALUE - len(caveat)) + caveat,
            "inline": False,
        })

    recon = sections.get("recon") or {}
    if recon.get("takeovers"):
        fields.append({
            "name": "⚠ Subdomain takeover",
            "value": _bullets([f"`{t.get('host')}` → **{t.get('service')}**"
                               for t in recon["takeovers"]]),
            "inline": False,
        })

    sites = [s for s in (sections.get("sites") or []) if s.get("exists")]
    if sites:
        fields.append({
            "name": f"Found on {len(sites)} site(s)",
            "value": _bullets([f"`{s.get('site', '?')}`" for s in sites], sep=" "),
            "inline": False,
        })

    # The title names the task; the subject leads the description.
    lines = [f"__{subject}__", _verdict(score, label)]
    if poc:
        lines.append(_note("Proof of concept, may not be accurate."))
    return _embed(f"Task: {kind.capitalize()} Check", "\n".join(lines),
                  COLORS.get(label, DEFAULT_COLOR), fields)


def watch_embed(new_findings: dict[str, list[str]]) -> dict:
    """A Discord embed for watch-mode alerts: only what is newly discovered."""
    total = sum(len(v) for v in new_findings.values())
    fields = [
        {"name": _clip(subject, MAX_FIELD_NAME),
         "value": _bullets([f"- {label}" for label in labels]),
         "inline": False}
        for subject, labels in list(new_findings.items())[:MAX_FIELDS]
    ]
    return _embed(
        "Task: Watch Check",
        f"{DOTS['Critical']} __{total} new finding(s)__\n"
        + _note("New since the last check."),
        NEW_FINDING_COLOR, fields,
    )


def bulk_embed(run) -> dict:
    """A Discord embed summarising a bulk run, worst-scoring subjects first."""
    total = len(run.results)
    exposed = run.exposed
    errors = [r for r in run.results if r.error]
    worst = sorted(exposed, key=lambda r: -r.score)

    fields: list[dict] = []
    if worst:
        fields.append({
            "name": f"Exposed ({len(exposed)} of {total})",
            # A password run labels rows by line number. The webhook is the
            # one place the real password is useful, so it goes here.
            "value": _bullets([f"{DOTS.get(r.risk, '')} `{r.score:>3}` "
                               f"**{getattr(r, 'secret', None) or r.label}** "
                               f"{r.detail}" for r in worst]),
            "inline": False,
        })
    if run.notes:
        fields.append({"name": "Notes", "value": _bullets(run.notes), "inline": False})
    if errors:
        fields.append({
            "name": f"Failed ({len(errors)})",
            "value": _bullets([f"`{r.label}` {r.error}" for r in errors]),
            "inline": False,
        })

    top = max((r.score for r in run.results), default=0)
    label = label_for(top)
    return _embed(
        f"Task: Bulk {run.kind.capitalize()} Check",
        f"__{total} subject(s) · {len(exposed)} exposed__\n"
        f"{_verdict(top, label, prefix='highest ')}",
        COLORS.get(label, DEFAULT_COLOR), fields,
    )


def password_embed(exposure, value: str | None = None) -> dict:
    """A password result. `value` puts the password itself in the message.

    Off by default: a webhook message lands in a channel history that outlives
    the check.
    """
    exposed = getattr(exposure, "exposed", False)
    count = getattr(exposure, "count", 0)
    fields: list[dict] = []
    if value:
        # Fenced so leading and trailing spaces survive the render.
        fields.append({"name": "Password", "inline": False,
                       "value": _clip(f"```\n{value}\n```", MAX_FIELD_VALUE)})
    return _embed(
        "Task: Password Check",
        (f"{DOTS['Critical']} **Compromised**, seen {count:,} time(s) in breach corpora."
         if exposed else
         f"{DOTS['Minimal']} **Not found** in the Pwned Passwords set."),
        COLORS["Critical"] if exposed else COLORS["Minimal"],
        fields,
    )


def test_embed() -> dict:
    return _embed("Task: Webhook Test",
                  f"{DOTS['Minimal']} This webhook is configured correctly.",
                  COLORS["Minimal"])


# --- sending

def report_attachment(payload: dict[str, Any]) -> tuple[str, bytes] | None:
    """Render the payload as an HTML report to attach to the message.

    The embed is only ever a summary, so the file carries the full record.
    """
    subject = str(payload.get("subject", "report"))
    name = f"footprint-{subject}.html".replace("@", "_at_")
    name = "".join(c for c in name if c.isalnum() or c in "-_.") or "report.html"
    try:
        blob = reports.render(payload).encode("utf-8")
    except (ValueError, TypeError):
        return None
    if len(blob) > MAX_ATTACHMENT:
        return None
    return name, blob


def _post(config: Config, url: str, embed: dict, raw: dict | None,
          attachments: list[tuple[str, bytes]]) -> None:
    """POST one payload, with any attachments. Raises SourceError on failure."""
    if is_discord(url):
        body: dict[str, Any] = {"embeds": [embed]}
        if attachments:
            # Discord wants the JSON in a `payload_json` part alongside the
            # files, linked by attachment index.
            files = {}
            body["attachments"] = []
            for i, (name, blob) in enumerate(attachments[:MAX_FILES]):
                body["attachments"].append({"id": i, "filename": name})
                files[f"files[{i}]"] = (name, blob, "text/html")
            _check(fetch(
                config, url, method="POST", source="webhook", cache_ttl=0,
                data={"payload_json": json.dumps(body)}, files=files,
            ))
            return
    else:
        # Non-Discord endpoints get the full result plus a summary line, so a
        # simple consumer still has something to display. Fields go in too --
        # a password check has nothing else to say.
        lines = [f"{embed.get('title', '')}: {embed.get('description', '')}"]
        lines += [f"{f.get('name', '')}: {f.get('value', '')}"
                  for f in embed.get("fields") or []]
        body = {"text": _clip("\n".join(lines), MAX_CONTENT)}
        if raw is not None:
            body["result"] = raw

    _check(fetch(config, url, method="POST", json_body=body,
                 source="webhook", cache_ttl=0))


def _check(result) -> None:
    # Discord returns 200; other services use 201/202/204.
    if result.status_code not in (200, 201, 202, 204):
        raise SourceError(
            f"webhook returned HTTP {result.status_code}: "
            f"{_clip(result.text or '(no body)', 200)}"
        )


def send(config: Config, embed: dict, raw: dict | None = None,
         attachments: list[tuple[str, bytes]] | None = None,
         attach: bool = True) -> list[tuple[str, str | None]]:
    """Deliver `embed` to every configured webhook.

    Returns one (url, error) per webhook; error is None on success. Failures
    are reported, never raised. A scan that worked shouldn't fail because
    Discord was down.

    Pass `attachments` to send several reports (bulk runs do); otherwise one
    is rendered from `raw`. Disabled webhooks are skipped.
    """
    files = list(attachments or [])
    if attach and not files and raw is not None:
        one = report_attachment(raw)
        if one:
            files = [one]

    results: list[tuple[str, str | None]] = []
    for hook in config.active_webhooks:
        url = hook.url
        try:
            _post(config, url, embed, raw, files if attach else [])
            results.append((url, None))
        except SourceError as exc:
            results.append((url, str(exc)))
        except Exception as exc:  # noqa: BLE001 - delivery must never crash a scan
            results.append((url, f"unexpected error: {exc}"))
    return results


def redact(url: str) -> str:
    """Webhook URLs are secrets: anyone holding one can post to the channel."""
    if len(url) <= 34:
        return url[:12] + "…"
    return url[:34] + "…" + url[-4:]
