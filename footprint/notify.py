"""Push results to user-configured webhooks.

Discord URLs get a formatted embed; anything else gets the plain result JSON,
which suits ntfy/Zapier/n8n endpoints.

Nothing is sent unless the user configures a webhook. Payloads carry the same
redacted data as every other output, but they do include the subject being
scanned — hence opt-in.
"""

from __future__ import annotations

import json
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

COLORS = {
    "Critical": 0xDC2626,
    "High": 0xDC2626,
    "Moderate": 0xD97706,
    "Medium": 0xD97706,
    "Low": 0x16A34A,
    "Minimal": 0x16A34A,
}
NEW_FINDING_COLOR = 0xDC2626


def is_discord(url: str) -> bool:
    return "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url


def _clip(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bullets(lines: list[str], limit: int = MAX_FIELD_VALUE) -> str:
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
    return "\n".join(out) or "—"


# ------------------------------------------------------------------ payloads

def profile_embed(payload: dict[str, Any]) -> dict:
    """A Discord embed summarising a finished scan."""
    subject = payload.get("subject", "?")
    kind = payload.get("kind", "result")
    sections = payload.get("sections") or {}
    risk = sections.get("risk") or {}
    score = risk.get("score", 0)
    label = risk.get("label", "Minimal")

    fields: list[dict] = []

    counts = []
    breaches = len(sections.get("breaches") or []) + len(sections.get("xon_breaches") or [])
    for name, n in (
        ("Breaches", breaches),
        ("Registered accounts", len(sections.get("accounts") or [])),
        ("Leak records", len(sections.get("leaks") or [])),
        ("Dark-web hits", len(sections.get("darkweb") or [])),
        ("Pastes", len(sections.get("pastes") or [])),
    ):
        if n:
            counts.append(f"**{name}:** {n}")
    if counts:
        fields.append({"name": "Found", "value": _bullets(counts), "inline": False})

    if risk.get("factors"):
        fields.append({
            "name": "Why",
            "value": _bullets([f"`+{f.get('points')}` {f.get('reason')}"
                               for f in risk["factors"]]),
            "inline": False,
        })

    if risk.get("actions"):
        fields.append({
            "name": "What to do now (proof of concept \u2014 may be inaccurate)",
            "value": _bullets([f"{i}. {a.get('title')}"
                               for i, a in enumerate(risk["actions"][:6], 1)]),
            "inline": False,
        })

    recon = sections.get("recon") or {}
    if recon.get("takeovers"):
        fields.append({
            "name": "⚠ Subdomain takeover",
            "value": _bullets([f"{t.get('host')} → {t.get('service')}"
                               for t in recon["takeovers"]]),
            "inline": False,
        })

    sites = [s for s in (sections.get("sites") or []) if s.get("exists")]
    if sites:
        fields.append({
            "name": f"Found on {len(sites)} site(s)",
            "value": _bullets([s.get("site", "?") for s in sites]),
            "inline": False,
        })

    return {
        # Brand goes in the footer only; the title is for the subject.
        "title": _clip(f"{kind.capitalize()}: {subject}", MAX_TITLE),
        "description": _clip(
            f"**Exposure score {score}/100 — {label}**"
            + ("\n*Proof of concept — may not be accurate.*"
               if kind.endswith("domain") else ""),
            MAX_DESC,
        ),
        "color": COLORS.get(label, 0x5865F2),
        "fields": fields[:MAX_FIELDS],
        "footer": {"text": "footprint"},
    }


def watch_embed(new_findings: dict[str, list[str]]) -> dict:
    """A Discord embed for watch-mode alerts: only what is newly discovered."""
    total = sum(len(v) for v in new_findings.values())
    fields = [
        {"name": _clip(subject, MAX_FIELD_NAME),
         "value": _bullets([f"• {label}" for label in labels]),
         "inline": False}
        for subject, labels in list(new_findings.items())[:MAX_FIELDS]
    ]
    return {
        "title": f"{total} new finding(s)",
        "description": "New exposure appeared since the last watch check.",
        "color": NEW_FINDING_COLOR,
        "fields": fields,
        "footer": {"text": "footprint"},
    }


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
            "value": _bullets([f"`{r.score:>3}` **{r.label}** — {r.detail}"
                               for r in worst]),
            "inline": False,
        })
    if run.notes:
        fields.append({"name": "Notes", "value": _bullets(run.notes), "inline": False})
    if errors:
        fields.append({
            "name": f"Failed ({len(errors)})",
            "value": _bullets([f"{r.label}: {r.error}" for r in errors]),
            "inline": False,
        })

    top = max((r.score for r in run.results), default=0)
    return {
        "title": f"Bulk {run.kind} scan — {total} subject(s)",
        "description": f"**{len(exposed)} exposed** · highest score {top}/100",
        "color": COLORS.get(label_for(top), 0x5865F2),
        "fields": fields[:MAX_FIELDS],
        "footer": {"text": "footprint"},
    }


def password_embed(exposure) -> dict:
    """A password result. Carries the verdict only, never the password."""
    exposed = getattr(exposure, "exposed", False)
    count = getattr(exposure, "count", 0)
    return {
        "title": "Password check",
        "description": (f"**Compromised** \u2014 seen {count:,} time(s) in breach corpora."
                        if exposed else
                        "**Not found** in the Pwned Passwords set."),
        "color": COLORS["Critical"] if exposed else COLORS["Minimal"],
        "footer": {"text": "footprint"},
    }


def test_embed() -> dict:
    return {
        "title": "Webhook test",
        "description": "This webhook is configured correctly.",
        "color": 0x16A34A,
        "footer": {"text": "footprint"},
    }


# -------------------------------------------------------------------- sending

def report_attachment(payload: dict[str, Any]) -> tuple[str, bytes] | None:
    """Render the payload as an HTML report to attach to the message.

    The embed is only ever a summary, so the file carries the full record.
    """
    import tempfile
    from pathlib import Path

    subject = str(payload.get("subject", "report"))
    name = f"footprint-{subject}.html".replace("@", "_at_")
    name = "".join(c for c in name if c.isalnum() or c in "-_.") or "report.html"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            reports.write_html(payload, str(path))
            blob = path.read_bytes()
    except (OSError, ValueError, TypeError):
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
        # simple consumer still has something to display.
        body = {"text": _clip(f"{embed.get('title', '')} — "
                              f"{embed.get('description', '')}", MAX_CONTENT)}
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
    are reported, never raised — a scan that worked shouldn't fail because
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
