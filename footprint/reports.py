"""Render a profile/result payload as a standalone HTML report.

Accepts the plain-dict shape produced by Profile.to_dict() (or the simpler
per-command dicts), so the same data drives the console, JSON, and files.
"""

from __future__ import annotations

import html
import io
import re
from datetime import datetime, timezone
from typing import Any

from footprint.scoring import classify_data

_GENERATED = "footprint report"

# Shown on every domain result.
DOMAIN_CAVEAT = "Proof of concept, may not give accurate results."
# Shown wherever remediation steps appear.
ACTIONS_CAVEAT = "Proof of concept, this advice may be inaccurate."


def _rows(payload: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """Flatten a payload into (type, name, detail, date) table rows."""
    rows: list[tuple[str, str, str, str]] = []
    sections = payload.get("sections", payload)

    for a in sections.get("accounts", []) or []:
        rows.append(("account", a.get("site", ""), a.get("domain", ""), ""))
    for p in sections.get("pastes", []) or []:
        rows.append(("paste", p.get("source", ""), p.get("title") or "", p.get("date") or ""))
    for r in sections.get("leaks", []) or []:
        rows.append(("leak", r.get("database", ""),
                     ", ".join(r.get("fields_present", [])), ""))
    for m in sections.get("darkweb", []) or []:
        rows.append(("darkweb", m.get("name", ""), m.get("bucket", ""), m.get("date") or ""))
    for h in sections.get("sites", []) or []:
        if h.get("exists"):
            rows.append(("site", h.get("site", ""), h.get("url", ""), ""))
    for b in sections.get("bulk", []) or []:
        rows.append((b.get("risk", ""), b.get("label", ""),
                     b.get("error") or b.get("detail", ""),
                     str(b.get("score", ""))))
    recon = sections.get("recon")
    if recon:
        for t in recon.get("takeovers", []) or []:
            rows.append(("takeover", t.get("host", ""),
                         f"{t.get('target', '')} ({t.get('service', '')})", ""))
        for sub in recon.get("subdomains", []):
            rows.append(("subdomain", sub, "", ""))
    return rows


def sections_of(payload: dict[str, Any]) -> dict[str, Any]:
    return payload.get("sections") or {}


def _breaches(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Merged, de-duplicated breaches, newest first."""
    sections = payload.get("sections", payload)
    merged: dict[str, dict] = {}
    for key in ("breaches", "xon_breaches"):
        for b in sections.get(key) or []:
            name = (b.get("name") or b.get("title") or "").strip().lower()
            if name and name not in merged:
                merged[name] = b
    return sorted(merged.values(), key=lambda b: b.get("breach_date") or "",
                  reverse=True)


def _strip_tags(text: str) -> str:
    """Breach descriptions arrive as HTML fragments; keep the words only."""
    return html.escape(re.sub(r"<[^>]+>", "", text)).strip()


def _breach_cells(b: dict[str, Any]) -> str:
    """One breach as four <td>s: name, date, accounts, exposed data."""
    name = html.escape(str(b.get("title") or b.get("name") or "?"))

    flags = ""
    if b.get("is_sensitive"):
        flags = " <span class='flag crit'>sensitive</span>"
    if b.get("is_verified") is False:
        flags += " <span class=flag>unverified</span>"

    extra = ""
    if b.get("domain"):
        extra += f"<div class=sub>{html.escape(str(b['domain']))}</div>"
    desc = _strip_tags(str(b.get("description") or ""))
    if desc:
        extra += f"<div class=desc>{desc}</div>"

    count = b.get("pwn_count") or 0
    accounts = f"{count:,}" if count else "?"

    classes = "".join(
        f"<span class='dc {classify_data(str(c))}'>{html.escape(str(c))}</span>"
        for c in (b.get("data_classes") or [])
    ) or "<span class=dc>not stated</span>"

    return (f"<td><b>{name}</b>{flags}{extra}</td>"
            f"<td class=date>{html.escape(str(b.get('breach_date') or '?'))}</td>"
            f"<td class=r>{accounts}</td>"
            f"<td>{classes}</td>")


def _risk(payload: dict[str, Any]) -> dict[str, Any]:
    """The locally-computed assessment, as a plain dict (may be empty)."""
    return (payload.get("sections") or {}).get("risk") or {}


def render(payload: dict[str, Any]) -> str:
    """Build the standalone HTML document for a payload."""
    subject = html.escape(str(payload.get("subject", "?")))
    kind = html.escape(str(payload.get("kind", "result")))
    rows = _rows(payload)
    body = io.StringIO()
    body.write(f"<h1>footprint report</h1><p class=sub>{kind}: <code>{subject}</code> · "
               f"generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}</p>")

    if str(payload.get("kind", "")).endswith("domain"):
        body.write(f"<p class=poc><b>Proof of concept.</b> {DOMAIN_CAVEAT}</p>")

    risk = _risk(payload)
    if risk:
        score = int(risk.get("score", 0))
        tier = str(risk.get("label", "")).lower()
        body.write(
            f"<div class='risk {html.escape(tier)}'>"
            f"<div class=score>{score}<span>/100</span></div>"
            f"<div class=meta><b>{html.escape(str(risk.get('label', '?')))}</b>"
            f"<div class=bar><i style='width:{score}%'></i></div></div></div>"
        )
        if risk.get("factors"):
            body.write("<ul class=factors>")
            for f in risk["factors"]:
                body.write(f"<li><code>+{int(f.get('points', 0))}</code> "
                           f"{html.escape(str(f.get('reason', '')))}</li>")
            body.write("</ul>")

    breaches = _breaches(payload)
    if breaches:
        body.write(f"<h2>Breaches ({len(breaches)})</h2>")
        body.write("<table class=breaches><thead><tr><th>Breach</th><th>Date</th>"
                   "<th class=r>Accounts</th><th>Exposed data</th></tr></thead><tbody>")
        for b in breaches:
            body.write("<tr>" + _breach_cells(b) + "</tr>")
        body.write("</tbody></table>")

    if rows:
        headers = (("Risk", "Subject", "Detail", "Score")
                   if sections_of(payload).get("bulk")
                   else ("Type", "Name", "Detail", "Date"))
        body.write("<table><thead><tr>"
                   + "".join(f"<th>{h}</th>" for h in headers)
                   + "</tr></thead><tbody>")
        for t, n, d, dt in rows:
            body.write("<tr>" + "".join(
                f"<td>{html.escape(str(c))}</td>" for c in (t, n, d, dt)
            ) + "</tr>")
        body.write("</tbody></table>")
    timeline = payload.get("timeline", [])
    if timeline:
        body.write("<h2>Timeline</h2><ul>")
        for e in timeline:
            body.write(f"<li><b>{html.escape(str(e.get('date') or '????'))}</b>: "
                       f"{html.escape(str(e.get('kind')))}: "
                       f"{html.escape(str(e.get('label')))}</li>")
        body.write("</ul>")
    if risk.get("actions"):
        body.write("<h2>What to do now</h2>")
        body.write(f"<p class=poc>{ACTIONS_CAVEAT}</p>")
        body.write("<ol class=actions>")
        for a in risk["actions"]:
            body.write(f"<li><b>{html.escape(str(a.get('title', '')))}</b>"
                       f"<p>{html.escape(str(a.get('detail', '')))}</p></li>")
        body.write("</ol>")

    notes = payload.get("notes", [])
    if notes:
        body.write("<h2>Notes</h2><ul>")
        for n in notes:
            body.write(f"<li>{html.escape(str(n))}</li>")
        body.write("</ul>")

    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>footprint report for {subject}</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
body{{color:#1a1a1a}}
h1{{margin-bottom:.2rem}} .sub{{color:#666}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:14px}}
th{{background:#f4f4f5}} code{{background:#f0f0f0;padding:.1rem .3rem;border-radius:4px}}
.risk{{display:flex;align-items:center;gap:1rem;margin:1.2rem 0;padding:1rem;
border:1px solid #ddd;border-radius:10px}}
.risk .score{{font:700 2.6rem/1 system-ui;color:#16a34a}}
.risk .score span{{font-size:1rem;color:#888;font-weight:400}}
.risk .meta{{flex:1}}
.risk .bar{{height:8px;background:#e5e5e5;border-radius:99px;margin-top:.4rem;
overflow:hidden}}
.risk .bar i{{display:block;height:100%;background:#16a34a}}
.risk.moderate .score,.risk.medium .score{{color:#d97706}}
.risk.moderate .bar i,.risk.medium .bar i{{background:#d97706}}
.risk.high .score,.risk.critical .score{{color:#dc2626}}
.risk.high .bar i,.risk.critical .bar i{{background:#dc2626}}
ul.factors{{list-style:none;padding:0;color:#444}}
ul.factors li{{padding:.15rem 0;font-size:14px}}
ol.actions li{{margin:.6rem 0}} ol.actions p{{margin:.2rem 0;color:#555}}
table.breaches td{{vertical-align:top}}
td.r,th.r{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}
.sub{{color:#777;font-size:12px}}
.desc{{color:#555;font-size:12.5px;margin-top:.3rem;max-width:46ch}}
.flag{{font-size:11px;padding:1px 6px;border-radius:4px;border:1px solid #ddd;
color:#666;margin-left:.3rem}}
.flag.crit{{color:#dc2626;border-color:#f2b8b8}}
.dc{{display:inline-block;font-size:11px;padding:1px 6px;margin:0 3px 3px 0;
border-radius:4px;border:1px solid #ddd;color:#666}}
.dc.critical{{color:#dc2626;border-color:#f2b8b8}}
.dc.high{{color:#b45309;border-color:#e8cd9a}}
.poc{{border:1px solid #e5c07b;background:#fdf6e3;border-radius:8px;
padding:.7rem .9rem;font-size:13.5px;color:#6b5320;margin:1rem 0}}
@media(prefers-color-scheme:dark){{body{{background:#111;color:#eee}}
th{{background:#222}} th,td{{border-color:#333}} code{{background:#222}} .sub{{color:#aaa}}
.risk{{border-color:#333}} .risk .bar{{background:#2a2a2a}}
ul.factors{{color:#bbb}} ol.actions p{{color:#aaa}}
.sub,.desc{{color:#9a9a9a}} .flag,.dc{{border-color:#3a3a3a;color:#aaa}}
.poc{{background:#2a2410;border-color:#5c4a1a;color:#d8c48c}}}}
</style></head><body>{body.getvalue()}</body></html>"""


def save(payload: dict[str, Any], path: str) -> None:
    """Write the report. HTML is the only format."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(payload))
