"""Local web GUI, served from the standard library. No extra dependencies.

`footprint gui` starts a threaded HTTP server on loopback and opens a browser
at it. Scans run in background threads and stream progress over Server-Sent
Events, so the page fills in source by source instead of freezing.

Two constraints worth keeping:

* Binds 127.0.0.1 only. This is a local UI, never a service.
* Every API call carries a per-run random token. Any page you have open could
  otherwise POST to localhost in the background; it cannot read the token.
"""

from __future__ import annotations

import json
import queue
import secrets
import threading
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from footprint import __version__, aggregate, bulk, notify, reports, scoring, storage
from footprint.config import Config, Webhook
from footprint.sources import holehe_scan, pwned_passwords
from footprint.sources import username as username_src
from footprint.sources.base import SourceError

_INDEX = Path(__file__).with_name("index.html")
MAX_BODY = 1 << 20  # 1 MiB is plenty for a form post; refuse anything larger.


@dataclass
class Job:
    """One running or finished scan, plus its stream of progress events."""

    kind: str
    subject: str
    # Bulk runs only: the lines to scan, and what they are.
    subjects: list[str] = field(default_factory=list)
    bulk_kind: str = "auto"
    events: queue.Queue = field(default_factory=queue.Queue)
    payload: dict[str, Any] | None = None
    error: str | None = None
    done: threading.Event = field(default_factory=threading.Event)
    cancel: threading.Event = field(default_factory=threading.Event)
    # Password runs only: {label: password}, for the webhook message. Kept off
    # the payload so it cannot reach a report, an export, or the history table.
    secrets: dict[str, str] = field(default_factory=dict)
    sent: int = 0
    notify_errors: list[str] = field(default_factory=list)


class State:
    """Shared server state: config, the token, and the job table."""

    def __init__(self, config: Config):
        self.config = config
        self.token = secrets.token_urlsafe(24)
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def new_job(self, kind: str, subject: str, subjects: list[str] | None = None,
                bulk_kind: str = "auto") -> tuple[str, Job]:
        job = Job(kind=kind, subject=subject, subjects=subjects or [],
                  bulk_kind=bulk_kind)
        job_id = secrets.token_urlsafe(12)
        with self._lock:
            # Keep the table small; this is a GUI session, not a database.
            if len(self.jobs) > 50:
                for stale in list(self.jobs)[:25]:
                    self.jobs.pop(stale, None)
            self.jobs[job_id] = job
        return job_id, job


def _run_scan(state: State, job: Job) -> None:
    """Execute one scan, pushing progress events as sources report in."""
    def progress(label: str, status: str) -> None:
        job.events.put({"type": "progress", "label": label, "status": status})

    try:
        if job.kind == "email":
            profile = aggregate.email_profile(job.subject, state.config,
                                              progress=progress)
            if profile.failed:
                raise SourceError(profile.failed)
            job.payload = profile.to_dict()
        elif job.kind == "domain":
            profile = aggregate.domain_profile(job.subject, state.config,
                                               progress=progress)
            if profile.failed:
                raise SourceError(profile.failed)
            job.payload = profile.to_dict()
        elif job.kind == "watch":
            items = storage.watchlist()
            if not items:
                raise SourceError("watchlist is empty")
            job.subject = f"{len(items)} subject(s)"
            job.events.put({"type": "total", "n": len(items)})
            rows = []
            for subject, kind in items:
                job.events.put({"type": "scanning", "label": subject})
                profile = (aggregate.domain_profile(subject, state.config)
                           if kind == "domain"
                           else aggregate.email_profile(subject, state.config))
                new = storage.diff_new(subject, storage.fingerprints(profile))
                row = {"subject": subject, "kind": kind, "new": list(new.values())}
                rows.append(row)
                job.events.put({"type": "watchrow", **row})
            job.payload = {
                "subject": "watchlist", "kind": "watch",
                "sections": {"watch": rows}, "timeline": [], "notes": [],
            }
        elif job.kind == "bulk":
            rows = bulk.parse_subjects("\n".join(job.subjects), job.bulk_kind)
            if not rows:
                raise SourceError("no subjects given")
            kind = job.bulk_kind
            if kind == "auto":
                kind = bulk.detect_kind_for(rows)
                job.events.put({"type": "bulkkind", "kind": kind})
            job.subject = f"{len(rows)} {kind}(s)"
            job.events.put({"type": "total", "n": len(rows)})

            def on_result(r):
                job.events.put({
                    "type": "bulkrow", "label": r.label, "score": r.score,
                    "risk": r.risk, "detail": r.detail, "exposed": r.exposed,
                    "error": r.error,
                })

            run = bulk.run(
                rows, kind, state.config,
                on_start=lambda label: job.events.put(
                    {"type": "scanning", "label": label}),
                on_result=on_result,
                should_stop=job.cancel.is_set,
            )
            job.secrets = {r.label: r.secret for r in run.results if r.secret}
            job.payload = run.to_dict()
        elif job.kind == "username":
            progress("Site sweep", "start")
            hits = username_src.check_username(job.subject, state.config,
                                               should_stop=job.cancel.is_set)
            progress("Site sweep", "ok")
            job.payload = {
                "subject": job.subject,
                "kind": "username",
                "sections": {"sites": [h.to_dict() for h in hits],
                             "risk": scoring.assess_username(hits).to_dict()},
                "timeline": [],
                "notes": [],
            }
        else:
            raise SourceError(f"unknown scan kind: {job.kind}")
    except SourceError as exc:
        job.error = str(exc)
    except Exception as exc:  # noqa: BLE001 - surface it in the UI, don't crash
        job.error = f"unexpected error: {exc}"
    finally:
        if job.payload is not None and state.config.history_enabled:
            if job.cancel.is_set():
                job.payload.setdefault("notes", []).append("stopped early")
            # The payload kind is the precise one ("bulk-password"), which is
            # what keeps password runs out of the history table.
            storage.record_scan(job.subject,
                                str(job.payload.get("kind", job.kind)), job.payload)
        if job.payload is not None and state.config.active_webhooks:
            # Enabled webhooks receive every finished scan, same as the CLI.
            try:
                embed = _embed_for(job.payload, job.secrets)
                if embed is not None:
                    for url, error in notify.send(state.config, embed, job.payload):
                        if error:
                            job.notify_errors.append(f"{notify.redact(url)}: {error}")
                        else:
                            job.sent += 1
            except Exception:  # noqa: BLE001 - delivery must not fail the scan
                pass
        job.events.put({"type": "done"})
        job.done.set()


def _finished_job(state: State, payload: dict[str, Any]) -> str:
    """Park a stored payload in the job table so the export routes can find it."""
    job_id, job = state.new_job(str(payload.get("kind", "result")),
                                str(payload.get("subject", "?")))
    job.payload = payload
    job.done.set()
    return job_id


def _password_payload(value: str, exposure) -> dict[str, Any]:
    """A password check in the same shape as every other result.

    The password is the subject, so the history entry, the report and its
    filename all name it. Anything less means going back to the breach site to
    work out which password the verdict was about.
    """
    count = getattr(exposure, "count", 0)
    score = scoring.password_score(count)
    return {
        "subject": value,
        "kind": "password",
        "sections": {
            "password": exposure.to_dict(),
            "risk": {"score": score, "label": scoring.label_for(score),
                     "factors": [], "actions": []},
        },
        "timeline": [],
        "notes": [],
    }


def _embed_for(payload: dict[str, Any],
               secrets: dict[str, str] | None = None) -> dict | None:
    """Pick the embed for a payload, or None when there is nothing to send."""
    kind = str(payload.get("kind", ""))
    if kind.startswith("bulk-"):
        return notify.bulk_embed(_BulkView(payload, secrets))
    if kind == "watch":
        found = {r["subject"]: r["new"]
                 for r in (payload.get("sections") or {}).get("watch", [])
                 if r.get("new")}
        # Nothing new is the normal case; staying silent is the whole point.
        return notify.watch_embed(found) if found else None
    return notify.profile_embed(payload)


class _BulkView:
    """Adapts a serialised bulk payload back to what bulk_embed expects."""

    def __init__(self, payload: dict[str, Any],
                 secrets: dict[str, str] | None = None):
        rows = (payload.get("sections") or {}).get("bulk") or []
        self.secrets = secrets or {}
        self.kind = str(payload.get("kind", "bulk-")).removeprefix("bulk-")
        self.notes = payload.get("notes") or []
        self.results = [_BulkRow(r, self.secrets) for r in rows]

    @property
    def exposed(self):
        return [r for r in self.results if r.exposed]


class _BulkRow:
    def __init__(self, row: dict[str, Any], secrets: dict[str, str] | None = None):
        self.label = row.get("label", "")
        self.secret = (secrets or {}).get(self.label)
        self.score = int(row.get("score", 0) or 0)
        self.risk = row.get("risk", "")
        self.detail = row.get("detail", "")
        self.exposed = bool(row.get("exposed"))
        self.error = row.get("error")


class Handler(BaseHTTPRequestHandler):
    server_version = f"footprint/{__version__}"
    state: State  # injected by serve()

    # --- plumbing
    def log_message(self, fmt, *args):  # noqa: A002 - silence stdlib access logs
        pass

    def _send(self, code: int, body: bytes, ctype: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Nothing here loads remotely, so a stray injection cannot phone home.
        self.send_header("Content-Security-Policy",
                         "default-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, default=str).encode(), "application/json")

    def _local_host(self) -> bool:
        """Reject a Host we did not hand out, which is how DNS rebinding gets in."""
        host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]")
        return host in ("127.0.0.1", "localhost", "::1", "")

    def _authorized(self, params: dict) -> bool:
        supplied = (params.get("token") or [""])[0]
        header = self.headers.get("X-Footprint-Token", "")
        return secrets.compare_digest(supplied or header, self.state.token)

    def _read_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length > MAX_BODY:
            # The body is still on the socket, so this connection is finished.
            self.close_connection = True
            return {}
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, ValueError):
            return {}

    # --- GET
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if not self._local_host():
            self._json(403, {"error": "bad host"})
            return
        parts = urlsplit(self.path)
        params = parse_qs(parts.query)
        route = parts.path

        if route == "/":
            try:
                html = _INDEX.read_text(encoding="utf-8")
            except OSError:
                self._send(500, b"index.html missing", "text/plain")
                return
            html = html.replace("__TOKEN__", self.state.token)
            html = html.replace("__VERSION__", __version__)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return

        if not self._authorized(params):
            self._json(403, {"error": "bad token"})
            return

        if route == "/api/settings":
            self._json(200, self._settings_payload())
            return

        if route == "/api/watch":
            self._json(200, {"items": [{"subject": s, "kind": k}
                                       for s, k in storage.watchlist()]})
            return

        if route == "/api/history":
            self._json(200, {"items": storage.history()})
            return

        if route == "/api/events":
            self._stream(params)
            return

        if route == "/api/report":
            self._report(params)
            return

        self._json(404, {"error": "not found"})

    # --- POST
    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if not self._local_host():
            self._json(403, {"error": "bad host"})
            return
        parts = urlsplit(self.path)
        params = parse_qs(parts.query)
        if not self._authorized(params):
            self._json(403, {"error": "bad token"})
            return

        body = self._read_body()
        route = parts.path

        if route == "/api/scan":
            kind = str(body.get("kind", "email"))
            subject = str(body.get("subject", "")).strip()
            subjects = [str(x) for x in (body.get("subjects") or [])]
            if kind == "bulk":
                if not any(x.strip() for x in subjects):
                    self._json(400, {"error": "no subjects given"})
                    return
            elif kind == "watch":
                pass  # the subjects come from the stored watchlist
            elif not subject:
                self._json(400, {"error": "no subject given"})
                return
            job_id, job = self.state.new_job(
                kind, subject, subjects=subjects,
                bulk_kind=str(body.get("bulk_kind", "auto")),
            )
            threading.Thread(target=_run_scan, args=(self.state, job),
                             daemon=True).start()
            self._json(200, {"job": job_id})
            return

        if route == "/api/password":
            value = str(body.get("value", ""))
            if not value:
                self._json(400, {"error": "no password given"})
                return
            try:
                exposure = pwned_passwords.check_password(value, self.state.config)
            except SourceError as exc:
                self._json(502, {"error": str(exc)})
                return

            config = self.state.config
            payload = _password_payload(value, exposure)
            job_id = _finished_job(self.state, payload)
            if config.history_enabled:
                storage.record_scan(payload["subject"], "password", payload)

            # Same as the CLI: the webhook carries the password itself, because
            # a verdict you cannot match to a password is not much use.
            sent = 0
            if config.active_webhooks:
                embed = notify.password_embed(exposure, value)
                sent = sum(1 for _, err in notify.send(config, embed, attach=False)
                           if err is None)
            self._json(200, {**exposure.to_dict(), "job": job_id, "sent": sent})
            return

        if route == "/api/history":
            if body.get("clear"):
                storage.clear_history()
                self._json(200, {"items": []})
                return
            payload = storage.history_payload(int(body.get("open") or 0))
            if payload is None:
                self._json(404, {"error": "no such scan"})
                return
            self._json(200, {"job": _finished_job(self.state, payload),
                             "payload": payload})
            return

        if route == "/api/stop":
            job = self.state.jobs.get(str(body.get("job", "")))
            if job is None:
                self._json(404, {"error": "no such job"})
                return
            job.cancel.set()
            self._json(200, {"stopping": True})
            return

        if route == "/api/settings":
            self._save_settings(body)
            return

        if route == "/api/notify":
            self._notify(body)
            return

        if route == "/api/watch":
            subject = str(body.get("subject", "")).strip()
            if not subject:
                self._json(400, {"error": "no subject given"})
                return
            if body.get("action") == "remove":
                storage.remove_from_watchlist(subject)
            else:
                kind = "domain" if body.get("kind") == "domain" else "email"
                storage.add_to_watchlist(subject, kind)
            self._json(200, {"items": [{"subject": s, "kind": k}
                                       for s, k in storage.watchlist()]})
            return

        self._json(404, {"error": "not found"})

    # --- handlers
    def _settings_payload(self) -> dict:
        c = self.state.config

        def mask(v: str | None) -> str:
            if not v:
                return ""
            return v[:4] + "…" + v[-2:] if len(v) > 6 else "set"

        return {
            "hibp": mask(c.hibp_api_key),
            "dehashed_email": c.dehashed_email or "",
            "dehashed": mask(c.dehashed_api_key),
            "intelx": mask(c.intelx_api_key),
            "hunter": mask(c.hunter_api_key),
            "emailrep": mask(c.emailrep_api_key),
            "cache": c.cache_enabled,
            "holehe": holehe_scan.available(),
            "profile": c.profile,
            "webhooks": [
                {"url": notify.redact(w.url), "enabled": w.enabled,
                 "discord": notify.is_discord(w.url)}
                for w in c.webhooks
            ],
            "webhook_count": len(c.active_webhooks),
        }

    def _save_settings(self, body: dict) -> None:
        c = self.state.config
        # Blank means "leave alone", so the masked display cannot wipe a key.
        for field_name, attr in (
            ("hibp", "hibp_api_key"),
            ("dehashed_email", "dehashed_email"),
            ("dehashed", "dehashed_api_key"),
            ("intelx", "intelx_api_key"),
            ("hunter", "hunter_api_key"),
            ("emailrep", "emailrep_api_key"),
        ):
            value = str(body.get(field_name, "")).strip()
            if value and "…" not in value:
                setattr(c, attr, value)
        if "cache" in body:
            c.cache_enabled = bool(body["cache"])
        if "webhook_states" in body:
            # {index: enabled} from the settings checkboxes.
            for key, enabled in (body.get("webhook_states") or {}).items():
                try:
                    c.webhooks[int(key)].enabled = bool(enabled)
                except (ValueError, IndexError):
                    continue
        if "add_webhooks" in body:
            # New URLs only. Redacted display values can never come back here,
            # so an existing hook cannot be clobbered by its own mask.
            existing = {w.url for w in c.webhooks}
            for raw_url in (body.get("add_webhooks") or []):
                url = str(raw_url).strip()
                if (url.startswith(("http://", "https://"))
                        and "…" not in url and url not in existing):
                    c.webhooks.append(Webhook(url=url))
                    existing.add(url)
        if "remove_webhooks" in body:
            drop = {int(i) for i in (body.get("remove_webhooks") or [])
                    if str(i).isdigit()}
            c.webhooks = [w for i, w in enumerate(c.webhooks) if i not in drop]
        try:
            path = c.save_profile()
        except OSError as exc:
            self._json(500, {"error": str(exc)})
            return
        self._json(200, {"saved": str(path), "settings": self._settings_payload()})

    def _notify(self, body: dict) -> None:
        """Push a finished scan (or a test message) to the webhooks."""
        config = self.state.config
        if not config.active_webhooks:
            self._json(400, {"error": "no enabled webhooks"})
            return

        if body.get("test"):
            embed, raw = notify.test_embed(), None
        else:
            job = self.state.jobs.get(str(body.get("job", "")))
            if job is None or job.payload is None:
                self._json(404, {"error": "no finished scan with that id"})
                return
            embed, raw = _embed_for(job.payload, job.secrets), job.payload
            if embed is None:
                self._json(200, {"sent": 0, "errors": ["nothing new to send"]})
                return

        sent, errors = 0, []
        for url, error in notify.send(config, embed, raw):
            if error:
                errors.append(f"{notify.redact(url)}: {error}")
            else:
                sent += 1
        self._json(200, {"sent": sent, "errors": errors})

    def _stream(self, params: dict) -> None:
        """Server-Sent Events: progress lines, then the finished payload."""
        job_id = (params.get("job") or [""])[0]
        job = self.state.jobs.get(job_id)
        if job is None:
            self._json(404, {"error": "no such job"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def emit(event: dict) -> bool:
            try:
                self.wfile.write(f"data: {json.dumps(event, default=str)}\n\n".encode())
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionError, OSError):
                return False  # the tab went away

        while True:
            try:
                event = job.events.get(timeout=30)
            except queue.Empty:
                # Keeps proxies and the browser from timing out.
                if not emit({"type": "ping"}):
                    return
                continue
            if event.get("type") == "done":
                emit({"type": "result", "payload": job.payload, "error": job.error,
                      "sent": job.sent, "errors": job.notify_errors})
                return
            if not emit(event):
                return

    def _report(self, params: dict) -> None:
        job_id = (params.get("job") or [""])[0]
        job = self.state.jobs.get(job_id)
        if job is None or job.payload is None:
            self._json(404, {"error": "no finished scan with that id"})
            return

        as_json = (params.get("format") or [""])[0] == "json"
        try:
            if as_json:
                data = json.dumps(job.payload, indent=2, default=str).encode("utf-8")
            else:
                data = reports.render(job.payload).encode("utf-8")
        except (ValueError, TypeError) as exc:
            self._json(500, {"error": str(exc)})
            return

        ext = "json" if as_json else "html"
        name = f"footprint-{job.subject}.{ext}".replace("@", "_at_")
        # A bulk subject is "2 email(s)", so strip anything awkward in a filename.
        name = "".join(c if c.isalnum() or c in "-_." else "-" for c in name)
        ctype = "application/json" if as_json else "text/html; charset=utf-8"
        self._send(200, data, ctype,
                   {"Content-Disposition": f'attachment; filename="{name}"'})


def serve(config: Config, *, port: int = 8731, open_browser: bool = True) -> int:
    """Run the GUI until interrupted. Returns a process exit code."""
    state = State(config)
    handler = type("BoundHandler", (Handler,), {"state": state})

    httpd = None
    for candidate in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", candidate), handler)
            port = candidate
            break
        except OSError:
            continue
    if httpd is None:
        print(f"could not bind a port in {port}-{port + 19}")
        return 2

    url = f"http://127.0.0.1:{port}/"
    # Plain ASCII: the legacy Windows console is cp1252 and raises otherwise.
    print(f"footprint GUI running at {url}")
    print("  bound to loopback only; press Ctrl-C to stop.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
