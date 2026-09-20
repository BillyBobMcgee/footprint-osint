"""The GUI server is stdlib-only, so these drive it over a real loopback socket."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
import responses

from footprint import storage
from footprint.config import Config, Webhook
from footprint.gui.server import Handler, State


@pytest.fixture()
def server():
    state = State(Config())
    handler = type("Bound", (Handler,), {"state": state})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    # The default 0.5s poll would make every teardown wait that long.
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base, state
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - loopback
        return resp.status, resp.read().decode()


def _post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - loopback
        return resp.status, json.loads(resp.read())


def test_index_is_served_with_the_token_substituted(server):
    base, state = server
    status, body = _get(base + "/")

    assert status == 200
    assert "__TOKEN__" not in body
    assert state.token in body
    assert "<title>footprint</title>" in body


def test_api_rejects_a_missing_token(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(base + "/api/settings")
    assert exc.value.code == 403


def test_api_rejects_a_wrong_token(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(base + "/api/settings?token=nope")
    assert exc.value.code == 403


def test_settings_round_trip_masks_keys(server, tmp_path, monkeypatch):
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server

    status, saved = _post(f"{base}/api/settings?token={state.token}",
                          {"hibp": "abcdef123456"})
    assert status == 200
    assert state.config.hibp_api_key == "abcdef123456"
    # The value never comes back in full.
    assert "abcdef123456" not in json.dumps(saved["settings"])
    assert saved["settings"]["hibp"].startswith("abcd")


def test_blank_setting_does_not_wipe_an_existing_key(server, tmp_path, monkeypatch):
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server
    state.config.hibp_api_key = "keepme12345"

    _post(f"{base}/api/settings?token={state.token}", {"hibp": ""})
    assert state.config.hibp_api_key == "keepme12345"


def test_masked_value_is_not_written_back_as_a_key(server, tmp_path, monkeypatch):
    """Posting the masked display string must not overwrite the real key."""
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server
    state.config.hibp_api_key = "realkey12345"

    _post(f"{base}/api/settings?token={state.token}", {"hibp": "real…45"})
    assert state.config.hibp_api_key == "realkey12345"


def test_scan_requires_a_subject(server):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/scan?token={state.token}", {"kind": "email", "subject": " "})
    assert exc.value.code == 400


def test_report_for_an_unknown_job_is_404(server):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{base}/api/report?job=nope&fmt=html&token={state.token}")
    assert exc.value.code == 404


def test_unknown_route_is_404(server):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{base}/api/nothing?token={state.token}")
    assert exc.value.code == 404


def test_each_state_gets_a_distinct_token():
    assert State(Config()).token != State(Config()).token


# --- webhooks

DISCORD = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOp"


def test_settings_reports_webhooks_redacted(server, tmp_path, monkeypatch):
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server

    _post(f"{base}/api/settings?token={state.token}", {"add_webhooks": [DISCORD]})
    assert [w.url for w in state.config.webhooks] == [DISCORD]

    _, body = _get(f"{base}/api/settings?token={state.token}")
    assert DISCORD not in body            # never returned in full
    assert '"webhook_count": 1' in body
    assert '"enabled": true' in body


def test_webhook_can_be_toggled_off_from_settings(server, tmp_path, monkeypatch):
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server
    _post(f"{base}/api/settings?token={state.token}", {"add_webhooks": [DISCORD]})

    _post(f"{base}/api/settings?token={state.token}", {"webhook_states": {"0": False}})

    assert state.config.webhooks[0].enabled is False
    assert state.config.active_webhooks == []


def test_disabled_webhook_is_not_counted_as_active(server, tmp_path, monkeypatch):
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server
    _post(f"{base}/api/settings?token={state.token}", {"add_webhooks": [DISCORD]})
    _post(f"{base}/api/settings?token={state.token}", {"webhook_states": {"0": False}})

    _, body = _get(f"{base}/api/settings?token={state.token}")
    assert '"webhook_count": 0' in body   # count reflects enabled, not total


def test_adding_a_duplicate_webhook_is_ignored(server, tmp_path, monkeypatch):
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server
    _post(f"{base}/api/settings?token={state.token}", {"add_webhooks": [DISCORD]})
    _post(f"{base}/api/settings?token={state.token}", {"add_webhooks": [DISCORD]})
    assert len(state.config.webhooks) == 1


def test_redacted_webhook_is_not_saved_back_as_a_url(server, tmp_path, monkeypatch):
    """Re-saving the settings dialog must not add a hook from its own mask."""
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server
    state.config.webhooks = [Webhook(url=DISCORD)]

    _post(f"{base}/api/settings?token={state.token}",
          {"add_webhooks": ["https://discord.com/api/webhooks/12345678…MnOp"]})

    assert [w.url for w in state.config.webhooks] == [DISCORD]


def test_webhooks_can_be_removed_by_index(server, tmp_path, monkeypatch):
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    base, state = server
    state.config.webhooks = [Webhook(url=DISCORD),
                             Webhook(url="https://example.com/a")]

    _post(f"{base}/api/settings?token={state.token}", {"remove_webhooks": [0]})

    assert [w.url for w in state.config.webhooks] == ["https://example.com/a"]


def test_notify_without_webhooks_is_a_400(server):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/notify?token={state.token}", {"test": True})
    assert exc.value.code == 400


def test_notify_for_an_unknown_job_is_a_404(server):
    base, state = server
    state.config.webhooks = [Webhook(url=DISCORD)]
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/notify?token={state.token}", {"job": "nope"})
    assert exc.value.code == 404


def test_notify_requires_the_token(server):
    base, state = server
    state.config.webhooks = [Webhook(url=DISCORD)]
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/notify", {"test": True})
    assert exc.value.code == 403


# --- bulk

def test_bulk_scan_requires_subjects(server):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/scan?token={state.token}",
              {"kind": "bulk", "subject": "", "subjects": ["  ", ""]})
    assert exc.value.code == 400


def test_bulk_job_carries_its_subjects(server):
    """Built directly: POSTing /api/scan would start a real scan thread."""
    _, state = server
    _, job = state.new_job("bulk", "", subjects=["a", "b"], bulk_kind="password")
    assert job.subjects == ["a", "b"]
    assert job.bulk_kind == "password"


def test_bulk_report_filename_is_sanitised():
    """A bulk subject is "2 email(s)", which must not reach a filename raw."""
    subject = "2 email(s)"
    name = f"footprint-{subject}.html".replace("@", "_at_")
    name = "".join(c if c.isalnum() or c in "-_." else "-" for c in name)
    assert " " not in name and "(" not in name
    assert name.endswith(".html")


# --- watch

@pytest.fixture()
def watchdir(tmp_path, monkeypatch):
    """Isolate the watch database from the user's real one."""
    monkeypatch.setattr("footprint.storage.config_dir", lambda: tmp_path)
    return tmp_path


def test_watch_list_add_and_remove(server, watchdir):
    base, state = server

    _, empty = _get(f"{base}/api/watch?token={state.token}")
    assert '"items": []' in empty

    _, body = _post(f"{base}/api/watch?token={state.token}",
                    {"subject": "me@example.com"})
    assert body["items"] == [{"subject": "me@example.com", "kind": "email"}]

    _, body = _post(f"{base}/api/watch?token={state.token}",
                    {"subject": "example.com", "kind": "domain"})
    assert {"subject": "example.com", "kind": "domain"} in body["items"]

    _, body = _post(f"{base}/api/watch?token={state.token}",
                    {"action": "remove", "subject": "me@example.com"})
    assert [i["subject"] for i in body["items"]] == ["example.com"]


def test_watch_add_requires_a_subject(server, watchdir):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/watch?token={state.token}", {"subject": "   "})
    assert exc.value.code == 400


def test_watch_kind_defaults_to_email(server, watchdir):
    base, state = server
    _, body = _post(f"{base}/api/watch?token={state.token}",
                    {"subject": "x@example.com", "kind": "nonsense"})
    assert body["items"][0]["kind"] == "email"


def test_watch_endpoints_need_the_token(server, watchdir):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"{base}/api/watch")
    assert exc.value.code == 403


def test_watch_check_on_an_empty_list_errors(server, watchdir):
    from footprint.gui.server import _run_scan

    _, job = server[1].new_job("watch", "")
    _run_scan(server[1], job)
    assert job.payload is None
    assert "empty" in job.error


def test_watch_embed_is_skipped_when_nothing_is_new():
    """A quiet check must not post 'nothing happened' to Discord."""
    from footprint.gui.server import _embed_for

    quiet = {"kind": "watch", "sections": {"watch": [
        {"subject": "a@example.com", "kind": "email", "new": []}]}}
    noisy = {"kind": "watch", "sections": {"watch": [
        {"subject": "a@example.com", "kind": "email", "new": ["breach: Adobe"]}]}}

    assert _embed_for(quiet) is None
    assert "Adobe" in json.dumps(_embed_for(noisy))


def test_a_foreign_host_header_is_rejected(server):
    """Loopback binding alone does not stop DNS rebinding."""
    base, state = server
    req = urllib.request.Request(base + "/", headers={"Host": "evil.example"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)  # noqa: S310 - loopback
    assert exc.value.code == 403


def test_username_scan_carries_an_exposure_score(server, monkeypatch):
    """The CLI scores a handle; the GUI must show the same thing."""
    from footprint.gui.server import _run_scan
    from footprint.models import SiteHit

    monkeypatch.setattr(
        "footprint.sources.username.check_username",
        lambda handle, config, **kw: [
            SiteHit(site="GitHub", url="https://github.com/x", exists=True),
            SiteHit(site="Reddit", url="https://reddit.com/u/x", exists=False),
        ],
    )
    state = server[1]
    _, job = state.new_job("username", "somehandle")
    _run_scan(state, job)

    risk = job.payload["sections"]["risk"]
    assert risk["score"] > 0
    assert risk["actions"]


# --- scan history

def _mock_range(password):
    """Stand in for the Pwned Passwords range endpoint."""
    import hashlib

    from footprint.sources.pwned_passwords import RANGE_URL

    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    responses.add(responses.GET, RANGE_URL.format(prefix=digest[:5]),
                  body=f"{digest[5:]}:282591", status=200)


def _payload(subject="a@x.com", kind="email", score=40):
    return {"subject": subject, "kind": kind, "timeline": [], "notes": [],
            "sections": {"risk": {"score": score, "label": "Moderate",
                                  "factors": [], "actions": []}}}


def test_history_starts_empty_and_records_a_scan(server):
    base, state = server
    status, body = _get(f"{base}/api/history?token={state.token}")
    assert status == 200 and json.loads(body)["items"] == []

    storage.record_scan("a@x.com", "email", _payload())
    items = json.loads(_get(f"{base}/api/history?token={state.token}")[1])["items"]
    assert [i["subject"] for i in items] == ["a@x.com"]
    assert items[0]["score"] == 40


def test_a_history_entry_reopens_as_a_finished_job(server):
    """Reopening has to give back a job id, or export and webhooks break."""
    base, state = server
    entry = storage.record_scan("a@x.com", "email", _payload())

    _, data = _post(f"{base}/api/history?token={state.token}", {"open": entry})

    assert data["payload"]["subject"] == "a@x.com"
    assert state.jobs[data["job"]].payload == data["payload"]


def test_history_can_be_cleared(server):
    base, state = server
    storage.record_scan("a@x.com", "email", _payload())

    _, data = _post(f"{base}/api/history?token={state.token}", {"clear": True})

    assert data["items"] == []
    assert storage.history() == []


def test_opening_an_unknown_history_entry_is_404(server):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/history?token={state.token}", {"open": 999})
    assert exc.value.code == 404


@responses.activate
def test_a_password_check_is_recorded_under_the_password(server):
    """Recent has to name it, or you cannot tell which verdict is which."""
    _mock_range("hunter2")
    base, state = server

    _, data = _post(f"{base}/api/password?token={state.token}", {"value": "hunter2"})

    assert data["exposed"] is True
    entry = storage.history()[0]
    assert entry["kind"] == "password"
    assert entry["subject"] == "hunter2"


@responses.activate
def test_a_password_check_goes_to_the_webhook_with_the_password(server, tmp_path):
    """The verdict is useless if you cannot tell which password it is about."""
    _mock_range("hunter2")
    base, state = server
    state.config.webhooks = [Webhook(url="https://example.com/hook")]
    responses.add(responses.POST, "https://example.com/hook", status=200)

    _, data = _post(f"{base}/api/password?token={state.token}", {"value": "hunter2"})

    assert data["sent"] == 1
    body = json.loads(responses.calls[-1].request.body)
    assert "hunter2" in json.dumps(body)


def test_a_bulk_password_row_names_the_password_not_the_line(server):
    from footprint.gui.server import _embed_for

    payload = {"subject": "1 password(s)", "kind": "bulk-password", "notes": [],
               "timeline": [], "sections": {"bulk": [
                   {"label": "line 1", "score": 95, "risk": "Critical",
                    "exposed": True, "detail": "seen 282,591x", "error": None}]}}

    named = _embed_for(payload, {"line 1": "hunter2"})
    anonymous = _embed_for(payload, None)

    assert "hunter2" in json.dumps(named)
    assert "line 1" in json.dumps(anonymous)


def test_the_secret_never_reaches_the_bulk_payload():
    """to_dict() is what becomes a report, an export, and a history row."""
    from footprint.bulk import BulkResult, BulkRun

    run = BulkRun(kind="password")
    run.results.append(BulkResult(label="line 1", kind="password", secret="hunter2"))

    assert "hunter2" not in json.dumps(run.to_dict())


# --- stopping and exporting

def test_stop_sets_the_cancel_flag(server):
    base, state = server
    job_id, job = state.new_job("username", "somehandle")

    _, data = _post(f"{base}/api/stop?token={state.token}", {"job": job_id})

    assert data["stopping"] is True
    assert job.cancel.is_set()


def test_stopping_an_unknown_job_is_404(server):
    base, state = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{base}/api/stop?token={state.token}", {"job": "nope"})
    assert exc.value.code == 404


def test_report_can_be_downloaded_as_json(server):
    base, state = server
    job_id, job = state.new_job("email", "a@x.com")
    job.payload = _payload()

    status, body = _get(f"{base}/api/report?format=json&job={job_id}&token={state.token}")

    assert status == 200
    assert json.loads(body)["sections"]["risk"]["score"] == 40


def test_settings_say_whether_holehe_is_installed(server):
    base, state = server
    body = json.loads(_get(f"{base}/api/settings?token={state.token}")[1])
    assert isinstance(body["holehe"], bool)


def _stub_sweep(monkeypatch):
    from footprint.models import SiteHit
    monkeypatch.setattr(
        "footprint.sources.username.check_username",
        lambda handle, config, **kw: [
            SiteHit(site="GitHub", url="https://github.com/x", exists=True),
        ],
    )


def test_a_finished_scan_is_recorded(server, monkeypatch):
    from footprint.gui.server import _run_scan

    _stub_sweep(monkeypatch)
    state = server[1]
    _, job = state.new_job("username", "somehandle")
    _run_scan(state, job)

    assert [h["subject"] for h in storage.history()] == ["somehandle"]


def test_nothing_is_recorded_when_history_is_switched_off(server, monkeypatch):
    from footprint.gui.server import _run_scan

    _stub_sweep(monkeypatch)
    state = server[1]
    state.config.history_enabled = False
    _, job = state.new_job("username", "somehandle")
    _run_scan(state, job)

    assert job.payload is not None
    assert storage.history() == []


def test_a_stopped_scan_says_so_in_its_notes(server, monkeypatch):
    from footprint.gui.server import _run_scan

    _stub_sweep(monkeypatch)
    state = server[1]
    _, job = state.new_job("username", "somehandle")
    job.cancel.set()
    _run_scan(state, job)

    assert "stopped early" in job.payload["notes"]


@responses.activate
def test_a_finished_scan_reports_how_delivery_went(server, monkeypatch):
    """Every kind of result shows it, not just the password check."""
    from footprint.gui.server import _run_scan

    _stub_sweep(monkeypatch)
    responses.add(responses.POST, "https://example.com/hook", status=200)
    responses.add(responses.POST, "https://example.com/dead", status=500)
    state = server[1]
    state.config.webhooks = [Webhook(url="https://example.com/hook"),
                             Webhook(url="https://example.com/dead")]
    _, job = state.new_job("username", "somehandle")

    _run_scan(state, job)

    assert job.sent == 1
    assert len(job.notify_errors) == 1
    assert "500" in job.notify_errors[0]
    # The URL is a secret even in an error message.
    assert "example.com/dead" not in job.notify_errors[0]
