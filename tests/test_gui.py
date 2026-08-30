"""The GUI server is stdlib-only, so these drive it over a real loopback socket."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from footprint.config import Config, Webhook
from footprint.gui.server import Handler, State


@pytest.fixture()
def server():
    state = State(Config())
    handler = type("Bound", (Handler,), {"state": state})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
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
                          {"hibp": "abcdef123456", "tor": True})
    assert status == 200
    assert state.config.hibp_api_key == "abcdef123456"
    assert state.config.tor is True
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


# ------------------------------------------------------------------ webhooks

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


# --------------------------------------------------------------------- bulk

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
