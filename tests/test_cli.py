import hashlib
import json

import responses

from footprint import storage
from footprint.cli import EXIT_FOUND, EXIT_OK, main
from footprint.sources.pwned_passwords import RANGE_URL


def _range_for(password: str):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    return digest[:5], digest[5:]


@responses.activate
def test_password_command_exit_found(capsys):
    prefix, suffix = _range_for("password")
    responses.add(responses.GET, RANGE_URL.format(prefix=prefix), body=f"{suffix}:5\n")

    code = main(["password", "password"])

    assert code == EXIT_FOUND
    assert "COMPROMISED" in capsys.readouterr().out


@responses.activate
def test_password_command_json(capsys):
    prefix, suffix = _range_for("password")
    responses.add(responses.GET, RANGE_URL.format(prefix=prefix), body=f"{suffix}:5\n")

    code = main(["password", "password", "--json"])

    out = capsys.readouterr().out
    assert code == EXIT_FOUND
    assert '"exposed": true' in out


@responses.activate
def test_password_command_clean_exit_ok():
    prefix, _ = _range_for("truly-unique-passphrase-42")
    responses.add(responses.GET, RANGE_URL.format(prefix=prefix), body="DEAD:1\n")

    assert main(["password", "truly-unique-passphrase-42"]) == EXIT_OK


def test_a_failed_scan_still_honours_json(monkeypatch, capsys):
    """A script asked for JSON; handing it a table on failure breaks the caller."""
    from footprint import aggregate
    from footprint.cli import EXIT_SOURCE_ERROR

    def dead(subject, config, **kw):
        p = aggregate.Profile(subject=subject, kind="email")
        p.failed = "could not reach any source. Not a clean result."
        return p

    monkeypatch.setattr("footprint.aggregate.email_profile", dead)

    code = main(["email", "a@example.com", "--json"])

    assert code == EXIT_SOURCE_ERROR
    assert json.loads(capsys.readouterr().out)["failed"]


# --- scan history

def _record(subject="you@example.com", kind="email", score=78, label="High"):
    return storage.record_scan(subject, kind, {
        "subject": subject, "kind": kind,
        "sections": {"risk": {"score": score, "label": label}}})


def test_history_lists_what_was_recorded(capsys):
    _record()
    assert main(["history"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "you@example.com" in out and "78" in out


def test_history_is_empty_before_anything_runs(capsys):
    assert main(["history"]) == EXIT_OK
    assert "nothing recorded" in capsys.readouterr().out


def test_history_clear_empties_the_table(capsys):
    _record()
    assert main(["history", "clear"]) == EXIT_OK
    assert "cleared 1 scan" in capsys.readouterr().out
    assert storage.history() == []


def test_history_off_is_saved_and_stops_the_gui_recording(capsys):
    """The GUI is what writes entries, so the switch has to reach its config."""
    from footprint.config import Config

    assert main(["history", "off"]) == EXIT_OK
    assert Config.resolve().history_enabled is False

    assert main(["history", "on"]) == EXIT_OK
    assert Config.resolve().history_enabled is True


def test_history_says_when_recording_is_off(capsys):
    _record()
    main(["history", "off"])
    capsys.readouterr()
    main(["history"])
    assert "recording is off" in capsys.readouterr().out


def test_history_json_carries_the_recording_state(capsys):
    _record()
    assert main(["history", "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["recording"] is True
    assert data["history"][0]["subject"] == "you@example.com"
