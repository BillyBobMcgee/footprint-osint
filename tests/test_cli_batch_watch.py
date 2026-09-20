import json

import pytest
import responses

from footprint import aggregate, storage
from footprint.cli import EXIT_FOUND, EXIT_OK, EXIT_USAGE, main
from footprint.models import Breach


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Keep the watch database out of the user's real config directory.

    storage.py does ``from footprint.config import config_dir``, so it holds its
    own reference. Patching ``footprint.config.config_dir`` alone would leave
    these tests reading and writing the real watchlist.
    """
    monkeypatch.setattr("footprint.storage.config_dir", lambda: tmp_path)
    monkeypatch.setattr("footprint.config.config_dir", lambda: tmp_path)
    yield


def _profile(subject, breaches=()):
    p = aggregate.Profile(subject=subject, kind="email")
    if breaches:
        p.sections["breaches"] = list(breaches)
    from footprint import scoring
    p.sections["risk"] = scoring.assess_email(p.sections)
    return p


def _breach(name="adobe", when="2013-10-04"):
    return Breach(name=name, title=name.title(), domain=f"{name}.com",
                  breach_date=when, added_date=None, pwn_count=100,
                  data_classes=["Passwords"])


def _stub_profiles(monkeypatch, mapping):
    monkeypatch.setattr(
        "footprint.aggregate.email_profile",
        lambda subject, config, **kw: _profile(subject, mapping.get(subject, ())),
    )


# --- batch

def test_batch_reports_each_address_and_exits_found(tmp_path, monkeypatch, capsys):
    _stub_profiles(monkeypatch, {"dirty@example.com": [_breach()]})
    listing = tmp_path / "emails.txt"
    listing.write_text("clean@example.com\ndirty@example.com\n", encoding="utf-8")

    code = main(["batch", str(listing)])

    out = capsys.readouterr().out
    assert code == EXIT_FOUND
    assert "clean@example.com" in out
    assert "dirty@example.com" in out


def test_batch_exits_ok_when_everything_is_clean(tmp_path, monkeypatch):
    _stub_profiles(monkeypatch, {})
    listing = tmp_path / "emails.txt"
    listing.write_text("clean@example.com\n", encoding="utf-8")

    assert main(["batch", str(listing)]) == EXIT_OK


def test_batch_skips_blank_lines_and_comments(tmp_path, monkeypatch, capsys):
    _stub_profiles(monkeypatch, {})
    listing = tmp_path / "emails.txt"
    listing.write_text("# a comment\n\nonly@example.com\n", encoding="utf-8")

    main(["batch", str(listing)])

    out = capsys.readouterr().out
    assert "only@example.com" in out
    assert "a comment" not in out


def test_batch_writes_one_report_per_subject(tmp_path, monkeypatch):
    _stub_profiles(monkeypatch, {"a@example.com": [_breach()]})
    listing = tmp_path / "emails.txt"
    listing.write_text("a@example.com\n", encoding="utf-8")
    out_dir = tmp_path / "reports"

    main(["batch", str(listing), "--save", "--out-dir", str(out_dir)])

    written = list(out_dir.glob("*.html"))
    assert len(written) == 1
    # The @ is replaced so the filename is portable.
    assert "_at_" in written[0].name
    assert "footprint report" in written[0].read_text(encoding="utf-8")


def test_batch_missing_file_is_a_usage_error(tmp_path):
    assert main(["batch", str(tmp_path / "nope.txt")]) == EXIT_USAGE


def test_batch_empty_file_is_a_usage_error(tmp_path):
    listing = tmp_path / "empty.txt"
    listing.write_text("\n\n", encoding="utf-8")
    assert main(["batch", str(listing)]) == EXIT_USAGE


# --- watch

def test_watch_add_list_remove(capsys):
    main(["watch", "add", "me@example.com"])
    main(["watch", "list"])
    assert "me@example.com" in capsys.readouterr().out

    main(["watch", "remove", "me@example.com"])
    main(["watch", "list"])
    assert "watchlist is empty" in capsys.readouterr().out


def test_watch_check_on_an_empty_list_is_a_usage_error():
    assert main(["watch", "check"]) == EXIT_USAGE


def test_watch_check_reports_new_findings_once(monkeypatch, capsys):
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["watch", "add", "me@example.com"])

    first = main(["watch", "check"])
    out = capsys.readouterr().out
    assert first == EXIT_FOUND
    assert "NEW exposure" in out

    # The same finding must not alert a second time.
    second = main(["watch", "check"])
    out = capsys.readouterr().out
    assert second == EXIT_OK
    assert "NEW exposure" not in out
    assert "no change" in out


def test_watch_check_quiet_prints_nothing_when_unchanged(monkeypatch, capsys):
    _stub_profiles(monkeypatch, {})
    main(["watch", "add", "me@example.com"])
    capsys.readouterr()

    code = main(["watch", "check", "--quiet"])

    assert code == EXIT_OK
    assert capsys.readouterr().out.strip() == ""


def test_watch_check_surfaces_a_newly_added_breach(monkeypatch, capsys):
    _stub_profiles(monkeypatch, {"me@example.com": [_breach("adobe")]})
    main(["watch", "add", "me@example.com"])
    main(["watch", "check"])
    capsys.readouterr()

    # A second breach appears upstream.
    _stub_profiles(monkeypatch,
                   {"me@example.com": [_breach("adobe"), _breach("linkedin", "2012-05")]})
    code = main(["watch", "check"])

    out = capsys.readouterr().out
    assert code == EXIT_FOUND
    assert "Linkedin" in out
    assert "Adobe" not in out  # already reported last time


def test_fingerprints_are_stable_across_runs():
    profile = _profile("me@example.com", [_breach()])
    assert storage.fingerprints(profile) == storage.fingerprints(profile)


# --- webhooks

DISCORD = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOp"


def test_webhook_add_list_remove(capsys):
    assert main(["webhook", "add", DISCORD]) == EXIT_OK
    main(["webhook", "list"])
    out = capsys.readouterr().out
    assert "Discord" in out
    assert DISCORD not in out  # redacted, never shown in full

    assert main(["webhook", "remove", DISCORD]) == EXIT_OK
    main(["webhook", "list"])
    assert "no webhooks configured" in capsys.readouterr().out


def test_webhook_add_rejects_a_non_url():
    assert main(["webhook", "add", "discord-please"]) == EXIT_USAGE


def test_webhook_remove_unknown_is_a_usage_error():
    assert main(["webhook", "remove", DISCORD]) == EXIT_USAGE


def test_webhook_add_is_idempotent(capsys):
    main(["webhook", "add", DISCORD])
    capsys.readouterr()
    main(["webhook", "add", DISCORD])
    assert "already configured" in capsys.readouterr().err


def test_webhook_survives_a_reload():
    """The URL must persist to the config file, not just the in-memory object."""
    main(["webhook", "add", DISCORD])
    from footprint.config import Config
    hooks = Config.resolve().webhooks
    assert [h.url for h in hooks] == [DISCORD]
    assert hooks[0].enabled is True


def test_webhook_disable_and_enable_by_number():
    from footprint.config import Config

    main(["webhook", "add", DISCORD])

    assert main(["webhook", "disable", "1"]) == EXIT_OK
    assert Config.resolve().webhooks[0].enabled is False
    assert Config.resolve().active_webhooks == []

    assert main(["webhook", "enable", "1"]) == EXIT_OK
    assert Config.resolve().webhooks[0].enabled is True


def test_webhook_disable_by_url_fragment():
    from footprint.config import Config

    main(["webhook", "add", DISCORD])
    main(["webhook", "disable", "123456789012345678"])
    assert Config.resolve().webhooks[0].enabled is False


def test_webhook_disable_unknown_target_is_a_usage_error():
    main(["webhook", "add", DISCORD])
    assert main(["webhook", "disable", "99"]) == EXIT_USAGE
    assert main(["webhook", "disable", "nope"]) == EXIT_USAGE


def test_list_shows_the_on_off_state(capsys):
    main(["webhook", "add", DISCORD])
    main(["webhook", "list"])
    assert "on" in capsys.readouterr().out

    main(["webhook", "disable", "1"])
    capsys.readouterr()
    main(["webhook", "list"])
    assert "off" in capsys.readouterr().out


@responses.activate
def test_watch_skips_delivery_when_every_webhook_is_disabled(monkeypatch):
    """A disabled hook must not be treated as 'no webhooks configured' silently."""
    responses.add(responses.POST, DISCORD, status=204)
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])
    main(["webhook", "disable", "1"])
    main(["watch", "add", "me@example.com"])

    assert main(["watch", "check"]) == EXIT_FOUND
    assert len(responses.calls) == 0


@responses.activate
def test_watch_check_pushes_new_findings_to_the_webhook(monkeypatch):
    responses.add(responses.POST, DISCORD, status=204)
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])
    main(["watch", "add", "me@example.com"])

    assert main(["watch", "check"]) == EXIT_FOUND

    assert len(responses.calls) == 1
    body = json.loads(responses.calls[0].request.body)
    assert "Adobe" in json.dumps(body["embeds"][0])


@responses.activate
def test_watch_check_sends_nothing_when_there_is_no_change(monkeypatch):
    responses.add(responses.POST, DISCORD, status=204)
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])
    main(["watch", "add", "me@example.com"])
    main(["watch", "check"])            # first run reports and delivers

    main(["watch", "check"])            # nothing new -> must stay silent
    assert len(responses.calls) == 1


@responses.activate
def test_watch_no_notify_suppresses_delivery(monkeypatch):
    responses.add(responses.POST, DISCORD, status=204)
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])
    main(["watch", "add", "me@example.com"])

    main(["watch", "check", "--no-notify"])
    assert len(responses.calls) == 0


@responses.activate
def test_a_failing_webhook_does_not_change_the_exit_code(monkeypatch, capsys):
    """The scan succeeded; a dead chat service must not turn that into failure."""
    responses.add(responses.POST, DISCORD, status=500, body="boom")
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])
    main(["watch", "add", "me@example.com"])

    assert main(["watch", "check"]) == EXIT_FOUND
    assert "webhook" in capsys.readouterr().err


# --- automatic webhook delivery

@responses.activate
def test_an_email_check_delivers_without_any_flag(monkeypatch):
    """The per-webhook switch is the control; no --notify to remember."""
    responses.add(responses.POST, DISCORD, status=204)
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])

    main(["email", "me@example.com"])

    assert len(responses.calls) == 1


@responses.activate
def test_a_disabled_webhook_receives_no_scan(monkeypatch):
    responses.add(responses.POST, DISCORD, status=204)
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])
    main(["webhook", "disable", "1"])

    main(["email", "me@example.com"])

    assert len(responses.calls) == 0


@responses.activate
def test_no_notify_suppresses_a_single_scan(monkeypatch):
    responses.add(responses.POST, DISCORD, status=204)
    _stub_profiles(monkeypatch, {"me@example.com": [_breach()]})
    main(["webhook", "add", DISCORD])

    main(["email", "me@example.com", "--no-notify"])

    assert len(responses.calls) == 0


@responses.activate
def test_a_password_check_delivers_the_password_with_its_verdict():
    """A verdict with no password is unreadable in a channel of them."""
    import hashlib

    from footprint.sources.pwned_passwords import RANGE_URL
    digest = hashlib.sha1(b"hunter2").hexdigest().upper()
    responses.add(responses.GET, RANGE_URL.format(prefix=digest[:5]),
                  body=f"{digest[5:]}:99\n")
    responses.add(responses.POST, DISCORD, status=204)
    main(["webhook", "add", DISCORD])

    main(["password", "hunter2"])

    posted = [c for c in responses.calls if c.request.method == "POST"]
    assert len(posted) == 1
    body = json.dumps(json.loads(posted[0].request.body))
    assert "hunter2" in body
    assert "Compromised" in body


def test_scans_stay_quiet_when_no_webhook_is_configured(capsys):
    """No webhooks is the normal case; it must not warn on every scan."""
    from footprint.config import Config

    assert Config.resolve().webhooks == []
    main(["webhook", "list"])
    assert "no webhooks" in capsys.readouterr().out


def test_interactive_watch_check_honours_the_stored_kind(monkeypatch):
    """The menu used to scan every watched subject as an email."""
    from footprint import interactive
    from footprint.config import Config

    storage.add_to_watchlist("example.com", "domain")
    storage.add_to_watchlist("a@example.com", "email")
    scanned = []

    def record(kind):
        def run(subject, config, **kw):
            scanned.append((kind, subject))
            return aggregate.Profile(subject=subject, kind=kind)
        return run

    monkeypatch.setattr("footprint.aggregate.domain_profile", record("domain"))
    monkeypatch.setattr("footprint.aggregate.email_profile", record("email"))

    interactive._run_watch_check(Config())

    assert scanned == [("domain", "example.com"), ("email", "a@example.com")]
