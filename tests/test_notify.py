import json
from datetime import datetime

import pytest
import responses

from footprint import aggregate, notify, scoring
from footprint.config import Config, Webhook, _parse_webhooks
from footprint.models import Breach

DISCORD = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrSt"
GENERIC = "https://example.com/hook"


def _breach(name="adobe", when="2013-10-04", classes=("Passwords",)):
    return Breach(name=name, title=name.title(), domain=f"{name}.com",
                  breach_date=when, added_date=None, pwn_count=1000,
                  data_classes=list(classes))


def _payload(**sections):
    """Build the exact shape a real scan emits: Profile.to_dict(), all plain.

    Going through Profile matters: the notifier serialises this payload, so a
    fixture holding live dataclasses would pass while real output failed.
    """
    p = aggregate.Profile(subject="you@example.com", kind="email")
    p.sections.update(sections)
    p.sections["risk"] = scoring.assess_email(p.sections)
    return p.to_dict()


# --- detection

def test_discord_urls_are_recognised():
    assert notify.is_discord(DISCORD)
    assert notify.is_discord("https://discordapp.com/api/webhooks/1/x")
    assert not notify.is_discord(GENERIC)


def test_webhook_urls_are_redacted_not_shown_in_full():
    out = notify.redact(DISCORD)
    assert out != DISCORD
    assert "AbCdEfGhIjKlMnOpQrSt" not in out


def _urls(hooks):
    return [h.url for h in hooks]


def test_config_parses_webhooks_from_list_and_string():
    assert _urls(_parse_webhooks([DISCORD])) == [DISCORD]
    assert _urls(_parse_webhooks(f"{DISCORD}, {GENERIC}")) == [DISCORD, GENERIC]
    assert _parse_webhooks("not-a-url") == []
    assert _parse_webhooks(None) == []


def test_bare_urls_from_an_older_config_default_to_enabled():
    """Config files written before the on/off switch must keep working."""
    assert _parse_webhooks([DISCORD])[0].enabled is True


def test_stored_objects_keep_their_enabled_state():
    hooks = _parse_webhooks([{"url": DISCORD, "enabled": False}])
    assert hooks[0].url == DISCORD
    assert hooks[0].enabled is False


@responses.activate
def test_a_disabled_webhook_receives_nothing():
    responses.add(responses.POST, DISCORD, status=204)
    config = Config(webhooks=[Webhook(url=DISCORD, enabled=False)])

    results = notify.send(config, notify.test_embed())

    assert results == []
    assert len(responses.calls) == 0


@responses.activate
def test_only_enabled_webhooks_are_delivered_to():
    responses.add(responses.POST, DISCORD, status=204)
    responses.add(responses.POST, GENERIC, status=200)
    config = Config(webhooks=[
        Webhook(url=DISCORD, enabled=False),
        Webhook(url=GENERIC, enabled=True),
    ])

    results = notify.send(config, notify.test_embed())

    assert [url for url, _ in results] == [GENERIC]
    assert len(responses.calls) == 1


def test_masked_config_never_reveals_a_webhook():
    masked = Config(webhooks=[DISCORD]).masked()
    assert DISCORD not in json.dumps(masked)


# --- embeds

def test_profile_embed_carries_score_counts_and_actions():
    embed = notify.profile_embed(_payload(breaches=[_breach()]))

    # The title names the task; the subject is underlined in the description.
    assert embed["title"] == "Task: Email Check"
    assert "__you@example.com__" in embed["description"]
    assert "footprint" not in embed["title"]
    assert "footprint" in embed["footer"]["text"]
    assert "/100" in embed["description"]
    names = [f["name"] for f in embed["fields"]]
    assert "Breaches" in names
    assert any(n.startswith("What to do now") for n in names)
    # Counts render as columns, so they must be inline.
    assert all(f["inline"] for f in embed["fields"] if f["name"] == "Breaches")


def test_actions_field_is_marked_proof_of_concept():
    embed = notify.profile_embed(_payload(breaches=[_breach()]))
    actions = next(f for f in embed["fields"] if f["name"].startswith("What to do"))
    assert "proof of concept" in actions["value"].lower()


def test_score_line_shows_a_meter_and_a_severity_dot():
    description = notify.profile_embed(_payload(breaches=[_breach()]))["description"]
    assert "█" in description or "░" in description
    assert any(dot in description for dot in notify.DOTS.values())


def test_every_embed_is_timestamped():
    """Discord renders it beside the footer, so a stale alert is obvious."""
    assert datetime.fromisoformat(notify.test_embed()["timestamp"]).tzinfo is not None


def test_domain_embeds_are_marked_proof_of_concept():
    domain = notify.profile_embed({"subject": "e.com", "kind": "domain",
                                   "sections": {}, "timeline": [], "notes": []})
    email = notify.profile_embed(_payload())
    assert "proof of concept" in domain["description"].lower()
    assert "proof of concept" not in email["description"].lower()


def test_embed_colour_tracks_severity():
    from footprint.models import DarkWebMatch, LeakRecord

    clean = notify.profile_embed(_payload())
    critical = notify.profile_embed(_payload(
        breaches=[_breach(f"b{i}", "2026-01-01",
                          ["Passwords", "Social security numbers", "Credit cards",
                           "Physical addresses", "Phone numbers"])
                  for i in range(20)],
        leaks=[LeakRecord(database=f"d{i}") for i in range(20)],
        darkweb=[DarkWebMatch(name=f"m{i}", bucket="leaks", date="2026-01-01")
                 for i in range(10)],
        accounts=[{"site": f"s{i}"} for i in range(30)],
    ))
    assert clean["color"] == notify.COLORS["Minimal"]
    assert critical["color"] == notify.COLORS["Critical"]


def test_takeovers_get_their_own_field():
    payload = {"subject": "example.com", "kind": "domain", "timeline": [], "notes": [],
               "sections": {"recon": {"takeovers": [
                   {"host": "shop.example.com", "target": "x.s3.amazonaws.com",
                    "service": "AWS S3"}]}}}
    fields = notify.profile_embed(payload)["fields"]
    assert any("takeover" in f["name"].lower() for f in fields)


def test_embed_stays_within_discord_limits_for_a_huge_profile():
    """A 200-breach profile must not blow past Discord's field/embed caps."""
    payload = _payload(
        breaches=[_breach(f"breach{i}", "2026-01-01",
                          ["Passwords", "Physical addresses", "Phone numbers"])
                  for i in range(200)],
        accounts=[{"site": f"site{i}"} for i in range(80)],
    )
    embed = notify.profile_embed(payload)

    assert len(embed["title"]) <= notify.MAX_TITLE
    assert len(embed["description"]) <= notify.MAX_DESC
    assert len(embed["fields"]) <= notify.MAX_FIELDS
    for f in embed["fields"]:
        assert len(f["name"]) <= notify.MAX_FIELD_NAME
        assert len(f["value"]) <= notify.MAX_FIELD_VALUE


def test_bullets_truncates_and_says_how_many_were_dropped():
    value = notify._bullets([f"line number {i} " + "x" * 60 for i in range(100)])
    assert len(value) <= notify.MAX_FIELD_VALUE
    assert "more" in value


def test_watch_embed_lists_only_the_new_findings():
    embed = notify.watch_embed({"you@example.com": ["breach: Adobe (2013)"]})
    assert embed["title"] == "Task: Watch Check"
    assert "1 new finding" in embed["description"]
    assert "Adobe" in embed["fields"][0]["value"]


# --- sending

@responses.activate
def test_discord_receives_an_embeds_payload():
    responses.add(responses.POST, DISCORD, status=204)

    results = notify.send(Config(webhooks=[DISCORD]), notify.test_embed())

    assert results == [(DISCORD, None)]
    body = json.loads(responses.calls[0].request.body)
    assert "embeds" in body and len(body["embeds"]) == 1
    assert body["embeds"][0]["title"] == "Task: Webhook Test"


@responses.activate
def test_generic_endpoint_receives_text_and_the_raw_result():
    responses.add(responses.POST, GENERIC, status=200)
    payload = _payload(breaches=[_breach()])

    notify.send(Config(webhooks=[GENERIC]), notify.profile_embed(payload), payload)

    body = json.loads(responses.calls[0].request.body)
    assert "embeds" not in body
    assert "text" in body
    assert body["result"]["subject"] == "you@example.com"


@responses.activate
def test_delivery_failure_is_reported_not_raised():
    """A dead webhook must never fail the scan that produced the result."""
    responses.add(responses.POST, DISCORD, status=404, body="unknown webhook")

    results = notify.send(Config(webhooks=[DISCORD]), notify.test_embed())

    assert len(results) == 1
    assert results[0][1] is not None
    assert "404" in results[0][1]


@responses.activate
def test_one_bad_webhook_does_not_stop_the_others():
    responses.add(responses.POST, DISCORD, status=500)
    responses.add(responses.POST, GENERIC, status=200)

    results = dict(notify.send(Config(webhooks=[DISCORD, GENERIC]), notify.test_embed()))

    assert results[DISCORD] is not None
    assert results[GENERIC] is None


def test_send_is_a_no_op_without_configured_webhooks():
    assert notify.send(Config(), notify.test_embed()) == []


@pytest.mark.parametrize("status", [200, 201, 202, 204])
@responses.activate
def test_all_success_statuses_accepted(status):
    responses.add(responses.POST, GENERIC, status=status)
    assert notify.send(Config(webhooks=[GENERIC]), notify.test_embed())[0][1] is None
