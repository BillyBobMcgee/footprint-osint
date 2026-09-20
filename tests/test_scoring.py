from datetime import date

import pytest

from footprint import scoring
from footprint.models import (
    Breach,
    DarkWebMatch,
    DomainRecon,
    LeakRecord,
    Paste,
    ReputationReport,
)

TODAY = date(2026, 8, 29)


def _breach(name, when, classes, **kw):
    return Breach(
        name=name, title=name.title(), domain=f"{name}.com", breach_date=when,
        added_date=None, pwn_count=kw.pop("pwn_count", 1000), data_classes=classes, **kw
    )


# --- classification

def test_classify_puts_credentials_in_critical():
    assert scoring.classify_data("Passwords") == "critical"
    assert scoring.classify_data("Password hashes") == "critical"
    assert scoring.classify_data("Social security numbers") == "critical"
    assert scoring.classify_data("Security questions and answers") == "critical"


def test_classify_separates_email_from_physical_address():
    # "Email addresses" contains "address" but must not read as a home address.
    assert scoring.classify_data("Email addresses") == "medium"
    assert scoring.classify_data("IP addresses") == "medium"
    assert scoring.classify_data("Physical addresses") == "high"


def test_classify_falls_back_to_low():
    assert scoring.classify_data("Purchasing habits") == "low"


# Real HIBP labels, including the ones an earlier keyword list missed by
# looking for the singular ("date of birth" never matched "Dates of birth").
HIBP_TIERS = {
    "critical": ["Passwords", "Password hashes", "Social security numbers",
                 "Government issued IDs", "Partial government issued IDs",
                 "Mnemonic phrases", "Encrypted keys", "PINs", "Payment methods",
                 "Bank account numbers", "Credit cards", "Passport numbers",
                 "Security questions and answers", "Auth tokens", "Account balances",
                 "Taxation records", "Driver's licenses"],
    "high": ["Dates of birth", "Partial dates of birth", "Places of birth",
             "Physical addresses", "Phone numbers", "HIV statuses", "Religions",
             "Sexual orientations", "Political views", "Ethnicities",
             "Private messages", "SMS messages", "Chat logs", "Browsing histories",
             "Latitude and longitude pairs", "MAC addresses", "Licence plates",
             "Credit scores", "Cryptocurrency wallet addresses", "Employers",
             "Income levels", "Financial transactions"],
    "medium": ["Email addresses", "IP addresses", "Usernames", "Names", "Genders",
               "Job titles", "Nicknames"],
    "low": ["Purchasing habits", "Astrological signs", "Beauty ratings",
            "IQ levels", "Survey results"],
}


@pytest.mark.parametrize("tier", sorted(HIBP_TIERS))
def test_real_hibp_labels_land_in_the_right_tier(tier):
    wrong = {x: scoring.classify_data(x) for x in HIBP_TIERS[tier]
             if scoring.classify_data(x) != tier}
    assert not wrong


def test_keywords_match_whole_words_only():
    """Plain substring matching found "PIN" inside "Shipping"."""
    assert scoring.classify_data("Shipment tracking numbers") == "low"
    assert scoring.classify_data("Shipping preferences") != "critical"


def test_a_leaked_password_outweighs_breach_volume():
    """Counting breaches used to beat knowing your password was in them."""
    many = scoring.assess_email({"breaches": [
        _breach(f"x{i}", "2016-01-01", ["Email addresses", "Usernames"])
        for i in range(10)]}, today=TODAY)
    one = scoring.assess_email({"breaches": [
        _breach("x", "2016-01-01", ["Passwords"])]}, today=TODAY)

    assert one.score > many.score


def test_a_password_leak_is_not_minimal():
    a = scoring.assess_email({"breaches": [
        _breach("x", "2026-04-01", ["Passwords"])]}, today=TODAY)
    assert a.score >= 40


def test_harmless_classes_stay_near_zero():
    a = scoring.assess_email({"breaches": [
        _breach(f"x{i}", "2016-01-01", ["Names", "Genders", "IP addresses"])
        for i in range(3)]}, today=TODAY)
    assert a.label == "Minimal"


def test_the_worst_class_sets_the_level():
    """One SSN has to beat one maiden name, not tie with it."""
    ssn = scoring.assess_email({"breaches": [
        _breach("x", "2016-01-01", ["Social security numbers"])]}, today=TODAY)
    maiden = scoring.assess_email({"breaches": [
        _breach("x", "2016-01-01", ["Mothers maiden names"])]}, today=TODAY)

    assert ssn.score > maiden.score


def test_data_weight_ranks_the_obvious_cases():
    w = scoring.data_weight
    assert w("Passwords") > w("Credit cards") > w("Mothers maiden names")
    assert w("HIV statuses") > w("Employers")
    assert w("Usernames") == 0


def test_label_boundaries():
    assert scoring.label_for(0) == "Minimal"
    assert scoring.label_for(20) == "Low"
    assert scoring.label_for(40) == "Moderate"
    assert scoring.label_for(60) == "High"
    assert scoring.label_for(80) == "Critical"


# --- emails

def test_clean_profile_scores_zero_and_advises_watching():
    a = scoring.assess_email({}, today=TODAY)
    assert a.score == 0
    assert a.label == "Minimal"
    assert any("watchlist" in x.detail for x in a.actions)


def test_breach_with_passwords_scores_and_says_rotate():
    sections = {"breaches": [_breach("adobe", "2013-10-04",
                                     ["Email addresses", "Passwords"])]}
    a = scoring.assess_email(sections, today=TODAY)

    assert a.score > 0
    assert any("Rotate" in x.title for x in a.actions)
    assert "Passwords" in a.exposed_data["critical"]


def test_rotate_advice_names_only_the_breaches_that_leaked_a_password():
    """Naming a breach that leaked no password sends the user to the wrong site."""
    sections = {"breaches": [
        _breach("lumenis", "2026-01-01", ["Email addresses", "Phone numbers"]),
        _breach("adobe", "2013-10-04", ["Email addresses", "Passwords"]),
    ]}
    a = scoring.assess_email(sections, today=TODAY)

    rotate = next(x for x in a.actions if "Rotate" in x.title)
    assert "Adobe" in rotate.detail
    assert "Lumenis" not in rotate.detail


def test_recent_breach_scores_higher_than_an_old_one():
    old = {"breaches": [_breach("old", "2011-01-01", ["Passwords"])]}
    new = {"breaches": [_breach("new", "2026-06-01", ["Passwords"])]}
    assert scoring.assess_email(new, today=TODAY).score > \
        scoring.assess_email(old, today=TODAY).score


def test_hibp_and_xon_duplicates_are_counted_once():
    b = _breach("adobe", "2013-10-04", ["Passwords"])
    both = {"breaches": [b], "xon_breaches": [_breach("adobe", "2013", ["Passwords"])]}
    a = scoring.assess_email(both, today=TODAY)
    assert "1 known breach" in a.factors[0].reason


def test_ssn_triggers_a_credit_freeze_action():
    sections = {"breaches": [_breach("x", "2024-01-01", ["Social security numbers"])]}
    actions = scoring.assess_email(sections, today=TODAY).actions
    assert any("Freeze your credit" in x.title for x in actions)


def test_government_id_triggers_a_credit_freeze():
    """HIBP calls these "Government issued IDs"; the old needle was singular."""
    a = scoring.assess_email(
        {"breaches": [_breach("acme", "2024-01-01", ["Government issued IDs"])]})
    assert any("Freeze your credit" in x.title for x in a.actions)


def test_a_leaked_seed_phrase_says_to_move_the_funds():
    a = scoring.assess_email(
        {"breaches": [_breach("acme", "2024-01-01", ["Mnemonic phrases"])]})
    assert any("new wallet" in x.title for x in a.actions)


def test_phone_triggers_sim_swap_advice():
    sections = {"breaches": [_breach("x", "2024-01-01", ["Phone numbers"])]}
    actions = scoring.assess_email(sections, today=TODAY).actions
    assert any("port-out PIN" in x.title for x in actions)


def test_accounts_trigger_2fa_advice_naming_the_count():
    sections = {"accounts": [object()] * 5}
    actions = scoring.assess_email(sections, today=TODAY).actions
    assert any("2FA across 5" in x.title for x in actions)


def test_leak_records_raise_the_score():
    sections = {"leaks": [LeakRecord(database="db", fields_present=["password"])]}
    assert scoring.assess_email(sections, today=TODAY).score > 0


def test_score_is_capped_at_100():
    """Every factor maxed at once must still land on 100, not overflow it."""
    sections = {
        "breaches": [_breach(f"b{i}", "2026-01-01",
                             ["Passwords", "Social security numbers", "Credit cards",
                              "Physical addresses", "Phone numbers"])
                     for i in range(20)],
        "leaks": [LeakRecord(database=f"d{i}") for i in range(20)],
        "darkweb": [DarkWebMatch(name=f"m{i}", bucket="leaks", date="2026-01-01")
                    for i in range(10)],
        "pastes": [Paste(source="pastebin", paste_id=str(i), title=None,
                         date="2026-01-01", email_count=1) for i in range(10)],
        "accounts": [object()] * 30,
        "reputation": ReputationReport(
            email="a@b.com", reputation="poor", suspicious=True, references=1,
            blacklisted=True, credentials_leaked=True, malicious_activity=True,
        ),
    }
    a = scoring.assess_email(sections, today=TODAY)
    assert sum(f.points for f in a.factors) > 100  # would have overflowed
    assert a.score == 100
    assert a.label == "Critical"


def test_factors_sum_to_the_score():
    sections = {"breaches": [_breach("a", "2020-01-01", ["Passwords"])]}
    a = scoring.assess_email(sections, today=TODAY)
    assert sum(f.points for f in a.factors) == a.score


# --- domains

def test_missing_spf_and_dmarc_score_badly_and_advise_publishing():
    sections = {"recon": DomainRecon(domain="example.com", mx=["10 mail"])}
    a = scoring.assess_domain(sections, today=TODAY)

    assert a.score >= 30
    titles = " ".join(x.title for x in a.actions)
    assert "Publish an SPF record" in titles
    assert "Publish a DMARC record" in titles


def test_fully_configured_domain_scores_low():
    recon = DomainRecon(
        domain="example.com", mx=["10 mail"], spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject", dmarc_policy="reject", dnssec=True,
        dkim_selectors=["default"], mta_sts="v=STSv1; id=1", tls_rpt="v=TLSRPTv1",
    )
    a = scoring.assess_domain({"recon": recon}, today=TODAY)
    assert a.score == 0
    assert a.label == "Minimal"


def test_dmarc_none_is_penalized_less_than_missing():
    missing = {"recon": DomainRecon(domain="e.com", spf="v=spf1 -all")}
    monitor = {"recon": DomainRecon(domain="e.com", spf="v=spf1 -all",
                                    dmarc="v=DMARC1; p=none", dmarc_policy="none")}
    assert scoring.assess_domain(monitor, today=TODAY).score < \
        scoring.assess_domain(missing, today=TODAY).score


def test_takeover_dominates_the_domain_score_and_is_the_first_action():
    recon = DomainRecon(
        domain="example.com", spf="v=spf1 -all", dmarc="v=DMARC1; p=reject",
        dmarc_policy="reject", dnssec=True, mta_sts="v=STSv1",
        takeovers=[{"host": "shop.example.com", "target": "x.s3.amazonaws.com",
                    "service": "AWS S3"}],
    )
    a = scoring.assess_domain({"recon": recon}, today=TODAY)

    assert a.score >= 12
    assert "dangling" in a.actions[0].title
    assert "shop.example.com" in a.actions[0].detail


def test_spf_plus_all_is_treated_as_no_spf():
    weak = {"recon": DomainRecon(domain="e.com", spf="v=spf1 +all")}
    assert any("+all" in f.reason for f in
               scoring.assess_domain(weak, today=TODAY).factors)


def test_assessment_round_trips_to_plain_dicts():
    sections = {"breaches": [_breach("a", "2020-01-01", ["Passwords"])]}
    payload = scoring.assess_email(sections, today=TODAY).to_dict()

    assert isinstance(payload["score"], int)
    assert isinstance(payload["factors"][0], dict)
    assert isinstance(payload["actions"][0]["title"], str)


# ------------------------------------------------- unreachable != clean

def test_a_scan_that_reached_nothing_is_a_failure(monkeypatch):
    """The worst failure mode: 'checked nothing' rendering as 'nothing found'."""
    from footprint import aggregate
    from footprint.sources.base import Unreachable

    def dead(*a, **kw):
        raise Unreachable("cannot reach example.com")

    monkeypatch.setattr("footprint.sources.hibp.breached_account", dead)
    monkeypatch.setattr("footprint.sources.hibp.pasted_account", dead)
    monkeypatch.setattr("footprint.sources.xposedornot.analytics", dead)
    monkeypatch.setattr("footprint.sources.emailrep.lookup", dead)
    monkeypatch.setattr("footprint.sources.dehashed.search_email", dead)
    monkeypatch.setattr("footprint.sources.intelx.search", dead)
    monkeypatch.setattr("footprint.sources.gravatar.lookup", dead)
    monkeypatch.setattr("footprint.sources.holehe_scan.available", lambda: False)

    from footprint.config import Config
    profile = aggregate.email_profile("a@example.com", Config())

    assert profile.failed is not None
    assert "not a clean result" in profile.failed
    # No score, because scoring nothing would imply a verdict.
    assert "risk" not in profile.sections


def test_a_partial_scan_still_produces_a_result(monkeypatch):
    """One dead source must not condemn a scan that others answered."""
    from footprint import aggregate
    from footprint.config import Config
    from footprint.sources.base import Unreachable

    def dead(*a, **kw):
        raise Unreachable("cannot reach it")

    monkeypatch.setattr("footprint.sources.hibp.breached_account", dead)
    monkeypatch.setattr("footprint.sources.hibp.pasted_account", dead)
    monkeypatch.setattr("footprint.sources.xposedornot.analytics",
                        lambda *a, **kw: ([], {}))
    monkeypatch.setattr("footprint.sources.emailrep.lookup", dead)
    monkeypatch.setattr("footprint.sources.dehashed.search_email", dead)
    monkeypatch.setattr("footprint.sources.intelx.search", dead)
    monkeypatch.setattr("footprint.sources.gravatar.lookup", dead)
    monkeypatch.setattr("footprint.sources.holehe_scan.available", lambda: False)

    profile = aggregate.email_profile("a@example.com", Config())

    assert profile.failed is None
    assert "risk" in profile.sections



