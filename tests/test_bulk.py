import hashlib

import pytest
import responses

from footprint import bulk, scoring, storage
from footprint.config import Config
from footprint.models import DomainRecon, SiteHit
from footprint.sources.pwned_passwords import RANGE_URL


def _digest(password):
    return hashlib.sha1(password.encode()).hexdigest().upper()


def _mock_range(password, count):
    d = _digest(password)
    responses.add(responses.GET, RANGE_URL.format(prefix=d[:5]),
                  body=f"{d[5:]}:{count}\n")


# ----------------------------------------------------------------- detection

@pytest.mark.parametrize("value,expected", [
    ("you@example.com", "email"),
    ("first.last+tag@sub.example.co.uk", "email"),
    ("example.com", "domain"),
    ("sub.example.co.uk", "domain"),
    ("somehandle", "username"),
    ("some_handle-99", "username"),
])
def test_detect_kind(value, expected):
    assert bulk.detect_kind(value) == expected


def test_passwords_are_never_auto_detected():
    """Guessing a line is a password would be unsafe — it must be explicit."""
    assert bulk.detect_kind("hunter2") == "username"
    assert "password" not in {bulk.detect_kind(v) for v in ("a@b.com", "x.com", "pw")}


# --------------------------------------------------------------------- input

def test_load_subjects_skips_blanks_and_comments(tmp_path):
    f = tmp_path / "in.txt"
    f.write_text("# note\n\na@example.com\nb@example.com\n", encoding="utf-8")
    assert bulk.load_subjects(f, "email") == [
        ("a@example.com", "a@example.com"), ("b@example.com", "b@example.com")]


def test_password_list_is_labelled_by_line_not_by_secret(tmp_path):
    f = tmp_path / "pw.txt"
    f.write_text("hunter2\nswordfish\n", encoding="utf-8")

    rows = bulk.load_subjects(f, "password")

    assert [label for label, _ in rows] == ["line 1", "line 2"]
    assert [value for _, value in rows] == ["hunter2", "swordfish"]


def test_every_non_blank_line_is_a_password(tmp_path):
    """No comment syntax here: '#pass' is a valid password, not a comment.

    Blanks are skipped but do not shift the numbering — the label points at the
    real line in the file, so you can go straight to it.
    """
    f = tmp_path / "pw.txt"
    f.write_text("#notacomment\n\nhunter2\n", encoding="utf-8")

    rows = bulk.load_subjects(f, "password")

    assert rows == [("line 1", "#notacomment"), ("line 3", "hunter2")]


def test_a_comma_separated_line_is_one_password(tmp_path):
    """Bulk input is plain text only; nothing is reinterpreted as a table."""
    f = tmp_path / "pw.txt"
    f.write_text("password,with,commas\nhunter2\n", encoding="utf-8")

    rows = bulk.load_subjects(f, "password")

    assert rows == [("line 1", "password,with,commas"), ("line 2", "hunter2")]


# ----------------------------------------------------------------- passwords

@responses.activate
def test_bulk_passwords_report_labels_never_secrets():
    _mock_range("hunter2", 5000)
    _mock_range("uniq-passphrase-xyz", 0)
    rows = [("line 1", "hunter2"), ("line 2", "uniq-passphrase-xyz")]

    run = bulk.run(rows, "password", Config())
    dumped = str(run.to_dict())

    assert "hunter2" not in dumped
    assert "uniq-passphrase-xyz" not in dumped
    assert "line 1" in dumped and "line 2" in dumped


@responses.activate
def test_bulk_passwords_flag_exposure_and_leave_clean_ones_alone():
    _mock_range("hunter2", 5000)
    _mock_range("uniq-passphrase-xyz", 0)

    run = bulk.run([("line 1", "hunter2"), ("line 2", "uniq-passphrase-xyz")],
                   "password", Config())

    by_label = {r.label: r for r in run.results}
    assert by_label["line 1"].exposed and by_label["line 1"].score >= 80
    assert not by_label["line 2"].exposed and by_label["line 2"].score == 0


@responses.activate
def test_reuse_is_detected_even_when_the_password_is_not_breached():
    _mock_range("uniq-passphrase-xyz", 0)

    run = bulk.run([("A", "uniq-passphrase-xyz"), ("B", "uniq-passphrase-xyz")],
                   "password", Config())

    assert all(r.exposed for r in run.results)
    assert all("reused" in r.detail for r in run.results)
    assert any("reused" in n for n in run.notes)


@responses.activate
def test_score_scales_with_how_common_the_password_is():
    _mock_range("common", 50000)
    _mock_range("rare-one", 5)
    run = bulk.run([("A", "common"), ("B", "rare-one")], "password", Config())
    by_label = {r.label: r.score for r in run.results}
    assert by_label["A"] > by_label["B"]


@responses.activate
def test_shared_hash_prefixes_are_fetched_once():
    """Passwords in the same range must not cost one request each."""
    _mock_range("hunter2", 10)
    before = len(responses.calls)

    bulk.run([("A", "hunter2"), ("B", "hunter2"), ("C", "hunter2")],
             "password", Config())

    assert len(responses.calls) - before == 1


@responses.activate
def test_passwords_produce_no_per_subject_report():
    """A report file would put the password list's shape on disk."""
    _mock_range("hunter2", 10)
    run = bulk.run([("line 1", "hunter2")], "password", Config())
    assert all(r.payload is None for r in run.results)


# ---------------------------------------------------------------- usernames

def test_username_scoring_rises_with_reach():
    few = scoring.assess_username([SiteHit("GitHub", "u", True)])
    many = scoring.assess_username(
        [SiteHit(f"Site{i}", "u", True) for i in range(15)])
    assert many.score > few.score


def test_username_not_found_anywhere_scores_zero():
    a = scoring.assess_username([SiteHit("GitHub", "u", False)])
    assert a.score == 0
    assert any("not widely reused" in x.title for x in a.actions)


def test_sensitive_sites_dominate_the_username_score():
    plain = scoring.assess_username([SiteHit("Goodreads", "u", True)])
    sensitive = scoring.assess_username([SiteHit("FetLife", "u", True)])
    assert sensitive.score > plain.score
    assert any("would not want linked" in x.title for x in sensitive.actions)


# ------------------------------------------------------- domain watch alerts

def test_takeover_is_fingerprinted_for_watch():
    from footprint import aggregate

    p = aggregate.Profile(subject="example.com", kind="domain")
    p.sections["recon"] = DomainRecon(
        domain="example.com", spf="v=spf1 -all", dmarc="v=DMARC1; p=reject",
        dmarc_policy="reject", dnssec=True,
        takeovers=[{"host": "shop.example.com", "target": "x.s3.amazonaws.com",
                    "service": "AWS S3"}])

    labels = list(storage.fingerprints(p).values())

    assert any("TAKEOVER" in x and "shop.example.com" in x for x in labels)


def test_a_healthy_domain_produces_no_watch_alerts():
    from footprint import aggregate

    p = aggregate.Profile(subject="ok.com", kind="domain")
    p.sections["recon"] = DomainRecon(
        domain="ok.com", spf="v=spf1 -all", dmarc="v=DMARC1; p=reject",
        dmarc_policy="reject", dnssec=True)
    assert storage.fingerprints(p) == {}


def test_dmarc_regression_reads_as_a_new_finding():
    """reject -> none must fingerprint differently, or it would pass silently."""
    from footprint import aggregate

    def fp(policy):
        p = aggregate.Profile(subject="e.com", kind="domain")
        p.sections["recon"] = DomainRecon(
            domain="e.com", spf="v=spf1 -all", dmarc="v=DMARC1", dmarc_policy=policy,
            dnssec=True)
        return set(storage.fingerprints(p))

    assert fp("reject") == set()
    assert fp("none") != set()


# ------------------------------------------------- shared text parsing

def test_parse_subjects_matches_load_subjects(tmp_path):
    """GUI (text) and CLI (file) must produce identical rows."""
    text = "a@example.com\nb@example.com\n"
    f = tmp_path / "in.txt"
    f.write_text(text, encoding="utf-8")
    assert bulk.parse_subjects(text, "email") == bulk.load_subjects(f, "email")


def test_detect_kind_for_uses_a_majority_vote():
    rows = [(v, v) for v in ("a@x.com", "b@x.com", "notanemail")]
    assert bulk.detect_kind_for(rows) == "email"


def test_detect_kind_for_empty_defaults_to_email():
    assert bulk.detect_kind_for([]) == "email"
