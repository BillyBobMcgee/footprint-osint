from footprint import reports

PAYLOAD = {
    "subject": "user@example.com",
    "kind": "email",
    "sections": {
        "breaches": [
            {"title": "Adobe", "data_classes": ["Email", "Passwords"],
             "breach_date": "2013-10-04"}
        ],
        "leaks": [{"database": "SomeDump", "fields_present": ["email", "password [REDACTED]"]}],
        "risk": {
            "score": 42,
            "label": "Moderate",
            "factors": [{"points": 42, "reason": "appears in 1 known breach"}],
            "actions": [{"title": "Rotate the exposed passwords", "detail": "Change it."}],
        },
    },
    "timeline": [
        {"date": "2013-10-04", "kind": "breach", "label": "Adobe", "source": "HIBP"}
    ],
    "notes": ["IntelX: needs an API key"],
}


def _render(tmp_path):
    out = tmp_path / "r.html"
    reports.save(PAYLOAD, str(out))
    return out.read_text(encoding="utf-8")


def test_html_report_is_a_standalone_document(tmp_path):
    text = _render(tmp_path)
    assert text.startswith("<!doctype html>")
    assert "<title>" in text and "</html>" in text
    # Everything is inlined, so the file works with no network access.
    assert "<style>" in text
    assert "src=" not in text


def test_html_report_includes_findings_and_timeline(tmp_path):
    text = _render(tmp_path)
    assert "Adobe" in text
    assert "SomeDump" in text
    assert "Timeline" in text


def test_html_report_includes_the_score_and_actions(tmp_path):
    text = _render(tmp_path)
    assert "42" in text and "Moderate" in text
    assert "appears in 1 known breach" in text
    assert "What to do now" in text
    assert "Rotate the exposed passwords" in text


def test_html_report_redacts_and_escapes(tmp_path):
    text = _render(tmp_path)
    # The redaction marker survives; no plaintext secret is ever present.
    assert "password [REDACTED]" in text


def test_html_report_escapes_markup_in_values(tmp_path):
    """A subject is attacker-influenced text, so it must not become markup."""
    payload = dict(PAYLOAD, subject="<script>alert(1)</script>")
    out = tmp_path / "x.html"
    reports.save(payload, str(out))
    text = out.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_save_handles_a_payload_with_no_sections(tmp_path):
    out = tmp_path / "empty.html"
    reports.save({"subject": "nobody@example.com", "kind": "email"}, str(out))
    assert "nobody@example.com" in out.read_text(encoding="utf-8")
