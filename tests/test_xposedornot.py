import responses

from footprint.config import Config
from footprint.sources import xposedornot


@responses.activate
def test_analytics_parses_breaches_and_risk():
    responses.add(
        responses.GET,
        "https://api.xposedornot.com/v1/breach-analytics",
        json={
            "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 80}]},
            "ExposedBreaches": {
                "breaches_details": [
                    {
                        "breach": "Adobe",
                        "domain": "adobe.com",
                        "xposed_date": "2013",
                        "xposed_records": 152445165,
                        "xposed_data": "Email addresses;Passwords;Usernames",
                        "verified": "Yes",
                        "details": "Adobe breach.",
                    }
                ]
            },
        },
        status=200,
    )

    breaches, risk = xposedornot.analytics("victim@example.com", Config())

    assert len(breaches) == 1
    b = breaches[0]
    assert b.title == "Adobe"
    assert b.pwn_count == 152445165
    assert "Passwords" in b.data_classes
    assert b.is_verified is True
    assert risk == {"label": "High", "score": 80}


@responses.activate
def test_analytics_clean_email_returns_empty():
    responses.add(
        responses.GET,
        "https://api.xposedornot.com/v1/breach-analytics",
        json={"Error": "Not found"},
        status=404,
    )
    breaches, risk = xposedornot.analytics("clean@example.com", Config())
    assert breaches == []
    assert risk == {}


def test_no_key_needed():
    # analytics must not require any credentials on the Config.
    assert Config().hibp_api_key is None
