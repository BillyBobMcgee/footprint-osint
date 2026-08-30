import pytest
import responses

from footprint.config import Config
from footprint.sources.base import SourceError
from footprint.sources.hibp import API_ROOT, breached_account, breaches_for_domain


def _cfg(key="test-key"):
    return Config(hibp_api_key=key)


@responses.activate
def test_breached_account_parses_results():
    responses.add(
        responses.GET,
        f"{API_ROOT}/breachedaccount/user%40example.com",
        json=[
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "PwnCount": 152445165,
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
            }
        ],
        status=200,
        match_querystring=False,
    )

    breaches = breached_account("user@example.com", _cfg())

    assert len(breaches) == 1
    assert breaches[0].title == "Adobe"
    assert "Passwords" in breaches[0].data_classes


@responses.activate
def test_breached_account_404_is_empty():
    responses.add(
        responses.GET,
        f"{API_ROOT}/breachedaccount/nobody%40example.com",
        status=404,
        match_querystring=False,
    )
    assert breached_account("nobody@example.com", _cfg()) == []


def test_missing_api_key_raises():
    with pytest.raises(SourceError):
        breached_account("user@example.com", Config(hibp_api_key=None))


@responses.activate
def test_domain_lookup_needs_no_key():
    responses.add(
        responses.GET,
        f"{API_ROOT}/breaches",
        json=[
            {
                "Name": "X",
                "Title": "X",
                "Domain": "example.com",
                "BreachDate": "2020-01-01",
                "PwnCount": 10,
                "DataClasses": ["Email addresses"],
            }
        ],
        status=200,
        match_querystring=False,
    )
    breaches = breaches_for_domain("example.com", Config(hibp_api_key=None))
    assert breaches[0].domain == "example.com"
