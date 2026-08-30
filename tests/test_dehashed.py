import responses

from footprint.config import Config
from footprint.sources import dehashed


def _cfg():
    return Config(dehashed_email="me@x.com", dehashed_api_key="k")


@responses.activate
def test_dehashed_redacts_secret_values():
    responses.add(
        responses.GET,
        "https://api.dehashed.com/search",
        json={
            "entries": [
                {
                    "database_name": "BigDump",
                    "email": "victim@x.com",
                    "username": "victim",
                    "password": "hunter2",          # must never surface
                    "hashed_password": "abcd1234",   # must never surface
                }
            ]
        },
        status=200,
        match_querystring=False,
    )

    records = dehashed.search_email("victim@x.com", _cfg())

    assert len(records) == 1
    rec = records[0]
    # Presence is reported…
    assert "password [REDACTED]" in rec.fields_present
    assert "hash [REDACTED]" in rec.fields_present
    # …but the actual secret values are nowhere in the model.
    dumped = str(rec.to_dict())
    assert "hunter2" not in dumped
    assert "abcd1234" not in dumped


def test_dehashed_requires_credentials():
    import pytest

    from footprint.sources.base import SourceError

    with pytest.raises(SourceError):
        dehashed.search_email("x@y.com", Config())
