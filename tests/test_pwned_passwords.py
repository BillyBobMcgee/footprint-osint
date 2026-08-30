import hashlib

import responses

from footprint.config import Config
from footprint.sources.pwned_passwords import RANGE_URL, check_password


def _range_for(password: str):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    return digest[:5], digest[5:]


@responses.activate
def test_exposed_password_reports_count():
    prefix, suffix = _range_for("password")
    body = f"0000000000000000000000000000000000:3\n{suffix}:42\n"
    responses.add(responses.GET, RANGE_URL.format(prefix=prefix), body=body, status=200)

    result = check_password("password", Config())

    assert result.exposed is True
    assert result.count == 42


@responses.activate
def test_clean_password_reports_not_found():
    prefix, _ = _range_for("a-very-unique-passphrase-xyz")
    responses.add(
        responses.GET,
        RANGE_URL.format(prefix=prefix),
        body="ABCDEF0000000000000000000000000000000:5\n",
        status=200,
    )

    result = check_password("a-very-unique-passphrase-xyz", Config())

    assert result.exposed is False
    assert result.count == 0


@responses.activate
def test_padding_zero_count_is_ignored():
    prefix, suffix = _range_for("password")
    responses.add(
        responses.GET,
        RANGE_URL.format(prefix=prefix),
        body=f"{suffix}:0\n",
        status=200,
    )

    result = check_password("password", Config())

    assert result.exposed is False
