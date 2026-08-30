import hashlib

import responses

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
