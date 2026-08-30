from footprint.sources import holehe_scan

SAMPLE_CSV = (
    "name,domain,rateLimit,exists,emailrecovery,phoneNumber,others\n"
    "github,github.com,False,True,,,\n"
    "spotify,spotify.com,False,True,ab***@gmail.com,,\n"
    "instagram,instagram.com,False,False,,,\n"
    "twitter,twitter.com,True,False,,,\n"
)


def test_parse_csv_keeps_only_existing_accounts():
    accounts = holehe_scan._parse_csv(SAMPLE_CSV)
    sites = [a.site for a in accounts]
    assert sites == ["github", "spotify"]  # sorted, only exists==True


def test_parse_csv_captures_recovery_hint():
    accounts = holehe_scan._parse_csv(SAMPLE_CSV)
    spotify = next(a for a in accounts if a.site == "spotify")
    assert spotify.email_recovery == "ab***@gmail.com"
    assert spotify.domain == "spotify.com"


def test_parse_csv_empty():
    assert holehe_scan._parse_csv("name,domain,rateLimit,exists\n") == []
