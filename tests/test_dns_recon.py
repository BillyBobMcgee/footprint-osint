from urllib.parse import parse_qs, urlsplit

import pytest
import responses

from footprint.config import Config
from footprint.sources import dns_recon
from footprint.sources.base import SourceError


def _doh_router(zone):
    """Answer DoH queries from a {(name, type): [data, ...]} map."""
    def handler(request):
        q = parse_qs(urlsplit(request.url).query)
        name = q.get("name", [""])[0]
        rtype = q.get("type", ["A"])[0]
        answers = zone.get((name, rtype), [])
        body = {"Answer": [{"data": a} for a in answers]}
        if zone.get("__ad__") and rtype == "A":
            body["AD"] = True
        return 200, {}, __import__("json").dumps(body)
    return handler


def _register(zone, subdomains=None):
    responses.add_callback(
        responses.GET, "https://cloudflare-dns.com/dns-query",
        callback=_doh_router(zone), content_type="application/json",
    )
    responses.add(
        responses.GET, "https://crt.sh/",
        json=[{"name_value": "\n".join(subdomains or [])}] if subdomains else [],
        status=200,
    )


# --------------------------------------------------------------- basic recon

@responses.activate
def test_recon_parses_spf_dmarc_and_subdomains():
    _register(
        {
            ("example.com", "MX"): ["10 mail.example.com"],
            ("example.com", "TXT"): ['"v=spf1 include:_spf.example.com ~all"'],
            ("_dmarc.example.com", "TXT"):
                ['"v=DMARC1; p=reject; rua=mailto:x@example.com"'],
        },
        subdomains=["www.example.com", "mail.example.com", "*.example.com"],
    )

    recon = dns_recon.recon("example.com", Config(), deep=False)

    assert recon.spf.startswith("v=spf1")
    assert recon.dmarc_policy == "reject"
    assert "www.example.com" in recon.subdomains
    assert "*.example.com" not in recon.subdomains  # wildcard stripped


@responses.activate
def test_shallow_recon_skips_the_deep_checks():
    _register({("example.com", "MX"): ["10 mail.example.com"]})

    recon = dns_recon.recon("example.com", Config(), deep=False)

    assert recon.dnssec is False
    assert recon.dkim_selectors == []
    assert recon.mta_sts is None
    assert recon.takeovers == []


def test_recon_rejects_non_domain():
    with pytest.raises(SourceError):
        dns_recon.recon("not-a-domain", Config())


# ---------------------------------------------------------------- deep recon

@responses.activate
def test_deep_recon_finds_dkim_mta_sts_tls_rpt_and_bimi():
    _register({
        ("example.com", "MX"): ["10 mail.example.com"],
        ("example.com", "TXT"): ['"v=spf1 -all"'],
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
        ("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=MIGf"'],
        ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=20260101"'],
        ("_smtp._tls.example.com", "TXT"): ['"v=TLSRPTv1; rua=mailto:t@example.com"'],
        ("default._bimi.example.com", "TXT"): ['"v=BIMI1; l=https://e.com/logo.svg"'],
        "__ad__": True,
    })

    recon = dns_recon.recon("example.com", Config())

    assert recon.dkim_selectors == ["google"]
    assert recon.mta_sts.startswith("v=STSv1")
    assert recon.tls_rpt.startswith("v=TLSRPTv1")
    assert recon.bimi.startswith("v=BIMI1")
    assert recon.dnssec is True


@responses.activate
def test_dnssec_is_false_without_the_ad_bit():
    _register({("example.com", "MX"): ["10 mail.example.com"]})
    assert dns_recon.recon("example.com", Config()).dnssec is False


@responses.activate
def test_takeover_flagged_when_cname_dangles_and_body_matches():
    _register(
        {("shop.example.com", "CNAME"): ["bucket.s3.amazonaws.com."]},
        subdomains=["shop.example.com"],
    )
    responses.add(responses.GET, "https://shop.example.com/",
                  body="<Error><Code>NoSuchBucket</Code></Error>", status=404)

    takeovers = dns_recon.recon("example.com", Config()).takeovers

    assert len(takeovers) == 1
    assert takeovers[0]["host"] == "shop.example.com"
    assert takeovers[0]["service"] == "AWS S3"


@responses.activate
def test_healthy_site_on_a_known_host_is_not_flagged():
    """A live S3-backed site must not be reported just for being on S3."""
    _register(
        {("shop.example.com", "CNAME"): ["bucket.s3.amazonaws.com."]},
        subdomains=["shop.example.com"],
    )
    responses.add(responses.GET, "https://shop.example.com/",
                  body="<html>our real storefront</html>", status=200)

    assert dns_recon.recon("example.com", Config()).takeovers == []


@responses.activate
def test_subdomain_without_a_cname_is_not_probed():
    _register({}, subdomains=["www.example.com"])
    assert dns_recon.recon("example.com", Config()).takeovers == []


# --------------------------------------------------- crt.sh failure handling

@responses.activate
def test_crtsh_failure_is_reported_not_silently_empty():
    """A 502 from crt.sh must not look like 'this domain has no subdomains'."""
    responses.add_callback(
        responses.GET, "https://cloudflare-dns.com/dns-query",
        callback=_doh_router({}), content_type="application/json",
    )
    responses.add(responses.GET, "https://crt.sh/", body="502 Bad Gateway", status=502)

    recon = dns_recon.recon("example.com", Config(), deep=False)

    assert recon.subdomains == []
    assert recon.subdomain_error is not None
    assert "502" in recon.subdomain_error


@responses.activate
def test_healthy_crtsh_leaves_no_error():
    _register({}, subdomains=["www.example.com"])
    recon = dns_recon.recon("example.com", Config(), deep=False)
    assert recon.subdomain_error is None
    assert recon.subdomains == ["www.example.com"]


@responses.activate
def test_crtsh_failure_surfaces_as_a_profile_note():
    from footprint import aggregate

    responses.add_callback(
        responses.GET, "https://cloudflare-dns.com/dns-query",
        callback=_doh_router({}), content_type="application/json",
    )
    responses.add(responses.GET, "https://crt.sh/", body="nope", status=502)
    responses.add(responses.GET, "https://haveibeenpwned.com/api/v3/breaches",
                  json=[], status=200)

    profile = aggregate.domain_profile("example.com", Config(), deep=False)

    assert any("crt.sh" in n for n in profile.notes)


@responses.activate
def test_null_dkim_key_is_not_reported_as_found():
    """An empty p= is a revoked key (RFC 6376), not a live one.

    Some domains publish a wildcard null key meaning "we send no mail"; without
    this, DKIM would be reported on every selector name we happen to try.
    """
    _register({
        ("example.com", "MX"): ["0 ."],
        ("google._domainkey.example.com", "TXT"): ['"v=DKIM1; p="'],
        ("s1._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p="'],
    })

    assert dns_recon.recon("example.com", Config()).dkim_selectors == []


@responses.activate
def test_a_real_key_is_still_found():
    _register({
        ("example.com", "MX"): ["10 mail.example.com"],
        ("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=MIIBIjANBg"'],
    })

    assert dns_recon.recon("example.com", Config()).dkim_selectors == ["google"]


@responses.activate
def test_a_cname_target_alone_is_not_a_key():
    """A selector CNAMEs to its ESP; the alias string must not count as a key."""
    _register({
        ("example.com", "MX"): ["10 mail.example.com"],
        ("k1._domainkey.example.com", "TXT"): ["dkim.mcsv.net."],
    })

    assert dns_recon.recon("example.com", Config()).dkim_selectors == []
