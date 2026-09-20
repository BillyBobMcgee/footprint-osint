"""Domain DNS / email-security posture and subdomain discovery.

Uses DNS-over-HTTPS (Cloudflare) for record lookups so no extra DNS
dependency is required, and crt.sh certificate transparency logs for
passive subdomain enumeration. All sources are public; no key needed.

Beyond the basics (MX/SPF/DMARC) this also checks the controls that decide
whether mail to the domain can be forged or downgraded (DNSSEC, DKIM,
MTA-STS, BIMI) and looks for subdomains whose CNAME points at a service
that no longer claims them, which is the classic takeover setup.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any, Callable
from urllib.parse import quote

from footprint.config import Config
from footprint.models import DomainRecon
from footprint.sources.base import SourceError, build_session, fetch

DOH_URL = "https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"
CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
# (connect, read) for crt.sh. A busy domain genuinely needs 30-40s to answer,
# but a dead host should fail fast instead of burning the whole budget.
CRT_TIMEOUT = (6.0, 45.0)

# Selectors used by the big mail providers and ESPs. A DKIM key is published
# at <selector>._domainkey.<domain>, and there is no way to enumerate them, so
# probing the common names is the standard passive approach.
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "mail", "dkim", "smtp", "mandrill", "zoho", "sendgrid", "everlytickey1",
)

# CNAME target -> the fingerprint an unclaimed instance serves. If a subdomain
# points at one of these and the body matches, the resource is dangling and
# anyone can claim the name.
TAKEOVER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("herokudns.com", "No such app", "Heroku"),
    ("ghost.io", "Domain error", "Ghost"),
    ("cargocollective.com", "404 Not Found", "Cargo"),
    ("wpengine.com", "The site you were looking for couldn't be found", "WP Engine"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"),
    ("readthedocs.io", "unknown to Read the Docs", "Read the Docs"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("surge.sh", "project not found", "Surge"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("netlify.app", "Not Found - Request ID", "Netlify"),
    ("shopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("unbouncepages.com", "The requested URL was not found on this server", "Unbounce"),
    ("helpjuice.com", "We could not find what you're looking for", "Helpjuice"),
    ("helpscoutdocs.com", "No settings were found for this company", "Help Scout"),
    ("tictail.com", "to target URL: <a href=\"https://tictail.com", "Tictail"),
    ("campaignmonitor.com", "Trying to access your account?", "Campaign Monitor"),
)

# crt.sh can return thousands of names and each check is a request, so only
# sample the first N rather than probing everything.
_TAKEOVER_LIMIT = 40


def _doh(config: Config, name: str, rtype: str) -> list[str]:
    """Query one record type over DNS-over-HTTPS. Returns record data strings."""
    result = fetch(
        config,
        DOH_URL.format(name=quote(name, safe=""), rtype=rtype),
        headers={"Accept": "application/dns-json"},
        source="DoH",
    )
    if result.status_code != 200:
        return []
    answers = (result.json() or {}).get("Answer", []) or []
    return [a.get("data", "").strip('"') for a in answers if a.get("data")]


def _doh_authenticated(config: Config, name: str, rtype: str = "A") -> bool:
    """True when the resolver reports the answer as DNSSEC-validated (AD bit)."""
    result = fetch(
        config,
        DOH_URL.format(name=quote(name, safe=""), rtype=rtype) + "&do=true",
        headers={"Accept": "application/dns-json"},
        source="DoH",
    )
    if result.status_code != 200:
        return False
    return bool((result.json() or {}).get("AD"))


def _subdomains(config: Config, domain: str) -> tuple[list[str], str | None]:
    """Passive subdomain enumeration via certificate transparency.

    Returns (subdomains, error). crt.sh is often down, and an empty list from a
    failed lookup looks identical to a domain with no subdomains, while also
    silently disabling takeover detection. So failures are reported.
    """
    # crt.sh needs 20-40s for a busy domain, so the 15s default cuts it off.
    # It also 502s constantly, and retrying a service that is shedding load
    # just multiplies the wait, so no status retries here.
    session = build_session(replace(config, max_retries=0))
    try:
        result = fetch(config, CRT_URL.format(domain=quote(domain, safe="")),
                       source="crt.sh", timeout=CRT_TIMEOUT, session=session)
    except SourceError as exc:
        return [], str(exc)
    finally:
        session.close()
    if result.status_code != 200:
        return [], (f"crt.sh returned HTTP {result.status_code}; subdomain and "
                    "takeover checks did not run")
    try:
        rows = result.json() or []
    except ValueError:
        return [], "crt.sh returned a malformed response"

    found: set[str] = set()
    for row in rows:
        for name in (row.get("name_value", "") or "").splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                found.add(name)
    return sorted(found), None


def _is_live_key(record: str) -> bool:
    """Whether a TXT record is a usable DKIM key.

    A record with an empty p= is a revoked key (RFC 6376), and some domains
    publish a wildcard null key to say "we send no mail", so counting those as
    found would report DKIM on every selector name tried.
    """
    text = record.strip().strip('"')
    lowered = text.lower()
    if "v=dkim1" not in lowered and "k=" not in lowered:
        return False
    for part in text.split(";"):
        part = part.strip()
        if part[:2].lower() == "p=" and part[2:].strip():
            return True
    return False


def _dkim_selectors(config: Config, domain: str) -> list[str]:
    """Probe the common DKIM selectors and return the ones that have a key."""
    def has_key(selector: str) -> str | None:
        records = _doh(config, f"{selector}._domainkey.{domain}", "TXT")
        return selector if any(_is_live_key(r) for r in records) else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        found = pool.map(has_key, DKIM_SELECTORS)
    return [s for s in found if s]


def _mta_sts(config: Config, domain: str) -> str | None:
    records = _doh(config, f"_mta-sts.{domain}", "TXT")
    return next((r for r in records if r.lower().startswith("v=stsv1")), None)


def _tls_rpt(config: Config, domain: str) -> str | None:
    records = _doh(config, f"_smtp._tls.{domain}", "TXT")
    return next((r for r in records if r.lower().startswith("v=tlsrptv1")), None)


def _bimi(config: Config, domain: str) -> str | None:
    records = _doh(config, f"default._bimi.{domain}", "TXT")
    return next((r for r in records if r.lower().startswith("v=bimi1")), None)


def _check_takeover(config: Config, host: str) -> dict | None:
    """Flag a subdomain whose CNAME points at an unclaimed hosted resource.

    Both conditions must hold: the CNAME target matches a known service, and
    fetching the host returns that service's "nothing here" page. Requiring the
    body match stops healthy sites being flagged just for their host.
    """
    cnames = _doh(config, host, "CNAME")
    if not cnames:
        return None
    target = cnames[0].rstrip(".").lower()

    for suffix, fingerprint, service in TAKEOVER_SIGNATURES:
        if suffix not in target:
            continue
        try:
            result = fetch(config, f"https://{host}/", source="takeover-probe",
                           cache_ttl=0)
        except SourceError:
            try:
                result = fetch(config, f"http://{host}/", source="takeover-probe",
                               cache_ttl=0)
            except SourceError:
                return None
        if fingerprint.lower() in (result.text or "").lower():
            return {"host": host, "target": target, "service": service}
        return None
    return None


def _find_takeovers(config: Config, domain: str, subdomains: list[str]) -> list[dict]:
    """Probe a bounded sample of subdomains for dangling CNAMEs."""
    candidates = [s for s in subdomains if s != domain][:_TAKEOVER_LIMIT]
    if not candidates:
        return []
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = pool.map(lambda h: _check_takeover(config, h), candidates)
    return [r for r in results if r]


def _dmarc_policy(record: str | None) -> str | None:
    for part in (record or "").split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return part.split("=", 1)[1].strip()
    return None


def _gather(jobs: dict[str, Callable[[], Any]]) -> dict[str, Any]:
    """Run independent lookups together; each is its own round-trip otherwise."""
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {key: pool.submit(fn) for key, fn in jobs.items()}
        return {key: future.result() for key, future in futures.items()}


def recon(domain: str, config: Config, *, deep: bool = True) -> DomainRecon:
    """Gather DNS, email-security posture, subdomains, and takeover risk.

    deep=False fetches only the cheap records (MX/SPF/DMARC and subdomains).
    """
    if not domain or "." not in domain:
        raise SourceError(f"'{domain}' does not look like a domain.")

    # MX first, on its own: it decides whether DKIM is worth probing at all.
    mx = sorted(_doh(config, domain, "MX"))

    jobs: dict[str, Callable[[], Any]] = {
        "txt": lambda: _doh(config, domain, "TXT"),
        "dmarc": lambda: _doh(config, f"_dmarc.{domain}", "TXT"),
        # crt.sh is the slow one, so it runs alongside the DNS work rather
        # than in front of it.
        "subs": lambda: _subdomains(config, domain),
    }
    if deep:
        jobs.update({
            "dnssec": lambda: _doh_authenticated(config, domain),
            "mta_sts": lambda: _mta_sts(config, domain),
            "tls_rpt": lambda: _tls_rpt(config, domain),
            "bimi": lambda: _bimi(config, domain),
            "dkim": lambda: _dkim_selectors(config, domain) if mx else [],
        })
    got = _gather(jobs)

    dmarc = next((t for t in got["dmarc"] if t.lower().startswith("v=dmarc1")), None)
    subdomains, subdomain_error = got["subs"]
    result = DomainRecon(
        domain=domain,
        mx=mx,
        spf=next((t for t in got["txt"] if t.lower().startswith("v=spf1")), None),
        dmarc=dmarc,
        dmarc_policy=_dmarc_policy(dmarc),
        subdomains=subdomains,
        subdomain_error=subdomain_error,
    )

    if not deep:
        return result

    result.dnssec = got["dnssec"]
    result.mta_sts = got["mta_sts"]
    result.tls_rpt = got["tls_rpt"]
    result.bimi = got["bimi"]
    result.dkim_selectors = got["dkim"]
    # Needs the subdomain list, so it cannot join the batch above.
    result.takeovers = _find_takeovers(config, domain, subdomains)
    return result
