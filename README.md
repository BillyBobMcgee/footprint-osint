# footprint

[![CI](https://github.com/BillyBobMcgee/footprint-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/BillyBobMcgee/footprint-osint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/footprint-osint)](https://pypi.org/project/footprint-osint/)
[![Python](https://img.shields.io/pypi/pyversions/footprint-osint)](https://pypi.org/project/footprint-osint/)
[![License](https://img.shields.io/github/license/BillyBobMcgee/footprint-osint)](LICENSE)

Check what an email, password, domain, or username exposes: public breach data,
leak indexes, public profiles. Then score it and say what to fix.

Works with **no API keys**. There's a CLI and a local web GUI.

```bash
pip install footprint-osint
footprint gui                      # web interface
footprint email you@example.com    # or the CLI
footprint                          # or an interactive menu
```

<!-- Screenshots: save them as docs/gui.png and docs/cli.png, then remove the comment markers.
![The GUI results page](docs/gui.png)
![CLI output with the exposure score](docs/cli.png)
-->

From source: `git clone https://github.com/BillyBobMcgee/footprint-osint && cd footprint-osint && pip install -e .`

## Authorized use only

For checking your own exposure, or assessments you're authorized to do. Using it
to profile or target people isn't supported and may be illegal.

## What it checks

| | | Needs a key? |
|---|---|---|
| **Email** | Breaches, pastes, leak records, dark-web hits, reputation, and which sites the address is registered on, merged into one timeline | no |
| **Password** | Whether it's in breach corpora, via k-anonymity | no |
| **Domain** *(proof of concept)* | SPF/DMARC/DKIM/DNSSEC/MTA-STS posture, subdomains, dangling-CNAME takeover checks | no |
| **Username** | Presence across ~700 sites, scored for cross-site linkability | no |
| **Bulk** | Any of the above, one subject per line | no |
| **Watch** | Re-scan a list and alert only on what's new | no |

API keys (HIBP, DeHashed, IntelX, Hunter) only add more; nothing needs them.
Install `footprint[holehe]` for keyless registered-account discovery.

## Exposure score

Every result gets a 0-100 score, worked out locally from what the sources
returned. No extra request, no key. It's a plain sum of the reasons listed
underneath it, so the numbers always add up:

```
Exposure score  ████████████████░░░░  78/100 - High
  ▲ +24  appears in 210 known breaches
  ▲ +26  critical data exposed: Auth tokens, Credit cards, Passwords
  ▲ +12  a breach occurred within the last year
  ▲ + 7  15 registered account(s) discoverable from this address
```

Bands are 0-19 Minimal, 20-39 Low, 40-59 Moderate, 60-79 High, 80+ Critical.
The total caps at 100.

### Email

| Finding | Points |
|---|---|
| Known breaches | 6 for the first, +3 each after, max 24 |
| Critical data leaked | what the worst class is worth, +4 each after, max 44 |
| Identity data leaked | what the worst class is worth, +2 each after, max 22 |
| Newest breach under a year old | 12 |
| Newest breach 1-3 years old | 6 |
| Leak records (DeHashed) | 6 for the first, +2 each after, max 14 |
| Dark-web index hits (IntelX) | 4 for the first, +2 each after, max 10 |
| Public pastes | 3, plus 1 each, max 8 |
| Registered accounts | 2, plus 1 per 3 accounts, max 8 |
| Reputation flags (EmailRep) | 4 each |

The two "data leaked" rows are what separate a bad breach from a boring one.
Each breach lists the categories of data it exposed, and each category carries
its own weight, because they are not remotely equal:

- **Critical**, 12 to 32 points: passwords and hashes and crypto seed phrases
  at the top, then private keys, social security numbers, bank and card
  details, passports and government IDs, auth tokens, PINs, security
  questions, tax records.
- **Identity**, 5 to 14 points: health and sexual orientation at the top, then
  religion, politics and ethnicity, date of birth, private messages, home
  address, geolocation, phone, finances, employer, vehicle and device
  identifiers.

The worst class sets the level and the rest adds on top. Everything else
(email addresses, usernames, gender, device details) scores nothing.

That ordering is the point. One breach that leaked your password scores higher
than ten that leaked nothing but your email address, and a leaked password
alone lands in Moderate rather than reading as fine.

### Domain

| Finding | Points |
|---|---|
| No DMARC record | 16 |
| No SPF record, or SPF ending in `+all` | 14 |
| DMARC `p=none` | 9 |
| DMARC `p=quarantine` | 3 |
| No DNSSEC | 5 |
| No MTA-STS policy | 4 |
| MX present but no DKIM at the common selectors | 4 |
| Dangling subdomain | 12 each, max 30 |
| Over 50 subdomains public in certificate transparency | 4 |
| Breaches affecting the domain | 4 for the first, +2 each after, max 12 |

### Username

This one measures linkability, not compromise. Nothing here means an account
was breached; it's about one handle tying your profiles together.

| Finding | Points |
|---|---|
| Handle found on public sites | 4, plus 2 per site, max 30 |
| Found on a sensitive site | 10 each, max 25 |
| Found on two or more identity-linked sites | 5 each, max 20 |

Which sites count comes from the category WhatsMyName gives each one: NSFW,
dating, health and political are sensitive; finance and business are
identity-linked.

### Advice

The same categories pick the remediation steps, which is why they're specific:
leaked security questions say to replace them with random strings, a leaked
phone number says to set a carrier port-out PIN.

> The advice is a proof of concept and may be inaccurate.

## Bulk

One subject per line, plain text.

```bash
footprint batch emails.txt                    # detects the kind
footprint batch domains.txt
footprint batch passwords.txt --kind password # passwords must be explicit
footprint batch emails.txt --save --out-dir reports
```

Passwords are never auto-detected, because guessing that a line is a secret
would be unsafe. In password mode entries are labelled by **line number**, so
you learn which one to fix without the secret ever being shown:

```
   95 Critical line 1  seen 65,763x · reused
    0 Minimal  line 2  not found
```

A password is never used as a subject or written to a report. The webhook
message does name it, since a verdict you cannot match to a password is not
much use; `--no-notify` skips that. Lookups are keyed by hash, and passwords
sharing a hash prefix share a single API call. Reuse is detected locally and
costs nothing.

Bulk is in the GUI too. Paste a list or load a .txt, and rows fill in as each
subject finishes.

## Watch

Track subjects and hear only about what's new. Everything already reported is
fingerprinted locally, so a breach is announced once.

The first check sets the baseline: it records what's already there without
alerting. Changes are flagged from the second check on.

```bash
footprint watch add you@example.com
footprint watch add example.com --kind domain
footprint watch check              # exits 1 if anything is new
footprint watch check --quiet      # silent unless something appears, for cron
```

Windows Task Scheduler:

```powershell
schtasks /create /tn "footprint-watch" /sc daily /st 09:00 ^
  /tr "C:\path\to\.venv\Scripts\python.exe -m footprint watch check --quiet"
```

> Watch is **at-most-once**: a finding is marked seen the moment it's reported,
> so if delivery fails you won't be told again. Test your webhook first.

## Webhooks

Push results to Discord, or any JSON endpoint.

```bash
footprint webhook add https://discord.com/api/webhooks/...
footprint webhook test
footprint webhook list          # redacted, a webhook URL is a secret
footprint webhook disable 1     # mute without deleting
```

Once a webhook is enabled **every check delivers to it**; there's no flag to
remember. Use `--no-notify` to skip one run, or switch the webhook off.

Discord messages are colour-coded by severity and carry the full HTML report as
an attachment, since the embed is only a summary. Bulk runs attach one report
per exposed subject.

Password checks name the password in the message, so you can tell which
verdict is which. `--no-notify` skips it.

A dead webhook never fails a scan; delivery errors are warnings.

## The GUI

```bash
footprint gui                    # http://127.0.0.1:8731
```

One hand-written page served by Python's own `http.server`. No Flask, no Node,
no build step, no extra dependency. Sources stream their progress as they
finish rather than hanging until everything returns. API keys and webhooks are
editable under Settings, saved to the same config the CLI uses.

It binds loopback only, and every API call carries a random per-run token, since
any site you have open could otherwise POST to `localhost` in the background.

**Recent** keeps the last 200 scans so you can reopen one without running it
again, password checks included. A password check is stored under a masked
subject (`h*****2`), so the entry tells you which password without a report or
a download filename ever holding the real one. Those entries hold real exposure
data, so the CLI can list and delete them:

```bash
footprint history           # what's stored
footprint history clear     # delete all of it
footprint history off       # stop recording new scans
``` A row of source chips under the input shows what will actually run, so a
missing key isn't a surprise afterwards. Long sweeps have a Stop button, and
results export as the HTML report or the raw JSON. Password checks are never
recorded.

## Exit codes

`0` nothing found · `1` exposure found · `2` source error · `3` usage error

Any finding exits 1, which for a long-lived address is always true. `--fail-on`
switches to a severity threshold instead:

```bash
footprint domain example.com --fail-on 60
```

## Configuration

Set keys in Settings, or as environment variables, which take precedence. Config
lives at `%APPDATA%\footprint\config.json` or `~/.config/footprint/config.json`,
and supports named profiles (`--profile work`).

```bash
export HIBP_API_KEY=...        # email/paste lookups
export DEHASHED_EMAIL=...      # DeHashed account email
export DEHASHED_API_KEY=...    # secrets are redacted
export INTELX_API_KEY=...      # metadata only
export HUNTER_API_KEY=...      # domain email pattern
export EMAILREP_API_KEY=...    # optional; raises the keyless rate limit
export FOOTPRINT_WEBHOOKS=...  # comma-separated webhook URLs
```

Global flags: `--json`, `--cache` / `--no-cache`, `--profile NAME`,
`--timeout SECONDS`. Reports are HTML: `--save` `--out PATH`.

The GUI records finished scans so you can reopen them. `footprint history off`
turns that off, and the config file keeps the setting as `"history": false`.

## Exposure, not credentials

footprint reports *which* breach, *when*, and *what categories* of data were
involved. It never returns or stores plaintext credentials. Sources that expose
raw secrets (DeHashed, IntelX) are integrated with their values redacted, so
footprint records that a password was present, not what it was.

The password check computes the SHA-1 locally and sends only the **first 5 hex
characters** to the Pwned Passwords range API, matching the rest on your
machine. The password itself never goes to any source.

It does go to your webhook, so the message says which password the verdict is
about. Use `--no-notify` if you'd rather it didn't. Bulk runs are unchanged;
those rows stay labelled by line number.

## Domain checks are a proof of concept

SPF, DMARC and MX come straight from DNS and are reliable. The rest is
best-effort: DKIM only probes 15 common selector names, takeover detection
samples up to 40 subdomains against 19 known services, and subdomain
enumeration depends on crt.sh, which is often down (footprint says so rather
than reporting zero).

Takeover detection needs **both** a CNAME pointing at a known service *and* that
service's "nothing here" page, so a healthy site isn't flagged for its host.

A clean result isn't proof. Verify anything that matters with a dedicated tool.

## Development

```bash
pip install -r requirements.txt   # editable install + test/lint tooling
pytest -q                         # HTTP is mocked; no network calls
ruff check .
```

Dependencies are declared once, in `pyproject.toml`. `requirements.txt` is a
one-line shim pointing at it.

## Sources

[XposedOrNot](https://xposedornot.com/) ·
[holehe](https://github.com/megadose/holehe) ·
[Have I Been Pwned](https://haveibeenpwned.com/) ·
[Pwned Passwords](https://haveibeenpwned.com/Passwords) ·
[EmailRep](https://emailrep.io/) ·
[DeHashed](https://dehashed.com/) ·
[Intelligence X](https://intelx.io/) ·
[Hunter.io](https://hunter.io/) ·
[crt.sh](https://crt.sh/) ·
Cloudflare DNS-over-HTTPS ·
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName) ·
[Gravatar](https://gravatar.com/)

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
