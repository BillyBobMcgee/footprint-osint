# footprint

Check what an email, password, domain, or username exposes — from public breach
data, leak indexes, and public profiles. Then score it and say what to fix.

Works with **no API keys**. There's a CLI and a local web GUI.

```bash
pip install -e .
footprint gui                      # web interface
footprint email you@example.com    # or the CLI
footprint                          # or an interactive menu
```

## Authorized use only

For checking your own exposure, or assessments you're authorized to do. Using it
to profile or target people isn't supported and may be illegal.

## What it checks

| | | Needs a key? |
|---|---|---|
| **Email** | Breaches, pastes, leak records, dark-web hits, reputation, and which sites the address is registered on — merged into one timeline | no |
| **Password** | Whether it's in breach corpora, via k-anonymity | no |
| **Domain** *(proof of concept)* | SPF/DMARC/DKIM/DNSSEC/MTA-STS posture, subdomains, dangling-CNAME takeover checks | no |
| **Username** | Presence across ~600 sites, scored for cross-site linkability | no |
| **Bulk** | Any of the above, one subject per line | no |
| **Watch** | Re-scan a list and alert only on what's *new* | no |

API keys (HIBP, DeHashed, IntelX, Hunter) only add more; nothing needs them.
Install `footprint[holehe]` for keyless registered-account discovery.

## Exposure score

Every result gets a 0–100 score, computed locally from the findings — no extra
request, no key. It's additive and explainable: the reasons always add up to the
number.

```
Exposure score  ████████████████░░░░  78/100 - High
  ▲ +24  appears in 210 known breaches
  ▲ +26  critical data exposed: Auth tokens, Credit card details, Government IDs
  ▲ +12  a breach occurred within the last year
  ▲ + 7  15 registered account(s) discoverable from this address
```

It weighs breach count, how recent, and **what actually leaked** — a leak of
email addresses isn't the same event as one of password hashes and government
IDs. Those same buckets drive the advice, which is why it's specific: leaked
security questions say to replace them with random strings, a leaked phone
number says to set a carrier port-out PIN.

> The advice is a proof of concept and may be inaccurate.

## Bulk

One subject per line, plain text.

```bash
footprint batch emails.txt                    # detects the kind
footprint batch domains.txt
footprint batch passwords.txt --kind password # passwords must be explicit
footprint batch emails.txt --save --out-dir reports
```

Passwords are never auto-detected — guessing that a line is a secret would be
unsafe. In password mode entries are labelled by **line number**, so you learn
which one to fix without the secret ever being shown:

```
   95 Critical line 1  seen 65,763x · reused
    0 Minimal  line 2  not found
```

A password is never used as a subject, written to a report, or sent to a
webhook. Lookups are keyed by hash, and passwords sharing a hash prefix share a
single API call. Reuse is detected locally and costs nothing.

Bulk is in the GUI too — paste a list or load a .txt, and rows fill in as each
subject finishes.

## Watch

Track subjects and hear only about what's new. Everything already reported is
fingerprinted locally, so a breach is announced once.

```bash
footprint watch add you@example.com
footprint watch add example.com --kind domain
footprint watch check              # exits 1 if anything is new
footprint watch check --quiet      # silent unless something appears — for cron
```

Windows Task Scheduler:

```powershell
schtasks /create /tn "footprint-watch" /sc daily /st 09:00 ^
  /tr "C:\path\to\.venv\Scripts\python.exe -m footprint watch check --quiet"
```

> Watch is **at-most-once**: a finding is marked seen the moment it's reported,
> so if delivery fails you won't be told again. Test your webhook first.

## Webhooks

Push results to Discord (or any JSON endpoint) so they reach you where you
actually look.

```bash
footprint webhook add https://discord.com/api/webhooks/...
footprint webhook test
footprint webhook list          # redacted — a webhook URL is a secret
footprint webhook disable 1     # mute without deleting
```

Once a webhook is enabled **every check delivers to it** — there's no flag to
remember. Use `--no-notify` to skip one run, or switch the webhook off.

Discord messages carry the full HTML report as an attachment, since the embed is
only ever a summary. Bulk runs attach one report per exposed subject.

Password checks send the verdict only — whether it was found and how often. The
password itself is never transmitted.

A dead webhook never fails a scan; delivery errors are warnings.

## The GUI

```bash
footprint gui                    # http://127.0.0.1:8731
```

One hand-written page served by Python's own `http.server` — no Flask, no Node,
no build step, no extra dependency. Sources stream their progress as they finish
rather than hanging until everything returns. API keys, Tor, and webhooks are
editable under Settings, saved to the same config the CLI uses.

It binds loopback only, and every API call carries a random per-run token — any
site you have open could otherwise POST to `localhost` in the background.

## Exit codes

`0` nothing found · `1` exposure found · `2` source error · `3` usage error

Any finding exits 1, which for a long-lived address is always true. `--fail-on`
switches to a severity threshold instead:

```bash
footprint domain example.com --fail-on 60
```

## Configuration

Set keys in Settings, or as environment variables. Config lives at
`%APPDATA%\footprint\config.json` or `~/.config/footprint/config.json`, and
supports named profiles (`--profile work`).

```bash
export HIBP_API_KEY=...        # email/paste lookups
export DEHASHED_EMAIL=...      # DeHashed account email
export DEHASHED_API_KEY=...    # secrets are redacted
export INTELX_API_KEY=...      # metadata only
export HUNTER_API_KEY=...      # domain email pattern
export EMAILREP_API_KEY=...    # optional; raises the keyless rate limit
export FOOTPRINT_WEBHOOKS=...  # comma-separated webhook URLs
```

Global flags: `--json`, `--tor`, `--cache` / `--no-cache`, `--profile NAME`,
`--timeout SECONDS`. Reports are HTML: `--save` `--out PATH`.

## Exposure, not credentials

footprint reports *which* breach, *when*, and *what categories* of data were
involved. It never returns or stores plaintext credentials. Sources that expose
raw secrets (DeHashed, IntelX) are integrated with their values redacted —
footprint records that a password was present, not what it was.

The password check computes the SHA-1 locally and sends only the **first 5 hex
characters** to the Pwned Passwords range API, matching the rest on your
machine. The password never leaves your computer.

## Domain checks are a proof of concept

SPF, DMARC and MX come straight from DNS and are reliable. The rest is
best-effort: DKIM only probes 15 common selector names, takeover detection
samples up to 40 subdomains against 19 known services, and subdomain
enumeration depends on crt.sh, which is often down (footprint says so rather
than reporting zero).

Takeover detection needs **both** a CNAME pointing at a known service *and* that
service's "nothing here" page, so a healthy site isn't flagged for its host.

A clean result isn't proof. Verify anything that matters with a dedicated tool.

## Tor

```bash
footprint --tor email you@example.com
```

Needs a running SOCKS proxy; defaults to `socks5h://127.0.0.1:9050`.

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

## License

MIT — see [LICENSE](LICENSE).
