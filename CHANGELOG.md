# Changelog

All notable changes to this project are documented here. Versions follow
[semantic versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [1.0.0] first release

Check what an email, password, domain, or username exposes, score it locally,
and say what to fix. Works with no API keys.

### Checks

- **Email**: breaches, pastes, leak records, dark-web index hits, reputation,
  and registered-account discovery, merged into one exposure timeline.
- **Password**: k-anonymity lookup against Pwned Passwords. Only the first 5
  characters of the SHA-1 go to the source. Webhook messages name the password
  so the verdict is readable, in bulk runs too; `--no-notify` skips it.
- **Domain** *(proof of concept)*: SPF/DMARC/DKIM/DNSSEC/MTA-STS/TLS-RPT/BIMI
  posture, certificate-transparency subdomains, and dangling-CNAME takeover
  detection across 19 hosting services.
- **Username**: presence across ~700 sites, scored for cross-site linkability.
- **Bulk**: any of the above from a plain text file, one subject per line.
  Password entries are labelled by line number on screen and in reports. Only
  the webhook message names them.
- **Watch**: re-scan a list and report only what is new since last time.

### Interfaces

- A CLI, an interactive menu, and a local web GUI (`footprint gui`) built on the
  standard library with no extra dependencies. The GUI streams source progress
  as results arrive, binds loopback only, and gates every API call behind a
  per-run random token.
- The GUI keeps the last 200 scans, so you can reopen one without running it
  again. It also shows which sources will run before you scan, stops a long
  sweep on request, and exports either the HTML report or the raw JSON.
  Password checks are recorded under a masked subject. `footprint history`
  lists what is stored, `history clear` deletes it, and `history off` stops
  recording.

### Output

- An explainable 0-100 exposure score computed locally, where the stated reasons
  always sum to the number, plus remediation steps derived from the data classes
  that actually leaked. Each leaked class carries its own weight, so one leaked
  password outranks a pile of breaches that only exposed an email address.
- Standalone HTML reports with a detailed breach table.
- Webhooks to Discord or any JSON endpoint, each with its own on/off switch.
  Discord embeds are colour-coded by severity and carry the full report as
  an attachment.
- `--fail-on SCORE` to gate the exit code on severity rather than on any finding.

### Notes

- A scan that cannot reach any source is reported as a failure and exits `2`,
  never as a clean result.
- crt.sh is frequently unavailable; when it is, footprint says so rather than
  reporting zero subdomains.
