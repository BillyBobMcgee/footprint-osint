# Changelog

All notable changes to this project are documented here. Versions follow
[semantic versioning](https://semver.org/).

## [0.3.0]

### Added

- **Bulk scanning** — `footprint batch` handles emails, domains, usernames, and
  passwords through one code path, auto-detecting the kind per file. Input is
  plain text, one subject per line. Password mode labels entries by line number
  and detects reuse locally; passwords are never used as a subject, written to
  a report, or sent to a webhook, lookups are keyed by hash, and entries
  sharing a hash prefix share a single API call. Available from the CLI, the
  interactive menu, and the GUI, which streams each row as it finishes.

- **Local web GUI** (`footprint gui`) built on the standard library — no extra
  dependencies. Sources stream progress over Server-Sent Events so results fill
  in as they arrive. Binds loopback only, and gates every API call behind a
  per-run random token.
- **Exposure scoring** — an explainable 0-100 score computed locally from
  breach count, recency, and the severity of what actually leaked, with the
  reasons always summing to the score.
- **Remediation advice** derived from the leaked data classes, so the steps are
  specific: leaked security questions say to replace them with random strings,
  a leaked phone number says to set a carrier port-out PIN.
- **Deeper domain recon** — DNSSEC, DKIM selector probing, MTA-STS, TLS-RPT,
  and BIMI, plus subdomain-takeover detection across 19 hosting services.
  Takeover requires both a matching CNAME target and the service's "nothing
  here" fingerprint, so healthy sites are not flagged for their host.
- **Username scoring** for cross-site linkability, weighting sensitive and
  identity-linked sites.
- **Webhooks** — push any result to Discord (rich embed plus the full HTML
  report as an attachment) or to any JSON endpoint. Managed with
  `footprint webhook add|remove|list|test|enable|disable`. Each webhook has its
  own on/off switch (a tickbox per webhook in the GUI) so one can be muted
  without deleting it; only enabled webhooks receive anything. Bulk runs attach
  one report per exposed subject.
- `footprint watch` and `footprint batch` as real subcommands; both were
  previously reachable only from the interactive menu.
- `--fail-on SCORE` to gate the exit code on severity rather than on any
  finding at all.

### Changed

- The interactive menu's batch option now uses the bulk module, so it handles
  domains, usernames, and passwords instead of only emails.
- Results are delivered to enabled webhooks automatically. `--notify` is no
  longer needed (it is kept as a no-op); use `--no-notify`, or switch the
  webhook off, to suppress delivery.
- Reports are HTML only. The Markdown and CSV writers are gone, along with the
  `--save {md,html,csv}` choice; `--save` is now a flag.
- Email profiles run their sources concurrently, cutting a profile from roughly
  eight sequential round-trips to one.
- Watch mode now fingerprints domain findings, so a new subdomain takeover or a
  DMARC policy regression raises an alert. Previously only HIBP breaches did.
- crt.sh gets a hard timeout and no status retries. It 502s often, and the
  shared session's retry policy turned an outage into a multi-minute stall.

### Fixed

- A failed crt.sh lookup reported "0 subdomains", which read as a clean result
  while also silently disabling takeover detection. Failures are now surfaced.
- DKIM selector detection no longer false-positives on unrelated text in a
  CNAME chain.
- Console output falls back to ASCII where the terminal encoding cannot
  represent box-drawing characters, instead of raising mid-report on the legacy
  Windows console.

## [0.2.0]

- Initial public release: email, password, domain, and username checks across
  HIBP, XposedOrNot, holehe, EmailRep, DeHashed, Intelligence X, Hunter.io,
  crt.sh, and the WhatsMyName dataset, with Markdown/HTML/CSV reports, Tor
  routing, and a response cache.
