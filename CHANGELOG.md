# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-23

### Added

- `redact()` — reversible secret & PII redaction with typed placeholders.
  - 20+ secret detectors: OpenAI, Anthropic, OpenRouter, Google, GitHub,
    GitLab, Slack (tokens + webhooks), Stripe, AWS (key IDs + secret
    assignments), SendGrid, Twilio, npm, Hugging Face, Shopify,
    DigitalOcean, Atlassian, JWTs, PEM private keys, bearer tokens,
    database connection strings, credential-bearing URLs, `.env`-style
    assignments, high-entropy tokens.
  - PII detectors: email, phone (E.164 + US), credit card (Luhn), IBAN
    (mod-97), US SSN (area validation), IPv4 (octet validation).
- `restore()` — placeholder → original-value substitution with collision-safe
  ordering and optional case-insensitive matching.
- `scan()` — unified secrets + PII + injection report.
- `scanInjection()` — 14 weighted prompt-injection rules with a 0–100 risk
  score and severity buckets.
- `createGuardSession()` — multi-turn sessions with stable placeholder
  identities and deep object redaction/restore for API payloads.
- CLI: `scan`, `redact`, `restore`, `detectors`, `rules` with `--json`,
  exit-code gates (`--fail-on`), mapping files, placeholder styles, and
  stdin support.
- Custom detectors (regex or function), allowlists, include/exclude filters.
- Dual ESM/CJS builds, zero runtime dependencies, Node 18.17+.
