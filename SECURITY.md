# Security Policy

## Scope and honest limitations

`llm-cloak` is a **local, heuristic** filter. It greatly reduces the
chance that credentials and PII reach a model provider, and catches the
common prompt-injection patterns seen in the wild. It is **not** a guarantee:

- Regex detectors recognize **format-defined** secrets. A random password
  pasted as bare prose with no key-like structure may not be redacted.
- Injection scanning catches known patterns. Novel, subtle, or multilingual
  payloads may pass. Treat severity as triage, not verdict.
- Never feed `restore()` output to untrusted sinks, and never log the
  `mappings` object — it contains the original secrets by design.

For adversarial settings, layer defense in depth: least-privilege tools,
egress allowlists, human review — use llm-cloak as the first gate, not
the only one.

## Reporting a vulnerability

If you found a way to bypass redaction or injection detection that you
believe is practically exploitable, please report it privately:

1. Open a GitHub Security Advisory (Security tab → "Report a vulnerability"),
   or
2. Email the maintainer via the address on the GitHub profile.

Please include a minimal reproduction. Public issues are fine for false
positives / missed-format bugs that are not exploitable bypasses.

## Handling

- Reports are acknowledged within 7 days.
- Fixes for accepted vulnerabilities ship within 30 days where feasible.
