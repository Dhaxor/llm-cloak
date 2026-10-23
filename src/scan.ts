import type { GuardOptions, ScanReport } from "./types.js";
import { collectSpans, maxSeverity, resolveDetectors, toFinding } from "./internal/match.js";
import { scanInjection } from "./injection.js";

/**
 * Scan text without redacting anything: every secret/PII finding plus a
 * prompt-injection risk assessment in one pass. This powers the CLI gate and
 * is the right entry point for CI checks and agent pre-flight hooks.
 */
export function scan(text: string, options: GuardOptions = {}): ScanReport {
  const detectors = resolveDetectors(options);
  const spans = collectSpans(text, detectors, options.allow ?? []);
  const findings = spans.map(toFinding);
  const injection = scanInjection(text);

  const counts = { secrets: 0, pii: 0, custom: 0, injection: injection.findings.length };
  let risk: ReturnType<typeof maxSeverity> = injection.severity;
  for (const finding of findings) {
    counts[finding.category] += 1;
    risk = maxSeverity(risk, finding.severity);
  }

  return { findings, injection, risk, counts };
}
