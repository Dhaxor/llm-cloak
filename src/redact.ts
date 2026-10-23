import type { Finding, GuardOptions, RedactionResult } from "./types.js";
import { buildPlaceholder, collectSpans, resolveDetectors, toFinding } from "./internal/match.js";

/**
 * Redact secrets and PII from text, replacing them with reversible placeholders.
 *
 * ```ts
 * import { redact } from "context-guard";
 *
 * const { text, mappings } = redact("Ping me at jane@acme.io about invoice 4111-1111-1111-1111");
 * // text: "Ping me at [EMAIL_1] about invoice [CREDIT_CARD_1]"
 * ```
 */
export function redact(text: string, options: GuardOptions = {}): RedactionResult {
  const detectors = resolveDetectors(options);
  const spans = collectSpans(text, detectors, options.allow ?? []);

  const style = options.placeholderStyle ?? "bracket";
  const builder = options.placeholderBuilder ?? ((typeName: string, index: number) => buildPlaceholder(style, typeName, index));

  const mappings: Record<string, string> = {};
  const findings: Finding[] = [];
  const counters = new Map<string, number>();

  // Number placeholders in document order, then splice back-to-front so
  // earlier offsets stay valid while the string is rebuilt.
  const placeholders = spans.map((span) => {
    const next = (counters.get(span.detector.typeName) ?? 0) + 1;
    counters.set(span.detector.typeName, next);
    findings.push(toFinding(span));
    const placeholder = builder(span.detector.typeName, next);
    mappings[placeholder] = span.value;
    return placeholder;
  });

  let out = text;
  for (let i = spans.length - 1; i >= 0; i--) {
    const span = spans[i]!;
    out = out.slice(0, span.start) + placeholders[i]! + out.slice(span.end);
  }

  return { text: out, findings, mappings, count: findings.length };
}