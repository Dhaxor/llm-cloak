import type { Finding, GuardOptions, GuardSession, RedactionResult, RestoreOptions } from "./types.js";
import { buildPlaceholder, collectSpans, resolveDetectors, toFinding, type NormalizedDetector } from "./internal/match.js";
import { restore as restoreText } from "./restore.js";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

/**
 * A multi-turn guard session with stable placeholder numbering.
 *
 * In chats and agents the same value appears across many turns; the session
 * keeps `jane@acme.io` pinned to `[EMAIL_1]` for the whole conversation, so
 * model responses can be restored at any point.
 *
 * ```ts
 * import { createGuardSession } from "llm-cloak";
 *
 * const guard = createGuardSession();
 * const { text } = guard.redact("Deploy with OPENAI_API_KEY=sk-proj-…");
 * // later, on the model's reply:
 * const clean = guard.restore(modelReply);
 * ```
 */
export function createGuardSession(options: GuardOptions = {}): GuardSession {
  const detectors: NormalizedDetector[] = resolveDetectors(options);
  const mappings: Record<string, string> = {};
  const findings: Finding[] = [];
  const counters = new Map<string, number>();
  const style = options.placeholderStyle ?? "bracket";
  const builder = options.placeholderBuilder ?? ((typeName: string, index: number) => buildPlaceholder(style, typeName, index));

  const redactString = (text: string): RedactionResult => {
    const spans = collectSpans(text, detectors, options.allow ?? []);
    const placeholders: string[] = [];
    const turnFindings: Finding[] = [];
    let count = 0;

    // Assign numbers in document order (stable with the session counters).
    for (const span of spans) {
      const next = (counters.get(span.detector.typeName) ?? 0) + 1;
      counters.set(span.detector.typeName, next);
      const placeholder = builder(span.detector.typeName, next);
      mappings[placeholder] = span.value;
      findings.push(toFinding(span));
      turnFindings.push(toFinding(span));
      placeholders.push(placeholder);
      count += 1;
    }

    let out = text;
    for (let i = spans.length - 1; i >= 0; i--) {
      const span = spans[i]!;
      out = out.slice(0, span.start) + placeholders[i]! + out.slice(span.end);
    }
    // Hand out a copy: the session keeps living in its own mappings object.
    return { text: out, findings: turnFindings, mappings: { ...mappings }, count };
  };

  const redactDeep = <T>(value: T): T => {
    if (typeof value === "string") return redactString(value).text as unknown as T;
    if (Array.isArray(value)) return value.map((item) => redactDeep(item)) as unknown as T;
    if (isPlainObject(value)) {
      const out: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value)) out[key] = redactDeep(item);
      return out as unknown as T;
    }
    return value;
  };

  const restore = (text: string, restoreOptions?: RestoreOptions): string => restoreText(text, mappings, restoreOptions);

  const restoreDeep = <T>(value: T, restoreOptions?: RestoreOptions): T => {
    if (typeof value === "string") return restore(value, restoreOptions) as unknown as T;
    if (Array.isArray(value)) return value.map((item) => restoreDeep(item, restoreOptions)) as unknown as T;
    if (isPlainObject(value)) {
      const out: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value)) out[key] = restoreDeep(item, restoreOptions);
      return out as unknown as T;
    }
    return value;
  };

  return {
    redact: redactString,
    redactDeep,
    restore,
    restoreDeep,
    get mappings() {
      return { ...mappings };
    },
    get findings() {
      return [...findings];
    },
    reset() {
      for (const key of Object.keys(mappings)) delete mappings[key];
      findings.length = 0;
      counters.clear();
    },
  };
}
