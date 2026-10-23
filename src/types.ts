/**
 * Shared types for llm-cloak.
 *
 * @packageDocumentation
 */

/** How seriously a finding should be taken. */
export type Severity = "none" | "low" | "medium" | "high" | "critical";

/** Broad detector families. `"custom"` is reserved for user-supplied detectors. */
export type DetectorCategory = "secrets" | "pii" | "custom";

/** Placeholder styles supported out of the box. */
export type PlaceholderStyle = "bracket" | "mustache" | "underscore";

/** A single detector description. Detectors are pure data + regex + optional validators. */
export interface Detector {
  /** Stable, kebab-case id, e.g. `"openai-api-key"`. Used for include/exclude lists and the CLI. */
  id: string;
  /** Human-readable label, e.g. `"OpenAI API key"`. */
  label: string;
  /** Which family the detector belongs to. */
  category: DetectorCategory;
  /** Severity when matched. Secrets are high/critical, most PII is medium. */
  severity: Severity;
  /** Baseline confidence (0–1) used by downstream consumers to triage. */
  confidence: number;
  /** Global regex. Must have the `g` flag. */
  regex: RegExp;
  /** 1-based capture group that holds the sensitive value. `undefined` means the whole match. */
  valueGroup?: number;
  /** Optional extra validation (e.g. Luhn check, IBAN mod-97) run on the captured value. */
  validate?: (value: string) => boolean;
  /** Higher priority wins when matches overlap. Defaults to 50. */
  priority?: number;
  /** Placeholder token name, e.g. `"OPENAI_API_KEY"`. Derived from `id` when omitted. */
  typeName?: string;
}

/** A match reported by {@link scan} / {@link redact}. */
export interface Finding {
  /** Detector id that produced this finding. */
  id: string;
  /** Human-readable label of what was found. */
  label: string;
  /** Detector family. */
  category: DetectorCategory;
  /** Severity of this individual finding. */
  severity: Severity;
  /** Detector confidence (0–1). */
  confidence: number;
  /** Start offset of the sensitive span in the scanned text. */
  start: number;
  /** End offset (exclusive). */
  end: number;
  /** The sensitive text itself. Never leave this in logs. */
  match: string;
  /** Masked preview safe for display, e.g. `sk-p…x9F2`. */
  preview: string;
}

/** Result of {@link redact}. */
export interface RedactionResult {
  /** The sanitized text with placeholders substituted in. */
  text: string;
  /** Findings for everything that was redacted. */
  findings: Finding[];
  /** Placeholder → original value. Keep this local; {@link restore} needs it. */
  mappings: Record<string, string>;
  /** Total number of redactions. */
  count: number;
}

/** Options for {@link redact}, {@link scan} and guard sessions. */
export interface GuardOptions {
  /** Only run these detector ids. Mutually exclusive with {@link exclude}. */
  detectors?: string[];
  /** Run everything except these detector ids. */
  exclude?: string[];
  /** Only run these categories (`"secrets"`, `"pii"`, `"custom"`). Default: all. */
  categories?: DetectorCategory[];
  /** Placeholder style. Default `"bracket"` → `[EMAIL_1]`. */
  placeholderStyle?: PlaceholderStyle;
  /** Fully custom placeholder builder. Overrides {@link placeholderStyle}. */
  placeholderBuilder?: (typeName: string, index: number) => string;
  /** Substrings (or regexes) that must never be redacted. */
  allow?: Array<string | RegExp>;
  /** Extra user-supplied detectors. */
  customDetectors?: CustomDetector[];
}

/**
 * A user-supplied detector. `pattern` is either a global regex, or a function
 * returning spans — for detectors that need real logic (checksums, parsers).
 */
export interface CustomDetector {
  /** Unique kebab-case id. */
  id: string;
  /** Human-readable label. */
  label?: string;
  /** Global regex, or a span-producing function. */
  pattern: RegExp | ((text: string) => Iterable<{ start: number; end: number }>);
  /** Defaults to `"high"`. */
  severity?: Severity;
  /** Placeholder token name. Defaults to the uppercased id. */
  typeName?: string;
}

/** Options for {@link restore}. */
export interface RestoreOptions {
  /** Match placeholders case-insensitively (models sometimes lowercase them). Default `false`. */
  caseInsensitive?: boolean;
}

/** Report from {@link scanInjection}. */
export interface InjectionReport {
  /** Aggregate risk score, 0–100. */
  score: number;
  /** Severity bucket derived from the score. */
  severity: Severity;
  /** Individual rule hits, most severe first. */
  findings: InjectionFinding[];
}

/** One prompt-injection rule hit. */
export interface InjectionFinding {
  /** Rule id, e.g. `"ignore-previous-instructions"`. */
  id: string;
  /** What the rule looks for. */
  label: string;
  /** Weight this rule contributed to the score. */
  weight: number;
  severity: Severity;
  /** Where the hit starts. */
  start: number;
  /** Where the hit ends. */
  end: number;
  /** The matched text, as evidence. */
  evidence: string;
}

/** Unified report from {@link scan}. */
export interface ScanReport {
  /** Secrets + PII findings, ordered by position. */
  findings: Finding[];
  /** Prompt-injection analysis of the same text. */
  injection: InjectionReport;
  /** Combined worst severity across both dimensions. */
  risk: Severity;
  /** Convenience counts by category. */
  counts: { secrets: number; pii: number; custom: number; injection: number };
}

/** Multi-turn guard session for agent/chat workloads. See {@link createGuardSession}. */
export interface GuardSession {
  /** Redact a string, continuing the session's placeholder numbering. */
  redact(text: string): RedactionResult;
  /** Redact every string inside a nested object/array (returns a transformed copy). */
  redactDeep<T>(value: T): T;
  /** Swap placeholders back to original values in a string. */
  restore(text: string, options?: RestoreOptions): string;
  /** Deep-restore placeholders inside a nested object/array (returns a transformed copy). */
  restoreDeep<T>(value: T, options?: RestoreOptions): T;
  /** All accumulated mappings (placeholder → original). */
  readonly mappings: Readonly<Record<string, string>>;
  /** Everything redacted so far, in order. */
  readonly findings: readonly Finding[];
  /** Forget all mappings and counters. */
  reset(): void;
}
