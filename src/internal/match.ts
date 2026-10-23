import type {
  CustomDetector,
  Detector,
  DetectorCategory,
  Finding,
  GuardOptions,
  PlaceholderStyle,
  Severity,
} from "../types.js";
import { mask } from "./utils.js";
import { secretDetectors } from "../detectors/secrets.js";
import { piiDetectors } from "../detectors/pii.js";

/** The full built-in detector registry. */
export const builtinDetectors: readonly Detector[] = [...secretDetectors, ...piiDetectors];

/** Internal, uniform shape for built-in and custom detectors alike. */
interface NormalizedDetector {
  id: string;
  label: string;
  category: DetectorCategory;
  severity: Severity;
  confidence: number;
  priority: number;
  typeName: string;
  findSpans(text: string): Iterable<{ start: number; end: number; value: string }>;
}

export interface Span {
  detector: NormalizedDetector;
  value: string;
  start: number;
  end: number;
}

const severityRank: Record<Severity, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityRank[a] >= severityRank[b] ? a : b;
}

function typeNameFromId(id: string): string {
  return id.toUpperCase().replace(/-/g, "_");
}

function normalizeBuiltin(detector: Detector): NormalizedDetector {
  // Rebuild the regex with the `d` flag so capture-group offsets are available.
  const regex = new RegExp(detector.regex.source, detector.regex.flags.includes("d") ? detector.regex.flags : detector.regex.flags + "d");
  return {
    id: detector.id,
    label: detector.label,
    category: detector.category,
    severity: detector.severity,
    confidence: detector.confidence,
    priority: detector.priority ?? 50,
    typeName: detector.typeName ?? typeNameFromId(detector.id),
    findSpans: function* (text: string) {
      regex.lastIndex = 0;
      for (const match of text.matchAll(regex)) {
        if (match.index === undefined) continue;
        let start = match.index;
        let end = match.index + match[0].length;
        let value = match[0];
        if (detector.valueGroup !== undefined) {
          const indices = match.indices?.[detector.valueGroup];
          if (!indices) continue;
          start = indices[0];
          end = indices[1];
          value = text.slice(start, end);
        }
        if (detector.validate && !detector.validate(value)) continue;
        yield { start, end, value };
      }
    },
  };
}

function normalizeCustom(detector: CustomDetector): NormalizedDetector {
  const pattern = detector.pattern;
  return {
    id: detector.id,
    label: detector.label ?? detector.id,
    category: "custom",
    severity: detector.severity ?? "high",
    confidence: 1,
    priority: 100, // user detectors outrank builtins
    typeName: detector.typeName ?? typeNameFromId(detector.id),
    findSpans: function* (text: string) {
      if (typeof pattern === "function") {
        yield* (function* () {
          for (const span of pattern(text)) {
            yield { start: span.start, end: span.end, value: text.slice(span.start, span.end) };
          }
        })();
      } else {
        if (!pattern.global) {
          throw new TypeError(`Custom detector "${detector.id}" regex must have the g flag.`);
        }
        const regex = new RegExp(pattern.source, pattern.flags.includes("d") ? pattern.flags : pattern.flags + "d");
        regex.lastIndex = 0;
        for (const match of text.matchAll(regex)) {
          if (match.index === undefined) continue;
          yield { start: match.index, end: match.index + match[0].length, value: match[0] };
        }
      }
    },
  };
}

/** Filter the registry (and custom detectors) down to what the options ask for. */
export function resolveDetectors(options: GuardOptions = {}): NormalizedDetector[] {
  const include = options.detectors ? new Set(options.detectors) : undefined;
  const exclude = new Set(options.exclude ?? []);
  const categories = options.categories ? new Set(options.categories) : undefined;

  const wanted = (id: string, category: DetectorCategory): boolean => {
    if (exclude.has(id)) return false;
    if (include && !include.has(id)) return false;
    if (categories && !categories.has(category)) return false;
    return true;
  };

  const resolved: NormalizedDetector[] = [];
  for (const detector of builtinDetectors) {
    if (wanted(detector.id, detector.category)) resolved.push(normalizeBuiltin(detector));
  }
  for (const custom of options.customDetectors ?? []) {
    if (!exclude.has(custom.id)) resolved.push(normalizeCustom(custom));
  }
  return resolved;
}

const placeholderLike = /^\[?[A-Z][A-Z0-9_]*_\d+\]?$|^\{\{[A-Z][A-Z0-9_]*_\d+\}\}$|^__[A-Z][A-Z0-9_]*_\d+__$/;

function isAllowed(value: string, allow: Array<string | RegExp>): boolean {
  for (const entry of allow) {
    if (typeof entry === "string") {
      if (value.includes(entry)) return true;
    } else if (entry.test(value)) {
      return true;
    }
  }
  return false;
}

/**
 * Run detectors and resolve overlaps: higher priority wins, then longer match,
 * then earlier position. Output spans are non-overlapping, ordered by start.
 */
export function collectSpans(text: string, detectors: NormalizedDetector[], allow: Array<string | RegExp> = []): Span[] {
  const candidates: Span[] = [];
  for (const detector of detectors) {
    for (const span of detector.findSpans(text)) {
      if (span.value.length === 0) continue;
      if (placeholderLike.test(span.value)) continue; // never redact our own placeholders
      if (span.value.trim().length === 0) continue;
      if (allow.length > 0 && isAllowed(span.value, allow)) continue;
      candidates.push({ detector, ...span });
    }
  }

  candidates.sort((a, b) => {
    const priorityDelta = b.detector.priority - a.detector.priority;
    if (priorityDelta !== 0) return priorityDelta;
    const lengthDelta = b.end - b.start - (a.end - a.start);
    if (lengthDelta !== 0) return lengthDelta;
    return a.start - b.start;
  });

  const selected: Span[] = [];
  for (const candidate of candidates) {
    const overlaps = selected.some((span) => candidate.start < span.end && span.start < candidate.end);
    if (!overlaps) selected.push(candidate);
  }
  selected.sort((a, b) => a.start - b.start);
  return selected;
}

export function toFinding(span: Span): Finding {
  return {
    id: span.detector.id,
    label: span.detector.label,
    category: span.detector.category,
    severity: span.detector.severity,
    confidence: span.detector.confidence,
    start: span.start,
    end: span.end,
    match: span.value,
    preview: mask(span.value),
  };
}

export function buildPlaceholder(style: PlaceholderStyle, typeName: string, index: number): string {
  switch (style) {
    case "mustache":
      return `{{${typeName}_${index}}}`;
    case "underscore":
      return `__${typeName}_${index}__`;
    default:
      return `[${typeName}_${index}]`;
  }
}

export type { NormalizedDetector };
