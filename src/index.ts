/**
 * llm-cloak — a zero-dependency context firewall for LLM apps.
 *
 * Three jobs, one small library:
 * 1. `redact()`    — replace secrets & PII with reversible placeholders before
 *                    text is sent to any model.
 * 2. `restore()`   — swap placeholders back to real values in model responses.
 * 3. `scanInjection()` / `scan()` — score untrusted content for prompt
 *                    injections before it reaches your agent.
 *
 * @packageDocumentation
 */

export { redact } from "./redact.js";
export { restore } from "./restore.js";
export { scan } from "./scan.js";
export { scanInjection, injectionRuleIds } from "./injection.js";
export type { ScanInjectionOptions } from "./injection.js";
export { createGuardSession } from "./session.js";
export { builtinDetectors as detectors } from "./internal/match.js";

export type {
  Severity,
  DetectorCategory,
  PlaceholderStyle,
  Detector,
  Finding,
  RedactionResult,
  GuardOptions,
  CustomDetector,
  RestoreOptions,
  InjectionReport,
  InjectionFinding,
  ScanReport,
  GuardSession,
} from "./types.js";
