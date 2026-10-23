import type { RestoreOptions } from "./types.js";
import { escapeRegExp } from "./internal/utils.js";

/**
 * Swap placeholders back to their original values.
 *
 * ```ts
 * import { redact, restore } from "context-guard";
 *
 * const { text, mappings } = redact("My email is jane@acme.io");
 * const reply = "Got it — I will email [EMAIL_1] shortly.";
 * restore(reply, mappings); // "Got it — I will email jane@acme.io shortly."
 * ```
 *
 * Longer placeholders are substituted first so `[EMAIL_1]` never eats part of
 * `[EMAIL_10]`. Placeholders with no mapping are left untouched.
 */
export function restore(text: string, mappings: Record<string, string>, options: RestoreOptions = {}): string {
  const keys = Object.keys(mappings)
    .filter((key) => mappings[key] !== undefined)
    .sort((a, b) => b.length - a.length);

  let result = text;
  for (const key of keys) {
    const pattern = new RegExp(escapeRegExp(key), options.caseInsensitive ? "gi" : "g");
    result = result.replace(pattern, () => mappings[key] as string);
  }
  return result;
}
