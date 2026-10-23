/** Internal helpers shared by detectors. Not part of the public API. */

/** Luhn checksum — used for credit/debit card validation. */
export function luhnValid(digits: string): boolean {
  const s = digits.replace(/[\s-]/g, "");
  if (!/^\d{8,19}$/.test(s)) return false;
  let sum = 0;
  let double = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = s.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** IBAN mod-97 checksum (ISO 7064). Input with or without spaces. */
export function ibanValid(raw: string): boolean {
  const iban = raw.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const part = code >= 65 ? String(code - 55) : ch;
    for (const digit of part) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

/**
 * Shannon entropy over a charset-normalized alphabet, in bits per character.
 * Used to keep the generic token detector out of prose.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Mask a secret for display: keeps at most 3 leading and 3 trailing chars. */
export function mask(value: string): string {
  if (value.length <= 8) return "***";
  const head = value.slice(0, 3);
  const tail = value.slice(-3);
  return `${head}…${tail}`;
}

/** True when the string contains at least one character from each class. */
export function hasAllClasses(value: string, classes: RegExp[]): boolean {
  return classes.every((c) => c.test(value));
}

/** Escape everything that is special inside a RegExp body. */
export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
