import type { Detector } from "../types.js";
import { ibanValid, luhnValid } from "../internal/utils.js";

/**
 * PII detectors. Formats that carry a checksum (cards, IBANs) are only
 * reported when the checksum validates, which keeps false positives low.
 */
export const piiDetectors: Detector[] = [
  {
    id: "email",
    label: "Email address",
    category: "pii",
    severity: "medium",
    confidence: 0.95,
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    priority: 50,
    typeName: "EMAIL",
  },
  {
    id: "phone",
    label: "Phone number",
    category: "pii",
    severity: "medium",
    confidence: 0.7,
    // E.164, or separated national formats; separators required for bare runs
    regex: /\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b|\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b/g,
    priority: 40,
    typeName: "PHONE",
  },
  {
    id: "credit-card",
    label: "Credit card number",
    category: "pii",
    severity: "high",
    confidence: 0.95,
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validate: luhnValid,
    priority: 55,
    typeName: "CREDIT_CARD",
  },
  {
    id: "iban",
    label: "IBAN",
    category: "pii",
    severity: "high",
    confidence: 0.95,
    // Final group may be 2–4 chars: IBANs are not always a multiple of 4 after the check digits
    regex: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{2,4}){3,8}\b/g,
    validate: ibanValid,
    priority: 55,
    typeName: "IBAN",
  },
  {
    id: "us-ssn",
    label: "US SSN",
    category: "pii",
    severity: "high",
    confidence: 0.9,
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    validate: (value) => {
      const [area = "", group = ""] = value.split("-");
      return area !== "000" && area !== "666" && !area.startsWith("9") && group !== "00";
    },
    priority: 50,
    typeName: "SSN",
  },
  {
    id: "ipv4",
    label: "IPv4 address",
    category: "pii",
    severity: "low",
    confidence: 0.8,
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: (value) => value.split(".").every((octet) => Number(octet) <= 255),
    priority: 30,
    typeName: "IP",
  },
];
