import { describe, expect, it } from "vitest";
import { redact } from "../src/index.js";

const ids = (result: { findings: { id: string }[] }) => result.findings.map((f) => f.id);

describe("PII detectors", () => {
  it("detects emails", () => {
    const result = redact("Reach out to jane.doe+news@example.co.uk today");
    expect(result.text).toContain("[EMAIL_1]");
    expect(result.text).not.toContain("jane.doe");
  });

  it("detects international and US phone numbers", () => {
    expect(ids(redact("Call +1 (555) 123-4567 now"))).toContain("phone");
    expect(ids(redact("Call 555-123-4567 now"))).toContain("phone");
    expect(ids(redact("Call +44 20 7946 0958 now"))).toContain("phone");
  });

  it("does not mistake timestamps for phone numbers", () => {
    expect(ids(redact("created_at=1730102400 by user"))).not.toContain("phone");
  });

  it("detects valid cards and rejects invalid Luhn numbers", () => {
    expect(ids(redact("Card: 4111 1111 1111 1111"))).toContain("credit-card");
    expect(ids(redact("Card: 4111-1111-1111-1111"))).toContain("credit-card");
    expect(ids(redact("Ref 4111111111111112 failed"))).not.toContain("credit-card");
  });

  it("detects valid IBANs (with spaces) and rejects broken checksums", () => {
    expect(ids(redact("IBAN GB29 NWBK 6016 1331 9268 19 for wire"))).toContain("iban");
    expect(ids(redact("IBAN GB29 NWBK 6016 1331 9268 18 for wire"))).not.toContain("iban");
  });

  it("detects plausible SSNs and rejects reserved area numbers", () => {
    expect(ids(redact("SSN: 123-45-6789"))).toContain("us-ssn");
    expect(ids(redact("SSN: 000-45-6789"))).not.toContain("us-ssn");
    expect(ids(redact("SSN: 912-45-6789"))).not.toContain("us-ssn");
  });

  it("detects valid IPv4 addresses only", () => {
    expect(ids(redact("host at 192.168.1.100:8080"))).toContain("ipv4");
    expect(ids(redact("version 999.999.999.999 badge"))).not.toContain("ipv4");
  });
});
