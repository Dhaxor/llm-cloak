import { describe, expect, it } from "vitest";
import { redact } from "../src/index.js";

const ids = (result: { findings: { id: string }[] }) => result.findings.map((f) => f.id);

describe("secret detectors", () => {
  it("detects OpenAI project keys", () => {
    const key = `sk-proj-${"a".repeat(40)}`;
    const result = redact(`Set OPENAI_API_KEY=${key} in your shell.`);
    expect(result.text).not.toContain(key);
    expect(result.text).toContain("OPENAI_API_KEY=");
    expect(ids(result)).toContain("openai-api-key");
  });

  it("detects classic OpenAI keys", () => {
    const key = `sk-${"Ab1".repeat(14)}`;
    expect(ids(redact(key))).toContain("openai-api-key");
  });

  it("detects Anthropic keys", () => {
    const key = `sk-ant-api03-${"x".repeat(30)}`;
    expect(ids(redact(`ANTHROPIC_API_KEY=${key}`))).toContain("anthropic-api-key");
  });

  it("detects OpenRouter keys", () => {
    const key = `sk-or-v1-${"a".repeat(48)}`;
    expect(ids(redact(key))).toContain("openrouter-api-key");
  });

  it("detects Google API keys", () => {
    const key = `AIza${"a1B2c3D4e5".repeat(7).slice(0, 35)}`;
    expect(ids(redact(`curl "https://maps.googleapis.com/?key=${key}"`))).toContain("google-api-key");
  });

  it("detects GitHub tokens", () => {
    expect(ids(redact(`ghp_${"a".repeat(36)}`))).toContain("github-token");
    expect(ids(redact(`github_pat_${"a1B2".repeat(10)}`))).toContain("github-token");
  });

  it("detects Slack tokens and webhooks", () => {
    expect(ids(redact("xoxb-1234567890abcdef"))).toContain("slack-token");
    // Assembled at runtime: the literal webhook URL trips GitHub push protection.
    const slackWebhook = ["https://hooks.slack.com/services", "T12345678/B12345678/XXXXXXXXXXXXXXXXXXXXXXXX"].join("/");
    expect(ids(redact(slackWebhook))).toContain("slack-webhook-url");
  });

  it("detects Stripe secret keys", () => {
    expect(ids(redact(`sk_live_${"a1b2".repeat(6)}`))).toContain("stripe-secret-key");
  });

  it("detects AWS access keys", () => {
    expect(ids(redact("AKIAIOSFODNN7EXAMPLE"))).toContain("aws-access-key-id");
    expect(ids(redact("ASIAIOSFODNN7EXAMPLE"))).toContain("aws-access-key-id");
  });

  it("detects AWS secret access key assignments", () => {
    const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // canonical AWS docs example
    const result = redact(`aws_secret_access_key = ${secret}`);
    expect(result.text).not.toContain(secret);
    expect(ids(result)).toContain("aws-secret-access-key");
  });

  it("detects SendGrid, npm and HuggingFace tokens", () => {
    expect(ids(redact(`SG.${"a".repeat(22)}.${"b".repeat(43)}`))).toContain("sendgrid-api-key");
    expect(ids(redact(`npm_${"a".repeat(36)}`))).toContain("npm-access-token");
    expect(ids(redact(`hf_${"a".repeat(34)}`))).toContain("huggingface-token");
  });

  it("detects JWTs", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const result = redact(`Authorization header was ${jwt}`);
    expect(result.text).not.toContain(jwt);
    expect(ids(result)).toContain("jwt");
  });

  it("detects PEM private key blocks", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----";
    const result = redact(`Sign with:\n${pem}\nthanks`);
    expect(result.text).not.toContain("MIIEpAIBAAKCAQEA7");
    expect(ids(result)).toContain("private-key-block");
  });

  it("detects bearer tokens", () => {
    const result = redact("Authorization: Bearer abc123def456ghi789");
    expect(result.text).not.toContain("abc123def456ghi789");
    expect(ids(result)).toContain("bearer-token");
  });

  it("detects database connection strings and keeps the scheme in prose out of them", () => {
    const uri = "postgresql://admin:hunter2@db.prod.internal:5432/app";
    const result = redact(`DATABASE_URL=${uri}`);
    expect(result.text).not.toContain("hunter2");
    expect(ids(result)).toContain("connection-string");
  });

  it("detects URLs with embedded credentials", () => {
    const result = redact("See https://deploy:pw123456@ci.example.com/job/42 for logs");
    expect(result.text).not.toContain("pw123456");
    expect(ids(result)).toContain("url-embedded-credentials");
  });

  it("detects generic credential assignments inside env var names", () => {
    const result = redact("MY_SERVICE_TOKEN=tok_abcdef123456 export ok");
    expect(result.text).not.toContain("tok_abcdef123456");
    expect(ids(result)).toContain("env-assignment");
  });

  it("ignores short assignment values", () => {
    const result = redact("password=abc123");
    expect(result.text).toBe("password=abc123");
    expect(result.count).toBe(0);
  });

  it("detects high-entropy blobs but not plain hashes or prose", () => {
    expect(ids(redact("qX7mK2pR9tL4wZ8nB3cV6yH1dJ5fG0sA7uE4iO"))).toContain("high-entropy-token");
    expect(ids(redact("e3ec8bbd297b62a71a3de52f2c8be3f4156ad5c7"))).not.toContain("high-entropy-token");
    expect(ids(redact("The quick brown fox jumps over the lazy dog repeatedly and often."))).not.toContain(
      "high-entropy-token",
    );
  });
});
