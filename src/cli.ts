#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { redact, restore, scan, detectors as builtinDetectors, injectionRuleIds } from "./index.js";
import type { DetectorCategory, PlaceholderStyle, Severity } from "./types.js";

const severityRank: Record<Severity, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function readVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const candidate of ["../../package.json", "../../../package.json", "../package.json"]) {
    const path = resolve(here, candidate);
    if (existsSync(path)) {
      const pkg = JSON.parse(readFileSync(path, "utf8")) as { version?: string };
      if (pkg.version) return pkg.version;
    }
  }
  return "0.0.0";
}

const USAGE = `llm-cloak — redact secrets & PII before they reach an LLM, and gate untrusted content

Usage:
  llm-cloak scan    [file]    Report secrets, PII and injection risk (exit 1 at --fail-on)
  llm-cloak redact  [file]    Print text with sensitive values replaced by placeholders
  llm-cloak restore [file]    Restore placeholders using --map <file>
  llm-cloak detectors         List built-in detector ids
  llm-cloak rules             List injection rule ids

Input: a file path, or "-" / omitted to read stdin.

Options:
  --json                 Machine-readable output
  --map <file>           redact: write the placeholder map here; restore: read it
  --out <file>           Write output to a file instead of stdout
  --fail-on <level>      scan: exit 1 when risk >= level (none|low|medium|high|critical, default low)
  --detectors <ids>      Only run these detector ids (comma-separated)
  --exclude <ids>        Skip these detector ids (comma-separated)
  --allow <values>       Never redact these substrings (comma-separated)
  --format <style>       Placeholder style: bracket | mustache | underscore (default bracket)
  --no-secrets           Skip secret detectors
  --no-pii               Skip PII detectors
  --case-insensitive     restore: tolerate changed placeholder case
  --version              Print version
  --help                 Show this help

Examples:
  llm-cloak scan docs/rag-index.md
  cat page.html | llm-cloak scan --json --fail-on high
  llm-cloak redact prompt.txt --map map.json --out prompt.safe.txt
  llm-cloak restore reply.txt --map map.json
`;

interface CliOptions {
  json?: boolean;
  map?: string;
  out?: string;
  "fail-on"?: string;
  detectors?: string;
  exclude?: string;
  allow?: string;
  format?: string;
  noSecrets?: boolean;
  noPii?: boolean;
  caseInsensitive?: boolean;
  version?: boolean;
  help?: boolean;
}

function fail(message: string, code = 2): never {
  process.stderr.write(`llm-cloak: ${message}\n`);
  process.exit(code);
}

function readInput(positional: string | undefined): string {
  if (!positional || positional === "-") {
    if (process.stdin.isTTY) fail("no input given — pass a file path or pipe text on stdin");
    return readFileSync(0, "utf8");
  }
  try {
    return readFileSync(positional, "utf8");
  } catch (error) {
    fail(`cannot read ${positional}: ${(error as Error).message}`);
  }
}

function writeOutput(text: string, out?: string): void {
  if (out) writeFileSync(out, text, "utf8");
  else process.stdout.write(text);
}

const color = {
  enabled: !!process.stdout.isTTY,
  red: (s: string) => (color.enabled ? `\x1b[31m${s}\x1b[0m` : s),
  yellow: (s: string) => (color.enabled ? `\x1b[33m${s}\x1b[0m` : s),
  dim: (s: string) => (color.enabled ? `\x1b[2m${s}\x1b[0m` : s),
  bold: (s: string) => (color.enabled ? `\x1b[1m${s}\x1b[0m` : s),
};

function colorizeSeverity(severity: string): string {
  const value = severity.toUpperCase();
  if (value === "CRITICAL" || value === "HIGH") return color.red(value);
  if (value === "MEDIUM" || value === "LOW") return color.yellow(value);
  return value;
}

function guardOptionsFrom(args: CliOptions) {
  const categories: DetectorCategory[] = [];
  if (!args.noSecrets) categories.push("secrets");
  if (!args.noPii) categories.push("pii");
  categories.push("custom");
  const format = args.format;
  if (format !== undefined && !["bracket", "mustache", "underscore"].includes(format)) {
    fail(`unknown --format "${format}" (expected bracket | mustache | underscore)`);
  }
  return {
    ...(categories.length > 0 ? { categories } : {}),
    ...(args.detectors ? { detectors: args.detectors.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
    ...(args.exclude ? { exclude: args.exclude.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
    ...(args.allow ? { allow: args.allow.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
    ...(format ? { placeholderStyle: format as PlaceholderStyle } : {}),
  };
}

function main(): void {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean" },
      map: { type: "string" },
      out: { type: "string" },
      "fail-on": { type: "string" },
      detectors: { type: "string" },
      exclude: { type: "string" },
      allow: { type: "string" },
      format: { type: "string" },
      "no-secrets": { type: "boolean" },
      "no-pii": { type: "boolean" },
      "case-insensitive": { type: "boolean" },
      version: { type: "boolean" },
      help: { type: "boolean" },
    },
  });
  const args = values as CliOptions;

  if (args.version) {
    process.stdout.write(`${readVersion()}\n`);
    return;
  }
  if (args.help || positionals.length === 0) {
    process.stdout.write(USAGE);
    return;
  }

  const command = positionals[0];
  const input = positionals[1];

  if (command === "detectors") {
    for (const detector of builtinDetectors) {
      process.stdout.write(`${detector.id.padEnd(28)}${detector.category.padEnd(9)}${detector.severity}\n`);
    }
    return;
  }

  if (command === "rules") {
    for (const id of injectionRuleIds()) process.stdout.write(`${id}\n`);
    return;
  }

  if (command === "scan") {
    const text = readInput(input);
    const failOn = (args["fail-on"] ?? "low") as Severity;
    if (!(failOn in severityRank)) fail(`unknown --fail-on level "${failOn}"`);
    const report = scan(text, guardOptionsFrom(args));
    if (args.json) {
      writeOutput(
        JSON.stringify(
          {
            risk: report.risk,
            counts: report.counts,
            injection: report.injection,
            findings: report.findings.map(({ match, ...rest }) => ({ ...rest, preview: rest.preview })),
          },
          null,
          2,
        ) + "\n",
        args.out,
      );
    } else {
      const lines: string[] = [];
      lines.push(`risk: ${colorizeSeverity(report.risk)}`);
      lines.push("");
      const grouped = new Map<string, typeof report.findings>();
      for (const finding of report.findings) {
        const list = grouped.get(finding.category) ?? [];
        list.push(finding);
        grouped.set(finding.category, list);
      }
      for (const [category, findings] of grouped) {
        lines.push(color.bold(category.toUpperCase()));
        for (const finding of findings) {
          lines.push(`  ${colorizeSeverity(finding.severity)} ${finding.label} @${finding.start} ${color.dim(`(${finding.preview})`)}`);
        }
        lines.push("");
      }
      if (report.injection.findings.length > 0) {
        lines.push(color.bold("INJECTION"));
        lines.push(`  score ${report.injection.score}/100 (${colorizeSeverity(report.injection.severity)})`);
        for (const finding of report.injection.findings) {
          lines.push(`  ${colorizeSeverity(finding.severity)} ${finding.id} ${color.dim(`"${finding.evidence}"`)}`);
        }
        lines.push("");
      }
      if (report.findings.length === 0 && report.injection.findings.length === 0) {
        lines.push("no secrets, PII or injection indicators found");
        lines.push("");
      }
      lines.push(
        `summary: ${report.counts.secrets} secret(s), ${report.counts.pii} pii, ${report.counts.injection} injection indicator(s)`,
      );
      writeOutput(lines.join("\n") + "\n", args.out);
    }
    process.exit(severityRank[report.risk] >= severityRank[failOn] ? 1 : 0);
    return;
  }

  if (command === "redact") {
    const text = readInput(input);
    const result = redact(text, guardOptionsFrom(args));
    if (args.json) {
      const payload = { text: result.text, mappings: result.mappings, count: result.count };
      writeOutput(JSON.stringify(payload, null, 2) + "\n", args.out);
    } else {
      writeOutput(result.text.endsWith("\n") ? result.text : result.text + "\n", args.out);
    }
    if (args.map) writeFileSync(args.map, JSON.stringify(result.mappings, null, 2) + "\n", "utf8");
    if (!args.json && !args.out && result.count > 0) {
      process.stderr.write(`redacted ${result.count} value(s)${args.map ? ` → map: ${args.map}` : " (pass --map <file> to save the mapping)"}\n`);
    }
    return;
  }

  if (command === "restore") {
    if (!args.map) fail("restore requires --map <file> (produced by `llm-cloak redact --map …`)");
    const text = readInput(input);
    let mappings: Record<string, string>;
    try {
      mappings = JSON.parse(readFileSync(args.map, "utf8")) as Record<string, string>;
    } catch (error) {
      fail(`cannot read mapping ${args.map}: ${(error as Error).message}`);
    }
    writeOutput(restore(text, mappings, { caseInsensitive: args.caseInsensitive }), args.out);
    return;
  }

  fail(`unknown command "${command}" — try --help`);
}

main();
