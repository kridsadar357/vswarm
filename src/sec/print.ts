// Terminal output for checks. Everything a gate prints goes to stderr, so `--then` can pass stdout through untouched.

import type { Check } from "./engine";
import type { Finding, Severity, Verdict } from "./types";

const color = (process.stderr.isTTY || process.env.FORCE_COLOR) && !process.env.NO_COLOR;
const paint = (code: string) => (t: string) => (color ? `\x1b[${code}m${t}\x1b[0m` : t);
export const c = {
  bold: paint("1"), dim: paint("2"), red: paint("38;2;239;107;107"), amber: paint("38;2;227;163;58"),
  green: paint("38;2;69;192;122"), cyan: paint("38;2;79;179;209"), violet: paint("38;2;180;140;255"),
};

const SEV: Record<Severity, [string, (t: string) => string]> = {
  critical: ["CRIT", c.red], high: ["HIGH", c.red], medium: ["MED ", c.amber], low: ["LOW ", c.dim], info: ["INFO", c.dim],
};

export const VERDICT: Record<Verdict, string> = {
  pass: c.green(c.bold("PASS")),
  warn: c.amber(c.bold("WARN")),
  block: c.red(c.bold("BLOCK")),
};

export function line(t = "") {
  process.stderr.write(t + "\n");
}

export function finding(f: Finding, verbose = true) {
  const [tag, col] = SEV[f.severity];
  line(`  ${col(tag)}  ${f.title}`);
  if (!verbose) return;
  for (const d of f.detail) if (d) line(`        ${c.dim(d)}`);
  if (f.fix) line(`        ${c.cyan("→")} ${f.fix}`);
  line(`        ${c.dim(`id ${f.id}`)}`);
}

export function summary(r: Check, opt: { all?: boolean; title?: string } = {}) {
  const shown = opt.all ? r.findings : r.findings.filter((f) => f.severity !== "info" && f.severity !== "low");
  const hidden = r.findings.length - shown.length;
  line(`${c.violet("▼ vswarm")} ${opt.title ?? "check"} ${c.dim(`· ${r.scan.items.length} items · ${r.ms} ms${r.baseline ? ` · baseline ${new Date(r.baseline.at).toLocaleString()}` : ""}`)}`);
  if (r.lock) line(`  ${c.red("LOCKED")}  incident ${r.lock.incident} is open (${r.lock.reason}) · vswarm unlock when the machine is clean`);
  if (!shown.length) line(`  ${c.green("✔")} nothing that needs attention`);
  for (const f of shown) finding(f);
  if (hidden) line(c.dim(`  … ${hidden} low/info finding${hidden > 1 ? "s" : ""} hidden · --all to see them`));
  if (r.accepted) line(c.dim(`  ${r.accepted} accepted finding${r.accepted > 1 ? "s" : ""} not shown · vswarm accept --list`));
  for (const n of r.notes) line(c.dim(`  · ${n}`));
  line(`${VERDICT[r.verdict]}${r.verdict === "block" ? c.dim(" · do not use this machine for production access · vswarm respond") : r.verdict === "warn" ? c.dim(" · allowed, but fix or accept these") : ""}`);
}
