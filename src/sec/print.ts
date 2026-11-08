// Terminal output for checks. A gate's output goes to stderr, so `--then` can pass stdout through untouched; a
// command whose output is the report (scan, diff, secrets, why …) sends it to stdout with toStdout(), so
// `vswarm scan > out.txt` keeps it. Questions always go to stderr.

import type { Check } from "./engine";
import type { Finding, Severity, Verdict } from "./types";

const wants = (s: NodeJS.WriteStream) => (!!s.isTTY || !!process.env.FORCE_COLOR) && !process.env.NO_COLOR;
let out: NodeJS.WriteStream = process.stderr;
let color = wants(out);
/** Report output goes to stdout from here on (and is coloured only when stdout is a terminal). */
export function toStdout() {
  out = process.stdout;
  color = wants(out);
}

const paint = (code: string) => (t: string) => (color ? `\x1b[${code}m${t}\x1b[0m` : t);
export const c = {
  bold: paint("1"), dim: paint("2"), red: paint("38;2;239;107;107"), amber: paint("38;2;227;163;58"),
  green: paint("38;2;69;192;122"), cyan: paint("38;2;79;179;209"), violet: paint("38;2;180;140;255"),
};

const SEV: Record<Severity, [string, (t: string) => string]> = {
  critical: ["CRIT", c.red], high: ["HIGH", c.red], medium: ["MED ", c.amber], low: ["LOW ", c.dim], info: ["INFO", c.dim],
};

export const VERDICT: Record<Verdict, string> = {
  get pass() {
    return c.green(c.bold("PASS"));
  },
  get warn() {
    return c.amber(c.bold("WARN"));
  },
  get block() {
    return c.red(c.bold("BLOCK"));
  },
};

// Names, paths and descriptions found on the machine are printed as they are. A control character in one could move
// the cursor or erase the line that reports it, so only vswarm's own colour codes get through.
const OWN_SGR_OR_CONTROL = /\x1b\[(?:0|1|2|38;2;\d{1,3};\d{1,3};\d{1,3})m|[\x00-\x08\x0b-\x1f\x7f-\x9f]/g;

export function clean(t: string): string {
  return t.replace(OWN_SGR_OR_CONTROL, (m) => (m.length > 1 ? m : ""));
}

export function line(t = "") {
  out.write(clean(t) + "\n");
}

/** One finding. `n` is its number in the last check (vswarm ok <n>, vswarm fix <n>); none for findings that are not saved. */
export function finding(f: Finding, verbose = true, n?: number) {
  const [tag, col] = SEV[f.severity];
  const num = n === undefined ? "" : `${c.bold(String(n).padStart(2))}  `;
  const pad = n === undefined ? "" : "    ";
  line(`  ${num}${col(tag)}  ${f.title}`);
  if (!verbose) return;
  for (const d of f.detail) if (d) line(`        ${pad}${c.dim(d)}`);
  if (f.fix) line(`        ${pad}${c.cyan("→")} ${f.fix}`);
  if (f.id) line(`        ${pad}${c.dim(n === undefined ? `id ${f.id}` : `accept: vswarm ok ${n}  ·  id ${f.id}`)}`);
}

/** Each finding's number: its place in the check as saved (last.json), so the numbers mean the same to ok and fix. */
export const numbers = (fs: Finding[]) => new Map(fs.map((f, i) => [f.id, i + 1]));

export function summary(r: Check, opt: { all?: boolean; title?: string; policy?: "allow" | "refuse"; numbered?: Map<string, number> } = {}) {
  const shown = opt.all ? r.findings : r.findings.filter((f) => f.severity !== "info" && f.severity !== "low");
  const hidden = r.findings.length - shown.length;
  const nums = opt.numbered ?? numbers(r.findings);
  line(`${c.violet("▼ vswarm")} ${opt.title ?? "check"} ${c.dim(`· ${r.scan.items.length} items · ${r.ms} ms${r.baseline ? ` · baseline ${new Date(r.baseline.at).toLocaleString()}` : ""}`)}`);
  if (r.lock) line(`  ${c.red("LOCKED")}  incident ${r.lock.incident} is open (${r.lock.reason}) · vswarm unlock when the machine is clean`);
  if (!shown.length) line(`  ${c.green("✔")} nothing that needs attention`);
  for (const f of shown) finding(f, true, nums.get(f.id));
  if (hidden) line(c.dim(`  … ${hidden} low/info finding${hidden > 1 ? "s" : ""} hidden · --all to see them`));
  if (r.accepted) line(c.dim(`  ${r.accepted} accepted finding${r.accepted > 1 ? "s" : ""} not shown · vswarm accept --list`));
  for (const n of r.notes) line(c.dim(`  · ${n}`));
  const warnTail = opt.policy === "refuse" ? " · refused by policy: fix or accept these (vswarm why)" : " · allowed, but fix or accept these (vswarm why)";
  line(`${VERDICT[r.verdict]}${r.verdict === "block" ? c.dim(" · do not use this machine for production access · vswarm respond") : r.verdict === "warn" ? c.dim(warnTail) : ""}`);
}
