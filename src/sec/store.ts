// What vswarm keeps on this machine, all under ~/.vswarm/sec with owner-only permissions:
//   baseline.json   the machine as it was when you said it was clean
//   last.json       the most recent scan, and the verdict preflight reuses for a short while
//   accepted.json   findings you reviewed and accepted
//   lock            present while an incident is open; preflight blocks until `vswarm unlock`
//   incidents/<id>/ evidence, quarantine and reports of one incident
//   osv-cache.json  answers from the known-malicious database

import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "../home";
import type { Finding, Scan, Verdict } from "./types";

export const SEC = () => process.env.VSWARM_SEC_DIR ?? join(HOME, "sec");

export const files = {
  baseline: () => join(SEC(), "baseline.json"),
  last: () => join(SEC(), "last.json"),
  accepted: () => join(SEC(), "accepted.json"),
  lock: () => join(SEC(), "lock"),
  incidents: () => join(SEC(), "incidents"),
  osv: () => join(SEC(), "osv-cache.json"),
  managed: () => join(SEC(), "managed.json"),
};

export function ensureSec(): string {
  if (!existsSync(SEC())) mkdirSync(SEC(), { recursive: true, mode: 0o700 });
  try {
    chmodSync(SEC(), 0o700);
  } catch {}
  return SEC();
}

export function writePrivate(path: string, data: unknown) {
  ensureSec();
  writeFileSync(path, typeof data === "string" ? data : JSON.stringify(data, null, 1), { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {}
}

function read<T>(path: string): T | undefined {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return;
  }
}

export const loadBaseline = () => read<Scan>(files.baseline());
export const saveBaseline = (s: Scan) => writePrivate(files.baseline(), s);

export interface Last {
  scan: Scan;
  findings: Finding[];
  verdict: Verdict;
  at: number;
}
export const loadLast = () => read<Last>(files.last());
export const saveLast = (l: Last) => writePrivate(files.last(), l);

export interface Accepted {
  [findingId: string]: { at: number; title: string };
}
export const loadAccepted = () => read<Accepted>(files.accepted()) ?? {};
export const saveAccepted = (a: Accepted) => writePrivate(files.accepted(), a);

export interface Lock {
  incident: string;
  at: number;
  reason: string;
}
export const loadLock = () => read<Lock>(files.lock());
export const setLock = (l: Lock) => writePrivate(files.lock(), l);
export const clearLock = () => rmSync(files.lock(), { force: true });

// Blocks vswarm writes into your files (PATH in ~/.zshrc, the ssh gate, the install guard, canaries). Their hashes
// are kept so a scan does not report vswarm's own lines as a change. A block that differs by one character from what
// vswarm wrote is not recognised, and is checked like any other line.
const BLOCK = /# >>> vswarm[^\n]*>>>\n[\s\S]*?# <<< vswarm[^\n]*<<<\n?/g;
const blockHash = (b: string) => createHash("sha256").update(b.trim()).digest("hex");

export function recordManaged(text: string) {
  const m = read<Record<string, number>>(files.managed()) ?? {};
  for (const b of text.match(BLOCK) ?? []) m[blockHash(b)] = Date.now();
  writePrivate(files.managed(), m);
}

export function stripManaged(text: string): string {
  const m = read<Record<string, number>>(files.managed()) ?? {};
  return text.replace(BLOCK, (b) => (m[blockHash(b)] ? "" : b));
}

/** Whole files vswarm writes (its own background job). Recognised by their exact content. */
export function recordManagedFile(text: string) {
  const m = read<Record<string, number>>(files.managed()) ?? {};
  m[`file:${createHash("sha256").update(text).digest("hex")}`] = Date.now();
  writePrivate(files.managed(), m);
}

export function isManagedFile(sha256hex: string | undefined): boolean {
  if (!sha256hex) return false;
  return Boolean((read<Record<string, number>>(files.managed()) ?? {})[`file:${sha256hex}`]);
}
