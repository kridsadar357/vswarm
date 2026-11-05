// Every `vswarm run` keeps a folder: its events (for replay), its metadata and the final answer.

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureHome, paths } from "./home";
import type { Stamped } from "./state";

export interface RunMeta {
  id: string;
  prompt: string;
  cwd: string;
  lead: string;
  /** Claude Code session id, for `vswarm resume`. */
  sid?: string;
  started: number;
  ended?: number;
  turns: number;
  subagents: number;
  costUsd: number;
  status: "running" | "done" | "error" | "interrupted";
}

export function runDir(id: string): string {
  return join(paths.runs(), id);
}

export function newRun(prompt: string, cwd: string, lead: string, t = Date.now()): RunMeta {
  ensureHome();
  const d = new Date(t);
  const stamp = [d.getFullYear(), d.getMonth() + 1, d.getDate()].map((n) => String(n).padStart(2, "0")).join("") +
    "-" + [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join("");
  const slug = prompt.toLowerCase().replace(/[^a-z0-9ก-๙]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || "session";
  const meta: RunMeta = { id: `${stamp}-${slug}`, prompt, cwd, lead, started: t, turns: 0, subagents: 0, costUsd: 0, status: "running" };
  mkdirSync(runDir(meta.id), { recursive: true });
  writeFileSync(join(runDir(meta.id), "events.jsonl"), "");
  saveMeta(meta);
  return meta;
}

export function saveMeta(m: RunMeta) {
  writeFileSync(join(runDir(m.id), "meta.json"), JSON.stringify(m, null, 2) + "\n");
}

export function listRuns(): RunMeta[] {
  if (!existsSync(paths.runs())) return [];
  const out: RunMeta[] = [];
  for (const id of readdirSync(paths.runs())) {
    try {
      out.push(JSON.parse(readFileSync(join(runDir(id), "meta.json"), "utf8")));
    } catch {}
  }
  return out.sort((a, b) => b.started - a.started);
}

/** A run by list number (1 = newest), full id, or id prefix. */
export function findRun(ref?: string): RunMeta {
  const runs = listRuns();
  if (!runs.length) throw new Error("no runs yet · start one with: vswarm run \"<prompt>\"");
  if (!ref) return runs[0];
  if (/^\d{1,3}$/.test(ref)) {
    const r = runs[Number(ref) - 1];
    if (r) return r;
  }
  const r = runs.find((x) => x.id === ref) ?? runs.find((x) => x.id.startsWith(ref)) ?? runs.find((x) => x.sid?.startsWith(ref));
  if (!r) throw new Error(`no run matches "${ref}" · see: vswarm history`);
  return r;
}

export function runEvents(id: string): Stamped[] {
  const out: Stamped[] = [];
  for (const l of readFileSync(join(runDir(id), "events.jsonl"), "utf8").split("\n")) {
    if (!l.trim()) continue;
    try {
      out.push(JSON.parse(l));
    } catch {}
  }
  return out;
}
