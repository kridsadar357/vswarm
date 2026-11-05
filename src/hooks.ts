// Claude Code hook entries that feed vswarm, and adding/removing them in a settings file.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { activeDir } from "./claude";

export const CLI = resolve(import.meta.dir, "cli.ts");

const HOOK_EVENTS = [
  "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure",
  "SubagentStart", "SubagentStop", "Stop", "SessionEnd",
];
/** These may wait for the advisor or Jev; the rest only record. */
const SLOW = new Set(["UserPromptSubmit", "PostToolUse", "PostToolUseFailure", "Stop"]);
/** Our entries are recognised by these names in the command, including the tool's earlier names. */
const MARKS = ["vswarm", "v-swarm", "swarmdeck"];

const q = (s: string) => `"${s.replace(/"/g, '\\"')}"`;

export function hookCommand(file?: string): string {
  return [q(process.execPath), q(CLI), "hook", ...(file ? ["--file", q(file)] : [])].join(" ");
}

export function hooksConfig(file?: string) {
  return Object.fromEntries(
    HOOK_EVENTS.map((e) => {
      const entry = { type: "command", command: hookCommand(file), timeout: SLOW.has(e) ? 300 : 10 };
      return [e, [e.includes("Tool") ? { matcher: "*", hooks: [entry] } : { hooks: [entry] }]];
    }),
  );
}

/** settings.json of the Claude Code account vswarm is set to. */
export function globalSettings(): string {
  return join(activeDir(), "settings.json");
}

export function projectSettings(dir: string): string {
  return join(resolve(dir), ".claude", "settings.local.json");
}

function readJson(path: string): any {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, "utf8"));
}

const ours = (h: any) => MARKS.some((m) => String(h.command ?? "").includes(m)) && / hook\b/.test(String(h.command ?? ""));

/** Drop our own entries; every other hook stays as it was. */
function stripOurs(settings: any) {
  for (const [event, groups] of Object.entries<any[]>(settings.hooks ?? {})) {
    const kept = groups.map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h: any) => !ours(h)) })).filter((g) => g.hooks.length);
    if (kept.length) settings.hooks[event] = kept;
    else delete settings.hooks[event];
  }
  if (settings.hooks && !Object.keys(settings.hooks).length) delete settings.hooks;
}

export function hasHooks(path: string): boolean {
  try {
    return Object.values<any[]>(readJson(path).hooks ?? {}).some((gs) => gs.some((g) => (g.hooks ?? []).some(ours)));
  } catch {
    return false;
  }
}

export function setHooks(path: string, on: boolean, file?: string) {
  const settings = readJson(path);
  stripOurs(settings);
  if (on) {
    settings.hooks ??= {};
    for (const [event, groups] of Object.entries(hooksConfig(file))) settings.hooks[event] = [...(settings.hooks[event] ?? []), ...groups];
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n");
}
