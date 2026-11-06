// One pass over the machine: every collector in parallel, each one's failure recorded instead of hidden.

import type { Ctx } from "./ctx";
import { brew, browsers, cargo, editors, node, python } from "./collect/packages";
import { appLoginItems, autostart, binaries, extensions, launchd, preload, running, startupFiles } from "./collect/system";
import { agents } from "./collect/agents";
import { windows } from "./collect/windows";
import type { Item, Scan } from "./types";

/** Every item kind the collectors produce; stored with a baseline so later checks know what it covered. */
export const COVERS = ["brew", "brew-tap", "npm", "pip", "cargo", "editor-ext", "browser-ext", "launch", "rc", "ssh", "cron", "git-hooks", "hosts", "preload", "bin", "proc", "conn", "mcp", "agent-hook", "agent-perm", "agent-plugin", "wmi", "shell-d", "app-agent", "sysext"];

export async function scan(ctx: Ctx, opt: { live?: boolean } = {}): Promise<Scan> {
  const gaps: Record<string, string> = {};
  ctx = { ...ctx, gap: (what, why) => (gaps[what] = why) };
  const items: Item[] = [];
  const texts: Record<string, string> = {};
  const parts: [string, () => Promise<Item[]>][] = [
    ["homebrew", () => brew(ctx)],
    ["npm", () => node(ctx)],
    ["python", () => python(ctx)],
    ["cargo", () => cargo(ctx)],
    ["editor extensions", () => editors(ctx)],
    ["browser extensions", () => browsers(ctx)],
    ["AI agents and MCP", () => agents(ctx)],
    ["launchd", () => launchd(ctx)],
    ["login items inside apps", () => appLoginItems(ctx)],
    ["system extensions", () => extensions(ctx)],
    ["systemd and autostart", () => autostart(ctx)],
    ["ld.so.preload", () => preload(ctx)],
    ["startup files", async () => {
      const r = await startupFiles(ctx);
      Object.assign(texts, r.texts);
      return r.items;
    }],
    // Run keys, Startup folders, tasks, services, WMI and PowerShell profiles; nothing outside Windows.
    ["Windows start-up places", async () => {
      const r = await windows(ctx);
      Object.assign(texts, r.texts);
      return r.items;
    }],
    ["PATH executables", () => binaries(ctx)],
    // Processes and connections change every second; they are checked now, never kept in a baseline.
    ...(opt.live === false ? [] : ([["processes", () => running(ctx)]] as [string, () => Promise<Item[]>][])),
  ];
  await Promise.all(parts.map(async ([name, fn]) => {
    try {
      items.push(...(await fn()));
    } catch (e: any) {
      gaps[name] = String(e?.message ?? e);
    }
  }));
  return { version: 1, host: ctx.host, user: ctx.user, home: ctx.home, at: Date.now(), items, texts, gaps, covers: COVERS };
}

/** A scan without the moment-to-moment parts, as stored for a baseline. */
export function forBaseline(s: Scan): Scan {
  return { ...s, items: s.items.filter((i) => i.kind !== "proc" && i.kind !== "conn") };
}
