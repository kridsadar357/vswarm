// One pass over the machine: every collector in parallel, each one's failure recorded instead of hidden.

import type { Ctx } from "./ctx";
import { brew, browsers, cargo, editors, node, python } from "./collect/packages";
import { autostart, binaries, launchd, preload, running, startupFiles } from "./collect/system";
import type { Item, Scan } from "./types";

export async function scan(ctx: Ctx, opt: { live?: boolean } = {}): Promise<Scan> {
  const gaps: Record<string, string> = {};
  ctx = { ...ctx, gap: (what, why) => (gaps[what] = why) };
  const items: Item[] = [];
  let texts: Record<string, string> = {};
  const parts: [string, () => Promise<Item[]>][] = [
    ["homebrew", () => brew(ctx)],
    ["npm", () => node(ctx)],
    ["python", () => python(ctx)],
    ["cargo", () => cargo(ctx)],
    ["editor extensions", () => editors(ctx)],
    ["browser extensions", () => browsers(ctx)],
    ["launchd", () => launchd(ctx)],
    ["systemd and autostart", () => autostart(ctx)],
    ["ld.so.preload", () => preload(ctx)],
    ["startup files", async () => {
      const r = await startupFiles(ctx);
      texts = r.texts;
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
  return { version: 1, host: ctx.host, user: ctx.user, home: ctx.home, at: Date.now(), items, texts, gaps };
}

/** A scan without the moment-to-moment parts, as stored for a baseline. */
export function forBaseline(s: Scan): Scan {
  return { ...s, items: s.items.filter((i) => i.kind !== "proc" && i.kind !== "conn") };
}
