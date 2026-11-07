// Software that was installed on purpose and can run code: Homebrew, npm/bun globals, Python, Cargo,
// editor extensions and browser extensions.

import { join } from "node:path";
import { blocked, isDir, ls, readJson, readText, type Ctx } from "../ctx";
import type { Item } from "../types";

/** Taps Homebrew itself maintains; anything else is a third party's code. */
export function officialTap(tap?: string): boolean {
  return !tap || tap.startsWith("homebrew/");
}

export async function brew(ctx: Ctx): Promise<Item[]> {
  if (!ctx.brew) return [];
  const out: Item[] = [];
  const taps = join(ctx.brew, "Library", "Taps");
  for (const user of ls(taps)) {
    for (const repo of ls(join(taps, user))) {
      const dir = join(taps, user, repo);
      const name = `${user}/${repo.replace(/^homebrew-/, "")}`;
      const cfg = readText(join(dir, ".git", "config")) ?? "";
      const remote = /url\s*=\s*(\S+)/.exec(cfg)?.[1];
      out.push({ kind: "brew-tap", id: name, name, source: remote, path: dir, meta: { official: officialTap(name) } });
    }
  }
  const cellar = join(ctx.brew, "Cellar");
  for (const f of ls(cellar)) {
    for (const v of ls(join(cellar, f))) {
      const r = readJson(join(cellar, f, v, "INSTALL_RECEIPT.json"));
      const tap = r?.source?.tap ?? undefined;
      out.push({
        kind: "brew", id: `formula:${f}`, name: f, version: v, source: tap, path: join(cellar, f, v),
        meta: { official: officialTap(tap), requested: Boolean(r?.installed_on_request), installed: r?.time },
      });
    }
  }
  const cask = join(ctx.brew, "Caskroom");
  for (const c of ls(cask)) {
    const meta = join(cask, c, ".metadata");
    const r = readJson(join(meta, "INSTALL_RECEIPT.json")) ?? readJson(join(meta, ls(meta).find((x) => !x.startsWith(".")) ?? "", "INSTALL_RECEIPT.json"));
    const tap = r?.source?.tap ?? undefined;
    const v = ls(join(cask, c)).find((x) => !x.startsWith("."));
    out.push({ kind: "brew", id: `cask:${c}`, name: c, version: v, source: tap, path: join(cask, c), meta: { official: officialTap(tap), cask: true } });
  }
  return out;
}

const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];

function nodeModules(root: string, kind: string, source: string): Item[] {
  const out: Item[] = [];
  const pkg = (dir: string) => {
    const p = readJson(join(dir, "package.json"));
    if (!p?.name) return;
    const scripts = INSTALL_SCRIPTS.filter((s) => typeof p.scripts?.[s] === "string");
    out.push({
      kind, id: p.name, name: p.name, version: p.version, source, path: dir,
      meta: { scripts: scripts.join(",") || undefined, bin: p.bin ? Object.keys(typeof p.bin === "string" ? { [p.name]: 1 } : p.bin).join(",") : undefined },
    });
  };
  for (const e of ls(root)) {
    if (e.startsWith(".")) continue;
    if (e.startsWith("@")) for (const s of ls(join(root, e))) pkg(join(root, e, s));
    else pkg(join(root, e));
  }
  return out;
}

/** npm as a command to run. On Windows it is npm.cmd, which only cmd.exe can start. */
function npmCommand(args: string[]): string[] {
  if (process.platform !== "win32") return ["npm", ...args];
  const cmd = Bun.which("npm.cmd");
  return cmd ? [join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe"), "/d", "/c", cmd, ...args] : ["npm", ...args];
}

export async function node(ctx: Ctx): Promise<Item[]> {
  const roots = new Set<string>();
  const npmRoot = (await ctx.run(npmCommand(["root", "-g"]), 8000))?.trim();
  if (npmRoot) roots.add(npmRoot);
  // %APPDATA%\npm is where npm puts global packages on Windows unless told otherwise.
  if (process.platform === "win32") roots.add(join(ctx.home, "AppData/Roaming/npm/node_modules"));
  for (const r of [join(ctx.home, ".npm-global/lib/node_modules"), ...(ctx.brew ? [join(ctx.brew, "lib/node_modules")] : []), ...(ctx.system ? ["/usr/local/lib/node_modules"] : [])]) {
    if (isDir(r)) roots.add(r);
  }
  const out: Item[] = [];
  for (const r of roots) out.push(...nodeModules(r, "npm", "npm-global"));
  const bunGlobal = join(ctx.home, ".bun/install/global/node_modules");
  if (isDir(bunGlobal)) out.push(...nodeModules(bunGlobal, "npm", "bun-global").map((i) => ({ ...i, id: `bun:${i.id}` })));
  // The same package can sit in two roots; keep one per id.
  return [...new Map(out.map((i) => [i.id, i])).values()];
}

function distInfo(site: string, source: string): Item[] {
  const out: Item[] = [];
  for (const d of ls(site)) {
    const m = /^(.+?)-([^-]+)\.(dist-info|egg-info)$/.exec(d);
    if (!m) continue;
    const metaText = readText(join(site, d, "METADATA")) ?? readText(join(site, d, "PKG-INFO")) ?? "";
    const name = /^Name:\s*(.+)$/m.exec(metaText)?.[1]?.trim() ?? m[1];
    out.push({ kind: "pip", id: `${source}:${name.toLowerCase()}`, name, version: m[2], source, path: join(site, d) });
  }
  return out;
}

export async function python(ctx: Ctx): Promise<Item[]> {
  const sites = new Set<string>();
  const code = "import site,json;print(json.dumps(site.getsitepackages()+[site.getusersitepackages()]))";
  // Windows has python (or the py launcher), no python3.
  const py = process.platform === "win32"
    ? (await ctx.run(["python", "-c", code], 8000)) ?? (await ctx.run(["py", "-3", "-c", code], 8000))
    : await ctx.run(["python3", "-c", code], 8000);
  try {
    for (const s of JSON.parse(py ?? "[]")) if (isDir(s) && (ctx.system || s.startsWith(ctx.home))) sites.add(s);
  } catch {}
  for (const v of ls(join(ctx.home, "Library/Python"))) {
    const s = join(ctx.home, "Library/Python", v, "lib/python/site-packages");
    if (isDir(s)) sites.add(s);
  }
  const out: Item[] = [];
  for (const s of sites) out.push(...distInfo(s, s.startsWith(ctx.home) ? "pip-user" : "pip"));
  // pipx: one venv per app
  const pipx = join(ctx.home, ".local/pipx/venvs");
  for (const app of ls(pipx)) {
    const libs = join(pipx, app, "lib");
    for (const pyv of ls(libs)) out.push(...distInfo(join(libs, pyv, "site-packages"), `pipx:${app}`).filter((i) => i.name.toLowerCase() === app.toLowerCase()));
  }
  return [...new Map(out.map((i) => [i.id, i])).values()];
}

export async function cargo(ctx: Ctx): Promise<Item[]> {
  const j = readJson(join(ctx.home, ".cargo/.crates2.json"));
  return Object.keys(j?.installs ?? {}).map((k) => {
    const [name, version, src] = k.split(" ");
    return { kind: "cargo", id: name, name, version, source: src?.replace(/[()]/g, "") };
  });
}

/**
 * Which extension folders the editor installed from its marketplace, from the extensions.json it keeps beside them
 * (VS Code and its forks record the gallery id of each). Undefined when there is no such file to go by.
 */
export function galleryInstalled(root: string): Set<string> | undefined {
  const list = readJson(join(root, "extensions.json"));
  if (!Array.isArray(list)) return;
  const out = new Set<string>();
  for (const e of list) {
    const m = e?.metadata;
    const folder = typeof e?.relativeLocation === "string" ? e.relativeLocation : typeof e?.location?.path === "string" ? e.location.path.split("/").pop() : undefined;
    if (folder && m && (m.source === "gallery" || (m.id && m.publisherId && m.source !== "vsix" && m.source !== "resource"))) out.add(folder);
  }
  return out;
}

export async function editors(ctx: Ctx): Promise<Item[]> {
  const out: Item[] = [];
  for (const [ed, dir] of [["vscode", ".vscode/extensions"], ["cursor", ".cursor/extensions"], ["windsurf", ".windsurf/extensions"], ["vscodium", ".vscode-oss/extensions"]]) {
    const root = join(ctx.home, dir);
    const gallery = galleryInstalled(root);
    for (const e of ls(root)) {
      const p = readJson(join(root, e, "package.json"));
      if (!p?.name) continue;
      const id = `${p.publisher ?? "?"}.${p.name}`;
      // Starts with the editor itself, not when one of its languages or commands is used.
      const events: unknown[] = Array.isArray(p.activationEvents) ? p.activationEvents : [];
      const startup = events.includes("*") || events.includes("onStartupFinished");
      out.push({ kind: "editor-ext", id: `${ed}:${id}`, name: id, version: p.version, source: ed, path: join(root, e), meta: { gallery: gallery ? gallery.has(e) : undefined, startup: startup || undefined } });
    }
  }
  return [...new Map(out.map((i) => [i.id, i])).values()];
}

const BROWSERS: [string, string][] = [
  ["chrome", "Library/Application Support/Google/Chrome"],
  ["brave", "Library/Application Support/BraveSoftware/Brave-Browser"],
  ["edge", "Library/Application Support/Microsoft Edge"],
  ["arc", "Library/Application Support/Arc/User Data"],
  ["chromium", "Library/Application Support/Chromium"],
  ["chrome", ".config/google-chrome"],
  ["chromium", ".config/chromium"],
  ["chrome", "AppData/Local/Google/Chrome/User Data"],
  ["edge", "AppData/Local/Microsoft/Edge/User Data"],
  ["brave", "AppData/Local/BraveSoftware/Brave-Browser/User Data"],
];

export async function browsers(ctx: Ctx): Promise<Item[]> {
  const out: Item[] = [];
  for (const [b, rel] of BROWSERS) {
    const root = join(ctx.home, rel);
    if (blocked(root)) {
      ctx.gap?.(`${b} extensions`, "macOS privacy protection; give your terminal Full Disk Access (System Settings → Privacy & Security) to include them");
      continue;
    }
    // Extensions Chrome installs on its own from a JSON file in "External Extensions": an update URL, or a .crx on disk.
    for (const f of ls(join(root, "External Extensions")).filter((x) => x.endsWith(".json"))) {
      const j = readJson(join(root, "External Extensions", f));
      if (!j || typeof j !== "object") continue;
      const id = f.replace(/\.json$/, "");
      out.push({ kind: "browser-sideload", id: `${b}:${id}`, name: id, source: b, path: join(root, "External Extensions", f),
        meta: { crx: typeof j.external_crx === "string" ? j.external_crx : undefined, update: typeof j.external_update_url === "string" ? j.external_update_url : undefined } });
    }
    for (const profile of ls(root)) {
      const ext = join(root, profile, "Extensions");
      if (!isDir(ext)) continue;
      for (const id of ls(ext)) {
        const ver = ls(join(ext, id)).filter((v) => !v.startsWith(".")).sort().at(-1);
        if (!ver) continue;
        const m = readJson(join(ext, id, ver, "manifest.json"));
        let name = String(m?.name ?? id);
        if (name.startsWith("__MSG_")) {
          const key = name.slice(6, -2);
          const msgs = readJson(join(ext, id, ver, "_locales", m?.default_locale ?? "en", "messages.json"));
          name = msgs?.[key]?.message ?? msgs?.[key.toLowerCase()]?.message ?? id;
        }
        out.push({
          kind: "browser-ext", id: `${b}:${id}`, name, version: m?.version ?? ver, source: `${b}/${profile}`, path: join(ext, id),
          meta: { permissions: [...(m?.permissions ?? []), ...(m?.host_permissions ?? [])].filter((x: any) => typeof x === "string").slice(0, 12).join(",") },
        });
      }
    }
  }
  return [...new Map(out.map((i) => [i.id, i])).values()];
}
