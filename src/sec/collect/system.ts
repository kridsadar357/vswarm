// Ways code keeps itself running or gets run without being asked: launchd jobs, shell startup files,
// cron, git hooks, ssh access files, new executables on PATH, and what is running and talking right now.

import { lstatSync, readlinkSync } from "node:fs";
import { join } from "node:path";
import { fileHash, ls, mtime, readText, sha256, type Ctx } from "../ctx";
import type { Item } from "../types";

export async function launchd(ctx: Ctx): Promise<Item[]> {
  const dirs = [join(ctx.home, "Library/LaunchAgents"), ...(ctx.system ? ["/Library/LaunchAgents", "/Library/LaunchDaemons"] : [])];
  const out: Item[] = [];
  for (const dir of dirs) {
    for (const f of ls(dir)) {
      if (!f.endsWith(".plist")) continue;
      const path = join(dir, f);
      let program = "";
      let label = f.replace(/\.plist$/, "");
      const json = await ctx.run(["plutil", "-convert", "json", "-o", "-", path], 5000);
      try {
        const p = JSON.parse(json ?? "");
        label = p.Label ?? label;
        program = [p.Program, ...(p.ProgramArguments ?? [])].filter(Boolean).join(" ");
      } catch {
        // Not plutil-readable (Linux, or a damaged file): fall back to the raw XML.
        const xml = readText(path) ?? "";
        program = [...xml.matchAll(/<string>([^<]+)<\/string>/g)].map((m) => m[1]).slice(1, 4).join(" ");
      }
      out.push({
        kind: "launch", id: path, name: label, path, hash: fileHash(path),
        source: dir.startsWith(ctx.home) ? "user" : dir.includes("Daemons") ? "system-daemon" : "system-agent",
        meta: { program: program.slice(0, 300) },
      });
    }
  }
  return out;
}

const RC_FILES = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish", ".gitconfig", ".ssh/config", ".ssh/authorized_keys", ".npmrc", ".curlrc"];

export async function startupFiles(ctx: Ctx): Promise<{ items: Item[]; texts: Record<string, string> }> {
  const items: Item[] = [];
  const texts: Record<string, string> = {};
  for (const rel of RC_FILES) {
    const path = join(ctx.home, rel);
    const t = readText(path, 1_000_000);
    if (t === undefined) continue;
    // Credentials in .npmrc are never stored; only the fact that the file changed.
    const keep = rel !== ".npmrc";
    items.push({ kind: rel.startsWith(".ssh/") ? "ssh" : "rc", id: rel, name: rel, path, hash: sha256(t), meta: { lines: t.split("\n").length } });
    if (keep) texts[rel] = t;
  }
  const cron = await ctx.run(["crontab", "-l"], 5000);
  if (cron !== undefined && ctx.system) {
    items.push({ kind: "cron", id: "crontab", name: "crontab", hash: sha256(cron), meta: { lines: cron.split("\n").filter((l) => l.trim() && !l.startsWith("#")).length } });
    texts.crontab = cron;
  }
  const hooksPath = (await ctx.run(["git", "config", "--global", "core.hooksPath"], 5000))?.trim();
  if (hooksPath && ctx.system) {
    const dir = hooksPath.replace(/^~/, ctx.home);
    for (const h of ls(dir)) items.push({ kind: "git-hooks", id: join(dir, h), name: h, path: join(dir, h), hash: fileHash(join(dir, h)) });
  }
  if (ctx.system) {
    const hosts = readText("/etc/hosts");
    if (hosts !== undefined) {
      items.push({ kind: "hosts", id: "/etc/hosts", name: "/etc/hosts", path: "/etc/hosts", hash: sha256(hosts) });
      texts["/etc/hosts"] = hosts;
    }
  }
  return { items, texts };
}

/** Executables in the PATH directories people install into. Size and time only; new ones are checked further. */
export async function binaries(ctx: Ctx): Promise<Item[]> {
  const out: Item[] = [];
  for (const dir of ctx.pathDirs) {
    for (const f of ls(dir)) {
      const path = join(dir, f);
      try {
        const st = lstatSync(path);
        if (st.isDirectory()) continue;
        const link = st.isSymbolicLink() ? readlinkSync(path) : undefined;
        if (!link && !(st.mode & 0o111)) continue;
        out.push({ kind: "bin", id: path, name: f, path, meta: { link, size: link ? undefined : st.size, mtime: Math.round(st.mtimeMs) } });
      } catch {}
    }
  }
  return out;
}

/** Hidden folders in the home directory that ordinary tools are known to use. */
const KNOWN_HIDDEN = /^\.(bun|cargo|rustup|npm|npm-global|nvm|volta|pyenv|rbenv|deno|local|vscode|cursor|windsurf|docker|orbstack|colima|ollama|claude[\w-]*|codex|gemini|vswarm|config|gradle|m2|sdkman|swiftpm|dotnet|android|pub-cache|fvm|flutter|conda|mamba|jenv|asdf|mise|nix-profile|lmstudio|cache\/(ms-playwright|puppeteer|huggingface|pre-commit|bazel|go-build|deno))(\/|$)/;

export function suspiciousLocation(path: string, home: string): string | undefined {
  if (/^\/(private\/)?(tmp|var\/tmp)\//.test(path)) return "runs from a temp folder";
  if (path.startsWith("/Users/Shared/")) return "runs from /Users/Shared";
  if (path.startsWith(home + "/")) {
    const rel = path.slice(home.length + 1);
    if (rel.startsWith("Library/Caches/")) return "runs from a cache folder";
    if (rel.startsWith(".") && !KNOWN_HIDDEN.test(rel)) return `runs from a hidden folder (~/${rel.split("/")[0]})`;
    if (/^(Downloads|Desktop)\//.test(rel)) return `runs from ~/${rel.split("/")[0]}`;
  }
}

/** Running programs, keyed by their executable, and which of them hold connections to other machines. */
export async function running(ctx: Ctx): Promise<Item[]> {
  if (!ctx.system) return [];
  const ps = await ctx.run(["ps", "-axww", "-o", "pid=,user=,comm="], 8000);
  const exeOf = new Map<string, string>();
  const out = new Map<string, Item>();
  for (const line of (ps ?? "").split("\n")) {
    const m = /^\s*(\d+)\s+(\S+)\s+(.+)$/.exec(line);
    if (!m) continue;
    const [, pid, user, exe] = m;
    exeOf.set(pid, exe);
    if (user !== ctx.user || !exe.startsWith("/")) continue;
    const where = suspiciousLocation(exe, ctx.home);
    if (where) out.set(`proc:${exe}`, { kind: "proc", id: exe, name: exe.split("/").pop()!, path: exe, meta: { where, pid: Number(pid) } });
  }
  const lsof = await ctx.run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], 10_000);
  const remotes = new Map<string, Set<string>>();
  for (const line of (lsof ?? "").split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    const pid = cols[1];
    const name = cols.find((c) => c.includes("->"));
    if (!pid || !name) continue;
    const remote = name.split("->")[1];
    if (/^(127\.|\[::1\]|localhost|\[fe80)/.test(remote)) continue;
    const exe = exeOf.get(pid) ?? cols[0];
    if (!remotes.has(exe)) remotes.set(exe, new Set());
    remotes.get(exe)!.add(remote);
  }
  for (const [exe, set] of remotes) {
    out.set(`conn:${exe}`, {
      kind: "conn", id: exe, name: exe.split("/").pop()!, path: exe,
      meta: { remotes: [...set].slice(0, 6).join(" "), count: set.size, where: exe.startsWith("/") ? suspiciousLocation(exe, ctx.home) : undefined },
    });
  }
  return [...out.values()];
}

export { mtime };
