// Ways code keeps itself running or gets run without being asked: launchd jobs (macOS), systemd units and XDG
// autostart entries (Linux), shell startup files, cron, git hooks, ssh access files, /etc/ld.so.preload, new
// executables on PATH, and what is running and talking right now.

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

/** systemd units and XDG autostart entries: the Linux equivalents of launchd login jobs. Same item kind, same rules. */
export async function autostart(ctx: Ctx): Promise<Item[]> {
  const dirs: [string, string][] = [
    [join(ctx.home, ".config/systemd/user"), "user"],
    [join(ctx.home, ".config/autostart"), "user"],
    ...(ctx.system ? ([["/etc/systemd/system", "system-daemon"], ["/etc/systemd/user", "system-agent"], ["/etc/xdg/autostart", "system-agent"]] as [string, string][]) : []),
  ];
  const out: Item[] = [];
  const seen = new Set<string>();
  const unit = (path: string, name: string, source: string) => {
    const text = readText(path, 200_000);
    if (text === undefined) return;
    // ExecStart=-/path …  (systemd prefixes: - @ : + !)   Exec=/path … (desktop entries); %h and $HOME are the home folder.
    const program = [...text.matchAll(/^\s*(?:ExecStart|ExecStartPre|Exec)\s*=\s*[-@:+!]*(.+)$/gm)].map((m) => m[1].trim()).join(" ; ")
      .replace(/%h|\$\{?HOME\}?/g, ctx.home);
    out.push({ kind: "launch", id: path, name, path, hash: sha256(text), source, meta: { program: program.slice(0, 300) } });
  };
  for (const [dir, source] of dirs) {
    for (const f of ls(dir)) {
      const path = join(dir, f);
      if (/\.(service|timer|desktop)$/.test(f)) {
        unit(path, f, source);
        seen.add(f);
      } else if (f.endsWith(".wants")) {
        // Enabled units are links in *.wants/; a link to a unit no package shipped is someone's own addition.
        for (const w of ls(path)) {
          if (seen.has(w) || !/\.(service|timer)$/.test(w)) continue;
          let target = "";
          try {
            target = readlinkSync(join(path, w));
          } catch {}
          if (/^\/(usr\/)?lib\/systemd\//.test(target)) continue;
          unit(join(path, w), w, source);
        }
      }
    }
  }
  return [...new Map(out.map((i) => [i.id, i])).values()];
}

/** /etc/ld.so.preload makes every program on the system load a library first: a classic Linux rootkit trick. */
export async function preload(ctx: Ctx): Promise<Item[]> {
  if (!ctx.system) return [];
  const t = readText("/etc/ld.so.preload");
  const libs = (t ?? "").split(/\s+/).filter((l) => l && !l.startsWith("#"));
  return libs.length ? [{ kind: "preload", id: "/etc/ld.so.preload", name: "/etc/ld.so.preload", path: "/etc/ld.so.preload", hash: sha256(t!), meta: { libs: libs.join(" ") } }] : [];
}

const RC_FILES = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".ssh/rc", ".xprofile", ".xinitrc", ".config/fish/config.fish", ".gitconfig", ".ssh/config", ".ssh/authorized_keys", ".npmrc", ".curlrc"];

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
  // System cron (Linux): /etc/crontab and /etc/cron.d, one item each, so added lines show up in a diff.
  if (ctx.system) {
    for (const path of ["/etc/crontab", ...ls("/etc/cron.d").map((f) => join("/etc/cron.d", f))]) {
      const t = readText(path, 500_000);
      if (t === undefined) continue;
      items.push({ kind: "cron", id: path, name: path, path, hash: sha256(t), meta: { lines: t.split("\n").filter((l) => l.trim() && !l.startsWith("#")).length } });
      texts[path] = t;
    }
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
  if (path.startsWith("/dev/shm/")) return "runs from shared memory (/dev/shm)";
  if (path.startsWith("/Users/Shared/")) return "runs from /Users/Shared";
  if (path.startsWith(home + "/")) {
    const rel = path.slice(home.length + 1);
    if (rel.startsWith("Library/Caches/")) return "runs from a cache folder";
    if (rel.startsWith(".") && !KNOWN_HIDDEN.test(rel)) return `runs from a hidden folder (~/${rel.split("/")[0]})`;
    if (/^(Downloads|Desktop)\//.test(rel)) return `runs from ~/${rel.split("/")[0]}`;
  }
}

/** Running programs, keyed by their executable, and which of them hold connections to other machines. */
/** pid, user and full executable path of every process. Linux ps prints only a short name, so /proc is read there. */
async function processes(ctx: Ctx): Promise<{ pid: string; user: string; exe: string }[]> {
  if (process.platform === "linux") {
    const out: { pid: string; user: string; exe: string }[] = [];
    for (const pid of ls("/proc")) {
      if (!/^\d+$/.test(pid)) continue;
      try {
        // Only our own processes can be resolved without root, which is what the rules look at anyway.
        out.push({ pid, user: ctx.user, exe: readlinkSync(`/proc/${pid}/exe`).replace(/ \(deleted\)$/, "") });
      } catch {}
    }
    return out;
  }
  const ps = await ctx.run(["ps", "-e", "-ww", "-o", "pid=,user=,comm="], 8000);
  return (ps ?? "").split("\n").map((l) => /^\s*(\d+)\s+(\S+)\s+(.+)$/.exec(l)).filter(Boolean).map((m) => ({ pid: m![1], user: m![2], exe: m![3] }));
}

/** Established TCP connections as [pid, remote]: lsof where it exists (macOS), ss on Linux. */
async function connections(ctx: Ctx): Promise<[string, string, string][]> {
  const out: [string, string, string][] = [];
  const lsof = await ctx.run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], 10_000);
  if (lsof !== undefined) {
    for (const line of lsof.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      const name = cols.find((c) => c.includes("->"));
      if (cols[1] && name) out.push([cols[1], name.split("->")[1], cols[0]]);
    }
    return out;
  }
  // ss -tnpH: State Recv-Q Send-Q Local Peer users:(("node",pid=123,fd=21))
  const ss = await ctx.run(["ss", "-tnpH", "state", "established"], 10_000);
  for (const line of (ss ?? "").split("\n")) {
    const cols = line.trim().split(/\s+/);
    const users = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
    // With a state filter ss leaves out the State column: Recv-Q Send-Q Local Peer [users]
    const peer = cols[cols[0] === "ESTAB" ? 4 : 3];
    if (users && peer) out.push([users[2], peer, users[1]]);
  }
  return out;
}

export async function running(ctx: Ctx): Promise<Item[]> {
  if (!ctx.system) return [];
  const exeOf = new Map<string, string>();
  const out = new Map<string, Item>();
  for (const { pid, user, exe } of await processes(ctx)) {
    exeOf.set(pid, exe);
    if (user !== ctx.user || !exe.startsWith("/")) continue;
    const where = suspiciousLocation(exe, ctx.home);
    if (where) out.set(`proc:${exe}`, { kind: "proc", id: exe, name: exe.split("/").pop()!, path: exe, meta: { where, pid: Number(pid) } });
  }
  const remotes = new Map<string, Set<string>>();
  for (const [pid, remote, cmd] of await connections(ctx)) {
    if (/^(127\.|\[::1\]|localhost|\[fe80|\[::ffff:127\.)/.test(remote)) continue;
    const exe = exeOf.get(pid) ?? cmd;
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
