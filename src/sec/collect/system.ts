// Ways code keeps itself running or gets run without being asked: launchd jobs (macOS), systemd units and XDG
// autostart entries (Linux), shell startup files, cron, git hooks, ssh access files, /etc/ld.so.preload, new
// executables on PATH, and what is running and talking right now.

import { lstatSync, readlinkSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileHash, ls, readJson, readText, sha256, type Ctx } from "../ctx";
import { signature, type Signature } from "../intel";
import { isManagedFile, SEC, stripManaged, writePrivate } from "../store";
import type { Item } from "../types";
import { maskSecrets } from "./tools";
import { winLive } from "./windows";

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

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
      const hash = fileHash(path);
      // vswarm's own background check (vswarm watch), exactly as vswarm wrote it.
      if (isManagedFile(hash)) continue;
      out.push({
        kind: "launch", id: path, name: label, path, hash,
        source: dir.startsWith(ctx.home) ? "user" : dir.includes("Daemons") ? "system-daemon" : "system-agent",
        meta: { program: program.slice(0, 300) },
      });
    }
  }
  return out;
}

/**
 * Login items apps carry inside their bundle (macOS 13+ SMAppService): Contents/Library/LaunchAgents plists and
 * LoginItems helper apps. Which of them are switched on lives in the Background Task Management database, which only
 * root can read (sfltool dumpbtm asks for an administrator); what an app *can* start at login is in its bundle, and
 * that is what this lists.
 */
export async function appLoginItems(ctx: Ctx): Promise<Item[]> {
  if (process.platform !== "darwin") return [];
  const out: Item[] = [];
  const roots = [join(ctx.home, "Applications"), ...(ctx.system ? ["/Applications"] : [])];
  for (const root of roots) {
    for (const app of ls(root).filter((a) => a.endsWith(".app"))) {
      const lib = join(root, app, "Contents/Library");
      for (const f of ls(join(lib, "LaunchAgents")).filter((x) => x.endsWith(".plist"))) {
        const path = join(lib, "LaunchAgents", f);
        const json = await ctx.run(["plutil", "-convert", "json", "-o", "-", path], 5000);
        let program = "";
        try {
          const p = JSON.parse(json ?? "");
          // BundleProgram is relative to the app.
          program = [p.BundleProgram ? join(root, app, p.BundleProgram) : p.Program, ...(p.ProgramArguments ?? [])].filter(Boolean).join(" ");
        } catch {}
        out.push({ kind: "app-agent", id: path, name: `${app.replace(/\.app$/, "")}: ${f.replace(/\.plist$/, "")}`, path, hash: fileHash(path), source: app, meta: { app: join(root, app), program: program.slice(0, 300) } });
      }
      for (const helper of ls(join(lib, "LoginItems")).filter((x) => x.endsWith(".app"))) {
        const path = join(lib, "LoginItems", helper);
        out.push({ kind: "app-agent", id: path, name: `${app.replace(/\.app$/, "")}: ${helper.replace(/\.app$/, "")}`, path, source: app, meta: { app: join(root, app), program: path } });
      }
    }
  }
  return out;
}

/** One line of `systemextensionsctl list`: enabled, active, team id, bundle id (version), name, [state]. */
export function parseSystemExtensions(text: string): Item[] {
  const out: Item[] = [];
  let category = "";
  for (const l of text.split("\n")) {
    const cat = /^---\s+(\S+)/.exec(l);
    if (cat) category = cat[1].replace(/^com\.apple\.system_extension\./, "");
    const m = /^([*\s])\t([*\s])\t(\S+)\t(\S+) \(([^)]*)\)\t(.*?)\t\[([^\]]*)\]/.exec(l);
    if (!m) continue;
    const [, enabled, active, team, bundle, version, name, state] = m;
    out.push({ kind: "sysext", id: `sysext:${team}:${bundle}`, name, source: team, version, hash: sha256(`${state}`), meta: { bundle, category: category || undefined, enabled: enabled === "*", active: active === "*", state } });
  }
  return out;
}

/**
 * System extensions (network filters, endpoint security, drivers) and third-party kernel extensions (macOS): code that
 * sees every connection or file event, or runs in the kernel. Neither needs root to list.
 */
export async function extensions(ctx: Ctx): Promise<Item[]> {
  if (process.platform !== "darwin" || !ctx.system) return [];
  const list = await ctx.run(["systemextensionsctl", "list"], 15_000);
  if (list === undefined) ctx.gap?.("system extensions", "systemextensionsctl did not answer");
  const out = parseSystemExtensions(list ?? "");
  for (const k of ls("/Library/Extensions").filter((x) => x.endsWith(".kext"))) {
    const path = join("/Library/Extensions", k);
    out.push({ kind: "sysext", id: path, name: k, path, source: "kext", hash: fileHash(join(path, "Contents/Info.plist")), meta: { category: "kernel extension" } });
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
    if (text === undefined || isManagedFile(sha256(text))) return;
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

export const RC_FILES = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".ssh/rc", ".xprofile", ".xinitrc", ".config/fish/config.fish", ".gitconfig", ".ssh/config", ".ssh/authorized_keys", ".npmrc", ".curlrc"];

export async function startupFiles(ctx: Ctx): Promise<{ items: Item[]; texts: Record<string, string> }> {
  const items: Item[] = [];
  const texts: Record<string, string> = {};
  for (const rel of RC_FILES) {
    const path = join(ctx.home, rel);
    const raw = readText(path, 1_000_000);
    if (raw === undefined) {
      // Present but unreadable or over the cap: say so, or a file padded past the cap would vanish from the diff.
      if (isFile(path)) ctx.gap?.(`~/${rel}`, "could not be read (larger than 1 MB, or no permission)");
      continue;
    }
    // vswarm's own blocks (PATH, gate, guard, canaries) are left out, exactly as vswarm wrote them.
    const t = stripManaged(raw);
    // A file that holds nothing but vswarm's own blocks (a ~/.ssh/config vswarm created for the gate) is not a new file.
    if (t !== raw && !t.trim()) continue;
    items.push({ kind: rel.startsWith(".ssh/") ? "ssh" : "rc", id: rel, name: rel, path, hash: sha256(t), meta: { lines: t.split("\n").length } });
    // Credentials in .npmrc are never stored: its lines are kept with each token replaced by a fingerprint, so a
    // changed registry shows in the diff and a changed token only as changed.
    texts[rel] = rel === ".npmrc" ? maskSecrets(t) : t;
  }
  // Folders of start-up snippets, read by every login shell: fish's conf.d, and /etc/profile.d (Linux). Their own kind,
  // so a baseline from before vswarm read them does not report every existing snippet as new.
  const dirs: [string, string, RegExp][] = [[join(ctx.home, ".config/fish/conf.d"), ".config/fish/conf.d/", /\.fish$/], ...(ctx.system ? ([["/etc/profile.d", "/etc/profile.d/", /\.(sh|zsh|bash|csh)$/]] as [string, string, RegExp][]) : [])];
  for (const [dir, prefix, re] of dirs) {
    for (const f of ls(dir)) {
      if (!re.test(f)) continue;
      const raw = readText(join(dir, f), 1_000_000);
      if (raw === undefined) continue;
      const t = stripManaged(raw);
      if (t !== raw && !t.trim()) continue;
      const id = prefix + f;
      items.push({ kind: "shell-d", id, name: id, path: join(dir, f), hash: sha256(t), meta: { lines: t.split("\n").length } });
      texts[id] = t;
    }
  }
  // The user's own crontab, through crontab -l (the spool itself is root's). A test context answers with a fake one.
  const cron = await ctx.run(["crontab", "-l"], 5000);
  if (cron !== undefined) {
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
  // git config --global follows includes and XDG; it reads the real home, so a test context reads the fake ~/.gitconfig.
  const hooksPath = ctx.system ? (await ctx.run(["git", "config", "--global", "core.hooksPath"], 5000))?.trim() : gitValue(readText(join(ctx.home, ".gitconfig")) ?? "", "core", "hookspath");
  if (hooksPath) {
    const dir = hooksPath.replace(/^~/, ctx.home);
    for (const h of ls(dir)) {
      if (h.endsWith(".sample")) continue;
      const text = readText(join(dir, h), 200_000) ?? "";
      items.push({ kind: "git-hooks", id: join(dir, h), name: h, path: join(dir, h), hash: fileHash(join(dir, h)), meta: { risky: RUNS_FETCHED.test(text) || undefined } });
    }
  }
  if (ctx.system) {
    const hostsFile = process.platform === "win32" ? join(process.env.SystemRoot ?? "C:\\Windows", "System32", "drivers", "etc", "hosts") : "/etc/hosts";
    const hosts = readText(hostsFile);
    if (hosts !== undefined) {
      items.push({ kind: "hosts", id: hostsFile, name: hostsFile, path: hostsFile, hash: sha256(hosts) });
      texts[hostsFile] = hosts;
    }
  }
  return { items, texts };
}

/** Script lines that fetch, decode or start something in the background (a short form of the rules' RISKY_LINE). */
const RUNS_FETCHED = /\b(curl|wget|nc|ncat|socat|base64|openssl\s+enc|python3?\s+-c|node\s+-e|perl\s+-e|nohup)\b|\|\s*(ba|z)?sh\b|&\s*$/m;

/** One value from git config text: the last `key = value` in a [section], as git reads it. */
export function gitValue(text: string, section: string, key: string): string | undefined {
  let cur = "";
  let val: string | undefined;
  for (const l of text.replace(/\r/g, "").split("\n")) {
    const sec = /^\s*\[\s*([\w.-]+)(?:\s+"[^"]*")?\s*\]/.exec(l);
    if (sec) cur = sec[1].toLowerCase();
    const kv = /^\s*([\w-]+)\s*=\s*(.*?)\s*$/.exec(l);
    if (kv && cur === section && kv[1].toLowerCase() === key) val = kv[2].replace(/^"|"$/g, "");
  }
  return val;
}

/** What Windows runs by name from PATH. */
export const WIN_EXEC = /\.(exe|com|cmd|bat|ps1|vbs|js)$/i;

/** Executables in the PATH directories people install into. Size and time only; new ones are checked further. */
export async function binaries(ctx: Ctx): Promise<Item[]> {
  const out: Item[] = [];
  const win = process.platform === "win32";
  for (const dir of ctx.pathDirs) {
    for (const f of ls(dir)) {
      const path = join(dir, f);
      try {
        const st = lstatSync(path);
        if (st.isDirectory()) continue;
        const link = st.isSymbolicLink() ? readlinkSync(path) : undefined;
        // Windows has no mode bits; it runs by extension.
        if (!link && !(win ? WIN_EXEC.test(f) : st.mode & 0o111)) continue;
        out.push({ kind: "bin", id: path, name: f, path, meta: { link, size: link ? undefined : st.size, mtime: Math.round(st.mtimeMs) } });
      } catch {}
    }
  }
  return out;
}

/** Hidden folders in the home directory that ordinary tools are known to use. */
const KNOWN_HIDDEN = /^\.(bun|cargo|rustup|npm|npm-global|nvm|volta|pyenv|rbenv|deno|local|vscode|cursor|windsurf|docker|orbstack|colima|ollama|claude[\w-]*|codex|gemini|vswarm|config|gradle|m2|sdkman|swiftpm|dotnet|android|pub-cache|fvm|flutter|conda|mamba|jenv|asdf|mise|nix-profile|lmstudio|cache\/(ms-playwright|puppeteer|huggingface|pre-commit|bazel|go-build|deno))(\/|$)/;

/** A Windows path with a drive letter, either separator. */
export const WIN_PATH = /^[A-Za-z]:[\\/]/;

const WIN_TEMP = (p: string) => /^[a-z]:\\windows\\temp\\/.test(p) || /\\appdata\\local\\temp\\/.test(p);

/** The same judgement for Windows paths: case-insensitive, either separator. */
function windowsLocation(path: string, home: string): string | undefined {
  const p = path.replace(/\//g, "\\").toLowerCase();
  const h = home.replace(/\//g, "\\").replace(/\\+$/, "");
  const inHome = WIN_PATH.test(h) && p.startsWith(h.toLowerCase() + "\\");
  // %TEMP% sits inside a real home, so a program there counts; a home that is itself in a temp folder (a test's fake
  // one) is judged as a home, the way suspiciousLocation does on macOS and Linux.
  if (WIN_TEMP(p) && !(inHome && WIN_TEMP(h.toLowerCase() + "\\"))) return "runs from a temp folder";
  if (/^[a-z]:\\windows\\(tasks|tracing|system32\\spool\\drivers\\color)\\/.test(p)) return "runs from a Windows folder any user can write to";
  if (/^[a-z]:\\users\\public\\/.test(p)) return "runs from C:\\Users\\Public";
  if (/^[a-z]:\\\$recycle\.bin\\/.test(p)) return "runs from the Recycle Bin";
  // Straight in ProgramData, not in a vendor's folder under it.
  if (/^[a-z]:\\programdata\\[^\\]+$/.test(p)) return "runs straight from C:\\ProgramData";
  // Downloads and Desktop of any profile, also when OneDrive holds them.
  const dl = /^[a-z]:\\users\\[^\\]+\\(?:onedrive[^\\]*\\)?(downloads|desktop)\\/.exec(p);
  if (dl) return `runs from the ${dl[1] === "downloads" ? "Downloads" : "Desktop"} folder`;
  if (inHome) {
    const rel = p.slice(h.length + 1).replace(/\\/g, "/");
    const top = path.replace(/\//g, "\\").slice(h.length + 1).split("\\")[0];
    if (rel.startsWith(".") && !KNOWN_HIDDEN.test(rel)) return `runs from a hidden folder (~\\${top})`;
  }
}

export function suspiciousLocation(path: string, home: string): string | undefined {
  if (WIN_PATH.test(path)) return windowsLocation(path, home);
  // The home folder first: a home that sits in a temp folder (a test's fake one) is judged as a home.
  if (!path.startsWith(home + "/")) {
    if (/^\/(private\/)?(tmp|var\/tmp)\//.test(path)) return "runs from a temp folder";
    if (path.startsWith("/dev/shm/")) return "runs from shared memory (/dev/shm)";
    if (path.startsWith("/Users/Shared/")) return "runs from /Users/Shared";
  } else {
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
  // Windows: the scan's one PowerShell snapshot already holds processes and connections.
  if (ctx.win) {
    const snap = await ctx.win();
    return snap ? winLive(snap, ctx.home) : [];
  }
  const exeOf = new Map<string, string>();
  const out = new Map<string, Item>();
  for (const { pid, user, exe } of await processes(ctx)) {
    exeOf.set(pid, exe);
    if (user !== ctx.user || !exe.startsWith("/")) continue;
    const where = suspiciousLocation(exe, ctx.home);
    if (where) out.set(`proc:${exe}`, { kind: "proc", id: exe, name: exe.split(/[\\/]/).pop()!, path: exe, meta: { where, pid: Number(pid) } });
  }
  const remotes = new Map<string, Set<string>>();
  const conns = (await connections(ctx)).filter(([, remote]) => !/^(127\.|\[::1\]|localhost|\[fe80|\[::ffff:127\.)/.test(remote));
  // ps names some programs only by their short name (claude, bun); lsof knows the file each one runs.
  const short = [...new Set(conns.map(([pid]) => pid).filter((pid) => !(exeOf.get(pid) ?? "").startsWith("/")))];
  const txt = short.length ? txtOf(await ctx.run(["lsof", "-a", "-p", short.join(","), "-d", "txt", "-Fpn"], 10_000)) : new Map<string, string>();
  for (const [pid, remote, cmd] of conns) {
    const exe = txt.get(pid) ?? exeOf.get(pid) ?? cmd;
    if (!remotes.has(exe)) remotes.set(exe, new Set());
    remotes.get(exe)!.add(remote);
  }
  for (const [exe, set] of remotes) {
    const abs = exe.startsWith("/");
    out.set(`conn:${exe}`, {
      kind: "conn", id: exe, name: exe.split(/[\\/]/).pop()!, path: exe,
      meta: {
        remotes: [...set].slice(0, 6).join(" "), count: set.size, where: abs ? suspiciousLocation(exe, ctx.home) : undefined,
        // How the program is signed (macOS), or whether it is a loose binary in the home folder (Linux): see rules.ts.
        signed: abs && process.platform === "darwin" ? (await signedCached(exe)).kind : undefined,
        loose: abs && process.platform === "linux" && exe.startsWith(ctx.home + "/") ? true : undefined,
      },
    });
  }
  return [...out.values()];
}

/** The executable of each process in `lsof -d txt -Fpn` output: the first file listed after its p line. */
export function txtOf(out: string | undefined): Map<string, string> {
  const m = new Map<string, string>();
  let pid = "";
  for (const l of (out ?? "").split("\n")) {
    if (l.startsWith("p")) pid = l.slice(1);
    else if (l.startsWith("n/") && pid && !m.has(pid)) m.set(pid, l.slice(1));
  }
  return m;
}

/** codesign is slow; its answer is kept per path, size and modification time (a replaced binary is asked again). */
async function signedCached(path: string): Promise<Signature> {
  let st: { size: number; mtimeMs: number };
  try {
    st = statSync(path);
  } catch {
    return { kind: "unknown" };
  }
  const file = join(SEC(), "codesign-cache.json");
  const cache = readJson<Record<string, { size: number; mtime: number; sig: Signature }>>(file) ?? {};
  const hit = cache[path];
  if (hit && hit.size === st.size && hit.mtime === Math.round(st.mtimeMs)) return hit.sig;
  const sig = await signature(path);
  cache[path] = { size: st.size, mtime: Math.round(st.mtimeMs), sig };
  writePrivate(file, cache);
  return sig;
}

/**
 * Places a program can be unsigned, or ad-hoc signed, for ordinary reasons: Homebrew and Nix builds, language
 * toolchains, and your own code folders (what you build locally is ad-hoc signed on Apple silicon).
 */
export function buildPlace(path: string, home: string): boolean {
  if (/^\/(opt\/homebrew|usr\/local\/(Cellar|opt|Homebrew)|home\/linuxbrew\/\.linuxbrew|nix\/store|usr\/(bin|sbin|lib|libexec)|bin|sbin|System|Library\/Apple)\//.test(path)) return true;
  if (!path.startsWith(home + "/")) return false;
  const rel = path.slice(home.length + 1);
  return /^(\.(bun|cargo|rustup|nvm|volta|fnm|nodenv|pyenv|rbenv|deno|asdf|sdkman|local\/share\/(mise|pnpm|fnm)|npm-global|linuxbrew|gradle|m2|dotnet|pub-cache|fvm)|go|Library\/pnpm|develop|code|projects|src|work|dev|git|repos)\//.test(rel);
}
