// From what a scan saw to what deserves attention. Two kinds of rule:
//   always   things that are wrong whatever the history (known-malicious package, code running from /tmp)
//   change   things that appeared or changed since the baseline you marked as clean

import { createHash } from "node:crypto";
import { redact } from "./ctx";
import { distance, knownPublisher, lookAlike, nameSignals, signature, type Malicious, type Signature } from "./intel";
import { argvOf, under } from "./collect/agents";
import { buildPlace, suspiciousLocation, WIN_PATH } from "./collect/system";
import { TOOL_CONFIGS } from "./collect/tools";
import { stockWmi, winLaunchRisk } from "./collect/windows";
import { ADDED_KINDS, type Finding, type Item, type Scan, type Severity } from "./types";

/** Lines in a shell startup file that fetch, decode or start something in the background. */
/** The command that names a process's parent, for the system vswarm runs on. */
const parentOf = (pid: unknown) =>
  process.platform === "win32" ? `Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid) || "PID"}" | Select-Object ParentProcessId` : `ps -o ppid= -p ${Number(pid) || "PID"}`;
const RISKY_LINE = /\b(curl|wget|nc|ncat|socat|base64|openssl\s+enc|eval|osascript|python3?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e|nohup|launchctl|chmod\s+\+x)\b|&\s*$|\|\s*(ba|z)?sh\b|\/tmp\/|\.cache\//;

/**
 * The same for PowerShell profiles: run code from a string, fetch it, decode it, start it hidden, or switch off
 * Defender for a folder. Case-insensitive like PowerShell itself; only profile scripts are held to it.
 */
const RISKY_PS = /\b(invoke-expression|iex|downloadstring|downloadfile|frombase64string)\b|\b(invoke-webrequest|iwr|invoke-restmethod|irm)\b.*\|\s*(iex|invoke-expression)\b|\s-(encodedcommand|enc|ec|e)\s|\bstart-process\b.*\s-w(indowstyle)?\s+h(idden)?\b|\badd-mppreference\b.*-exclusion|\bset-mppreference\b.*-disable/i;

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/**
 * How much a program's place weighs. A hidden folder of its own straight in the home (~/.lib, ~\.wsl-keepalive.vbs) is
 * where people and dev tools also keep their own things, so on its own it warns; temp, Downloads, Public and a hidden
 * folder inside another stay high. Once there is a baseline, a new one is reported as new anyway.
 */
export function placeSeverity(where: string): "high" | "medium" {
  return /^runs from a hidden folder \(~[\\/][^\\/)]+\)/.test(where) ? "medium" : "high";
}

// ── lines that change what a tool runs, or where packages come from

/** A program in a hidden folder inside another one (~/.config/.x/run): tools do not install there. */
function nestedHidden(path: string, home: string): string | undefined {
  // Either separator, and Windows does not care about case.
  const win = WIN_PATH.test(home);
  const norm = (s: string) => (win ? s.replace(/\\/g, "/").toLowerCase() : s);
  const p = norm(path), h = norm(home).replace(/\/+$/, "");
  if (!p.startsWith(h + "/")) return;
  const dirs = p.slice(h.length + 1).split("/").slice(0, -1);
  const deep = dirs.findIndex((d, i) => i > 0 && d.startsWith("."));
  if (deep > 0) return `runs from a hidden folder (~/${dirs.slice(0, deep + 1).join("/")})`;
}

/**
 * Where the program a config value starts lives, when that is somewhere software is not installed to: temp and cache
 * folders, Downloads, or a hidden folder inside another. A hidden folder of its own in the home (~/.krew, ~/.yarn) is
 * where many installers put their tools, so it does not count here.
 */
export function hiddenProgram(value: string, home: string): string | undefined {
  const v = value.trim().replace(/^!/, "");
  const first = (/^"([^"]+)"|^'([^']+)'|^(\S+)/.exec(v) ?? []).slice(1).find(Boolean) ?? "";
  const prog = first.replace(/^~(?=\/)/, home).replace(/^\$\{?HOME\}?(?=\/)/, home).replace(/^%h(?=\/)/, home);
  if (!prog.startsWith("/") && !WIN_PATH.test(prog)) return;
  const where = suspiciousLocation(prog, home);
  const topHidden = where?.startsWith("runs from a hidden folder") && !/\(~[\\/]\.cache\)/.test(where);
  return (topHidden ? undefined : where) ?? nestedHidden(prog, home);
}

/** The registries and indexes a package manager trusts by default. */
const OFFICIAL_HOSTS = ["registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com", "pypi.org", "files.pythonhosted.org", "pypi.python.org", "test.pypi.org",
  "crates.io", "index.crates.io", "static.crates.io", "rubygems.org", "conda.anaconda.org", "repo.anaconda.com"];
const flatHost = (h: string) => h.replace(/[.-]/g, "");
const domainOf = (h: string) => h.split(".").slice(-2).join(".");

/**
 * Why a registry or index URL is dangerous: no TLS, a bare IP address, or a host made to pass for an official one
 * (registry.npmjss.org, pypi-org.mirror.net). A company's own registry over https (npm.corp.example.com) is not.
 */
export function urlRisk(url: string): string | undefined {
  const m = /^(https?):\/\/(?:[^@/\s]*@)?(\[[^\]]+\]|[^:/\s"']+)/i.exec(url);
  if (!m) return;
  const host = m[2].toLowerCase();
  if (/^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(host)) return;
  if (/^\d+\.\d+\.\d+\.\d+$|^\[/.test(host)) return `is the bare IP address ${host}`;
  if (m[1].toLowerCase() === "http") return `is fetched from ${host} without TLS`;
  if (OFFICIAL_HOSTS.includes(host)) return;
  for (const o of OFFICIAL_HOSTS) if (distance(domainOf(host), domainOf(o), 1) === 1 || flatHost(host).includes(flatHost(o))) return `is ${host}, made to look like ${o}`;
}

/** Shell lines that make other programs load code, run code at every prompt, capture passwords, or hide history. */
function shellRisk(l: string, home: string): string | undefined {
  if (/\b(LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES)\s*=/.test(l)) return "makes programs started from here load a library first";
  if (/\bNODE_OPTIONS\s*=.*(--require|--import|--loader|--experimental-loader|["'\s=]-r\s)/.test(l)) return "makes every node process load a script first";
  if (/\bPROMPT_COMMAND\+?=["'(]?\s*(~|\$\{?HOME\}?|\/)[\w./-]/.test(l)) return "runs a program at every prompt";
  if (/\btrap\s+.+\s(DEBUG|RETURN)\s*$/.test(l)) return "runs a command before every command you type";
  // alias sudo='sudo ' and alias sudo='nocorrect sudo' still run the real one.
  const alias = /^alias\s+(sudo|su|doas|passwd|pkexec)=(["']?)(.*)\2$/.exec(l);
  if (alias && !new RegExp(`^((nocorrect|noglob|command|builtin)\\s+)*${alias[1]}(\\s[^;&|]*)?$`).test(alias[3].trim())) return `replaces ${alias[1]}, which is handed your password`;
  if (/^(function\s+(sudo|su|doas|passwd|pkexec)\b|(sudo|su|doas|passwd|pkexec)\s*\(\s*\))/.test(l)) return "replaces sudo with a function, which is handed your password";
  if (/^(unset\s+HISTFILE\b|(export\s+)?HISTFILE=["']?\/dev\/null|(export\s+)?(HISTSIZE|SAVEHIST|HISTFILESIZE)=["']?0\b|set\s+\+o\s+history\b)/.test(l)) return "switches off the shell history";
  const docker = /\bDOCKER_HOST=["']?tcp:\/\/([^:/"'\s]+)/.exec(l);
  if (docker && !/^(localhost|127\.)/.test(docker[1])) return `sends every docker command to ${docker[1]} without TLS`;
  // PATH=<dir>:$PATH, path=(<dir> $path), fish_add_path <dir>: a folder put before the system's own.
  const path = /^(?:export\s+)?PATH=["']?([^"'\s]+)/.exec(l)?.[1].split(":") ?? /^path=\(([^)]*)\)/.exec(l)?.[1].split(/\s+/) ?? /^(?:fish_add_path|set\s+-\w*x\w*\s+PATH)\s+(.+)$/.exec(l)?.[1].split(/\s+/);
  for (const d of path ?? []) {
    if (/^["']?\$\{?(PATH|path)\}?/.test(d)) break;
    const why = hiddenProgram(`${d.replace(/["']/g, "")}/x`, home);
    if (why) return `puts a folder first on PATH that ${why.replace(/^runs from/, "is")}`;
  }
}

/** git settings that run a program: fsmonitor on every status, sshCommand on every fetch and push, askpass, pager, gpg. */
function gitRisk(l: string, home: string): string | undefined {
  const kv = /^([\w.-]+)\s*=\s*(.*)$/.exec(l);
  if (!kv) return;
  const key = kv[1].toLowerCase();
  const val = kv[2].replace(/^"|"$/g, "");
  if (key === "fsmonitor" && !/^(true|false|yes|no|on|off|1|0)$/i.test(val)) return "makes git run this program on every status, in every repository";
  if (["sshcommand", "askpass", "pager", "editor", "program", "helper"].includes(key)) {
    const why = hiddenProgram(val, home);
    if (why) return `makes git start a program that ${why}`;
  }
}

/** ssh client settings that run commands: LocalCommand, KnownHostsCommand, Match exec, and proxies from odd places. */
function sshRisk(l: string, home: string): string | undefined {
  if (/^match\b.*\bexec\b/i.test(l)) return "makes ssh run this command to choose settings, for every connection";
  const kv = /^(\w+)(?:\s*=\s*|\s+)(.*)$/.exec(l);
  if (!kv) return;
  const key = kv[1].toLowerCase();
  if (key === "localcommand" || key === "knownhostscommand") return `makes ssh run this command itself (${kv[1]})`;
  if (["proxycommand", "pkcs11provider", "securitykeyprovider"].includes(key)) {
    const why = hiddenProgram(kv[2], home);
    if (why) return `makes ssh start a program that ${why}`;
  }
}

/** Package manager settings: the registry or index, and the programs npm and cargo start for you. */
function configRisk(l: string, home: string): string | undefined {
  for (const u of l.match(/https?:\/\/[^\s"',]+/gi) ?? []) {
    const why = urlRisk(u);
    if (why) return `the package source ${why}`;
  }
  const kv = /^["']?([\w.:@/-]+)["']?\s*[=:]\s*(.*)$/.exec(l);
  if (!kv) return;
  const key = kv[1].toLowerCase().replace(/^.*\./, "");
  const val = kv[2].trim().replace(/^["']|["']$/g, "");
  if (key === "node-options" && /--require|--import|--loader|(^|\s)-r\s/.test(val)) return "makes every node process npm starts load a script first";
  if (["script-shell", "shell", "git", "onload-script", "runner", "rustc-wrapper", "rustc-workspace-wrapper", "linker", "rustc", "rustdoc"].includes(key)) {
    const why = hiddenProgram(val, home);
    if (why) return `starts a program that ${why}`;
  }
}

/**
 * Why one line added to a start-up or config file is dangerous, beyond RISKY_LINE's downloads and background jobs.
 * Undefined for an ordinary line. Which reading applies depends on the file.
 */
export function lineRisk(id: string, line: string, home: string): string | undefined {
  const l = line.trim();
  if (id === ".gitconfig") return gitRisk(l, home);
  if (id === ".ssh/config") return sshRisk(l, home);
  if (id === ".npmrc" || TOOL_CONFIGS.includes(id)) return configRisk(l, home);
  if (/\.ps1$/i.test(id) || id === "crontab" || id.startsWith("/") || /^[A-Za-z]:/.test(id)) return;
  return shellRisk(l, home);
}

/** Python code that fetches, decodes or starts something: what malicious .pth files and sitecustomize hooks do. */
const PY_RISKY = /\b(exec|eval)\s*\(|b64decode|base64|subprocess|os\.system|os\.popen|urllib|urlopen|requests\.get|socket\.|__import__\(\s*["'](base64|subprocess|os|socket|urllib)/;

/** Why a program another tool runs for you is dangerous, if it is. */
function toolExecRisk(i: Item, home: string): string | undefined {
  // Behind vswarm's own gate, the command it hands on is what runs (collect/tools.ts behindGate).
  const prog = String(i.meta?.gated ?? i.meta?.program ?? "");
  if (String(i.id).startsWith("docker-context:")) {
    const m = /^tcp:\/\/([^:/]+)(?::(\d+))?/.exec(prog);
    if (m && i.meta?.current && !/^(localhost|127\.)/.test(m[1]) && (m[2] !== "2376" || i.meta?.skipTls)) return `sends every docker command to ${prog} without TLS`;
    return;
  }
  if (String(i.id).startsWith("python:")) return !i.meta?.stock && (PY_RISKY.test(prog) || RISKY_LINE.test(prog)) ? "runs code that downloads, decodes or starts a program, at every Python start" : undefined;
  if (RISKY_LINE.test(prog.replace(/\.cache\//g, ""))) return "runs a command that downloads, decodes or backgrounds something";
  const where = hiddenProgram(prog, home);
  if (where) return `starts a program that ${where}`;
}

/** What vswarm gate aws writes for an SSO profile behind its gate: only aws, asking vswarm's companion profile. */
const SSO_GATE = /^aws configure export-credentials --profile '?vswarm-src-[^\s']+'? --format process$/;

/** Commands that are handed passwords and tokens: a copy found earlier on PATH sees them first. */
const SHADOWED = new Set(["sudo", "su", "doas", "pkexec", "passwd", "login", "ssh", "scp", "sftp", "ssh-add", "ssh-agent", "ssh-keygen", "git", "gpg", "gpg2", "security"]);

/**
 * The program an MCP server or hook runs, and the package it pulls when it is started through npx/uvx/bunx. `parts`
 * are an MCP server's command and arguments as its config gives them (a hook's shell line split on spaces); `base` is
 * the folder its agent starts it in, when known, which a ./ or ../ path is read from.
 */
export function launcher(parts: string[], home: string, base?: string): { exe?: string; pkg?: { eco: "npm" | "pip"; name: string } } {
  const placed = parts.map((p) => (base && /^\.\.?[\\/]/.test(p) ? under(base, p) : p));
  const exe = placed.find((p) => p.startsWith("/") || p.startsWith("~/") || WIN_PATH.test(p))?.replace(/^~(?=\/)/, home);
  const runner = parts.findIndex((p) => /(^|\/)(npx|bunx|pnpx|uvx|pipx)$/.test(p) || p === "dlx");
  if (runner < 0) return { exe };
  const eco = /uvx|pipx/.test(parts[runner]) ? "pip" : "npm";
  // Skip flags and their values (--from x, -y, --offline); the package is the first plain word after that.
  let name: string | undefined;
  for (let i = runner + 1; i < parts.length; i++) {
    if (parts[i] === "--from") return { exe, pkg: { eco, name: parts[i + 1]?.replace(/[=@<>].*$/, "") } };
    if (parts[i].startsWith("-")) continue;
    name = parts[i];
    break;
  }
  return { exe, pkg: name ? { eco, name: name.replace(/(?<=.)@[^/]*$/, "").replace(/[=<>].*$/, "") } : undefined };
}

function key(i: Item) {
  return `${i.kind}|${i.id}`;
}

function addedLines(before: string | undefined, after: string | undefined): string[] {
  if (after === undefined) return [];
  const old = new Set((before ?? "").split("\n").map((l) => l.trim()));
  return after.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !old.has(l));
}

export interface RuleInput {
  scan: Scan;
  baseline?: Scan;
  malicious: Malicious[];
  secrets: Finding[];
  /** Overridable for tests. */
  sign?: (path: string) => Promise<Signature>;
}

/** Checks the baseline did not cover yet, by name, so the summary can say so. */
export function uncovered(scan: Scan, baseline?: Scan): string[] {
  if (!baseline) return [];
  const kinds = new Set(scan.items.map((i) => i.kind));
  const names = [...kinds].filter((k) => (baseline.covers ? !baseline.covers.includes(k) : ADDED_KINDS[k])).map((k) => ADDED_KINDS[k] ?? k);
  return [...new Set(names)];
}

export async function evaluate(input: RuleInput): Promise<Finding[]> {
  const { scan, baseline } = input;
  const sign = input.sign ?? signature;
  const home = scan.home;
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);
  const before = new Map((baseline?.items ?? []).map((i) => [key(i), i]));
  // A baseline from before a check existed says nothing about what that check finds.
  const covered = (kind: string) => (baseline?.covers ? baseline.covers.includes(kind) : !ADDED_KINDS[kind]);
  const isNew = (i: Item) => baseline !== undefined && covered(i.kind) && !before.has(key(i));
  const changed = (i: Item) => {
    const b = before.get(key(i));
    return b !== undefined && b.hash !== undefined && i.hash !== undefined && b.hash !== i.hash;
  };
  const newBins = new Set(scan.items.filter((i) => i.kind === "bin" && isNew(i)).map((i) => i.path));

  // ── always
  for (const m of input.malicious) {
    add({
      id: `malicious:${m.item.kind}:${m.item.name}@${m.item.version}`, rule: "malicious", severity: "critical",
      title: `Known-malicious package installed: ${m.item.name}@${m.item.version} (${m.item.kind})`,
      detail: [m.ids.join(", "), m.item.path ?? ""].filter(Boolean),
      fix: "Treat this machine as compromised: vswarm respond", item: m.item,
    });
  }
  // Windows: a program in temp or a hidden folder that a known publisher signed (an installer or updater) is said, not
  // counted; the signer goes in the finding either way. Asked only for programs placed there, so a check stays fast.
  const signers = new Map<string, Promise<string | undefined>>();
  const publisher = (path?: string) => {
    if (!path || !WIN_PATH.test(path)) return Promise.resolve(undefined);
    if (!signers.has(path)) signers.set(path, sign(path).then((s) => knownPublisher(s, path)).catch(() => undefined));
    return signers.get(path)!;
  };
  for (const i of scan.items) {
    if (i.kind === "proc") {
      const by = await publisher(i.path);
      add({ id: `proc:${i.id}`, rule: "proc-location", severity: by ? "low" : placeSeverity(String(i.meta?.where ?? "")), title: `Program running from an unusual place: ${i.path}${by ? ` (signed by ${by})` : ""}`,
        detail: [String(i.meta?.where ?? ""), `pid ${i.meta?.pid}`, by ? `validly signed by ${by}, as installers and updaters that run from there are` : ""].filter(Boolean), fix: `Find out what started it (${parentOf(i.meta?.pid)}); if you do not know it, vswarm respond`, item: i });
    }
    if (i.kind === "conn") {
      const where = i.meta?.where as string | undefined;
      const fresh = i.path && newBins.has(i.path);
      const by = where ? await publisher(i.path) : undefined;
      if (where || fresh) {
        add({ id: `conn:${i.id}`, rule: "conn", severity: by ? "low" : where ? placeSeverity(where) : "high",
          title: `${i.name} is connected to other machines${where ? ` and ${where}` : " and is new since the baseline"}${by ? ` (signed by ${by})` : ""}`,
          detail: [`remotes: ${i.meta?.remotes}`, i.path ?? "", by ? `validly signed by ${by}` : ""].filter(Boolean), fix: "If you do not recognise it, disconnect from the network and run vswarm respond", item: i });
      } else if (i.path && !buildPlace(i.path, home) && (i.meta?.signed === "unsigned" || i.meta?.signed === "adhoc" || i.meta?.loose)) {
        // Implants are rarely signed by a developer; real apps are. Builds of your own and toolchains are left out.
        const how = i.meta?.signed === "unsigned" ? "is not code-signed" : i.meta?.signed === "adhoc" ? "is only ad-hoc signed (by nobody)" : "is a loose program in your home folder that no package manager installed";
        add({ id: `conn-unsigned:${i.id}`, rule: "conn-unsigned", severity: "medium", title: `${i.name} is connected to other machines, and its program ${how}`,
          detail: [`remotes: ${i.meta?.remotes}`, i.path], fix: "Fine if you built or downloaded it yourself (vswarm accept it); if you do not know it, find what started it and run vswarm respond", item: i });
      }
    }
    if (i.kind === "mcp" || i.kind === "agent-hook") {
      const cmd = String(i.meta?.command ?? "");
      const what = i.kind === "mcp" ? `MCP server ${i.name} (${i.source})` : `Agent hook ${i.name}`;
      // An MCP server's own command, placed where its agent starts it, comes first; then any program in its arguments.
      const exe = i.meta?.exe ? String(i.meta.exe) : undefined;
      const l = launcher(argvOf(i) ?? cmd.split(/\s+/).filter(Boolean), home, i.meta?.base ? String(i.meta.base) : undefined);
      const where = (exe ? suspiciousLocation(exe, home) : undefined) ?? (l.exe ? suspiciousLocation(l.exe, home) : undefined);
      const like = l.pkg ? lookAlike(l.pkg.eco, l.pkg.name) : undefined;
      // A server its agent will not start (Codex enabled = false, Gemini CLI excluded) runs nothing and connects nowhere;
      // a token pasted into it is still stored, and turning it on is reported as a change below.
      const off = i.kind === "mcp" && i.meta?.disabled === true;
      if (!off && (where || like || (cmd && RISKY_LINE.test(cmd.replace(/\.cache\//g, ""))))) {
        add({ id: `agent-risky:${i.kind}:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-risky", severity: "high",
          title: `${what} ${where ? `starts a program that ${where}` : like ? `runs ${l.pkg!.name}, which looks like ${like}` : "runs a command that downloads, decodes or backgrounds something"}`,
          detail: [redact(cmd.slice(0, 200)), i.path ?? ""], fix: "An agent runs this with your access. Remove it unless you set it up yourself; then vswarm respond", item: i });
      }
      // A relative command whose folder is not known cannot be judged by place, and it need not be the program you
      // set up: whatever sits at that path in the folder the agent was started in runs instead.
      if (i.kind === "mcp" && !off && i.meta?.relative && !where)
        add({ id: `agent-relative:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-relative", severity: "medium", title: `${what} starts a program by a relative path (${redact(String(argvOf(i)?.[0] ?? cmd).slice(0, 120))})`,
          detail: [String(i.meta.relative), i.path ?? ""], fix: "Give the command as an absolute path, so the same program runs wherever the agent is started", item: i });
      const url = String(i.meta?.url ?? "");
      // Read the host with a regex: a URL that does not parse ("http://") must not stop the whole check.
      if (!off && /^http:\/\//.test(url) && !/^http:\/\/(localhost|127\.|\[::1\])/.test(url)) {
        // Shown, not stored: a password in the URL's userinfo or a token in its query is masked.
        const shown = redact(url);
        add({ id: `agent-http:${i.id}`, rule: "agent-http", severity: "medium", title: `${what} talks to ${/^http:\/\/([^/?#]+)/.exec(shown)?.[1] ?? shown} without TLS`, detail: [shown], fix: "Anyone on the network path can read or change what the agent sends and gets; use https", item: i });
      }
      if (i.meta?.secrets)
        add({ id: `agent-secret:${i.id}`, rule: "secret", severity: "medium", title: `${what} keeps a token in plain text: ${i.meta.secrets}`, detail: [i.path ?? ""],
          fix: "Reference an environment variable or the OS keychain instead of pasting the value into the config", item: i });
    }
    if (i.kind === "tool-exec") {
      const why = toolExecRisk(i, home);
      if (why)
        add({ id: `tool-exec-risky:${i.id}:${i.hash?.slice(0, 12)}`, rule: "tool-exec-risky", severity: "high", title: `${capital(String(i.meta?.what ?? "helper"))} ${i.name} ${why}`,
          detail: [redact(String(i.meta?.program ?? "").slice(0, 200)), i.path ?? ""], fix: "It runs with your access every time that tool does. Remove it unless you set it up yourself; then vswarm respond", item: i });
    }
    if (i.kind === "agent-perm" && i.meta?.bypass)
      add({ id: `agent-bypass:${i.id}`, rule: "agent-perm", severity: "low", title: `${i.name}: the agent may run commands without asking (bypass permissions)`, detail: [i.path ?? ""], item: i });
    if (i.kind === "preload") {
      add({ id: `preload:${i.hash?.slice(0, 12)}`, rule: "preload", severity: "high", title: "/etc/ld.so.preload makes every program load a library first",
        detail: [`libraries: ${i.meta?.libs}`, "Almost no normal system uses this file; Linux rootkits and credential stealers do."],
        fix: "Unless your own security or debugging tool put it there, vswarm respond", item: i });
    }
    if (i.kind === "launch") {
      const prog = String(i.meta?.program ?? "");
      // Windows entries (Run values, tasks, services, Startup) say what they are, and their command lines are Windows'.
      const what = i.meta?.what ? capital(String(i.meta.what)) : undefined;
      if (what) {
        // Against the Windows home the entry belongs to (the scan's own, or a snapshot fixture's).
        const r = winLaunchRisk(prog, String(i.meta?.home ?? home));
        if (r.risky || r.where) {
          add({ id: `launch-location:${i.id}`, rule: "launch-location", severity: r.risky ? "high" : placeSeverity(r.where!), title: `${what} ${i.name} ${r.risky ?? `starts a program that ${r.where}`}`,
            detail: [i.path ?? "", redact(prog.slice(0, 300))], fix: "Unless you set this up yourself, vswarm respond", item: i });
        }
      } else {
        const exe = prog.split(" ").find((p) => p.startsWith("/") && !/^\/(bin|usr\/bin)\/(ba|z)?sh$/.test(p) && !/^\/usr\/bin\/(env|python3?|osascript|open)$/.test(p)) ?? "";
        const where = exe ? suspiciousLocation(exe, home) : undefined;
        if (where) {
          add({ id: `launch-location:${i.id}`, rule: "launch-location", severity: placeSeverity(where), title: `Login job ${i.name} starts a program that ${where}`,
            detail: [i.path ?? "", prog], fix: "Unless you set this up yourself, vswarm respond", item: i });
        }
      }
    }
    if (i.kind === "wmi" && !stockWmi(i)) {
      // A permanent subscription runs on its own whenever its event fires, as SYSTEM: fileless persistence.
      const runs = i.meta?.type === "CommandLineEventConsumer" || i.meta?.type === "ActiveScriptEventConsumer";
      add({ id: `wmi:${i.id}:${i.hash?.slice(0, 12)}`, rule: "wmi", severity: runs ? "high" : "medium",
        title: runs ? `WMI subscription runs a ${i.meta?.type === "ActiveScriptEventConsumer" ? "script" : "command"} on an event: ${i.name}` : `WMI subscription that Windows does not ship: ${i.name} (${i.meta?.type})`,
        detail: [i.meta?.command ? redact(String(i.meta.command).slice(0, 200)) : "", i.meta?.filter ? `when: ${i.meta.filter}` : "not bound to an event filter"].filter(Boolean),
        fix: "Almost no software uses these; unless you know this one, vswarm respond", item: i });
    }
  }

  // An agent that runs any command without asking, on a machine whose production ssh keys need no passphrase: one
  // poisoned README away from using them. Each half alone is a smaller finding of its own; together they are a path.
  const loose = scan.items.filter((i) => i.kind === "agent-perm" && (i.meta?.bypass || i.meta?.wide));
  const prodKeys = input.secrets.filter((f) => f.meta?.production);
  if (loose.length && prodKeys.length) {
    const ids = [...loose.map((i) => i.id), ...prodKeys.map((f) => f.id)].sort().join("|");
    add({
      id: `agent-prod:${createHash("sha256").update(ids).digest("hex").slice(0, 12)}`, rule: "agent-prod", severity: "medium",
      title: `${loose.map((i) => i.name).join(", ")} may run any command without asking, and ${prodKeys.length === 1 ? "a production ssh key here has" : `${prodKeys.length} production ssh keys here have`} no passphrase`,
      detail: [...prodKeys.map((f) => String(f.meta?.file ?? f.id).replace(home, "~")), ...loose.map((i) => `${i.meta?.bypass ? "bypass permissions" : `allows ${i.meta?.wide}`}: ${String(i.path ?? "").replace(home, "~")}`)],
      fix: "Put the production keys in vswarm's vault (vswarm fix <n> on each key), or let the agent ask before shell commands; vswarm hook install claude also checks production commands before they run",
    });
  }

  // A package source over plain http, at a bare IP address or on a look-alike host is wrong whenever it is there. With
  // a baseline, a newly added one is reported with the file's other changes below.
  if (!baseline) {
    for (const i of scan.items) {
      if (i.id !== ".npmrc" && !TOOL_CONFIGS.includes(i.id)) continue;
      const bad = (scan.texts[i.id] ?? "").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !/^[#;]/.test(l)).map((l) => [l, configRisk(l, home)] as const).filter(([, why]) => why?.startsWith("the package source"));
      if (bad.length)
        add({ id: `pkg-source:${i.id}:${i.hash?.slice(0, 12)}`, rule: "pkg-source", severity: "medium", title: `~/${i.id} takes packages from an unsafe source`,
          detail: bad.slice(0, 4).map(([l, why]) => `${redact(l.slice(0, 160))} · ${why}`), fix: "Point it back at the official registry or your company's https mirror, unless you set this up on purpose (vswarm fix removes the lines)", item: i,
          meta: { lines: bad.map(([l]) => l) } });
    }
  }

  // ── change (only with a baseline)
  if (baseline) {
    const newTaps = scan.items.filter((i) => i.kind === "brew-tap" && isNew(i) && !i.meta?.official);
    for (const t of newTaps) {
      const formulas = scan.items.filter((i) => i.kind === "brew" && i.source === t.name).map((i) => `${i.name} ${i.version ?? ""}`.trim());
      add({ id: `tap:${t.id}`, rule: "brew-tap", severity: "high", title: `New third-party Homebrew tap: ${t.name}`,
        detail: [`from ${t.source ?? "unknown remote"}`, formulas.length ? `installed from it: ${formulas.join(", ")}` : "nothing installed from it yet"],
        fix: "If you did not mean to trust this publisher: brew untap " + t.name + " and remove what came from it", item: t });
    }
    for (const i of scan.items) {
      // An MCP server switched on since the baseline starts from now on: reported like a new one.
      const was = i.kind === "mcp" ? before.get(key(i)) : undefined;
      if (was && was.meta?.disabled === true && i.meta?.disabled !== true) {
        add({ id: `agent-mcp-enabled:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-mcp-enabled", severity: "medium",
          title: `MCP server for ${i.source} turned on: ${i.name}${changed(i) ? ", with a different definition" : ""}`, detail: [redact(String(i.meta?.command ?? i.meta?.url ?? "")), i.path ?? ""],
          fix: "It was switched off when you took the baseline; an MCP server acts with the agent's access to your files and shell, so keep it on only if you turned it on", item: i });
        continue;
      }
      if (!isNew(i) && !changed(i)) continue;
      // Added or changed while switched off: nothing runs yet; turning it on is what gets reported.
      if (i.kind === "mcp" && i.meta?.disabled === true) continue;
      const fresh = isNew(i);
      switch (i.kind) {
        case "brew":
          if (!i.meta?.official && fresh && !newTaps.some((t) => t.name === i.source)) {
            add({ id: `brew:${i.id}`, rule: "brew-thirdparty", severity: "medium", title: `New package from third-party tap ${i.source}: ${i.name}`, detail: [i.path ?? ""], item: i });
          }
          break;
        case "npm":
        case "pip":
        case "cargo": {
          if (!fresh) break;
          const eco = i.kind === "npm" ? "npm" : i.kind === "pip" ? "pip" : "";
          const like = lookAlike(eco, i.name);
          const says = eco ? nameSignals(eco, i.name) : [];
          if (like) {
            add({ id: `lookalike:${i.kind}:${i.name}`, rule: "lookalike", severity: "high", title: `New ${i.kind} package ${i.name} looks like "${like}"`,
              detail: [`${i.name}@${i.version ?? "?"}`, i.path ?? ""], fix: `Check you meant ${i.name}, not ${like}; if not, remove it and vswarm respond`, item: i });
          } else if (says.length) {
            add({ id: `name-signal:${i.kind}:${i.name}`, rule: "lookalike", severity: "high", title: `New ${i.kind} package ${i.name}: ${says[0].split(":")[0]}`,
              detail: [...says, `${i.name}@${i.version ?? "?"}`, i.path ?? ""], fix: "Remove it unless it is your own test package, then vswarm respond", item: i });
          } else if (i.kind === "npm" && i.meta?.scripts) {
            add({ id: `npm-scripts:${i.id}`, rule: "install-scripts", severity: "medium", title: `New global npm package runs scripts at install: ${i.name}`,
              detail: [`scripts: ${i.meta.scripts}`, `${i.name}@${i.version ?? "?"}`], fix: "Make sure you installed it on purpose and know its publisher", item: i });
          } else {
            add({ id: `pkg:${i.kind}:${i.id}`, rule: "new-package", severity: "low", title: `New ${i.kind} package: ${i.name}@${i.version ?? "?"}`, detail: [], item: i });
          }
          break;
        }
        case "editor-ext":
          if (!fresh) break;
          // Not in the editor's own list of marketplace installs: copied into the folder, or installed from a .vsix.
          if (i.meta?.gallery === false)
            add({ id: `ext:${i.id}`, rule: "editor-ext", severity: i.meta?.startup ? "high" : "medium",
              title: `New ${i.source} extension that did not come from the marketplace${i.meta?.startup ? ", and it starts with the editor" : ""}: ${i.name} ${i.version ?? ""}`,
              detail: [i.path ?? "", "Its folder is not in extensions.json as a marketplace install: it was copied in, or installed from a .vsix file."],
              fix: "Remove the folder unless you installed it from a file yourself; extensions run with your access", item: i });
          else add({ id: `ext:${i.id}`, rule: "editor-ext", severity: "low", title: `New ${i.source} extension: ${i.name} ${i.version ?? ""}`, detail: [i.path ?? ""], item: i });
          break;
        case "browser-sideload":
          if (fresh)
            add({ id: `bside:${i.id}`, rule: "browser-ext", severity: i.meta?.crx ? "high" : "medium",
              title: i.meta?.crx ? `New ${i.source} extension side-loaded from a file: ${i.name}` : `New extension ${i.source} installs on its own: ${i.name}`,
              detail: [i.path ?? "", String(i.meta?.crx ?? i.meta?.update ?? "")].filter(Boolean), fix: "Remove the file unless an app you trust put it there, then remove the extension in the browser", item: i });
          break;
        case "tool-exec":
          add({ id: `tool-exec:${i.id}:${i.hash?.slice(0, 12)}`, rule: fresh ? "tool-exec-new" : "tool-exec-changed", severity: i.meta?.stock || SSO_GATE.test(String(i.meta?.gated ?? "")) ? "low" : "medium",
            title: `${fresh ? "New" : "Changed"} ${i.meta?.what ?? "helper"} ${i.name}: ${redact(String(i.meta?.program ?? "")).slice(0, 80)}`, detail: [i.path ?? ""],
            fix: "Another tool runs this for you, with your access; keep it only if you set it up", item: i });
          break;
        case "browser-ext": {
          if (!fresh) break;
          const perms = String(i.meta?.permissions ?? "");
          const wide = /<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/|cookies|webRequest|debugger|nativeMessaging/.test(perms);
          add({ id: `bext:${i.id}`, rule: "browser-ext", severity: wide ? "medium" : "low", title: `New browser extension (${i.source}): ${i.name}`,
            detail: [wide ? `can read or change pages/cookies: ${perms}` : perms].filter(Boolean), fix: wide ? "Remove it unless you know the publisher" : undefined, item: i });
          break;
        }
        case "launch":
          add({ id: `launch:${i.id}:${i.hash?.slice(0, 12)}`, rule: fresh ? "launch-new" : "launch-changed", severity: fresh ? "high" : "medium",
            title: `${fresh ? "New" : "Changed"} ${i.meta?.what ?? "login job"}: ${i.name}`, detail: [i.path ?? "", `runs: ${i.meta?.program ?? "?"}`],
            fix: "If you did not install software that needs this, vswarm respond", item: i });
          break;
        case "rc":
        case "shell-d":
        case "ssh":
        case "cron":
        case "hosts":
        case "tool-config": {
          const lines = addedLines(baseline.texts[i.id], scan.texts[i.id]);
          const ps = /\.ps1$/i.test(i.id);
          // Each risky line with why, when there is more to say than "downloads or backgrounds something".
          const why = new Map(lines.map((l) => [l, lineRisk(i.id, l, home)]));
          const risky = lines.filter((l) => RISKY_LINE.test(l) || (ps && RISKY_PS.test(l)) || why.get(l));
          const authKeys = i.id === ".ssh/authorized_keys";
          // Only lines removed: less risky than anything added, but still a change you should recognise.
          const sev: Severity = authKeys || risky.length || i.kind === "cron" ? "high" : lines.length ? "medium" : "low";
          const shown = risky.length ? risky : lines;
          add({ id: `file:${i.id}:${i.hash?.slice(0, 12)}`, rule: "startup-file", severity: sev,
            title: authKeys ? "~/.ssh/authorized_keys changed: someone may have added a way to log in" : `${i.id === "crontab" ? "crontab" : /^(\/|[A-Za-z]:[\\/])/.test(i.name) ? i.name : "~/" + i.name} changed`,
            detail: shown.slice(0, 6).map((l) => `+ ${l.slice(0, 160)}${why.get(l) ? ` · ${why.get(l)}` : ""}`).concat(shown.length > 6 ? [`… ${shown.length - 6} more ${risky.length ? "such " : "added "}lines`] : []),
            fix: risky.some((l) => why.get(l)) ? "These lines change what runs, or where packages come from; remove them unless you wrote them"
              : risky.length ? "These lines download, decode or start something in the background; remove them unless you wrote them" : "Check the change is yours", item: i,
            // The lines themselves, whole: what respond and vswarm fix take out (the detail above is for reading).
            meta: { lines: shown } });
          break;
        }
        case "wmi":
          if (!stockWmi(i))
            add({ id: `wmi-new:${i.id}:${i.hash?.slice(0, 12)}`, rule: fresh ? "wmi-new" : "wmi-changed", severity: "medium", title: `${fresh ? "New" : "Changed"} WMI subscription: ${i.name} (${i.meta?.type})`,
              detail: [i.meta?.command ? redact(String(i.meta.command).slice(0, 200)) : "", i.meta?.filter ? `when: ${i.meta.filter}` : ""].filter(Boolean), fix: "If you did not install software that needs this, vswarm respond", item: i });
          break;
        case "mcp":
          add({ id: `agent-mcp:${i.id}:${i.hash?.slice(0, 12)}`, rule: fresh ? "agent-mcp-new" : "agent-mcp-changed", severity: "medium",
            title: `${fresh ? "New" : "Changed"} MCP server for ${i.source}: ${i.name}`, detail: [redact(String(i.meta?.command ?? i.meta?.url ?? "")), i.path ?? ""],
            fix: "An MCP server acts with the agent's access to your files and shell; keep it only if you added it", item: i });
          break;
        case "agent-hook":
          add({ id: `agent-hook:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-hook", severity: "medium",
            title: `${fresh ? "New" : "Changed"} agent hook: ${i.name}`, detail: [redact(String(i.meta?.command ?? "")), i.path ?? ""],
            fix: "Hooks run shell commands on their own, every time the agent starts or uses a tool; keep it only if you wrote it", item: i });
          break;
        case "agent-perm":
          if (i.meta?.bypass || i.meta?.wide)
            add({ id: `agent-perm:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-perm-wider", severity: "medium", title: `${i.name}: the agent was given more freedom`,
              detail: [i.meta?.bypass ? "bypass permissions is on" : "", i.meta?.wide ? `allows without asking: ${i.meta.wide}` : "", i.path ?? ""].filter(Boolean), fix: "Check you changed this yourself", item: i });
          break;
        case "agent-plugin":
          if (fresh) add({ id: `agent-plugin:${i.id}`, rule: "agent-plugin", severity: "low", title: `New agent plugin (${i.source}): ${i.name}`, detail: [], item: i });
          break;
        case "git-hooks":
          if (fresh || i.meta?.risky)
            add({ id: `hook:${i.id}`, rule: "git-hook", severity: i.meta?.risky ? "high" : "medium", title: `${fresh ? "New" : "Changed"} global git hook: ${i.name}${i.meta?.risky ? ", which downloads, decodes or starts something" : ""}`,
              detail: [i.path ?? "", "It runs in every repository on this machine."], fix: i.meta?.risky ? "Remove it unless you wrote it, then vswarm respond" : undefined, item: i });
          break;
        case "app-agent": {
          if (!fresh) break;
          // Many signed apps ship a helper that starts at login; one from an app nobody signed is how fake installers persist.
          const sig = i.meta?.app ? await sign(String(i.meta.app)) : { kind: "unknown" as const };
          const signedBy = sig.kind === "developer-id" || sig.kind === "apple" ? sig.who : undefined;
          add({ id: `app-agent:${i.id}`, rule: "app-agent", severity: signedBy ? "low" : "high", title: `${i.source} can start ${signedBy ? "a helper" : "a program"} at login${signedBy ? "" : `, and ${i.source} is ${sig.kind === "adhoc" ? "only ad-hoc signed" : sig.kind === "unsigned" ? "not signed" : "not signed by a known developer"}`}`,
            detail: [`runs: ${i.meta?.program ?? "?"}`, signedBy ? `signed by ${signedBy}` : "", "Turn it off in System Settings → General → Login Items & Extensions"].filter(Boolean),
            fix: signedBy ? undefined : "Unless you installed this app on purpose from a source you trust, move it to the Trash and run vswarm respond", item: i });
          break;
        }
        case "sysext":
          if (fresh) {
            const kext = i.source === "kext";
            add({ id: `sysext:${i.id}`, rule: "sysext", severity: kext ? "high" : "medium", title: `New ${kext ? "kernel extension" : `system extension${i.meta?.category ? ` (${i.meta.category})` : ""}`}: ${i.name}`,
              detail: [kext ? String(i.path) : `team ${i.source} · ${i.meta?.bundle} ${i.version ?? ""} · ${i.meta?.state ?? ""}`, kext ? "Kernel code sees and can change everything on the machine." : "A network or endpoint extension sees every connection or file event."],
              fix: "Keep it only if you installed its app on purpose (a VPN, a security tool); otherwise remove the app and vswarm respond", item: i });
          }
          break;
        case "bin": {
          if (!fresh) break;
          const link = String(i.meta?.link ?? "");
          // Formulae link into the Cellar; their origin is judged by the tap rules above.
          if (link.includes("/Cellar/") || link.includes("/Caskroom/")) break;
          const sig = await sign(i.path!);
          const base = i.name.replace(/\.(exe|cmd|bat|ps1)$/i, "").toLowerCase();
          if (SHADOWED.has(base) && sig.kind !== "developer-id" && sig.kind !== "apple") {
            add({ id: `bin:${i.id}`, rule: "new-bin", severity: "high", title: `New program on PATH named like the system's ${base}: ${i.path}`,
              detail: [i.path ?? "", link ? `→ ${link}` : "", `Found before the real ${base}, it sees what you type into it: passwords, tokens, the hosts you reach.`].filter(Boolean),
              fix: "Remove it unless you put it there; then vswarm respond", item: i });
            break;
          }
          if (sig.kind === "developer-id" || sig.kind === "apple") {
            add({ id: `bin:${i.id}`, rule: "new-bin", severity: "info", title: `New signed program on PATH: ${i.name}`, detail: [`${sig.who}`, i.path ?? ""], item: i });
          } else if (sig.kind === "script") {
            add({ id: `bin:${i.id}`, rule: "new-bin", severity: "low", title: `New script on PATH: ${i.name}`, detail: [i.path ?? ""], item: i });
          } else {
            add({ id: `bin:${i.id}`, rule: "new-bin", severity: "medium", title: `New ${sig.kind === "unsigned" ? "unsigned" : sig.kind === "adhoc" ? "self-signed (ad-hoc)" : "unverified"} program on PATH: ${i.name}`,
              detail: [i.path ?? "", link ? `→ ${link}` : ""].filter(Boolean), fix: "Make sure you know where it came from", item: i });
          }
          break;
        }
      }
    }
  }

  out.push(...input.secrets);
  return foldRunning(out);
}

/**
 * A program that a login entry starts and that is running now is one finding, not two: the entry keeps it, and says
 * it is running. Paths compare the way the system does (case-insensitive on Windows).
 */
function foldRunning(findings: Finding[]): Finding[] {
  // A command line starts with a quote as often as with the drive letter.
  const norm = (p: string) => (/[A-Za-z]:[\\/]/.test(p) ? p.replace(/\//g, "\\").toLowerCase() : p);
  const launches = findings.filter((f) => f.rule === "launch-location");
  if (!launches.length) return findings;
  return findings.filter((f) => {
    if (f.rule !== "proc-location" || !f.item?.path) return true;
    const exe = norm(f.item.path);
    const entry = launches.find((l) => norm(String(l.item?.meta?.program ?? "")).includes(exe));
    if (!entry) return true;
    entry.detail = [...(entry.detail ?? []), `running now: pid ${f.item.meta?.pid}`];
    return false;
  });
}
