// A reminder in front of commands that have no credential hook: telnet, ftp, psql, mysql, mongosh, redis-cli, sqlcmd,
// nc, or anything you name.
//
// `vswarm gate cmd psql "*.prod.internal"` adds a shell function (zsh, bash) or a PowerShell function that reads the
// target host from the command line the way that tool does (psql -h, postgres:// URIs, host= conninfo, mysql --host=,
// mongodb:// URIs, redis-cli -h/-u, sqlcmd -S …) and, when it matches, runs the quiet preflight first. BLOCK stops the
// command with the reason; WARN prints one line. Without patterns every run is checked.
//
// It is a reminder, not a control: `command psql …`, a script, another shell or any other program goes straight to
// the real binary. Where a tool has a credential hook (ssh, aws, kubectl, gcloud with an external account) vswarm
// gates the credential instead; see cloudgate.ts.
//
// Passwords on the command line are never read: only host options and the host part of URIs are looked at, and what
// is printed has any user:password@ masked.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { readJson, readText, shq } from "./ctx";
import { c, line } from "./print";
import { SEC, writePrivate } from "./store";

export const CMDGATE_START = "# >>> vswarm cmdgate >>>";
export const CMDGATE_END = "# <<< vswarm cmdgate <<<";

export interface CmdGateConfig {
  /** Gated commands and the host patterns that trigger the check; no patterns: every run. */
  tools: Record<string, { patterns: string[]; at: number }>;
}

const cfgFile = () => join(SEC(), "cmdgate.json");
export const loadCmdGates = (): CmdGateConfig => {
  const c = readJson<CmdGateConfig>(cfgFile());
  return c && typeof c.tools === "object" && c.tools ? c : { tools: {} };
};
export const saveCmdGates = (g: CmdGateConfig) => writePrivate(cfgFile(), g);

// ── where a command connects to

/** Syntax families: each tool vswarm knows reads its host the way one of these does. */
type Family = "telnet" | "ftp" | "nc" | "psql" | "mysql" | "mongo" | "redis" | "sqlcmd" | "gcloud" | "az";
const FAMILY: Record<string, Family> = {
  telnet: "telnet", rlogin: "telnet", rsh: "telnet",
  ftp: "ftp", tftp: "ftp",
  nc: "nc", ncat: "nc", netcat: "nc",
  psql: "psql", pg_dump: "psql", pg_dumpall: "psql", pg_restore: "psql", pgcli: "psql",
  mysql: "mysql", mariadb: "mysql", mysqldump: "mysql", mycli: "mysql", mysqlsh: "mysql",
  mongosh: "mongo", mongo: "mongo", mongodump: "mongo", mongorestore: "mongo", mongoexport: "mongo", mongoimport: "mongo",
  "redis-cli": "redis", "valkey-cli": "redis",
  sqlcmd: "sqlcmd", bcp: "sqlcmd",
  gcloud: "gcloud", az: "az",
};
export const KNOWN_TOOLS = Object.keys(FAMILY);

/** Options that take a value, per family, so the value is not taken for the host. Password options are among them, and their values are skipped unread. */
const VALUE_OPTS: Record<string, string[]> = {
  telnet: ["-l", "-e", "-n", "-b", "-X", "-k", "-S", "-s"],
  ftp: ["-P", "-o", "-r", "-q", "-s", "-T", "-u", "-x", "-H"],
  nc: ["-p", "-s", "-w", "-i", "-x", "-X", "-I", "-O", "-T", "-V", "-q", "-e", "-c", "-M", "-m", "-b", "-W"],
  mongo: ["-u", "--username", "-p", "--password", "--port", "--eval", "-f", "--file", "--authenticationDatabase", "--authenticationMechanism", "--tlsCAFile", "--tlsCertificateKeyFile", "--apiVersion", "--db", "-d", "--collection", "-c", "--out", "-o", "--archive"],
};

const LOCAL = "localhost";

/** host[:port] or [v6]:port, lower-cased; a path (a Unix socket) is this machine. */
export function hostOnly(hp: string): string {
  let h = hp.trim();
  try {
    h = decodeURIComponent(h);
  } catch {}
  if (!h) return "";
  if (h.startsWith("/") || h.startsWith("@")) return LOCAL;
  if (h.startsWith("[")) return h.slice(1, h.indexOf("]") > 0 ? h.indexOf("]") : undefined).toLowerCase();
  // One colon is host:port; more is a bare IPv6 address.
  if ((h.match(/:/g) ?? []).length === 1) h = h.slice(0, h.indexOf(":"));
  return h.toLowerCase();
}

/** user@host, user:password@host → host. The part before @ is dropped unread. */
const afterAt = (s: string) => (s.includes("@") ? s.slice(s.lastIndexOf("@") + 1) : s);

const URI = /([a-z][a-z0-9+.-]*):\/\/([^/?#\s]*)/i;

/** The hosts in a URI's authority (comma-separated lists too: postgres and mongodb allow several), or undefined when s is no URI. */
export function uriHosts(s: string, schemes?: RegExp): string[] | undefined {
  const m = URI.exec(s);
  if (!m || (schemes && !schemes.test(m[1]))) return;
  const auth = afterAt(m[2]);
  // postgresql:///db (no host) is the local socket.
  if (!auth) return [LOCAL];
  return auth.split(",").map(hostOnly).filter(Boolean);
}

/** host=… (and hostaddr=…) in a libpq conninfo string; quoted values and lists of hosts too. */
function conninfoHosts(s: string): string[] {
  const out: string[] = [];
  const re = /(?:^|\s)(?:host|hostaddr)\s*=\s*(?:'((?:[^'\\]|\\.)*)'|(\S+))/g;
  for (let m; (m = re.exec(s)); ) out.push(...(m[1] ?? m[2]).split(",").map(hostOnly).filter(Boolean));
  return out;
}

/** Every value of an option: -h x, -hx, --host x, --host=x. */
export function optValues(args: string[], shorts: string[], longs: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (shorts.includes(a) || longs.includes(a)) {
      if (i + 1 < args.length) out.push(args[++i]);
      continue;
    }
    const long = longs.find((l) => a.startsWith(`${l}=`));
    if (long) out.push(a.slice(long.length + 1));
    else {
      const short = shorts.find((s) => s.length === 2 && a.startsWith(s) && a.length > 2 && !a.startsWith("--"));
      if (short) out.push(a.slice(2));
    }
  }
  return out;
}

/** Plain words: not options, not the values of options that take one. */
function positionals(args: string[], valueOpts: string[] = []): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    }
    if (valueOpts.includes(a)) {
      i++;
      continue;
    }
    if (a.startsWith("-") && a.length > 1) continue;
    out.push(a);
  }
  return out;
}

export interface Where {
  /** Hosts the command connects to, as the tool reads them; empty when it connects nowhere (nc -l). */
  hosts: string[];
  /** False for a tool vswarm does not know: then any argument that matches a pattern counts. */
  known: boolean;
}

interface Env {
  env: Record<string, string | undefined>;
  home: string;
}

const uniq = (xs: string[]) => [...new Set(xs.filter(Boolean))];

/** Where `tool args` would connect. Passwords are never looked at: only host options, URIs' host parts and the tool's defaults. */
export function targets(tool: string, args: string[], at: Env = { env: process.env, home: homedir() }): Where {
  const fam = FAMILY[tool.toLowerCase().replace(/\.exe$/, "")];
  const env = at.env;
  const fromUris = (re?: RegExp) => args.flatMap((a) => uriHosts(a, re) ?? []);
  switch (fam) {
    case "telnet": {
      const first = positionals(args, VALUE_OPTS.telnet)[0];
      return { hosts: first ? [uriHosts(first)?.[0] ?? hostOnly(afterAt(first))] : [], known: true };
    }
    case "ftp": {
      // ftp host, ftp ftp://user:pass@host/path, ftp user@host:path (BSD auto-fetch).
      const first = positionals(args, VALUE_OPTS.ftp)[0];
      if (!first) return { hosts: [], known: true };
      return { hosts: [uriHosts(first)?.[0] ?? hostOnly(afterAt(first).replace(/:.*$/, ""))], known: true };
    }
    case "nc": {
      if (args.some((a) => /^-[a-zA-Z]*l/.test(a) && !a.startsWith("--"))) return { hosts: [], known: true };
      const first = positionals(args, VALUE_OPTS.nc)[0];
      return { hosts: first ? [hostOnly(first)] : [], known: true };
    }
    case "psql": {
      const hosts = [
        ...optValues(args, ["-h"], ["--host"]).flatMap((v) => v.split(",").map(hostOnly)),
        ...fromUris(/^postgres(ql)?$/i),
        ...args.flatMap(conninfoHosts),
      ];
      if (!hosts.length && env.PGHOST) hosts.push(...env.PGHOST.split(",").map(hostOnly));
      return { hosts: uniq(hosts.length ? hosts : [LOCAL]), known: true };
    }
    case "mysql": {
      const hosts = [...optValues(args, ["-h"], ["--host"]).map(hostOnly), ...fromUris(/^mysqlx?$/i)];
      if (!hosts.length && env.MYSQL_HOST) hosts.push(hostOnly(env.MYSQL_HOST));
      return { hosts: uniq(hosts.length ? hosts : [LOCAL]), known: true };
    }
    case "mongo": {
      // --host rs0/h1:27017,h2:27017 names a replica set before the slash.
      const hosts = [
        ...optValues(args, [], ["--host", "--uri"]).flatMap((v) => uriHosts(v) ?? v.replace(/^[^/]*\//, "").split(",").map(hostOnly)),
        ...fromUris(/^mongodb(\+srv)?$/i),
      ];
      if (!hosts.length) {
        // mongosh [db address]: a URI, host[:port]/db, or a database name (names have no dots).
        const first = positionals(args, VALUE_OPTS.mongo)[0];
        if (first && !uriHosts(first) && (first.includes("/") || first.includes(".") || /:\d+$/.test(first))) hosts.push(hostOnly(first.split("/")[0]));
      }
      return { hosts: uniq(hosts.length ? hosts : [LOCAL]), known: true };
    }
    case "redis": {
      const hosts = [...optValues(args, ["-h"], []).map(hostOnly), ...optValues(args, ["-u"], []).flatMap((u) => uriHosts(u) ?? [])];
      return { hosts: uniq(hosts.length ? hosts : [LOCAL]), known: true };
    }
    case "sqlcmd": {
      // -S [tcp:|np:|lpc:|admin:]server[\instance][,port]; . and (local) are this machine.
      const raw = optValues(args, ["-S"], ["--server"]);
      if (!raw.length && env.SQLCMDSERVER) raw.push(env.SQLCMDSERVER);
      const hosts = raw.map((s) => {
        let v = s.replace(/^(tcp|np|lpc|admin|sqlserver):/i, "");
        if (v.startsWith("\\\\")) v = v.slice(2);
        v = v.split(/[\\,]/)[0];
        return /^(\.|\(local\)|\(localdb\))$/i.test(v) ? LOCAL : hostOnly(v);
      });
      return { hosts: uniq(hosts.length ? hosts : [LOCAL]), known: true };
    }
    case "gcloud":
      return { hosts: gcloudTargets(args, at), known: true };
    case "az":
      return { hosts: azTargets(args, at), known: true };
  }
  // Not a tool vswarm knows: every argument is a candidate, and so is the host in any URI or user@host among them.
  const cands = args.flatMap((a) => {
    const u = uriHosts(a);
    return u ? u : a.includes("@") && !a.startsWith("-") ? [hostOnly(afterAt(a).split("/")[0])] : [];
  });
  return { hosts: uniq(cands), known: false };
}

// ── gcloud and az: the project, configuration or subscription a command acts on

export function gcloudDir(at: Env): string {
  if (at.env.CLOUDSDK_CONFIG) return at.env.CLOUDSDK_CONFIG;
  return process.platform === "win32" && at.env.APPDATA ? join(at.env.APPDATA, "gcloud") : join(at.home, ".config", "gcloud");
}

/** A value from an INI file (gcloud's configurations); comments and CRLF allowed. */
export function iniGet(text: string, section: string, key: string): string | undefined {
  let cur = "";
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.trim();
    const s = /^\[([^\]]+)\]$/.exec(l);
    if (s) cur = s[1].trim();
    else if (cur === section) {
      const kv = /^([\w.-]+)\s*[=:]\s*(.*)$/.exec(l);
      if (kv && kv[1] === key) return kv[2].trim();
    }
  }
}

function gcloudTargets(args: string[], at: Env): string[] {
  const dir = gcloudDir(at);
  const config = optValues(args, [], ["--configuration"])[0] ?? at.env.CLOUDSDK_ACTIVE_CONFIG_NAME ?? readText(join(dir, "active_config"))?.trim() ?? "default";
  const project = optValues(args, [], ["--project"])[0] ?? at.env.CLOUDSDK_CORE_PROJECT ?? iniGet(readText(join(dir, "configurations", `config_${config}`)) ?? "", "core", "project");
  return uniq([config, project ?? ""].map((s) => s.toLowerCase()));
}

function azTargets(args: string[], at: Env): string[] {
  const given = optValues(args, [], ["--subscription"]);
  if (given.length) return uniq(given.map((s) => s.toLowerCase()));
  // The default subscription, from the profile az keeps (it starts with a BOM).
  const dir = at.env.AZURE_CONFIG_DIR ?? join(at.home, ".azure");
  try {
    const p = JSON.parse((readText(join(dir, "azureProfile.json")) ?? "").replace(/^\uFEFF/, ""));
    const d = (p?.subscriptions ?? []).find((s: any) => s?.isDefault);
    return d ? uniq([String(d.name ?? ""), String(d.id ?? "")].map((s) => s.toLowerCase())) : [];
  } catch {
    return [];
  }
}

// ── patterns

const PATTERN = /^!?[A-Za-z0-9*?._:@\/-]+$/;
const TOOL = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

/** A glob like ssh's: * and ?, case does not matter. */
export function globMatch(pattern: string, s: string): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");
  return re.test(s);
}

/** The first pattern that matches, unless a !pattern excludes the value. */
export function matchOf(patterns: string[], value: string): string | undefined {
  if (patterns.some((p) => p.startsWith("!") && globMatch(p.slice(1), value))) return;
  return patterns.find((p) => !p.startsWith("!") && globMatch(p, value));
}

export interface Decision {
  check: boolean;
  /** The host to name in messages, when the tool's syntax gave one. */
  host?: string;
  /** The pattern that matched. */
  pattern?: string;
}

/** Whether this run gets the preflight: always without patterns, else when a target matches one. */
export function decide(tool: string, args: string[], patterns: string[], at?: Env): Decision {
  const w = targets(tool, args, at);
  if (!patterns.filter((p) => !p.startsWith("!")).length) {
    // Only exclusions: everything else is checked.
    const host = w.hosts[0];
    return { check: !w.hosts.length || !w.hosts.every((h) => patterns.some((p) => globMatch(p.slice(1), h))), host: w.known ? host : undefined };
  }
  for (const h of w.hosts) {
    const p = matchOf(patterns, h);
    if (p) return { check: true, host: w.known ? h : undefined, pattern: p };
  }
  if (!w.known) {
    // Any argument as typed; it may be a password, so it is never printed, only the pattern it matched.
    for (const a of args) {
      const p = matchOf(patterns, a);
      if (p) return { check: true, pattern: p };
    }
  }
  return { check: false };
}

/** user:password@ in anything printed becomes user:•••@. */
export function mask(s: string): string {
  return s.replace(/([^\s:/@]+):[^\s/@]*@/g, "$1:•••@");
}

// ── the wrapper vswarm calls

/** `vswarm cmdgate <tool> [patterns…] -- <the tool's arguments>`: 0 lets the command run, 3 stops it. */
export async function cmdgateRun(tool: string, patterns: string[], args: string[]): Promise<number> {
  if (process.env.VSWARM_CMDGATE === "off") return 0;
  const d = decide(tool, args, patterns);
  if (!d.check) return 0;
  const { gateVerdict } = await import("./gate");
  // The quiet preflight prints the findings on BLOCK and one line on WARN; WARN stops it only when the policy says so.
  const g = await gateVerdict({ quiet: true });
  if (g.allowed) return 0;
  const to = d.host ? ` to ${mask(d.host)}` : d.pattern ? ` (matches ${d.pattern})` : "";
  line(`${c.red("✖")} vswarm: ${tool}${to} stopped: ${g.verdict === "block" ? "this machine did not pass preflight" : "preflight warns, and the policy refuses WARN"}`);
  line(c.dim(`  fix or accept what is listed above (vswarm why) · skip once: ${skipOnce(tool)} · this gate is a reminder you can bypass, not a control`));
  return g.code;
}

export const skipOnce = (tool: string, win = process.platform === "win32") => (win ? `${tool}.exe …` : `command ${tool} …`);

// ── the shell text

/** Functions for ~/.zshrc and ~/.bashrc. `function name {` keeps zsh from expanding an alias of the same name. */
export function cmdGateBlock(launcher: string, g: CmdGateConfig): string {
  const q = shq(launcher);
  const tools = Object.keys(g.tools).sort();
  return [
    CMDGATE_START,
    "# A reminder, not a control: these commands ask vswarm preflight first. Skip once: command <name> ...   Turn off: vswarm gate cmd --off <name>",
    ...tools.map((t) => {
      const pats = g.tools[t].patterns.map(shq).join(" ");
      return `function ${t} { ${q} cmdgate ${t}${pats ? ` ${pats}` : ""} -- "$@" || return $?; command ${t} "$@"; }`;
    }),
    CMDGATE_END,
  ].join("\n");
}

/**
 * The same for PowerShell (profile.ps1), ASCII only. bun and the CLI are called by full path, not vswarm.cmd, so
 * cmd.exe never reads & or | in an argument; the real program is found as an application on PATH.
 */
export function psCmdGateBlock(bun: string, cli: string, g: CmdGateConfig): string {
  const q = (s: string) => `'${s.replace(/['\u2018\u2019\u201a\u201b]/g, "$&$&")}'`;
  const tools = Object.keys(g.tools).sort();
  return [
    CMDGATE_START,
    "# A reminder, not a control: these commands ask vswarm preflight first. Skip once: <name>.exe ...   Turn off: vswarm gate cmd --off <name>",
    "function __vswarm_cmdgate($tool, $pats, $a) {",
    "  $real = Get-Command -Name $tool -CommandType Application -TotalCount 1 -ErrorAction SilentlyContinue",
    "  if (-not $real) { Write-Error \"${tool}: not found on PATH\"; return }",
    `  & ${q(bun)} ${q(cli)} cmdgate $tool @pats '--' @a`,
    "  if ($LASTEXITCODE -ne 0) { return }",
    "  & $real @a",
    "}",
    ...tools.map((t) => `function ${t} { __vswarm_cmdgate ${t} @(${g.tools[t].patterns.map(q).join(", ")}) $args }`),
    CMDGATE_END,
  ].join("\n");
}

// ── vswarm gate cmd

/** Commands that already have a real gate, or that the install guard wraps. */
const REFUSE: Record<string, string> = {
  ssh: "ssh has a credential gate: vswarm gate ssh \"<host>\" and vswarm agent",
  scp: "scp uses ssh's config and agent: vswarm gate ssh \"<host>\" and vswarm agent",
  sftp: "sftp uses ssh's config and agent: vswarm gate ssh \"<host>\" and vswarm agent",
  aws: "aws has a credential hook: vswarm gate aws <profile>, which runs preflight from the profile's credential_process",
  kubectl: "kubectl has a credential hook: vswarm gate kube <context>, which runs preflight from the user's exec plugin",
  gcloud: "use vswarm gate gcloud, which hooks the credential where gcloud allows it",
  az: "use vswarm gate az",
  vswarm: "vswarm cannot gate itself",
};
const SHELL_WORDS = new Set(["command", "builtin", "exec", "eval", "source", "cd", "sudo", "doas", "env", "sh", "bash", "zsh", "fish", "pwsh", "powershell", "function", "if", "then", "else", "fi", "for", "while", "do", "done", "case", "esac", "test", "echo", "printf", "set", "unset", "export", "alias", "type", "which", "time", "exit", "return", "local", "read", "trap", "kill", "wait"]);

export interface GateFiles {
  /** rc files or PowerShell profiles; tests hand in their own. */
  files: string[];
  /** The text for one file: zsh/bash, or PowerShell for .ps1. */
  body(g: CmdGateConfig, file: string): string;
}

/** Where the block goes and what it says, as `vswarm guard` does it. */
export async function realGateFiles(adding: boolean): Promise<GateFiles> {
  const { CLI, ensureLauncher, guardFiles, launcherPath } = await import("../setup");
  const win = process.platform === "win32";
  const launcher = adding && !win ? ensureLauncher((t) => line(t)) : launcherPath();
  return {
    files: await guardFiles(adding),
    body: (g, f) => (f.toLowerCase().endsWith(".ps1") ? psCmdGateBlock(process.execPath, CLI, g) : cmdGateBlock(launcher, g)),
  };
}

/** Writes the block for the gates in g into every file (or removes it when there are none). Returns the files that changed. */
export async function writeCmdGates(g: CmdGateConfig, where: GateFiles): Promise<string[]> {
  const { setBlock } = await import("../setup");
  const changed: string[] = [];
  const empty = !Object.keys(g.tools).length;
  for (const f of where.files) {
    if (empty && !existsSync(f)) continue;
    if (setBlock(f, empty ? null : where.body(g, f), CMDGATE_START, CMDGATE_END)) changed.push(f);
  }
  return changed;
}

export function checkTool(name: string) {
  if (!TOOL.test(name)) throw new Error(`"${name}" is not a command name (letters, digits, _ and -)`);
  const lower = name.toLowerCase();
  if (REFUSE[lower]) throw new Error(REFUSE[lower]);
  if (SHELL_WORDS.has(lower)) throw new Error(`${name} is a shell word; wrapping it would break your shell`);
}

export function checkPatterns(pats: string[]) {
  const bad = pats.find((p) => !PATTERN.test(p));
  if (bad !== undefined) throw new Error(`"${bad}" is not a host pattern (letters, digits, . - _ : @ / * ? and a leading !)`);
}

/** Adds or replaces one gated command (internal: gate gcloud and gate az use it too). */
export async function addCmdGate(tool: string, patterns: string[], where: GateFiles): Promise<string[]> {
  checkPatterns(patterns);
  const g = loadCmdGates();
  g.tools[tool] = { patterns, at: Date.now() };
  // The block first: a write that fails leaves the saved list as it was.
  const changed = await writeCmdGates(g, where);
  saveCmdGates(g);
  return changed;
}

export async function removeCmdGate(tool: string | undefined, where: GateFiles): Promise<{ removed: string[]; changed: string[] }> {
  const g = loadCmdGates();
  const removed = tool === undefined ? Object.keys(g.tools) : g.tools[tool] ? [tool] : [];
  for (const t of removed) delete g.tools[t];
  const changed = await writeCmdGates(g, where);
  saveCmdGates(g);
  return { removed, changed };
}

/** Which files hold the block now. */
export function filesWithBlock(files: string[], readKept: (f: string) => { text: string } | undefined): string[] {
  return files.filter((f) => (readKept(f)?.text ?? "").includes(CMDGATE_START));
}

const ok = (t: string, d = "") => console.log(`  ${c.green("✔")} ${t}${d ? "  " + c.dim(d) : ""}`);
const note = (t: string) => console.log(`  ${c.dim(t)}`);

export function honest(tool: string) {
  note(`a reminder you can bypass, not a control: ${skipOnce(tool)}, a script, another shell or any other program runs the real ${tool} unchecked`);
}

/** vswarm gate cmd [<name> [patterns…] | --off <name> | --list] */
export async function gateCmd(args: string[], where?: GateFiles) {
  const offAt = args.indexOf("--off");
  const off = offAt >= 0;
  if (off) args.splice(offAt, 1);
  const listAt = args.indexOf("--list");
  if (listAt >= 0) args.splice(listAt, 1);
  const name = args.shift();
  if (!name) {
    if (off) throw new Error("usage: vswarm gate cmd --off <name>");
    return listCmdGates(where);
  }
  checkTool(name);
  if (off) {
    const r = await removeCmdGate(name, where ?? (await realGateFiles(false)));
    if (!r.removed.length) return note(`${name} is not gated · vswarm gate cmd lists the gated commands`);
    ok(`${name} no longer checks preflight`, r.changed.join(", "));
    if (process.platform !== "win32") note(`this terminal still has the function: unset -f ${name}`);
    return;
  }
  checkPatterns(args);
  const w = where ?? (await realGateFiles(true));
  const changed = await addCmdGate(name, args, w);
  ok(`${name} checks preflight ${args.length ? `when it connects to ${args.join(", ")}` : "every time it runs"}`, changed.length ? changed.join(", ") : "already in place");
  if (!FAMILY[name.toLowerCase()]) note(`vswarm does not know ${name}'s syntax: any argument (or the host in a URI) matching a pattern counts`);
  honest(name);
  note(process.platform === "win32" ? "new PowerShell windows have it" : `new terminals have it; this one: source ${w.files[0] ?? "~/.zshrc"}`);
}

export async function listCmdGates(where?: GateFiles) {
  const g = loadCmdGates();
  const tools = Object.keys(g.tools).sort();
  if (!tools.length) return note("no command gates · add one: vswarm gate cmd psql \"*.prod.internal\"");
  const { readKept } = await import("../setup");
  const w = where ?? (await realGateFiles(false));
  const inFiles = filesWithBlock(w.files, readKept);
  for (const t of tools) ok(t, g.tools[t].patterns.length ? g.tools[t].patterns.join(", ") : "every run");
  if (!inFiles.length) console.log(`  ${c.amber("!")} the block is in none of ${w.files.join(", ")}; vswarm gate cmd <name> writes it again`);
  else note(`in ${inFiles.join(", ")} · a reminder you can bypass (command <name> …), not a control`);
}
