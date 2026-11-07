// AI coding agents run code on your behalf, and their settings say what they may run without asking:
//   MCP servers   programs (or remote URLs) an agent starts and talks to: Claude Code, Claude Desktop, Cursor,
//                 Windsurf, VS Code, Gemini CLI, Codex
//   hooks         shell commands that run on agent events (Claude Code hooks, statusLine)
//   permissions   whether the agent may skip asking (bypassPermissions, Bash(*) allow rules)
// A malicious MCP server or hook is persistence with the agent's access: your repos, your shell, your tokens.

import { join, posix, win32 } from "node:path";
import { ls, readJson, readText, sha256, type Ctx } from "../ctx";
import type { Item } from "../types";
import { WIN_PATH } from "./system";

export interface Server {
  command?: string;
  args?: string[];
  /** The folder the server is started in (Codex, Gemini CLI). */
  cwd?: string;
  /** Codex: `enabled = false` keeps the server from starting. */
  enabled?: boolean;
  url?: string;
  type?: string;
  env?: Record<string, string>;
  headers?: Record<string, string>;
}

/** Names of env vars and headers that carry a literal secret (not a ${VAR} reference). Never the values. */
export function literalSecrets(s: Server): string[] {
  const out: string[] = [];
  const entries = (o: unknown) => (o && typeof o === "object" ? Object.entries(o as Record<string, unknown>) : []);
  for (const [k, v] of [...entries(s.env), ...entries(s.headers)]) {
    // "Bearer ${GITHUB_TOKEN}" is a reference too; the value is filled in from the environment.
    if (typeof v !== "string" || v.length < 12 || /\$\{[^}]*\}|^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v)) continue;
    if (/token|secret|key|password|auth|bearer|credential/i.test(k) || /^(Bearer\s+)?(sk-|ghp_|gho_|github_pat_|xox[bp]-|AKIA|eyJ)/.test(v)) out.push(k);
  }
  return out;
}

/** Agent configs are JSON; ~/.claude.json also holds session history and outgrows the usual 2 MB cap. */
const cfg = (file: string) => readJson(file, 64_000_000);

// ── what a relative command means
//
// An agent hands `command` and `args` to the system as they are (no shell), so a command with a path separator that is
// not absolute is read from the folder the server is started in. Which folder that is depends on the agent:
//   Codex         the entry's `cwd`, else the folder Codex itself runs in (codex-rs stdio_server_launcher: `cwd` or the
//                 caller's working directory; a plugin's .mcp.json gets its plugin folder written in when installed)
//   Gemini CLI    the entry's `cwd`, else the folder gemini runs in
//   Claude Code   the folder the session runs in: a project's own servers start in the project, the rest anywhere
//   Claude Desktop, Cursor, Windsurf, VS Code: not documented, so not guessed
// Where the folder is not known, the command is reported as relative instead of judged or started from a wrong place.

/** A path that names its own place: /x, C:\x, \\server\x. */
export const absolute = (p: string) => p.startsWith("/") || WIN_PATH.test(p) || p.startsWith("\\\\");

/** A command with a folder in it, as opposed to a bare name looked up on PATH (npx). */
const pathLike = (p: string) => /[\\/]/.test(p);

/** What an agent starts for one server entry. */
export interface Launch {
  /** The program as an absolute path, when the command is a path. A bare name (npx) is looked up on PATH. */
  exe?: string;
  /** The folder the server starts in (and relative arguments are read from), when it is known. */
  base?: string;
  /** Why a relative command could not be placed. */
  relative?: string;
}

const AGENT_NAMES: Record<string, string> = { "claude-code": "Claude Code", "claude-desktop": "Claude Desktop", cursor: "Cursor", windsurf: "Windsurf", vscode: "VS Code", gemini: "Gemini CLI", codex: "Codex" };

/** A relative path read from a folder, with that folder's separators. */
export const under = (base: string, rel: string) => (WIN_PATH.test(base) || base.startsWith("\\\\") ? win32.join(base, rel) : posix.join(base, rel));

/** Where `app` (a scan item's source) starts the server `s`; `project` is the Claude Code project the entry is under. */
export function launchOf(app: string, s: Server, project?: string): Launch {
  const command = typeof s.command === "string" ? s.command : "";
  const agent = app.split(":")[0];
  const cwd = typeof s.cwd === "string" && s.cwd ? s.cwd : undefined;
  const own = agent === "codex" || agent === "gemini";
  const base = own ? (cwd && absolute(cwd) ? cwd : undefined) : agent === "claude-code" ? project : undefined;
  if (!command || !pathLike(command)) return { base };
  if (absolute(command)) return { exe: command, base };
  if (base) return { exe: under(base, command), base };
  const name = AGENT_NAMES[agent] ?? agent;
  const relative = own
    ? `${name} starts it in ${cwd ? `cwd "${cwd}", which is read from ` : ""}the folder ${name} itself runs in, so which program runs depends on where ${name} was started`
    : agent === "claude-code"
      ? "Claude Code starts it in the folder each session runs in, so any project can put its own program there"
      : `${name} does not document which folder a relative command is read from`;
  return { relative };
}

// ── servers the agent will not start
//
// Only switches the agent itself reads count; one it ignores would let a planted server hide behind it:
//   Codex        `enabled = false` on the entry (codex-rs mcp_types: `enabled`, default true)
//   Gemini CLI   the server's name in excludeMCPServers / mcp.excluded, or missing from a set allowMCPServers /
//                mcp.allowed (settings.json; exclusion wins)
//   Claude Code, Claude Desktop, Cursor, Windsurf, VS Code: no switch in the files read here that the agent is
//   documented to honour (Cursor and VS Code keep the toggle in their own state; Claude Code's
//   disabledMcpjsonServers is for project .mcp.json files), so their entries count as enabled.
// A disabled server stays an item, so turning it on later is a change since the baseline.

/** Whether Gemini CLI connects to server `name`, from its settings. */
export function geminiOff(settings: any, name: string): boolean {
  const list = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : undefined);
  const excluded = [...(list(settings?.excludeMCPServers) ?? []), ...(list(settings?.mcp?.excluded) ?? [])];
  const allowed = list(settings?.allowMCPServers) ?? list(settings?.mcp?.allowed);
  return excluded.includes(name) || (allowed !== undefined && !allowed.includes(name));
}

function serverItem(app: string, file: string, name: string, s: Server, project?: string, off = false): Item {
  // One malformed entry (args that is not a list) must not take the whole collector down.
  const args = Array.isArray(s.args) ? s.args.map(String) : [];
  const cmd = typeof s.command === "string" ? s.command : undefined;
  const command = [cmd, ...args].filter(Boolean).join(" ");
  const l = launchOf(app, s, project);
  // The folder decides what a relative command is; for any other command it stays out, so earlier pins keep matching.
  const rel = !!cmd && pathLike(cmd) && !absolute(cmd);
  const def = JSON.stringify({ command: s.command, args, url: s.url ?? (s as any).httpUrl ?? (s as any).serverUrl, env: Object.keys(s.env && typeof s.env === "object" ? s.env : {}).sort(), ...(rel ? { base: l.base ?? null } : {}) });
  // The command and its arguments as the config gives them: a path with spaces in it stays one word.
  const argv = cmd ? JSON.stringify([cmd, ...args]) : undefined;
  return {
    kind: "mcp", id: `${app}:${name}`, name, source: app, path: file, hash: sha256(def),
    meta: {
      command: command.slice(0, 300) || undefined, argv: argv && argv.length <= 4000 ? argv : undefined, exe: l.exe, base: l.base, relative: l.relative,
      url: s.url ?? (s as any).httpUrl ?? (s as any).serverUrl, secrets: literalSecrets(s).join(",") || undefined,
      // Not in the hash: switching a server off and on is not a new definition (pins and drift stay as they were).
      disabled: off || (app === "codex" && s.enabled === false) || undefined,
    },
  };
}

function servers(app: string, file: string, map: unknown, prefix = "", project?: string, off?: (name: string) => boolean): Item[] {
  if (!map || typeof map !== "object") return [];
  return Object.entries(map as Record<string, Server>).filter(([, s]) => s && typeof s === "object").map(([n, s]) => serverItem(app, file, prefix + n, s, project, off?.(n) ?? false));
}

/** The command and arguments a scan recorded for an MCP server, as the config gave them. */
export function argvOf(i: Item): string[] | undefined {
  try {
    const a = JSON.parse(String(i.meta?.argv ?? ""));
    return Array.isArray(a) && a.length && a.every((x) => typeof x === "string") ? a : undefined;
  } catch {}
}

/** Path separators: Windows takes both. */
const SEP = process.platform === "win32" ? /[\\/]/ : "/";

/** Claude Code keeps its settings in ~/.claude, or in another folder per profile (CLAUDE_CONFIG_DIR). */
function claudeDirs(home: string): string[] {
  return ls(home).filter((d) => /^\.claude([\w.-]*)$/.test(d) && !d.endsWith(".json")).map((d) => join(home, d));
}

function claude(home: string): Item[] {
  const out: Item[] = [];
  const configs = [join(home, ".claude.json"), ...claudeDirs(home).map((d) => join(d, ".claude.json"))];
  for (const f of configs) {
    const j = cfg(f);
    if (!j) continue;
    const app = f === join(home, ".claude.json") ? "claude-code" : `claude-code:${f.split(SEP).at(-2)}`;
    out.push(...servers(app, f, j.mcpServers));
    for (const [proj, p] of Object.entries<any>(j.projects ?? {})) out.push(...servers(app, f, p?.mcpServers, `${proj.replace(home, "~")} › `, proj));
  }
  for (const dir of claudeDirs(home)) {
    for (const name of ["settings.json", "settings.local.json"]) {
      const f = join(dir, name);
      const j = cfg(f);
      if (!j) continue;
      const app = `claude-code:${dir.split(SEP).pop()}`;
      for (const [event, matchers] of Object.entries<any>(j.hooks ?? {})) {
        (Array.isArray(matchers) ? matchers : []).forEach((m: any, i: number) =>
          (m?.hooks ?? []).forEach((h: any, k: number) => {
            if (typeof h?.command !== "string") return;
            out.push({ kind: "agent-hook", id: `${f}:${event}:${m.matcher ?? ""}:${i}.${k}`, name: `${app} ${event}${m.matcher ? ` (${m.matcher})` : ""}`, source: app, path: f, hash: sha256(h.command), meta: { command: h.command.slice(0, 300) } });
          }));
      }
      if (typeof j.statusLine?.command === "string")
        out.push({ kind: "agent-hook", id: `${f}:statusLine`, name: `${app} statusLine`, source: app, path: f, hash: sha256(j.statusLine.command), meta: { command: j.statusLine.command.slice(0, 300) } });
      const allow: string[] = Array.isArray(j.permissions?.allow) ? j.permissions.allow : [];
      const wide = allow.filter((a) => /^(Bash|Bash\(\*\)|Bash\(:\*\)|\*|mcp__\*)$/.test(a));
      const bypass = j.permissions?.defaultMode === "bypassPermissions" || j.skipDangerousModePermissionPrompt === true;
      out.push({ kind: "agent-perm", id: f, name: `${app} ${name}`, source: app, path: f, hash: sha256(JSON.stringify({ wide, bypass })), meta: { bypass, wide: wide.join(",") || undefined } });
      for (const p of Object.keys(j.enabledPlugins ?? {})) if (j.enabledPlugins[p]) out.push({ kind: "agent-plugin", id: `${app}:${p}`, name: p, source: app, path: f });
    }
  }
  return out;
}

// ── Codex's config.toml, read by hand (just the shapes MCP entries take; no TOML library)

/** A dotted TOML key split into its parts: mcp_servers."name with spaces".env → [mcp_servers, name with spaces, env]. */
const keyPath = (s: string) => [...s.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|([\w-]+)/g)].map((m) => (m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2] ?? m[3]));
/** A TOML string value: "basic" with escapes, or 'literal'. */
const tomlStr = (v: string) => {
  const m = /^"((?:[^"\\]|\\.)*)"|^'([^']*)'/.exec(v.trim());
  return m ? (m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2]) : undefined;
};
/** Every string in a TOML array text, `[ "a", 'b' ]`, spread over any number of lines. */
const tomlStrs = (v: string) => [...v.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((m) => (m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2]));

/** The MCP servers in a Codex config: `[mcp_servers.<name>]` tables and `name = { … }` inline tables under `[mcp_servers]`. */
export function codexServers(toml: string): Record<string, Server> {
  const out: Record<string, Server> = {};
  // Comments go first, outside strings only: a `# "x"` comment inside an args array is not an argument.
  const lines = toml.split("\n").map((l) => l.replace(/("(?:[^"\\]|\\.)*"|'[^']*')|#.*$/g, (m, s) => s ?? "").trim());
  let cur: Server | undefined; // inside [mcp_servers.<name>]
  let root = false; // inside [mcp_servers] itself
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!l) continue;
    const head = /^\[([^\]]+)\]/.exec(l);
    if (head) {
      const path = keyPath(head[1]);
      cur = undefined;
      root = path[0] === "mcp_servers" && path.length === 1;
      // Deeper tables (.env, .headers) hold values, not servers; they are left out as before.
      if (path[0] === "mcp_servers" && path.length === 2) cur = out[path[1]] ??= {};
      continue;
    }
    const kv = /^((?:"(?:[^"\\]|\\.)*"|'[^']*'|[\w.-]+)+)\s*=\s*([\s\S]*)$/.exec(l);
    if (!kv) continue;
    let val = kv[2];
    // An array may run over several lines; read on until it closes (in any table, so its lines are not taken for headers).
    if (val.startsWith("[")) while (!/\]$/.test(val) && i + 1 < lines.length) val += "\n" + lines[++i];
    if (!(cur || root)) continue;
    const key = keyPath(kv[1]);
    if (root) {
      if (key.length !== 1 || !val.startsWith("{")) continue;
      const s: Server = (out[key[0]] ??= {});
      const field = (k: string) => new RegExp(`(?:^\\{|,)\\s*${k}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*"|'[^']*')`).exec(val)?.[1];
      const command = field("command"), url = field("url"), cwd = field("cwd");
      if (command) s.command = tomlStr(command);
      if (cwd) s.cwd = tomlStr(cwd);
      if (url) s.url = tomlStr(url);
      const args = /(?:^\{|,)\s*args\s*=\s*\[([^\]]*)\]/.exec(val)?.[1];
      if (args !== undefined) s.args = tomlStrs(args);
      // Only the entry's own `enabled`, not one inside a nested table (tools = { x = { enabled = false } }).
      let inner = val.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, '""');
      inner = inner.slice(1, inner.lastIndexOf("}") > 0 ? inner.lastIndexOf("}") : undefined);
      for (let n = 0; n < 16 && /\{[^{}]*\}/.test(inner); n++) inner = inner.replace(/\{[^{}]*\}/g, "");
      if (/(?:^|,)\s*enabled\s*=\s*false\b/.test(inner)) s.enabled = false;
      continue;
    }
    if (key.length !== 1) continue;
    if (key[0] === "enabled") cur!.enabled = /^false\b/.test(val.trim()) ? false : undefined;
    else if (key[0] === "command") cur!.command = tomlStr(val);
    else if (key[0] === "cwd") cur!.cwd = tomlStr(val);
    else if (key[0] === "url") cur!.url = tomlStr(val);
    else if (key[0] === "args" && val.startsWith("[")) cur!.args = tomlStrs(val);
  }
  return out;
}

export async function agents(ctx: Ctx): Promise<Item[]> {
  const h = ctx.home;
  const mac = (rel: string) => join(h, "Library/Application Support", rel);
  const appData = (rel: string) => join(h, "AppData/Roaming", rel);
  const out: Item[] = [...claude(h)];
  const plain: [string, string, string][] = [
    ["claude-desktop", mac("Claude/claude_desktop_config.json"), "mcpServers"],
    ["claude-desktop", join(h, ".config/Claude/claude_desktop_config.json"), "mcpServers"],
    ["claude-desktop", appData("Claude/claude_desktop_config.json"), "mcpServers"],
    ["cursor", join(h, ".cursor/mcp.json"), "mcpServers"],
    ["windsurf", join(h, ".codeium/windsurf/mcp_config.json"), "mcpServers"],
    ["gemini", join(h, ".gemini/settings.json"), "mcpServers"],
    ["vscode", mac("Code/User/mcp.json"), "servers"],
    ["vscode", join(h, ".config/Code/User/mcp.json"), "servers"],
    ["vscode", mac("Code/User/settings.json"), "mcp.servers"],
    ["vscode", join(h, ".config/Code/User/settings.json"), "mcp.servers"],
    ["vscode", appData("Code/User/mcp.json"), "servers"],
    ["vscode", appData("Code/User/settings.json"), "mcp.servers"],
  ];
  for (const [app, f, key] of plain) {
    const j = cfg(f);
    if (j) out.push(...servers(app, f, key === "mcp.servers" ? j["mcp"]?.servers ?? j["mcp.servers"] : j[key], "", undefined, app === "gemini" ? (n) => geminiOff(j, n) : undefined));
  }
  // Codex: TOML, [mcp_servers.<name>] tables with command / args / url.
  const codexFile = join(h, ".codex/config.toml");
  const toml = readText(codexFile);
  if (toml) for (const [name, s] of Object.entries(codexServers(toml))) out.push(serverItem("codex", codexFile, name, s));
  return [...new Map(out.map((i) => [`${i.kind}:${i.id}`, i])).values()];
}
