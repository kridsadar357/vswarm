// Plain-text protocols and stored database passwords: telnet, ftp, rsh and rlogin send the password and everything
// typed in clear text, and password files for psql, mysql, mongosh and database GUIs hand a copy of the disk the
// databases they name. Reported, never read out: history is only counted and its hosts named, password files only
// say where, how open and to which hosts. Values are never printed or stored.

import { statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { isDir, ls, readText, type Ctx } from "./ctx";
import { stripManaged } from "./store";
import type { Finding, Severity } from "./types";

const finding = (id: string, severity: Severity, title: string, detail: string[], fix: string): Finding =>
  ({ id: `secret:${id}`, rule: "secret", severity, title, detail: detail.filter(Boolean), fix });

const short = (hosts: string[]) => hosts.slice(0, 6).join(", ") + (hosts.length > 6 ? ` … ${hosts.length - 6} more` : "");
const tag = (xs: string[]) => createHash("sha256").update(xs.join(",")).digest("hex").slice(0, 10);

const LOCAL = /^(localhost|127(\.\d+){3}|::1|0\.0\.0\.0|ip6-localhost|\[::1\])$/i;
/** A word that names a host: a name, an IPv4 address, an [IPv6] address. Variables, quotes and flags are not hosts. */
const HOSTLIKE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)*|\[[0-9a-fA-F:]+\])$/;

/** Group or others can read it (meaningless on Windows, where folders carry the permissions). */
function openToOthers(p: string): boolean {
  if (process.platform === "win32") return false;
  try {
    return (statSync(p).mode & 0o077) !== 0;
  } catch {
    return false;
  }
}
const modeOf = (p: string) => {
  try {
    return (statSync(p).mode & 0o777).toString(8).padStart(4, "0");
  } catch {
    return "?";
  }
};

// ── telnet, ftp, rsh, rlogin

const PLAIN_TOOLS = "telnet|ftp|tftp|rsh|rlogin|rexec";
/** The tool and its host in a command: `telnet -l me host 23`, `ftp ftp://user:pw@host/`, `rsh user@host`. */
// Only where a command starts (line start, after ; & | ( { ` or an alias's quote or =, or after sudo/exec), so
// `brew install telnet inetutils` or `man ftp` is not a connection.
const PLAIN_CMD = new RegExp(`(?:^|[;&|({\`'"=])\\s*(?:(?:sudo|exec|command|nohup|time|noglob)\\s+)*(${PLAIN_TOOLS})((?:\\s+[^\\s;&|)'"\`]+)+)`, "g");
const VALUE_FLAGS = new Set(["-l", "-e", "-n", "-b", "-X", "-k", "-P", "-o", "-p", "-s"]);

/** Hosts a command line connects to with a plain-text tool; the user and password parts of a URL are dropped unread. */
export function plainHosts(line: string): { tool: string; host: string; inlinePassword: boolean }[] {
  const out: { tool: string; host: string; inlinePassword: boolean }[] = [];
  for (const m of line.matchAll(PLAIN_CMD)) {
    const words = m[2].trim().split(/\s+/);
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      if (VALUE_FLAGS.has(w)) {
        i++;
        continue;
      }
      if (w.startsWith("-")) continue;
      // ftp://user:password@host/path: only whether there was a password, never what it was.
      const url = /^[a-z]+:\/\/([^/?#]*)/i.exec(w);
      const auth = url ? url[1] : w;
      const inlinePassword = !!url && /^[^@]*:[^@]*@/.test(auth);
      let host = auth.slice(auth.lastIndexOf("@") + 1);
      if (!url) host = host.replace(/:.*$/, "");
      else host = host.replace(/:\d+$/, "");
      if (HOSTLIKE.test(host) && !LOCAL.test(host)) out.push({ tool: m[1], host: host.toLowerCase(), inlinePassword });
      break;
    }
  }
  return out;
}

const RC = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".config/fish/config.fish", ".kshrc", ".cshrc", ".tcshrc"];
const HISTORY = [".zsh_history", ".bash_history", ".history", ".sh_history", ".local/share/fish/fish_history", "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"];
/** ssh config lines that run a command: the place an ssh-config-like entry would start telnet. */
const SSH_CMD = /^\s*(ProxyCommand|LocalCommand|RemoteCommand|Match\s.*\bexec)\b(.*)$/i;

/** Aliases, functions and ssh config entries that run telnet/ftp/rsh/rlogin to a host; .rhosts; .telnetrc hosts. */
function plainConfig(h: string): Finding[] {
  const out: Finding[] = [];
  const where = new Map<string, Set<string>>();
  const add = (file: string, host: string) => where.set(file, (where.get(file) ?? new Set()).add(host));
  for (const rel of RC) {
    const raw = readText(join(h, rel));
    if (!raw) continue;
    // vswarm's own blocks (the command gate wraps telnet) are not the user's.
    for (const l of stripManaged(raw).split(/\r?\n/)) {
      if (/^\s*#/.test(l)) continue;
      for (const x of plainHosts(l)) add(`~/${rel}`, x.host);
    }
  }
  const ssh = readText(join(h, ".ssh/config"));
  if (ssh)
    for (const l of stripManaged(ssh).split(/\r?\n/)) {
      const m = SSH_CMD.exec(l);
      if (m) for (const x of plainHosts(m[2])) add("~/.ssh/config", x.host);
    }
  // ~/.telnetrc: a line that starts with a host name holds commands for it.
  const telnetrc = readText(join(h, ".telnetrc"));
  if (telnetrc)
    for (const l of telnetrc.split(/\r?\n/)) {
      const host = /^([^\s#]+)/.exec(l)?.[1];
      if (host && host !== "DEFAULT" && HOSTLIKE.test(host) && !LOCAL.test(host)) add("~/.telnetrc", host.toLowerCase());
    }
  if (where.size) {
    const hosts = [...new Set([...where.values()].flatMap((s) => [...s]))].sort();
    out.push(finding(`plaintext:config:${tag(hosts)}`, "low", `Shortcuts that open telnet/ftp/rsh/rlogin to ${hosts.length} host${hosts.length > 1 ? "s" : ""}`,
      [...[...where].map(([f, s]) => `${f}: ${short([...s].sort())}`), "These send the password and everything typed in clear text: anyone on the network path can read and replay it."],
      "Use ssh (or sftp/scp) instead, or the service's TLS client; if the device only speaks telnet, reach it through an ssh jump host or a VPN."));
  }
  const rhosts = join(h, ".rhosts");
  if ((readText(rhosts) ?? "").trim())
    out.push(finding("plaintext:rhosts", "medium", "~/.rhosts lets rsh and rlogin log in as you without a password",
      ["~/.rhosts", "Trust by host name: anyone who can claim one of those names gets in, over a clear-text protocol."], "Delete ~/.rhosts and use ssh keys (or vswarm agent) instead."));
  return out;
}

/** History is counted per host, never kept: how many lines ran telnet/ftp/rsh/rlogin to it. */
function plainHistory(h: string): Finding[] {
  const counts = new Map<string, number>();
  const files: string[] = [];
  let inline = 0;
  for (const rel of HISTORY) {
    const t = readText(join(h, rel), 64_000_000);
    if (!t) continue;
    let hit = false;
    // zsh extended history: ": 1700000000:0;command"; fish: "- cmd: command".
    for (const raw of t.split(/\r?\n/)) {
      if (!/telnet|ftp|rsh|rlogin|rexec/.test(raw)) continue;
      const l = raw.replace(/^: \d+:\d+;/, "").replace(/^- cmd: /, "");
      for (const x of plainHosts(l)) {
        counts.set(x.host, (counts.get(x.host) ?? 0) + 1);
        if (x.inlinePassword) inline++;
        hit = true;
      }
    }
    if (hit) files.push(`~/${rel}`);
  }
  if (!counts.size) return [];
  const hosts = [...counts.keys()].sort();
  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  return [finding(`plaintext:history:${tag(hosts)}`, inline ? "medium" : "low",
    `Shell history shows ${total} telnet/ftp/rsh/rlogin session${total > 1 ? "s" : ""} to ${hosts.length} host${hosts.length > 1 ? "s" : ""}${inline ? `, ${inline} with a password in the command line` : ""}`,
    [`hosts: ${short(hosts.map((x) => `${x} (${counts.get(x)})`))}`, `in ${files.join(", ")}`, "Passwords typed into these went over the network in clear text."],
    inline
      ? "Change the passwords that were typed into those command lines (they are in your history file too), and use sftp/ssh from now on."
      : "Use ssh, sftp or the service's TLS client; change passwords you typed into these sessions if the network was not yours.")];
}

// ── stored database passwords

/** The host field of each ~/.pgpass entry (host:port:db:user:password); the rest of the line is not kept. */
export function pgpassHosts(text: string): string[] {
  const out: string[] = [];
  for (const l of text.split(/\r?\n/)) {
    if (!l.trim() || l.trim().startsWith("#")) continue;
    // A \: is part of the field.
    const host = /^((?:[^:\\]|\\.)*):/.exec(l)?.[1];
    if (host !== undefined) out.push(host.replace(/\\(.)/g, "$1").toLowerCase());
  }
  return out;
}

/** Whether a my.cnf holds a password, and the hosts it names. The password value is never kept. */
export function myCnf(text: string): { password: boolean; hosts: string[] } {
  let password = false;
  const hosts: string[] = [];
  for (const l of text.split(/\r?\n/)) {
    if (/^\s*password\s*=\s*\S/i.test(l)) password = true;
    const h = /^\s*host\s*=\s*["']?([^"'\s#]+)/i.exec(l)?.[1];
    if (h) hosts.push(h.toLowerCase());
  }
  return { password, hosts };
}

const isLocal = (h: string) => LOCAL.test(h) || h.startsWith("/");

function dbPasswords(h: string): Finding[] {
  const out: Finding[] = [];
  const win = process.platform === "win32";

  // ~/.pgpass (Windows: %APPDATA%\postgresql\pgpass.conf)
  for (const rel of win ? ["AppData/Roaming/postgresql/pgpass.conf"] : [".pgpass"]) {
    const p = join(h, rel);
    const t = readText(p);
    if (t === undefined) continue;
    const hosts = [...new Set(pgpassHosts(t))].sort();
    if (!hosts.length) continue;
    const remote = hosts.filter((x) => !isLocal(x));
    const open = openToOthers(p);
    const sev: Severity = open ? "medium" : remote.length ? "low" : "info";
    out.push(finding(`dbpass:pgpass:${tag(remote)}`, sev,
      open ? `PostgreSQL passwords in ~/${rel} are readable by other users (mode ${modeOf(p)})` : remote.length ? `PostgreSQL passwords for ${remote.length} remote host${remote.length > 1 ? "s" : ""} in ~/${rel}` : `PostgreSQL passwords for local databases in ~/${rel}`,
      [`hosts: ${short(remote.length ? remote : hosts)}${remote.length && remote.length < hosts.length ? ` (and ${hosts.length - remote.length} local)` : ""}`, remote.includes("*") ? "a * entry gives its password to any host psql connects to" : "",
        open ? "psql ignores a .pgpass others can read, but they can still read it." : "Stored in plain text: a copy of this file logs into those databases from anywhere."],
      open ? `chmod 600 ~/${rel}, then change the passwords in it.` : "For production, use short-lived credentials (IAM / Entra ID database auth, Vault dynamic secrets) or a password manager instead of a file; keep .pgpass for local databases."));
  }

  // ~/.my.cnf with a password; ~/.mylogin.cnf is obfuscated, not encrypted.
  for (const rel of [".my.cnf", ".mysql/my.cnf"]) {
    const p = join(h, rel);
    const t = readText(p);
    if (!t) continue;
    const m = myCnf(t);
    if (!m.password) continue;
    const hosts = [...new Set(m.hosts.length ? m.hosts : ["localhost"])].sort();
    const remote = hosts.filter((x) => !isLocal(x));
    const open = openToOthers(p);
    out.push(finding(`dbpass:mycnf:${rel}:${tag(remote)}`, open ? "medium" : remote.length ? "low" : "info",
      open ? `MySQL password in ~/${rel} is readable by other users (mode ${modeOf(p)})` : `MySQL password stored in ~/${rel}${remote.length ? ` for ${short(remote)}` : " (local server)"}`,
      [`hosts: ${short(hosts)}`, "Plain text: every program you run, and every copy of the disk, can read it."],
      open ? `chmod 600 ~/${rel}, and change the password.` : "Remove the password line and let the client ask (or use mysql_config_editor for local use only); use short-lived credentials for production."));
  }
  const login = join(h, ".mylogin.cnf");
  if ((statSafe(login) ?? 0) > 0)
    out.push(finding("dbpass:mylogin", "low", "MySQL login paths in ~/.mylogin.cnf (obfuscated, not encrypted)",
      ["~/.mylogin.cnf", "mysql_config_editor scrambles it with a key stored in the same file: tools read the passwords back in one step."],
      "Keep production passwords out of it; use short-lived credentials (IAM database auth, Vault) or a password manager."));

  // MongoDB URIs with a password in ~/.mongoshrc.js (and the old ~/.mongorc.js)
  for (const rel of [".mongoshrc.js", ".mongorc.js"]) {
    const t = readText(join(h, rel));
    if (!t) continue;
    const hosts: string[] = [];
    for (const m of t.matchAll(/mongodb(?:\+srv)?:\/\/[^\s:@/'"`]+:[^\s@/'"`]+@([^/?\s'"`]+)/g)) hosts.push(...m[1].split(",").map((x) => x.replace(/:\d+$/, "").toLowerCase()));
    if (!hosts.length) continue;
    const uniq = [...new Set(hosts)].sort();
    const remote = uniq.filter((x) => !isLocal(x));
    out.push(finding(`dbpass:mongorc:${rel}:${tag(remote)}`, remote.length ? "low" : "info", `MongoDB connection string with a password in ~/${rel}`,
      [`hosts: ${short(uniq)}`, "mongosh runs this file at every start; the password sits in it in plain text."],
      "Take the password out of the URI and let mongosh ask, or use short-lived credentials (MONGODB-AWS, OIDC, x.509)."));
  }

  // redis: a config folder some clients and scripts keep passwords in.
  const redisDir = join(h, ".config/redis");
  if (isDir(redisDir)) {
    const withPass = ls(redisDir).filter((f) => /^\s*(requirepass|masterauth|password|pass|auth)\s*[=\s]\s*\S/im.test(readText(join(redisDir, f), 1_000_000) ?? ""));
    if (withPass.length)
      out.push(finding(`dbpass:redis:${withPass.sort().join(",")}`, "low", `Redis passwords in ~/.config/redis (${withPass.length} file${withPass.length > 1 ? "s" : ""})`,
        withPass.slice(0, 6).map((f) => `~/.config/redis/${f}`), "Use REDISCLI_AUTH from a secrets manager for the session, or ACL users with short-lived passwords."));
  }

  // DBeaver: saved passwords are encrypted with a key every copy of DBeaver shares.
  for (const base of ["Library/DBeaverData", ".local/share/DBeaverData", "AppData/Roaming/DBeaverData"]) {
    const ws = join(h, base, "workspace6");
    if (!isDir(ws)) continue;
    const stores = ls(ws).map((p) => join(ws, p, ".dbeaver", "credentials-config.json")).filter((f) => (statSafe(f) ?? 0) > 0);
    if (stores.length)
      out.push(finding("dbpass:dbeaver", "low", "DBeaver saved database passwords",
        [...stores.map((f) => f.replace(h, "~")), "DBeaver encrypts them with a key built into DBeaver: anyone with this file can read them."],
        "Turn off \"Save password\" for production connections, or use DBeaver's secure storage (the OS keychain) instead."));
  }

  // JetBrains IDEs (DataGrip …) keep passwords in the OS keychain unless set to a KeePass file.
  for (const base of ["Library/Application Support/JetBrains", ".config/JetBrains", "AppData/Roaming/JetBrains"]) {
    const root = join(h, base);
    if (!isDir(root)) continue;
    const kdbx = ls(root).filter((p) => (statSafe(join(root, p, "c.kdbx")) ?? 0) > 0 && (statSafe(join(root, p, "c.pwd")) ?? 0) > 0);
    if (kdbx.length)
      out.push(finding(`dbpass:jetbrains:${kdbx.sort().join(",")}`, "low", `JetBrains IDE passwords in a KeePass file with its key beside it (${kdbx.join(", ")})`,
        [`~/${base}/<product>/c.kdbx and c.pwd`, "The master password file sits next to the database, so a copy of the folder opens it."],
        "Settings → Passwords: \"In native Keychain\", or a KeePass file with a master password you type."));
  }
  return out;
}

const statSafe = (p: string) => {
  try {
    const s = statSync(p);
    return s.isFile() ? s.size : undefined;
  } catch {
    return;
  }
};

/** Everything in this module, for `vswarm secrets` and every scan. */
export function plaintext(ctx: Ctx): Finding[] {
  return [...plainConfig(ctx.home), ...plainHistory(ctx.home), ...dbPasswords(ctx.home)];
}
