// Where collectors look and how they run commands. Tests point it at a fake home with planted items.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir, hostname, userInfo } from "node:os";
import { join } from "node:path";

export interface Ctx {
  home: string;
  /** Homebrew prefix, or undefined when Homebrew is not installed. */
  brew?: string;
  /** Directories on PATH worth watching for new executables. */
  pathDirs: string[];
  /** Runs a command and returns stdout, or undefined when it fails or is missing. */
  run(cmd: string[], timeoutMs?: number): Promise<string | undefined>;
  /** System locations (/Library/…); tests turn them off. */
  system: boolean;
  host: string;
  user: string;
  /** Records a place that could not be checked, so a gap is reported instead of looking clean. */
  gap?: (what: string, why: string) => void;
}

/** Whether a folder exists but the OS refuses to list it (macOS privacy protection). */
export function blocked(dir: string): boolean {
  try {
    readdirSync(dir);
    return false;
  } catch (e: any) {
    return e?.code === "EPERM" || e?.code === "EACCES";
  }
}

/** The login name. Bun reads it from $USER and says "unknown" without it (cron, containers); ask the system then. */
export function whoami(): string {
  const u = userInfo().username;
  if (u && u !== "unknown") return u;
  if (process.env.LOGNAME) return process.env.LOGNAME;
  try {
    const out = Bun.spawnSync(["id", "-un"], { stdout: "pipe", stderr: "ignore" }).stdout.toString().trim();
    if (out) return out;
  } catch {}
  return u;
}

export interface Exec {
  code: number;
  out: string;
  err: string;
}

/**
 * Runs a command and waits for it. `tty` hands the terminal to the command (ssh-keygen asking for a passphrase);
 * its stderr is then not captured. Throws when the program cannot be started at all.
 */
export async function exec(cmd: string[], opt: { cwd?: string; env?: Record<string, string | undefined>; timeoutMs?: number; tty?: boolean } = {}): Promise<Exec> {
  const p = Bun.spawn(cmd, { cwd: opt.cwd, env: opt.env, stdin: opt.tty ? "inherit" : "ignore", stdout: "pipe", stderr: opt.tty ? "inherit" : "pipe" });
  const timer = opt.timeoutMs ? setTimeout(() => p.kill(), opt.timeoutMs) : undefined;
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), opt.tty ? Promise.resolve("") : new Response(p.stderr as ReadableStream).text(), p.exited]);
  clearTimeout(timer);
  return { code, out, err };
}

/** stdout of a command that exits 0; undefined when it is missing, fails or times out. */
export async function run(cmd: string[], timeoutMs = 15_000): Promise<string | undefined> {
  try {
    if (!Bun.which(cmd[0]) && !existsSync(cmd[0])) return;
    const r = await exec(cmd, { timeoutMs });
    return r.code === 0 ? r.out : undefined;
  } catch {
    return;
  }
}

// ── text that ends up in shells, regexes

/** One word for /bin/sh: plain names stay as they are, anything else is single-quoted. */
export function shq(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`;
}

/** The same inside "…", where $ and ` would still expand. */
export function dq(s: string): string {
  return `"${s.replace(/[\\"$`]/g, "\\$&")}"`;
}

export function reEscape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── secrets in text that gets printed

const MASK = "•••";
/** A credential flag, as a whole dash-separated word (--token, --api-key, --auth-token, --key=…), and its value. */
const FLAG_VALUE = /(--(?:[\w-]*-)?(?:token|api-?key|key|secret|password|passwd|auth)(?:-[\w-]*)?)(=|\s+)(?!-)(\S+)/gi;
const URL_PASSWORD = /(\w[\w+.-]*:\/\/[^\s/@:]+:)([^\s/@]+)@/g;
const QUERY_SECRET = /([?&#](?:access_token|refresh_token|id_token|token|api[_-]?key|apikey|key|secret|password|auth)=)([^&\s"'#]+)/gi;
const KNOWN_TOKEN = /\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[abpr]-[A-Za-z0-9-]{8,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?)/g;
const HEX_RUN = /(?<!\w)[0-9a-f]{32,}(?!\w)/gi;
const BASE64_RUN = /(?<![\w+/=])[A-Za-z0-9+/]{32,}={0,2}(?![\w+/=])/g;

/**
 * Masks what looks like a credential in a command line or URL about to be printed: values of --token-style flags,
 * passwords in URLs, token= query values, and bare strings shaped like known tokens or long hex/base64. For display
 * only; what vswarm stores and hashes is never passed through this.
 */
export function redact(s: string): string {
  return s
    .replace(FLAG_VALUE, `$1$2${MASK}`)
    .replace(URL_PASSWORD, `$1${MASK}@`)
    .replace(QUERY_SECRET, `$1${MASK}`)
    .replace(KNOWN_TOKEN, MASK)
    .replace(HEX_RUN, MASK)
    // A path is a long run of the same characters; a secret mixes cases and digits and does not start with a slash.
    .replace(BASE64_RUN, (m) => (m.startsWith("/") || !/[A-Z]/.test(m) || !/[a-z]/.test(m) || !/\d/.test(m) ? m : MASK));
}

export function realCtx(): Ctx {
  const home = homedir();
  const brew = ["/opt/homebrew", "/usr/local/Homebrew", "/home/linuxbrew/.linuxbrew"].find((p) => existsSync(join(p, "bin", "brew")) || existsSync(join(p, "Library")))
    ?.replace(/\/Homebrew$/, "");
  const fromPath = (process.env.PATH ?? "").split(":").filter(Boolean);
  const watch = [
    ...(brew ? [join(brew, "bin"), join(brew, "sbin")] : []),
    "/usr/local/bin", join(home, ".local/bin"), join(home, "bin"), join(home, ".cargo/bin"), join(home, "go/bin"),
    join(home, ".bun/bin"), join(home, ".npm-global/bin"), join(home, ".deno/bin"),
    ...fromPath.filter((d) => d.startsWith(home)),
  ];
  return {
    home,
    brew,
    pathDirs: [...new Set(watch)].filter((d) => existsSync(d)),
    run,
    system: true,
    host: hostname(),
    user: whoami(),
  };
}

// ── small file helpers the collectors share

export function ls(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

export function readText(path: string, max = 2_000_000): string | undefined {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > max) return;
    return readFileSync(path, "utf8");
  } catch {
    return;
  }
}

export function readJson<T = any>(path: string, max?: number): T | undefined {
  const t = readText(path, max);
  if (t === undefined) return;
  try {
    return JSON.parse(t);
  } catch {
    return;
  }
}

export function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export function fileHash(path: string, max = 200_000_000): string | undefined {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > max) return;
    return sha256(readFileSync(path));
  } catch {
    return;
  }
}

export function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export function mtime(p: string): number | undefined {
  try {
    return statSync(p).mtimeMs;
  } catch {
    return;
  }
}
