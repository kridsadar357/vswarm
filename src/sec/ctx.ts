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

export async function run(cmd: string[], timeoutMs = 15_000): Promise<string | undefined> {
  try {
    if (!Bun.which(cmd[0]) && !existsSync(cmd[0])) return;
    const p = Bun.spawn(cmd, { stdout: "pipe", stderr: "ignore", stdin: "ignore" });
    const timer = setTimeout(() => p.kill(), timeoutMs);
    const [out, code] = await Promise.all([new Response(p.stdout).text(), p.exited]);
    clearTimeout(timer);
    return code === 0 ? out : undefined;
  } catch {
    return;
  }
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
