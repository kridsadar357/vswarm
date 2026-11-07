// Where vswarm keeps the key that seals its own state files (last verdict, lock, baseline, accepted findings, the
// incident log), and the seal itself: an HMAC-SHA256 over the file's name and bytes.
//
//   macOS    the login Keychain, through /usr/bin/security (service dev.vswarm.seal)
//   Linux    the desktop Secret Service through secret-tool, when there is one; else a file
//   Windows  a DPAPI blob under %LOCALAPPDATA%\vswarm, which only this Windows user can unprotect
//   else     a file readable by you only (~/.config/vswarm), and `vswarm doctor` says so
//
// What this buys: a last.json edited to say "pass", or a lock file deleted by hand, is noticed. What it does not: a
// program running as you can ask the Keychain for the key exactly the way vswarm does. The store is injectable, and
// tests always use a file in a temp folder.

import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { exec, powershell, type Exec } from "./ctx";

export type KeyKind = "keychain" | "secret-service" | "dpapi" | "file";

export interface KeyStore {
  kind: KeyKind;
  /** Where the key is, in words, for doctor. */
  where: string;
  /** The value, or undefined when there is none yet. Throws when the store is there but does not answer (locked, no D-Bus). */
  get(name: string): Promise<string | undefined>;
  set(name: string, value: string): Promise<void>;
  remove(name: string): Promise<void>;
}

/** How a store runs its helper program; tests replace it to see the command lines without running them. */
export type Runner = (cmd: string[], opt?: { stdin?: string; env?: Record<string, string | undefined> }) => Promise<Exec>;

const realRun: Runner = (cmd, opt = {}) => exec(cmd, { stdin: opt.stdin, env: opt.env ? { ...process.env, ...opt.env } : undefined, timeoutMs: 20_000 }).catch((e) => ({ code: 127, out: "", err: String(e?.message ?? e) }));

const SERVICE = "dev.vswarm.seal";
const first = (s: string) => s.trim().split("\n")[0]?.slice(0, 160) ?? "";

/**
 * One argument for the command parser of `security -i`: in double quotes, with backslash and double quote escaped.
 * It reads a line at a time, so a line break (or a NUL) cannot be passed at all and is refused.
 */
export function securityArg(s: string): string {
  if (/[\r\n\0]/.test(s)) throw new Error("a Keychain value cannot contain a line break");
  return `"${s.replace(/[\\"]/g, "\\$&")}"`;
}

/** The add-generic-password line `security -i` reads on stdin: -U updates an item that is there already. */
export function keychainAddLine(name: string, value: string): string {
  return `${["add-generic-password", "-U", "-s", SERVICE, "-a", name, "-l", "vswarm: seal of its own state files", "-w", value].map(securityArg).join(" ")}\n`;
}

/** macOS: a generic password in the login Keychain. Items `security` creates can be read back by `security` without a prompt. */
export function keychainStore(run: Runner = realRun): KeyStore {
  const sec = "/usr/bin/security";
  return {
    kind: "keychain",
    where: `login Keychain, item ${SERVICE}`,
    async get(name) {
      const r = await run([sec, "find-generic-password", "-s", SERVICE, "-a", name, "-w"]);
      if (r.code === 0) return r.out.trim() || undefined;
      // errSecItemNotFound
      if (r.code === 44) return undefined;
      throw new Error(`the Keychain did not answer (${first(r.err) || `security exit ${r.code}`})`);
    },
    async set(name, value) {
      // The value goes to `security -i` on stdin, never on the command line, where any process could read it in ps.
      const r = await run([sec, "-i"], { stdin: keychainAddLine(name, value) });
      if (r.code !== 0) throw new Error(`could not write to the Keychain (${first(r.err) || `security exit ${r.code}`})`);
    },
    async remove(name) {
      await run([sec, "delete-generic-password", "-s", SERVICE, "-a", name]);
    },
  };
}

/** Linux: the Secret Service (GNOME Keyring, KWallet) through secret-tool. The value goes in on stdin, never on the command line. */
export function secretServiceStore(run: Runner = realRun): KeyStore {
  return {
    kind: "secret-service",
    where: `Secret Service, service=${SERVICE}`,
    async get(name) {
      const r = await run(["secret-tool", "lookup", "service", SERVICE, "account", name]);
      if (r.code === 0 && r.out.trim()) return r.out.trim();
      // Not found is exit 1 and nothing said; anything on stderr is a keyring or D-Bus that is not there.
      if (r.code <= 1 && !r.err.trim()) return undefined;
      throw new Error(`the Secret Service did not answer (${first(r.err) || `secret-tool exit ${r.code}`})`);
    },
    async set(name, value) {
      const r = await run(["secret-tool", "store", `--label=vswarm: seal of its own state files (${name})`, "service", SERVICE, "account", name], { stdin: value });
      if (r.code !== 0) throw new Error(`could not write to the Secret Service (${first(r.err) || `secret-tool exit ${r.code}`})`);
    },
    async remove(name) {
      await run(["secret-tool", "clear", "service", SERVICE, "account", name]);
    },
  };
}

// The value travels in an environment variable, so nothing in it is read as PowerShell.
export const DPAPI_PROTECT =
  "Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($env:VSWARM_SEAL_IN), $null, 'CurrentUser'))";
export const DPAPI_UNPROTECT =
  "Add-Type -AssemblyName System.Security; [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($env:VSWARM_SEAL_BLOB), $null, 'CurrentUser'))";

/** Windows: DPAPI for the current user. The blob is a file; only this user, logged in on this machine, can open it. */
export function dpapiStore(dir: string, run: Runner = realRun, ps = powershell()): KeyStore {
  const blob = (name: string) => join(dir, `${name}.dpapi`);
  const cmd = (script: string) => [ps, "-NoProfile", "-NonInteractive", "-Command", script];
  return {
    kind: "dpapi",
    where: `DPAPI (current user), ${dir}`,
    async get(name) {
      if (!existsSync(blob(name))) return undefined;
      const r = await run(cmd(DPAPI_UNPROTECT), { env: { VSWARM_SEAL_BLOB: readFileSync(blob(name), "utf8").trim() } });
      if (r.code === 0 && r.out.trim()) return r.out.trim();
      throw new Error(`DPAPI could not open the key (${first(r.err) || `exit ${r.code}`})`);
    },
    async set(name, value) {
      const r = await run(cmd(DPAPI_PROTECT), { env: { VSWARM_SEAL_IN: value } });
      if (r.code !== 0 || !r.out.trim()) throw new Error(`DPAPI could not protect the key (${first(r.err) || `exit ${r.code}`})`);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(blob(name), r.out.trim() + "\n", { mode: 0o600 });
    },
    async remove(name) {
      rmSync(blob(name), { force: true });
    },
  };
}

/** A folder of owner-only files: the fallback, and what tests use. */
export function fileStore(dir: string): KeyStore {
  return {
    kind: "file",
    where: dir,
    async get(name) {
      try {
        return readFileSync(join(dir, name), "utf8").trim() || undefined;
      } catch (e: any) {
        if (e?.code === "ENOENT") return undefined;
        throw e;
      }
    },
    async set(name, value) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(join(dir, name), value + "\n", { mode: 0o600 });
    },
    async remove(name) {
      rmSync(join(dir, name), { force: true });
    },
  };
}

/** Where the fallback file store lives: outside ~/.vswarm, so wiping that folder does not also wipe the key. */
export function fallbackDir(home = homedir()): string {
  if (process.platform === "win32") return join(process.env.LOCALAPPDATA ?? join(home, "AppData", "Local"), "vswarm", "keys");
  return join(process.env.XDG_CONFIG_HOME ?? join(home, ".config"), "vswarm");
}

/** The store this system would pick first. `secretTool` says whether secret-tool is installed (Linux). */
export function platformStore(platform = process.platform, secretTool = !!Bun.which("secret-tool")): KeyStore {
  if (platform === "darwin" && existsSync("/usr/bin/security")) return keychainStore();
  if (platform === "win32") return dpapiStore(join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "vswarm"));
  if (platform === "linux" && secretTool) return secretServiceStore();
  return fileStore(fallbackDir());
}

/** A store by its recorded kind, so a machine keeps using the store it started with. */
export function storeOfKind(kind: KeyKind): KeyStore {
  if (kind === "keychain") return keychainStore();
  if (kind === "secret-service") return secretServiceStore();
  if (kind === "dpapi") return dpapiStore(join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "vswarm"));
  return fileStore(fallbackDir());
}

// ── the seal

/** The seal of one state file: HMAC-SHA256 over its own name and its bytes, so seals cannot be swapped between files. */
export function sealOf(key: Buffer, file: string, data: string | Buffer): string {
  return createHmac("sha256", key).update(`vswarm-seal-v1\0${basename(file)}\0`).update(data).digest("hex");
}

export function sameHex(a: string, b: string): boolean {
  const x = Buffer.from(a, "hex"), y = Buffer.from(b, "hex");
  return x.length === 32 && x.length === y.length && timingSafeEqual(x, y);
}

/** One incident-log entry's MAC: its fields and the MAC before it, so entries can be neither changed nor reordered. */
export function entryMac(key: Buffer, e: { n: number; at: number; event: string; incident?: string; reason?: string; prev: string }): string {
  return createHmac("sha256", key).update("vswarm-log-v1\0").update(JSON.stringify([e.n, e.at, e.event, e.incident ?? "", e.reason ?? "", e.prev])).digest("hex");
}
