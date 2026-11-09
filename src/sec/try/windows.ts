// The Windows try sandbox, from vswarm's side: the AppContainer profile, what it may read, the loopback exemption
// that lets it reach vswarm's proxy, its environment, and the command line for winbox.ts (the launcher).
//
//   files    reads: what Windows opens to every app (Windows, Program Files) and the toolchains below, read-only;
//            writes: only its box. Your profile, other users' files and the rest of the disk are closed to it.
//   network  none at all, unless the profile has a loopback exemption (one administrator approval, once): then only
//            this computer's loopback, where vswarm's proxy filters and records by host. An AppContainer has no
//            per-port loopback rule, so with the exemption it can also reach services listening on localhost here.
//   records  Windows keeps no log of what the container was refused (macOS and Linux do): reads of your files are
//            blocked, not listed. Hosts it asked the proxy for, files it planted and processes it left are listed.

import { dlopen, FFIType, ptr, toArrayBuffer } from "bun:ffi";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readJson, run } from "../ctx";
import { powershell } from "../schedule";
import { NODE_SHIM, type Box } from "./sandbox";

export const PROFILE = "vswarm.try";
const W = (s: string) => Buffer.from(s + "\0", "utf16le");

function wide(p: number): string {
  const u = new Uint16Array(toArrayBuffer(p as any, 0, 512));
  let s = "";
  for (const ch of u) {
    if (!ch) break;
    s += String.fromCharCode(ch);
  }
  return s;
}

/** The container's SID (S-1-15-2-…), making the profile the first time. */
export function containerSid(profile = PROFILE): string {
  const userenv = dlopen("userenv.dll", {
    CreateAppContainerProfile: { args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.u32, FFIType.ptr], returns: FFIType.i32 },
    DeriveAppContainerSidFromAppContainerName: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.i32 },
  });
  const advapi = dlopen("advapi32.dll", { ConvertSidToStringSidW: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.i32 } });
  const name = W(profile);
  const sid = new BigUint64Array(1);
  let hr = userenv.symbols.CreateAppContainerProfile(ptr(name), ptr(W("vswarm try")), ptr(W("vswarm try: untrusted code runs here")), null, 0, ptr(sid));
  // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS): made by an earlier run.
  if (hr !== 0) hr = userenv.symbols.DeriveAppContainerSidFromAppContainerName(ptr(name), ptr(sid));
  if (hr !== 0) throw new Error(`could not make the Windows sandbox (AppContainer profile ${profile}: 0x${(hr >>> 0).toString(16)})`);
  const str = new BigUint64Array(1);
  if (!advapi.symbols.ConvertSidToStringSidW(Number(sid[0]) as any, ptr(str))) throw new Error("could not read the sandbox's SID");
  return wide(Number(str[0]));
}

/**
 * The program folders of toolchains in your profile that code may read and run (node, bun, python …), never write.
 * Only where the programs are: a toolchain's own folder also holds its logins (.cargo\credentials.toml, an npmrc
 * with a registry token, scoop's persisted app data), and Windows lets a full path through a profile that is closed.
 */
const TOOLCHAINS = [
  ".bun\\bin", ".cargo\\bin", ".rustup\\toolchains", ".deno\\bin", "scoop\\apps", "scoop\\shims", "go\\bin", ".local\\bin",
  "AppData\\Roaming\\npm", "AppData\\Roaming\\nvm", "AppData\\Local\\Volta\\bin", "AppData\\Local\\Volta\\tools\\image", "AppData\\Local\\fnm\\node-versions",
  "AppData\\Local\\pnpm", "AppData\\Local\\Programs\\Python", "AppData\\Local\\Programs\\nodejs", "AppData\\Local\\Microsoft\\WinGet\\Links",
];
/** Inside those, what holds logins rather than programs: refused to the sandbox outright (a deny entry wins). */
const SECRETS_INSIDE = ["AppData\\Roaming\\npm\\etc", "AppData\\Local\\pnpm\\config", "scoop\\apps\\scoop\\current\\config.json"];

export function winToolchains(realHome: string): string[] {
  return TOOLCHAINS.map((t) => join(realHome, t)).filter((p) => existsSync(p));
}

/** Read and run for the container on each folder, once (kept in try/acl.json), and a deny on the logins inside them. */
export async function grantToolchains(sid: string, dirs: string[], state: string, realHome: string): Promise<string[]> {
  const kept = readJson<{ sid: string; dirs: string[]; denied?: string[] }>(state);
  const done = new Set(kept?.sid === sid ? kept.dirs : []);
  const denied = new Set(kept?.sid === sid ? kept.denied ?? [] : []);
  const failed: string[] = [];
  for (const d of dirs.filter((d) => !done.has(d))) {
    if ((await run(["icacls", d, "/grant", `*${sid}:(OI)(CI)RX`, "/Q"], 300_000)) === undefined) failed.push(d);
    else done.add(d);
  }
  for (const f of SECRETS_INSIDE.map((x) => join(realHome, x)).filter((f) => existsSync(f) && !denied.has(f)))
    if ((await run(["icacls", f, "/deny", `*${sid}:(OI)(CI)(R,X)`, "/Q"], 120_000)) !== undefined) denied.add(f);
  writeFileSync(state, JSON.stringify({ sid, dirs: [...done], denied: [...denied] }, null, 1) + "\n");
  return failed;
}

/** For uninstall: every grant and deny try made for the container, taken out again. */
export async function revokeToolchains(state: string): Promise<string[]> {
  const kept = readJson<{ sid: string; dirs: string[]; denied?: string[] }>(state);
  if (!kept?.sid) return [];
  const gone: string[] = [];
  for (const d of [...kept.dirs, ...(kept.denied ?? [])]) if (existsSync(d) && (await run(["icacls", d, "/remove", `*${kept.sid}`, "/Q"], 300_000)) !== undefined) gone.push(d);
  return gone;
}

/**
 * Read, write and delete in the box for the container, for this run; taken back afterwards (a later run cannot read
 * it). Modify, not full control: no changing the folder's permissions or taking ownership of it.
 */
export async function grantBox(dir: string, sid: string): Promise<void> {
  if ((await run(["icacls", dir, "/grant", `*${sid}:(OI)(CI)M`, "/Q"], 120_000)) === undefined) throw new Error(`could not open ${dir} to the sandbox (icacls)`);
}

export async function revokeBox(dir: string, sid: string): Promise<void> {
  await run(["icacls", dir, "/remove:g", `*${sid}`, "/T", "/Q"], 300_000);
}

/** Whether the profile may reach this computer's loopback (CheckNetIsolation LoopbackExempt). */
export async function loopbackExempt(sid: string): Promise<boolean> {
  const out = await run(["CheckNetIsolation.exe", "LoopbackExempt", "-s"], 20_000);
  return !!out && out.toUpperCase().includes(sid.toUpperCase());
}

/** The one administrator approval: Windows shows its own prompt for CheckNetIsolation, and nothing else runs elevated. */
export async function askLoopbackExempt(sid: string): Promise<boolean> {
  await run([powershell(), "-NoProfile", "-NonInteractive", "-Command",
    `Start-Process -FilePath CheckNetIsolation.exe -ArgumentList 'LoopbackExempt','-a','-p=${sid}' -Verb RunAs -Wait -WindowStyle Hidden`], 300_000);
  return loopbackExempt(sid);
}

/** The command to give it by hand, in an administrator terminal. */
export const exemptCommand = (sid: string) => `CheckNetIsolation LoopbackExempt -a -p=${sid}`;

/**
 * Node in an AppContainer: Windows does not let the container read C:\ itself, and Node's realpath (in JavaScript)
 * looks at every folder from the drive down, so every require fails with EPERM. Modules are therefore loaded by the
 * path they were found at (--preserve-symlinks, also for the main script), and fs.realpath goes to Windows' own
 * (GetFinalPathNameByHandle), which opens only the file itself. A package layout made of links (pnpm) may resolve
 * differently in the sandbox than outside it.
 */
export const NODE_WIN_PRELUDE = `"use strict";
{ const fs = require("fs");
  const sync = fs.realpathSync.native, cb = fs.realpath.native;
  fs.realpathSync = Object.assign((p, o) => sync(p, o), { native: sync });
  fs.realpath = Object.assign((p, o, f) => cb(p, o, f), { native: cb }); }
`;

/** The environment untrusted code gets on Windows: the system's own variables, a fake profile in the box, the proxy. */
export function winEnv(box: Box, proxyPort: number | undefined): Record<string, string> {
  const keep = ["PATH", "PATHEXT", "SystemRoot", "SystemDrive", "windir", "ComSpec", "OS", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "ProgramData", "LANG", "TERM", "USERNAME"];
  const env: Record<string, string> = {};
  for (const k of keep) if (process.env[k]) env[k] = process.env[k]!;
  const shim = join(box.tmp, "node-netlog.cjs");
  writeFileSync(shim, NODE_WIN_PRELUDE + NODE_SHIM);
  Object.assign(env, {
    USERPROFILE: box.home, HOME: box.home, HOMEDRIVE: box.home.slice(0, 2), HOMEPATH: box.home.slice(2),
    APPDATA: join(box.home, "AppData", "Roaming"), LOCALAPPDATA: join(box.home, "AppData", "Local"),
    TEMP: box.tmp, TMP: box.tmp,
    PROMPT: "(vswarm try) $P$G",
    // NODE_OPTIONS reads a backslash inside quotes as an escape: the path goes with forward slashes, which Node takes.
    NODE_OPTIONS: `--preserve-symlinks --preserve-symlinks-main --require "${shim.replace(/\\/g, "/")}"`,
    VSWARM_TRY_NETLOG: box.netlog,
    VSWARM_TRY: "1",
  });
  if (proxyPort) {
    const proxy = `http://127.0.0.1:${proxyPort}`;
    Object.assign(env, {
      HTTP_PROXY: proxy, HTTPS_PROXY: proxy, http_proxy: proxy, https_proxy: proxy, ALL_PROXY: proxy, all_proxy: proxy,
      NO_PROXY: "localhost,127.0.0.1,::1", no_proxy: "localhost,127.0.0.1,::1",
      npm_config_proxy: proxy, npm_config_https_proxy: proxy, NODE_USE_ENV_PROXY: "1",
    });
  }
  return env;
}

/** One argument for CreateProcessW, as the C runtime splits a command line (backslashes before a quote doubled). */
export function winArg(a: string): string {
  if (a && !/[\s"]/.test(a)) return a;
  return `"${a.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
}

/**
 * The command line for the sandbox. A .cmd or .bat (npm, npx, pnpm …) runs only through cmd.exe, which reads
 * & | < > ^ itself: those are refused in its arguments rather than escaped twice over.
 */
export function winCommandLine(cmd: string[], which: (c: string) => string | null = (c) => Bun.which(c)): string {
  const exe = which(cmd[0]) ?? cmd[0];
  if (/\.(cmd|bat)$/i.test(exe)) {
    const bad = cmd.slice(1).find((a) => /["%&|<>^\r\n]/.test(a));
    if (bad !== undefined) throw new Error(`not run: ${JSON.stringify(bad)} would be read by cmd.exe, and ${cmd[0]} runs only through cmd.exe`);
    return `${winArg(process.env.ComSpec ?? "C:\\Windows\\System32\\cmd.exe")} /d /s /c "${[exe, ...cmd.slice(1)].map(winArg).join(" ")}"`;
  }
  return [exe, ...cmd.slice(1)].map(winArg).join(" ");
}
