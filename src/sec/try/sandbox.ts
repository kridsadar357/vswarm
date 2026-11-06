// The macOS sandbox (Seatbelt) that `vswarm try` runs untrusted code in.
//   files    reads: the system and your toolchains, nothing else in your home; writes: only its own work, home and tmp
//   secrets  no keychain, no clipboard, no Apple Events (scripting other apps)
//   network  localhost only; the outside world only through the vswarm proxy, which records and filters by host
// The code also gets a fake HOME and a clean environment, so tokens in your shell are not handed over.

import { existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

/** Toolchain folders in the real home that code may read (to run node, bun, python …), never write. */
const TOOLCHAINS = [
  ".bun", ".nvm", ".npm-global", ".volta", ".fnm", ".nodenv", ".pyenv", ".rbenv", ".rustup", ".cargo/bin", ".deno",
  ".local/bin", ".local/share/pnpm", "Library/pnpm", ".asdf", ".local/share/mise", ".sdkman", "go/bin", ".cache/ms-playwright",
  ".local/share/fnm", ".local/lib", ".linuxbrew",
];

export function toolchains(realHome: string): string[] {
  return TOOLCHAINS.map((t) => join(realHome, t)).filter((p) => existsSync(p));
}

const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

export interface Box {
  dir: string;
  work: string;
  home: string;
  tmp: string;
  netlog: string;
}

export function profile(realHome: string, box: Box, proxyPort: number, extraRead: string[] = []): string {
  const tools = [...toolchains(realHome), ...extraRead];
  const mine = [box.work, box.home, box.tmp];
  // The box and the folders above it (~/.vswarm/try, ~/.vswarm) as listings only: runtimes walk up from their working folder
  // at start-up (bun drops its whole environment when it cannot), and a listing shows names, not contents.
  const above: string[] = [];
  for (let a = box.dir; a !== "/" && a !== "."; a = dirname(a)) if (a.startsWith(realHome + "/") || a.startsWith("/private/var/folders")) above.push(a);
  return `(version 1)
(deny default)
(allow process-exec process-fork)
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow ipc-posix-shm ipc-posix-sem)
(allow mach-lookup)
; secrets and other apps: keychain, clipboard, scripting other apps, privacy database
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.security.agent")
  (global-name-prefix "com.apple.pasteboard")
  (global-name "com.apple.coreservices.appleevents")
  (global-name-prefix "com.apple.tccd"))
; files: read the system, not your home (except toolchains) and not other apps' temp files
(allow file-read*)
(deny file-read* (subpath ${q(realHome)}) (subpath "/private/var/folders") (subpath "/Volumes"))
(allow file-read* (literal ${q(realHome)})${above.map((a) => ` (literal ${q(a)})`).join("")}${tools.map((t) => ` (subpath ${q(t)})`).join("")}${mine.map((m) => ` (subpath ${q(m)})`).join("")})
(allow file-read-metadata)
(allow file-write*${mine.map((m) => ` (subpath ${q(m)})`).join("")} (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper") (regex #"^/dev/tty") (regex #"^/dev/fd/"))
(allow file-ioctl (regex #"^/dev/tty"))
; network: localhost (dev servers, the vswarm proxy on port ${proxyPort}); nothing else, not even DNS
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
`;
}

/** Records every outside hostname Node code looks up or connects to, even code that ignores proxy settings. */
export const NODE_SHIM = `"use strict";
const fs = require("fs"), dns = require("dns"), net = require("net");
const LOG = process.env.VSWARM_TRY_NETLOG;
const local = (h) => !h || /^(localhost|127\\.|::1|\\[::1\\]|0\\.0\\.0\\.0)/.test(String(h));
const rec = (host, port, how) => { if (local(host)) return; try { fs.appendFileSync(LOG, JSON.stringify({ at: Date.now(), host: String(host), port, how, pid: process.pid }) + "\\n"); } catch {} };
const lookup = dns.lookup;
dns.lookup = function (h, ...a) { rec(h, undefined, "dns"); return lookup.call(this, h, ...a); };
if (dns.promises) { const pl = dns.promises.lookup; dns.promises.lookup = function (h, ...a) { rec(h, undefined, "dns"); return pl.call(this, h, ...a); }; }
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) {
  try {
    // net.connect() hands over [options, callback] as one normalized array.
    const first = Array.isArray(a[0]) ? a[0][0] : a[0];
    const o = first && typeof first === "object" ? first : { port: a[0], host: a[1] };
    if (o.host) rec(o.host, o.port, "connect");
  } catch {}
  return connect.apply(this, a);
};
`;

/** The environment untrusted code gets: your PATH and locale, a fake HOME, the proxy, and nothing secret. */
export function cleanEnv(box: Box, proxyPort: number, realHome: string): Record<string, string> {
  const keep = ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "SHELL", "USER", "LOGNAME"];
  const env: Record<string, string> = {};
  for (const k of keep) if (process.env[k]) env[k] = process.env[k]!;
  const proxy = `http://127.0.0.1:${proxyPort}`;
  // Inside tmp/, which the sandbox lets the code read; anywhere else Node could not load it.
  const shim = join(box.tmp, "node-netlog.cjs");
  writeFileSync(shim, NODE_SHIM);
  Object.assign(env, {
    HOME: box.home,
    ZDOTDIR: box.home,
    TMPDIR: box.tmp + "/",
    HTTP_PROXY: proxy, HTTPS_PROXY: proxy, http_proxy: proxy, https_proxy: proxy, ALL_PROXY: proxy, all_proxy: proxy,
    NO_PROXY: "localhost,127.0.0.1,::1", no_proxy: "localhost,127.0.0.1,::1",
    npm_config_proxy: proxy, npm_config_https_proxy: proxy,
    NODE_USE_ENV_PROXY: "1",
    NODE_OPTIONS: `--require ${/\s/.test(shim) ? `"${shim}"` : shim}`,
    VSWARM_TRY_NETLOG: box.netlog,
    VSWARM_TRY: "1",
    // Toolchains whose state lives in the real home keep working, read-only.
    ...(existsSync(join(realHome, ".rustup")) ? { RUSTUP_HOME: join(realHome, ".rustup") } : {}),
    ...(existsSync(join(realHome, ".nvm")) ? { NVM_DIR: join(realHome, ".nvm") } : {}),
  });
  return env;
}
