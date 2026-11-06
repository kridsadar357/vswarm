// After the code ran: what it tried. Three sources —
//   the sandbox's own deny log (macOS unified log), for reads of your files, writes outside, network, keychain
//   the fake home, for login jobs and shell files it tried to plant
//   the proxy and the Node hostname recorder, for every host it tried to reach

import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { run } from "../ctx";
import { REGISTRIES, type ProxyHit } from "./proxy";
import type { Finding, Severity } from "../types";

export interface Denial {
  proc: string;
  pid: number;
  op: string;
  target: string;
}

/** What inside the real home is worth stealing; reading these is the clearest sign of an info-stealer. */
const SENSITIVE: [RegExp, string][] = [
  [/\/\.ssh\//, "SSH keys"],
  [/\/\.aws\//, "AWS credentials"],
  [/\/\.kube\//, "Kubernetes credentials"],
  [/\/\.config\/(gh|gcloud)\/|\/\.azure\//, "cloud / GitHub CLI credentials"],
  [/\/\.docker\/config\.json/, "Docker registry credentials"],
  [/\/\.(npmrc|pypirc|netrc|git-credentials)\b/, "package or git tokens"],
  [/\/Library\/Keychains\//, "the keychain"],
  [/Local Extension Settings|IndexedDB\/chrome-extension|nkbihfbeogaeaoehlefnkodbefgpgknn/, "browser wallet extensions"],
  [/\/Library\/Application Support\/(Google\/Chrome|BraveSoftware|Microsoft Edge|Arc|Firefox)\/.*(Cookies|Login Data|Web Data|Local State)/, "browser passwords and cookies"],
  [/\/Library\/Application Support\/(Exodus|Electrum|atomic|Ledger Live|Bitcoin|Ethereum|Phantom)/, "crypto wallets"],
  [/\/Library\/(Messages|Mail|Safari|Cookies)\//, "Messages, Mail or Safari data"],
  [/\/\.config\/(google-chrome|chromium|BraveSoftware|microsoft-edge)\/.*(Cookies|Login Data|Web Data|Local State)|\/\.mozilla\/firefox\//, "browser passwords and cookies"],
  [/\/\.config\/(Exodus|Electrum|atomic|Ledger Live)\/|\/\.electrum\/|\/\.bitcoin\/|\/\.ethereum\//, "crypto wallets"],
  [/\/\.local\/share\/keyrings\/|\/\.gnupg\/|\/\.password-store\//, "the keyring or GPG keys"],
  [/\/\.(zsh|bash)_history$/, "shell history"],
  [/\/(Desktop|Documents|Downloads)\//, "personal documents"],
];

/** Denials that every program triggers and that say nothing about intent. */
const NOISE = /system-info|\/dev\/dtracehelper|\.CFUserTextEncoding|file-read-metadata|\/Library\/Preferences\/|com\.apple\.(lsd|cfprefsd|logd|trustd|diagnosticd)|user-preference-read|iokit/;

function stamp(t: number) {
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export async function denials(since: number, minPid: number, ours?: { pids: Set<number>; names: Set<string> }): Promise<Denial[] | undefined> {
  const out = await run(["/usr/bin/log", "show", "--start", stamp(since - 1000), "--style", "ndjson", "--predicate", 'sender == "Sandbox"'], 60_000);
  if (out === undefined) return;
  const seen = new Set<string>();
  const list: Denial[] = [];
  for (const l of out.split("\n")) {
    let m: any;
    try {
      m = JSON.parse(l);
    } catch {
      continue;
    }
    const msg: string = m.eventMessage ?? "";
    const x = /Sandbox: (.+?)\((\d+)\) deny\(\d+\) (\S+) ?(.*)$/.exec(msg);
    if (!x) continue;
    const [, proc, pid, op, target] = x;
    // Processes the try started have higher pids than its first one; system daemons denied at the same time do not.
    if (Number(pid) < minPid || NOISE.test(`${op} ${target}`)) continue;
    // Only processes the run started: seen in its process tree, or carrying a name seen there (short-lived ones).
    if (ours && !ours.pids.has(Number(pid)) && !ours.names.has(proc)) continue;
    const key = `${op} ${target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    list.push({ proc, pid: Number(pid), op, target });
  }
  return list;
}

function walk(dir: string, root = dir, out: string[] = []): string[] {
  let entries: string[] = [];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e);
    try {
      const st = lstatSync(p);
      if (st.isDirectory()) walk(p, root, out);
      else out.push(relative(root, p));
    } catch {}
  }
  return out;
}

/** Caches and settings tools create on their own; not a sign of anything. */
const ORDINARY = /^(\.npm|\.cache|\.bun|\.yarn|\.pnpm-store|\.node-gyp|\.config\/(configstore|yarn|pnpm|npm)|Library\/Caches|\.cargo\/registry|\.local\/share\/(pnpm|virtualenv)|\.zcompdump|\.zsh_history|\.zsh_sessions|\.lesshst|\.python_history|\.node_repl_history|\.gitconfig$|\.zshrc$)/;

export function plantedFiles(home: string, seeded: Set<string>, seedText: Record<string, string>): { path: string; why: string; severity: Severity }[] {
  const out: { path: string; why: string; severity: Severity }[] = [];
  for (const rel of walk(home)) {
    const changed = seeded.has(rel) && seedText[rel] !== undefined && readFileSync(join(home, rel), "utf8") !== seedText[rel];
    if (seeded.has(rel) && !changed) continue;
    if (/^Library\/LaunchAgents\/|^\.config\/(systemd\/user|autostart)\//.test(rel)) out.push({ path: rel, why: "tried to install a login job (runs at every login)", severity: "high" });
    else if (/^\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)$|^\.config\/fish\//.test(rel)) out.push({ path: rel, why: changed ? "changed your shell start-up file" : "created a shell start-up file", severity: "high" });
    else if (/^\.ssh\//.test(rel)) out.push({ path: rel, why: "wrote into ~/.ssh (keys or authorized_keys)", severity: "high" });
    else if (/^Library\/Application Support\//.test(rel)) out.push({ path: rel, why: "wrote into Application Support", severity: "medium" });
    else if (!ORDINARY.test(rel)) out.push({ path: rel, why: "created a file in your home", severity: "low" });
  }
  return out;
}

export interface NetAttempt {
  host: string;
  port?: number;
  allowed: boolean;
  via: string;
}

export function network(hits: ProxyHit[], netlog: string): NetAttempt[] {
  const map = new Map<string, NetAttempt>();
  for (const h of hits) map.set(`${h.host}`, { host: h.host, port: h.port, allowed: h.allowed || map.get(h.host)?.allowed === true, via: "proxy" });
  try {
    for (const l of readFileSync(netlog, "utf8").split("\n")) {
      if (!l.trim()) continue;
      const e = JSON.parse(l);
      if (!map.has(e.host)) map.set(e.host, { host: e.host, port: e.port, allowed: false, via: "node (ignored the proxy)" });
    }
  } catch {}
  return [...map.values()];
}

/** Turns what the run did into findings. */
export function behaviour(d: Denial[] | undefined, planted: ReturnType<typeof plantedFiles>, net: NetAttempt[], realHome: string): Finding[] {
  const out: Finding[] = [];
  const add = (id: string, severity: Severity, title: string, detail: string[]) => out.push({ id: `try:${id}`, rule: "try-run", severity, title, detail });
  const reads = new Map<string, Set<string>>();
  for (const x of d ?? []) {
    if (x.op.startsWith("file-read") && x.target.startsWith(realHome + "/")) {
      const what = SENSITIVE.find(([re]) => re.test(x.target))?.[1];
      if (what) {
        if (!reads.has(what)) reads.set(what, new Set());
        reads.get(what)!.add(`${x.target.replace(realHome, "~")} (${x.proc})`);
      }
    }
  }
  for (const [what, paths] of reads) add(`read:${what}`, "high", `Tried to read ${what}`, [...paths].slice(0, 6));
  const writes = (d ?? []).filter((x) => x.op.startsWith("file-write") && !/^\/dev\//.test(x.target));
  if (writes.length) add("write-outside", writes.some((w) => /LaunchAgents|LaunchDaemons|\/etc\/|\/usr\/local\/bin|\.zshrc|\.bashrc|\.profile|systemd\/user|\/autostart\/|\.ssh\//.test(w.target)) ? "high" : "medium",
    `Tried to write outside its folder (${writes.length})`, writes.slice(0, 6).map((w) => `${w.target.replace(realHome, "~")} (${w.proc})`));
  const keychain = (d ?? []).filter((x) => (x.op === "mach-lookup" && /SecurityServer|securityd|pasteboard|appleevents|tccd/.test(x.target)) ||
    (x.op === "unix-connect" && /bus|keyring|docker\.sock|ssh|gnupg|gpg-agent|containerd|podman/.test(x.target)));
  if (keychain.length) add("services", "high", "Tried to reach the keychain, clipboard, agents or other apps", keychain.slice(0, 6).map((k) => `${k.target} (${k.proc})`));
  // DNS: macOS asks mDNSResponder; Linux connects to the resolver on port 53.
  const isDns = (x: Denial) => /mDNSResponder/.test(x.target) || /:53$/.test(x.target);
  const direct = (d ?? []).filter((x) => x.op.startsWith("network-outbound") && !isDns(x));
  const dns = (d ?? []).some((x) => x.op.startsWith("network-outbound") && isDns(x));
  const detached = (d ?? []).filter((x) => x.op === "setsid");
  if (detached.length) add("detached", "medium", "Started a background process that detaches from the terminal (ended with the sandbox)", detached.slice(0, 5).map((x) => `${x.proc} (pid ${x.pid} inside)`));
  for (const p of planted) add(`planted:${p.path}`, p.severity, `${p.why}: ~/${p.path}`, []);
  const pm = net.filter((n) => !n.allowed && REGISTRIES.some((r) => n.host === r || n.host.endsWith("." + r)));
  if (pm.length) add("net-registry", "info", `The package manager tried its registry (blocked; --net registries allows it)`, pm.map((n) => n.host));
  const blocked = net.filter((n) => !n.allowed && !pm.includes(n));
  const rawIp = blocked.filter((n) => /^\d{1,3}(\.\d{1,3}){3}$/.test(n.host));
  if (rawIp.length) add("net-ip", "high", `Tried to contact raw IP addresses`, rawIp.map((n) => `${n.host}${n.port ? ":" + n.port : ""} via ${n.via}`));
  const named = blocked.filter((n) => !rawIp.includes(n));
  if (named.length) add("net-host", "medium", `Tried to contact ${named.length} host${named.length > 1 ? "s" : ""} (blocked)`, named.slice(0, 10).map((n) => `${n.host}${n.port ? ":" + n.port : ""} via ${n.via}`));
  if (direct.length || (dns && !blocked.length)) add("net-direct", "medium", "Tried to open network connections directly, around the proxy", direct.slice(0, 6).map((x) => `${x.target}${x.proc === "?" ? "" : ` (${x.proc})`}`).concat(dns ? ["DNS lookups (blocked)"] : []));
  const allowed = net.filter((n) => n.allowed);
  if (allowed.length) add("net-allowed", "info", `Reached ${allowed.length} allowed host${allowed.length > 1 ? "s" : ""}`, allowed.map((n) => n.host));
  return out;
}
