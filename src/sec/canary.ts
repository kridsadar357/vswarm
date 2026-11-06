// Canary tokens: decoy credentials planted where stealers look. Nobody has a reason to use them, so any use means
// the machine (or a copy of its files) is in someone else's hands. The alert comes from the token service you
// created them with (canarytokens.org, free, by Thinkst), not from vswarm: it works even after the files have left.
//
//   aws   a decoy profile in ~/.aws/credentials (an AWS-keys token)
//   dns   a decoy host in ~/.ssh/config whose name is a DNS token: resolving it (scanning, trying it) alerts
//   env   a decoy .env-style file in a folder of your choice, with an AWS-keys token in it

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { files, recordManaged, writePrivate } from "./store";

export interface Canary {
  id: string;
  kind: "aws" | "dns" | "env";
  /** File it was planted in. */
  where: string;
  /** What to recognise it by: profile name, host alias. Never the secret. */
  label: string;
  /** Public part only: the AWS key id, or the DNS token hostname. */
  token: string;
  at: number;
}

const canaryFile = () => join(dirname(files.baseline()), "canaries.json");

export function loadCanaries(): Canary[] {
  try {
    return JSON.parse(readFileSync(canaryFile(), "utf8"));
  } catch {
    return [];
  }
}

function save(list: Canary[]) {
  writePrivate(canaryFile(), list);
}

const START = (id: string) => `# >>> vswarm canary ${id} >>>`;
const END = (id: string) => `# <<< vswarm canary ${id} <<<`;

function append(path: string, id: string, body: string, opt: { top?: boolean } = {}) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const old = existsSync(path) ? readFileSync(path, "utf8") : "";
  // Markers keep it removable; they read like any tool's managed block, not like a trap.
  const block = `${START(id)}\n${body.trimEnd()}\n${END(id)}\n`;
  const next = opt.top ? `${block}\n${old}` : `${old.trimEnd()}${old.trim() ? "\n\n" : ""}${block}`;
  writeFileSync(path, next, { mode: 0o600 });
  recordManaged(block);
}

function strip(path: string, id: string) {
  if (!existsSync(path)) return;
  const re = new RegExp(`\\n?${START(id).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\\s\\S]*?${END(id).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\n?`, "g");
  writeFileSync(path, readFileSync(path, "utf8").replace(re, "\n").replace(/\n{3,}/g, "\n\n").replace(/^\n+/, ""));
}

const reEscape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const newId = () => Math.random().toString(36).slice(2, 8);

export function plantAws(keyId: string, secret: string, opt: { profile?: string; home?: string } = {}): Canary {
  if (!/^AKIA[0-9A-Z]{16}$/.test(keyId)) throw new Error("that does not look like an AWS access key id (AKIA…)");
  if (secret.length < 30) throw new Error("that does not look like an AWS secret key");
  const home = opt.home ?? homedir();
  const path = join(home, ".aws", "credentials");
  const profile = opt.profile ?? "prod-backup-admin";
  const existing = existsSync(path) ? readFileSync(path, "utf8") : "";
  if (new RegExp(`^\\s*\\[${reEscape(profile)}\\]`, "m").test(existing)) throw new Error(`profile [${profile}] already exists in ${path}`);
  const id = newId();
  append(path, id, `[${profile}]\naws_access_key_id = ${keyId}\naws_secret_access_key = ${secret}\nregion = ap-southeast-1`);
  const c: Canary = { id, kind: "aws", where: path, label: `[${profile}]`, token: keyId, at: Date.now() };
  save([...loadCanaries(), c]);
  return c;
}

export function plantDns(tokenHost: string, opt: { alias?: string; home?: string } = {}): Canary {
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(tokenHost)) throw new Error("give the DNS token's hostname (…canarytokens.com)");
  const home = opt.home ?? homedir();
  const path = join(home, ".ssh", "config");
  const alias = opt.alias ?? "prod-bastion-old";
  const id = newId();
  // At the top, so it is the first thing anyone reading the file sees, and it does not depend on Host * rules below.
  append(path, id, `Host ${alias}\n    HostName ${tokenHost}\n    User root\n    IdentityFile ~/.ssh/id_ed25519`, { top: true });
  const c: Canary = { id, kind: "dns", where: path, label: alias, token: tokenHost, at: Date.now() };
  save([...loadCanaries(), c]);
  return c;
}

export function plantEnv(dir: string, keyId: string, secret: string): Canary {
  if (!/^AKIA[0-9A-Z]{16}$/.test(keyId)) throw new Error("that does not look like an AWS access key id (AKIA…)");
  const path = join(resolve(dir), ".env.production");
  if (existsSync(path) && !readFileSync(path, "utf8").includes("vswarm canary")) throw new Error(`${path} already exists; pick another folder`);
  const id = newId();
  append(path, id, `# deploy credentials\nAWS_ACCESS_KEY_ID=${keyId}\nAWS_SECRET_ACCESS_KEY=${secret}\nAWS_REGION=ap-southeast-1`);
  const c: Canary = { id, kind: "env", where: path, label: ".env.production", token: keyId, at: Date.now() };
  save([...loadCanaries(), c]);
  return c;
}

export function removeCanary(id: string): Canary[] {
  const list = loadCanaries();
  const gone = id === "all" ? list : list.filter((c) => c.id === id);
  if (!gone.length) throw new Error(`no canary ${id} · vswarm canary list`);
  for (const c of gone) strip(c.where, c.id);
  save(list.filter((c) => !gone.includes(c)));
  return gone;
}

/** Canary key ids, so the credential scan does not report your own decoys as a problem. */
export function canaryKeyIds(): Set<string> {
  return new Set(loadCanaries().filter((c) => c.kind !== "dns").map((c) => c.token));
}

export function canaryWhere(): Set<string> {
  return new Set(loadCanaries().map((c) => c.where));
}
