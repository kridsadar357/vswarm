// `vswarm agent`: an SSH agent that holds your production keys and signs only while this machine passes.
//
// The ssh gate in ~/.ssh/config is advice to one client: `ssh -F /dev/null`, an IP address instead of the host name,
// VS Code Remote, a GUI client, paramiko or libssh2 never read it. The agent moves the control to the key. Once
// `vswarm agent protect ~/.ssh/prod_key` has run, that key exists only inside the agent's vault, and every signature
// with it is decided at the moment it is asked for: a sealed verdict at most 30 seconds old, or a fresh quiet check,
// as preflight decides (an open incident always blocks), and PASS only unless the key was protected --allow-warn.
// Whatever program asks, by whatever route, gets SSH_AGENT_FAILURE from a machine that does not pass, and the
// refusal is logged and shown.
//
//   ~/.vswarm/agent/            0700, owned by you
//     agent.sock                the agent (draft-miller-ssh-agent), 0600; on Windows a named pipe instead,
//                               \\.\pipe\vswarm-agent-<folder hash>, run by the Task Scheduler task \vswarm\agent
//     keys/<id>.json            protected keys: AES-256-GCM, the wrapping key in the Keychain / Secret Service / DPAPI
//     config.json               the upstream agent, when you named one (agent on --upstream)
//   ~/.vswarm/sec/audit.log     every signature and refusal, sealed and chained like the incident log
//   <key>.vswarm-backup         the original key file, encrypted with a recovery code printed once
//
// Keys the agent does not hold are passed to your usual agent (upstream) untouched, so git and other ssh keep
// working through the same socket. What this does not stop: a program running as you can ask the agent to sign while
// the machine passes, and could read the agent's memory. See docs/guide.md, "vswarm agent".

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { appendFileSync, chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { GLOBAL_TAG, HOME, paths } from "../home";
import { exec, readJson, readText, run, shq, type Ctx } from "./ctx";
import { verdictNow } from "./gate";
import { c, line } from "./print";
import { t } from "../i18n";
import { notify as desktopNotify, powershell } from "./schedule";
import { keyFromWire, fingerprint, parsePublicLine, publicLine, readPrivate, Reader, signedFor, signWith, Writer, type SignedFor, type SshKey } from "./sshkey";
import { activeStore, appendAudit, blockRegex, lockState, readAudit, recordManaged, recordManagedFile, removeBlock } from "./store";
import type { Verdict } from "./types";
import { AGENT_END, AGENT_START, blockHosts, cmdWord, GATE_END, GATE_START, refusedLine } from "./sshblocks";
import { effective, readPolicy, type KeyPolicy, type WarnPolicy } from "./policy";
import { blocks, expandPath, hostView, listMatch, literal, namedHosts, ownHosts } from "./sshconfig";
import { keyEncrypted } from "./secrets";

const WIN = process.platform === "win32";

/**
 * Windows has no Unix sockets for OpenSSH: the agent is a named pipe, one per agent folder, so a VSWARM_HOME of its
 * own (or a test) gets an agent of its own. Pipe names are global to the machine and the first to create one owns it,
 * so the name is a random one, kept in the agent folder (in your profile, which other users cannot read): another
 * account cannot guess it and sit on it before the agent starts.
 */
export function pipeFor(dir: string): string {
  const file = join(dir, "pipe");
  let id = readText(file)?.trim();
  if (!id || !/^[0-9a-f]{32}$/.test(id)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    id = randomBytes(16).toString("hex");
    writeFileSync(file, id + "\n", { mode: 0o600 });
  }
  return `\\\\.\\pipe\\vswarm-agent-${id}`;
}
const isPipe = (p: string) => /^[\\/]{2}\.[\\/]pipe[\\/]/i.test(p);
/** The agent's address as ~/.ssh/config and ssh -o take it: OpenSSH for Windows reads a pipe only as //./pipe/<name>. */
export const sshAgentPath = (sock: string) => (isPipe(sock) ? sock.replace(/\\/g, "/") : sock);
/** Whether there may be an agent at `sock`: a socket file, or on Windows a pipe (which has no file to look for). */
/** This vswarm's launcher, as `vswarm install` writes it (setup.ts launcherPath; not imported, setup imports this file). */
const ownLauncher = () => join(paths.bin(), WIN ? "vswarm.cmd" : "vswarm");
export const mayAnswer = (sock: string) => isPipe(sock) || existsSync(sock);

export const agentPaths = {
  dir: () => process.env.VSWARM_AGENT_DIR ?? join(HOME, "agent"),
  sock: () => (WIN ? pipeFor(agentPaths.dir()) : join(agentPaths.dir(), "agent.sock")),
  keys: () => join(agentPaths.dir(), "keys"),
  config: () => join(agentPaths.dir(), "config.json"),
  log: () => join(agentPaths.dir(), "agent.log"),
  /** Which host name each host key belongs to, and when ssh last asked for it (written by `agent check`). */
  hosts: () => join(agentPaths.dir(), "hosts.json"),
};

interface HostSeen {
  host: string;
  at: number;
}

/** host key fingerprint → the name you typed for it, from hosts.json. */
export function hostNames(): Record<string, string> {
  const j = readJson<Record<string, HostSeen>>(agentPaths.hosts()) ?? {};
  const out: Record<string, string> = {};
  for (const [fp, s] of Object.entries(j)) if (typeof s?.host === "string" && /^SHA256:/.test(fp)) out[fp] = s.host;
  return out;
}

// Message numbers, draft-miller-ssh-agent §6.1.
export const MSG = {
  FAILURE: 5, SUCCESS: 6,
  REQUEST_IDENTITIES: 11, IDENTITIES_ANSWER: 12, SIGN_REQUEST: 13, SIGN_RESPONSE: 14,
  ADD_IDENTITY: 17, REMOVE_IDENTITY: 18, REMOVE_ALL_IDENTITIES: 19, LOCK: 22, UNLOCK: 23, ADD_ID_CONSTRAINED: 25, EXTENSION: 27,
} as const;
const CONSTRAIN_LIFETIME = 1, CONSTRAIN_CONFIRM = 2;
// OpenSSH's own limit on one message.
const MAX_MSG = 256 * 1024;
const FAIL = Buffer.from([MSG.FAILURE]);
const OK = Buffer.from([MSG.SUCCESS]);

// ── framing

const frame = (payload: Buffer) => new Writer().u32(payload.length).raw(payload).out();

/** Splits a byte stream into agent messages (length, then that many bytes). A length out of bounds ends the stream. */
function framer(onMsg: (m: Buffer) => void, onBad: () => void) {
  let buf = Buffer.alloc(0);
  return (chunk: Uint8Array) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const n = buf.readUInt32BE(0);
      if (n === 0 || n > MAX_MSG) return onBad();
      if (buf.length < 4 + n) break;
      onMsg(buf.subarray(4, 4 + n));
      buf = buf.subarray(4 + n);
    }
  };
}

interface Out {
  pending: Buffer[];
}

/** Writes all of it: what the socket did not take now goes when it drains. */
function send(s: { write(b: Buffer): number; data: Out }, b: Buffer) {
  if (s.data.pending.length) return void s.data.pending.push(b);
  const n = s.write(b);
  if (n < b.length) s.data.pending.push(b.subarray(Math.max(n, 0)));
}

function drain(s: { write(b: Buffer): number; data: Out }) {
  while (s.data.pending.length) {
    const b = s.data.pending[0];
    const n = s.write(b);
    if (n < b.length) {
      s.data.pending[0] = b.subarray(Math.max(n, 0));
      return;
    }
    s.data.pending.shift();
  }
}

/** One request to an agent at `path` and its answer (type byte first), or undefined when it does not answer in time. */
export function agentCall(path: string, payload: Buffer, timeoutMs = 10_000): Promise<Buffer | undefined> {
  return new Promise((done) => {
    let finished = false;
    let sock: { end(): void } | undefined;
    const finish = (v?: Buffer) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try {
        sock?.end();
      } catch {}
      done(v);
    };
    const timer = setTimeout(() => finish(), timeoutMs);
    const feed = framer((m) => finish(Buffer.from(m)), () => finish());
    Bun.connect<Out>({
      unix: path,
      socket: {
        open(s) {
          sock = s;
          s.data = { pending: [] };
          send(s as any, frame(payload));
        },
        data: (_s, d) => feed(d),
        drain: (s) => drain(s as any),
        close: () => finish(),
        error: () => finish(),
        connectError: () => finish(),
      },
    }).catch(() => finish());
  });
}

export interface Identity {
  blob: Buffer;
  comment: string;
}

/** The identities an agent answers with, or undefined when it does not answer. */
export async function listIdentities(path: string, timeoutMs = 10_000): Promise<Identity[] | undefined> {
  const r = await agentCall(path, Buffer.from([MSG.REQUEST_IDENTITIES]), timeoutMs);
  if (!r || r[0] !== MSG.IDENTITIES_ANSWER) return;
  try {
    const rd = new Reader(r, 1);
    const n = rd.u32();
    const out: Identity[] = [];
    for (let i = 0; i < n && i < 10_000; i++) out.push({ blob: Buffer.from(rd.str()), comment: rd.text() });
    return out;
  } catch {
    return;
  }
}

// ── the vault

const VAULT_AAD = (fp: string, path: string) => Buffer.from(`vswarm-agent-vault-v1\0${fp}\0${path}`);
const WRAP_NAME = "agent-key";

/** The key that opens protected keys, from the same store as the sealing key. Made the first time a key is protected. */
async function wrapKey(create = false): Promise<Buffer> {
  const s = (await activeStore()).store;
  let hex = await s.get(WRAP_NAME);
  if (!hex && create) {
    const made = randomBytes(32).toString("hex");
    await s.set(WRAP_NAME, made);
    if ((await s.get(WRAP_NAME)) !== made) throw new Error(`${s.where} did not keep the key that protects your ssh keys`);
    hex = made;
  }
  if (!hex || !/^[0-9a-f]{64}$/.test(hex)) throw new Error(`the key that opens protected ssh keys is not in ${s.where}; restore a key from its .vswarm-backup file: vswarm agent restore <file>`);
  return Buffer.from(hex, "hex");
}

function seal(key: Buffer, aad: Buffer, plain: Buffer): string {
  const iv = randomBytes(12);
  const ci = createCipheriv("aes-256-gcm", key, iv).setAAD(aad);
  const ct = Buffer.concat([ci.update(plain), ci.final()]);
  return Buffer.concat([iv, ci.getAuthTag(), ct]).toString("base64");
}

function unseal(key: Buffer, aad: Buffer, box: string): Buffer {
  const b = Buffer.from(box, "base64");
  const de = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12)).setAAD(aad);
  de.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([de.update(b.subarray(28)), de.final()]);
}

export interface Vault {
  v: 1;
  fp: string;
  type: string;
  comment: string;
  /** Where the key file was, and where unprotect puts it back. */
  path: string;
  pub: string;
  at: number;
  box: string;
}

interface VaultInside {
  wire: string;
  original: string;
  confirm: boolean;
  /** Written by 2.6 and older, where false was the default; no longer read. */
  strict?: boolean;
  /** WARN signs too (protect --allow-warn). Written by 2.7, and kept beside `policy` so 2.7 reads a vault the same way. */
  allowWarn?: boolean;
  /** What WARN does with this key (2.8): its own "allow" or "refuse", or "inherit" the policy (vswarm policy). */
  policy?: KeyPolicy;
}

/**
 * A key's own WARN setting. Vaults from before the shared policy have none: they keep what they were protected with,
 * which was "refuse" unless --allow-warn (2.7 made protected keys strict, and read 2.6's vaults as strict too).
 */
export const keyPolicyOf = (inside: Pick<VaultInside, "policy" | "allowWarn">): KeyPolicy =>
  inside.policy === "allow" || inside.policy === "refuse" || inside.policy === "inherit" ? inside.policy : inside.allowWarn === true ? "allow" : "refuse";

const sealedInside = (inside: VaultInside, policy: KeyPolicy): VaultInside => {
  const { strict: _old, ...rest } = inside;
  return { ...rest, policy, allowWarn: policy === "allow" };
};

const vaultFile = (fp: string) => join(agentPaths.keys(), `${createHash("sha256").update(fp).digest("hex").slice(0, 24)}.json`);

export function listVaults(): { file: string; v: Vault }[] {
  const dir = agentPaths.keys();
  if (!existsSync(dir)) return [];
  const out: { file: string; v: Vault }[] = [];
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".json")).sort()) {
    const v = readJson<Vault>(join(dir, f));
    if (v?.v === 1 && typeof v.fp === "string" && typeof v.box === "string" && typeof v.path === "string") out.push({ file: join(dir, f), v });
  }
  return out;
}

async function openVault(v: Vault, key?: Buffer): Promise<VaultInside> {
  return JSON.parse(unseal(key ?? (await wrapKey()), VAULT_AAD(v.fp, v.path), v.box).toString("utf8"));
}

// ── the backup: the original file, encrypted with a recovery code you keep

const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };

export function recoveryCode(): string {
  const b = randomBytes(30);
  const chars = [...b].map((x) => CODE_ALPHABET[x % CODE_ALPHABET.length]).join("");
  return chars.match(/.{5}/g)!.join("-");
}

const normCode = (code: string) => code.toUpperCase().replace(/[^A-Z0-9]/g, "");

export interface Backup {
  v: 1;
  what: string;
  fp: string;
  path: string;
  salt: string;
  box: string;
}

function writeBackup(file: string, original: Buffer, fp: string, keyPath: string, code: string) {
  const salt = randomBytes(16);
  const k = scryptSync(normCode(code), salt, 32, SCRYPT);
  const b: Backup = { v: 1, what: "vswarm agent protect: the original key file, encrypted. Restore: vswarm agent restore <this file>", fp, path: keyPath, salt: salt.toString("base64"), box: seal(k, VAULT_AAD(fp, keyPath), original) };
  writeFileSync(file, JSON.stringify(b, null, 1) + "\n", { mode: 0o600 });
}

function openBackup(b: Backup, code: string): Buffer {
  const k = scryptSync(normCode(code), Buffer.from(b.salt, "base64"), 32, SCRYPT);
  try {
    return unseal(k, VAULT_AAD(b.fp, b.path), b.box);
  } catch {
    throw new Error("that recovery code does not open this backup");
  }
}

// ── reading a key file: ssh-add does it, into a throwaway agent of our own

/**
 * The private key in `keyfile`, whatever its format, read by ssh-add: a passphrase is typed into ssh's own prompt
 * (or SSH_ASKPASS), never into vswarm. ssh-add hands the key to a one-off agent on a socket in a fresh 0700 folder.
 */
export async function captureKey(keyfile: string, env: Record<string, string | undefined> = process.env): Promise<SshKey> {
  const dir = mkdtempSync(join(tmpdir(), "vswarm-add-"));
  const sock = WIN ? `\\\\.\\pipe\\vswarm-add-${randomBytes(12).toString("hex")}` : join(dir, "s");
  let got: SshKey | undefined;
  let why = "";
  const srv = Bun.listen<Out & { feed?: (d: Uint8Array) => void }>({
    unix: sock,
    socket: {
      open(s) {
        s.data = { pending: [] };
      },
      data(s, d) {
        const feed = (s.data.feed ??= framer((m) => {
          let reply: Buffer = FAIL;
          if (m[0] === MSG.REQUEST_IDENTITIES) reply = new Writer().u8(MSG.IDENTITIES_ANSWER).u32(0).out();
          else if (m[0] === MSG.ADD_IDENTITY || m[0] === MSG.ADD_ID_CONSTRAINED) {
            try {
              const k = readPrivate(new Reader(m, 1));
              got ??= k;
              reply = OK;
            } catch (e: any) {
              why ||= String(e?.message ?? e);
            }
          }
          send(s as any, frame(reply));
        }, () => s.end()));
        feed(d);
      },
      drain: (s) => drain(s as any),
    },
  });
  try {
    const p = Bun.spawn(["ssh-add", keyfile], { env: { ...env, SSH_AUTH_SOCK: sock }, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
    await p.exited;
  } finally {
    srv.stop(true);
    rmSync(dir, { recursive: true, force: true });
  }
  if (!got) throw new Error(why ? `ssh-add read the key, but ${why}` : `ssh-add could not read ${keyfile} (wrong passphrase, or not a private key)`);
  return got;
}

/** Overwritten, flushed, then removed. On SSDs and copy-on-write file systems old blocks may survive; see the docs. */
function shred(path: string) {
  const n = statSync(path).size;
  const fd = openSync(path, "r+");
  try {
    writeSync(fd, randomBytes(n), 0, n, 0);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  rmSync(path);
}

export interface Protected {
  fp: string;
  vault: string;
  backup: string;
  /** The recovery code of the backup; empty when this run only finished an earlier one. */
  code: string;
  pubWritten: boolean;
  /** Why the key file is still on disk: it is in the vault, but removing the file failed. Running protect again finishes. */
  left?: string;
  /** This run found the key already in the vault and its file still on disk, and removed the file. */
  finished?: boolean;
}

/** Protected keys whose key file is still on disk (protect was cut short after the vault was written). */
export function leftOnDisk(): { path: string; fp: string }[] {
  return listVaults().filter((x) => existsSync(x.v.path)).map((x) => ({ path: x.v.path, fp: x.v.fp }));
}

/**
 * Moves a private key into the vault: read (by ssh-add), encrypted at rest, a backup encrypted with a recovery code,
 * both checked by opening them again, and only then the key file overwritten and removed. Its .pub stays (or is
 * written), so ssh still knows which agent key an IdentityFile means.
 */
export async function protect(keyfile: string, opt: { confirm?: boolean; allowWarn?: boolean; policy?: KeyPolicy; env?: Record<string, string | undefined>; shred?: (path: string) => void } = {}): Promise<Protected> {
  const path = resolve(keyfile);
  const wipe = opt.shred ?? shred;
  const prior = listVaults().find((x) => x.v.path === path);
  if (prior) {
    if (!existsSync(path)) throw new Error(`${path} is already protected · vswarm agent status`);
    // An earlier protect wrote the vault and the backup but could not remove the file: this run finishes the job, when
    // the file is still that key, byte for byte.
    const inside = await openVault(prior.v);
    if (!readFileSync(path).equals(Buffer.from(inside.original, "base64")))
      throw new Error(`${path} is already protected, and the file there now is not that key (an earlier protect may have overwritten it, then failed to remove it); look at it, then remove it yourself`);
    wipe(path);
    return { fp: prior.v.fp, vault: prior.file, backup: `${path}.vswarm-backup`, code: "", pubWritten: false, finished: true };
  }
  if (!existsSync(path)) throw new Error(`no key file at ${path}`);
  const st = lstatSync(path);
  if (!st.isFile()) throw new Error(`${path} is not a plain file${st.isSymbolicLink() ? " (a symlink: protect the file it points to)" : ""}`);
  if (path.endsWith(".pub")) throw new Error(`${path} is a public key; name the private key file`);
  const original = readFileSync(path);
  const k = await captureKey(path, opt.env);
  const fp = fingerprint(k.blob);
  if (listVaults().some((x) => x.v.fp === fp)) throw new Error(`this key (${fp}) is already protected`);
  const pubPath = `${path}.pub`;
  let pubWritten = false;
  if (existsSync(pubPath)) {
    const blob = parsePublicLine(readFileSync(pubPath, "utf8"));
    if (!blob?.equals(k.blob)) throw new Error(`${pubPath} is not the public half of this key; move it aside first`);
  } else {
    writeFileSync(pubPath, publicLine(k) + "\n", { mode: 0o644 });
    pubWritten = true;
  }
  const wk = await wrapKey(true);
  // A key protected now follows the shared policy unless it is given its own setting.
  const inside = sealedInside({ wire: k.wire.toString("base64"), original: original.toString("base64"), confirm: !!opt.confirm }, opt.policy ?? (opt.allowWarn ? "allow" : "inherit"));
  const v: Vault = { v: 1, fp, type: k.type, comment: k.comment, path, pub: publicLine(k), at: Date.now(), box: seal(wk, VAULT_AAD(fp, path), Buffer.from(JSON.stringify(inside))) };
  mkdirSync(agentPaths.keys(), { recursive: true, mode: 0o700 });
  const file = vaultFile(fp);
  const backup = `${path}.vswarm-backup`;
  if (existsSync(backup)) throw new Error(`${backup} exists from an earlier protect; restore or move it aside first`);
  const code = recoveryCode();
  try {
    writeFileSync(`${file}.tmp`, JSON.stringify(v, null, 1) + "\n", { mode: 0o600 });
    writeBackup(backup, original, fp, path, code);
    // Both are opened again before the original goes: a vault that does not open would lose the key.
    const back = await openVault(v, wk);
    if (!Buffer.from(back.original, "base64").equals(original) || !keyFromWire(Buffer.from(back.wire, "base64")).blob.equals(k.blob)) throw new Error("the vault did not read back; nothing was changed");
    if (!openBackup(JSON.parse(readFileSync(backup, "utf8")), code).equals(original)) throw new Error("the backup did not read back; nothing was changed");
    renameSync(`${file}.tmp`, file);
  } catch (e) {
    for (const f of [`${file}.tmp`, backup, ...(pubWritten ? [pubPath] : [])]) rmSync(f, { force: true });
    throw e;
  }
  // The key is in the vault now. When its file cannot be removed the recovery code must still reach you: said, not thrown.
  let left: string | undefined;
  try {
    wipe(path);
  } catch (e: any) {
    left = String(e?.message ?? e);
  }
  return { fp, vault: file, backup, code, pubWritten, left };
}

/** Puts a protected key file back where it was, byte for byte, and removes its vault and backup. */
function findVault(target: string) {
  const full = resolve(target);
  const hit = listVaults().find((x) => x.v.fp === target || x.v.path === full || x.v.path === full.replace(/\.pub$/, ""));
  if (!hit) throw new Error(`${target} is not a protected key · vswarm agent status lists them`);
  return hit;
}

/**
 * What WARN does with a protected key: "allow" signs, "refuse" does not, "inherit" follows the shared policy
 * (vswarm policy). `true`/`false` are 2.7's allow/refuse. The vault is sealed again with the new setting; a running
 * agent reads it when the vault folder changes.
 */
export async function setKeyPolicy(target: string, policy: KeyPolicy | boolean): Promise<{ path: string; fp: string }> {
  const hit = findVault(target);
  const wk = await wrapKey();
  const inside = await openVault(hit.v, wk);
  const p: KeyPolicy = policy === true ? "allow" : policy === false ? "refuse" : policy;
  const v: Vault = { ...hit.v, box: seal(wk, VAULT_AAD(hit.v.fp, hit.v.path), Buffer.from(JSON.stringify(sealedInside(inside, p)))) };
  writeFileSync(`${hit.file}.tmp`, JSON.stringify(v, null, 1) + "\n", { mode: 0o600 });
  renameSync(`${hit.file}.tmp`, hit.file);
  return { path: hit.v.path, fp: hit.v.fp };
}

export async function unprotect(target: string): Promise<{ path: string; fp: string }> {
  const hit = findVault(target);
  const inside = await openVault(hit.v);
  const original = Buffer.from(inside.original, "base64");
  const path = hit.v.path;
  if (existsSync(path) && !readFileSync(path).equals(original)) throw new Error(`a different file is at ${path} now; move it aside, then unprotect again`);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, original, { mode: 0o600 });
  if (!readFileSync(path).equals(original)) throw new Error(`could not write ${path}; the vault is kept`);
  rmSync(hit.file);
  rmSync(`${path}.vswarm-backup`, { force: true });
  return { path, fp: hit.v.fp };
}

/** From a backup and its recovery code, for when the vault or its key is gone. Never overwrites a file. */
export function restore(backupFile: string, code: string): { path: string; fp: string } {
  const b = readJson<Backup>(resolve(backupFile));
  if (b?.v !== 1 || typeof b.box !== "string" || typeof b.path !== "string") throw new Error(`${backupFile} is not a vswarm key backup`);
  const original = openBackup(b, code);
  if (existsSync(b.path)) throw new Error(`${b.path} exists; move it aside first`);
  mkdirSync(dirname(b.path), { recursive: true, mode: 0o700 });
  writeFileSync(b.path, original, { mode: 0o600 });
  return { path: b.path, fp: b.fp };
}

// ── the agent

interface Held {
  key: SshKey;
  fp: string;
  /** From the vault: stays until unprotect, whatever ssh-add -d says. */
  vault?: string;
  confirm: boolean;
  /** What WARN does with this key: its own setting, or "inherit" the shared policy (keys added with ssh-add inherit). */
  policy: KeyPolicy;
  expires?: number;
}

interface Conn extends Out {
  feed?: (d: Uint8Array) => void;
  chain: Promise<unknown>;
  /** The server's host key, from session-bind@openssh.com (as the client reports it). */
  hostKey?: string;
  forwarded?: boolean;
}

export interface AgentOptions {
  sock: string;
  /** Your usual agent, for keys this one does not hold. */
  upstream?: string;
  /** How the verdict is taken. Default: preflight's (sealed recent verdict, or a fresh quiet check; a lock blocks). */
  verdict?: () => Promise<Verdict>;
  /** How old a sealed verdict may be and still decide a signature (default AGENT_MAX_AGE). */
  maxAge?: number;
  /** How long the upstream agent may take over a signature (default UPSTREAM_SIGN_TIMEOUT). */
  upstreamSignTimeout?: number;
  ctx?: Ctx;
  offline?: boolean;
  notify?: (title: string, body: string) => Promise<void>;
  /** Asks you whether to allow one signature with a confirm-on-use key. */
  confirm?: (question: string) => Promise<boolean>;
  /** Load protected keys from the vault (default true). */
  vaults?: boolean;
  log?: (text: string) => void;
  /** The shared WARN policy (default: vswarm policy, read at each signature). */
  policy?: () => Promise<WarnPolicy>;
  /** Host names for host keys, as `agent check` recorded them (default: hosts.json in the agent's folder). */
  hostNames?: () => Record<string, string>;
}

export interface Agent {
  sock: string;
  held(): { fp: string; comment: string; vault: boolean; confirm: boolean; policy: KeyPolicy }[];
  stop(): void;
}

/** Whether `p` names the same socket as `q` (a pipe in either spelling, any case). */
const same = (p: string, q: string) => (isPipe(p) || isPipe(q) ? p.replace(/\//g, "\\").toLowerCase() === q.replace(/\//g, "\\").toLowerCase() : resolve(p) === resolve(q));

/** Windows' own agent (the ssh-agent service), where ssh looks when SSH_AUTH_SOCK is not set. */
export const WIN_UPSTREAM = "\\\\.\\pipe\\openssh-ssh-agent";

/** Your usual agent: the one configured with agent on --upstream, else $SSH_AUTH_SOCK, never this agent itself. */
export function resolveUpstream(env: Record<string, string | undefined> = process.env, own = agentPaths.sock()): string | undefined {
  const cfg = readJson<{ upstream?: string }>(agentPaths.config());
  const v = env.VSWARM_AGENT_UPSTREAM ?? cfg?.upstream ?? env.SSH_AUTH_SOCK ?? (WIN ? WIN_UPSTREAM : undefined);
  if (!v || v === "none" || same(v, own)) return;
  return v;
}

/** The socket's folder: made 0700 if missing, and refused when someone else owns it or others may enter it. */
function safeDir(dir: string) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // Windows has no mode bits to read; the folder is in your profile, which only you (and administrators) can open.
  if (WIN) return;
  const st = statSync(dir);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) throw new Error(`${dir} belongs to another user; the agent will not listen there`);
  if (st.mode & 0o077) throw new Error(`${dir} can be entered by other users (mode ${(st.mode & 0o777).toString(8)}); chmod 700 it`);
}

const CONFIRM_TIMEOUT = 30;
/**
 * A signature with a protected key is decided on a verdict at most this old (preflight reuses one for two minutes).
 * Older, the agent checks afresh, quietly and offline-first as preflight does, and the next 30 seconds reuse that.
 */
export const AGENT_MAX_AGE = 30_000;
/**
 * The upstream agent may ask you before it signs (ssh-add -c, a hardware key waiting for a touch): it gets this long,
 * not the 10 seconds other requests get. `agent on --upstream-timeout <seconds>` changes it.
 */
export const UPSTREAM_SIGN_TIMEOUT = 60_000;

/** Asks on the desktop: a dialog on macOS and Windows, SSH_ASKPASS or zenity on Linux. No way to ask means no. */
export async function askOnDesktop(question: string, title = "vswarm agent"): Promise<boolean> {
  if (WIN) {
    // Yes/No, No the default, gone after the timeout (-1). The question is passed in the environment, never parsed.
    const r = await exec([powershell(), "-NoProfile", "-NonInteractive", "-Command", `if ((New-Object -ComObject WScript.Shell).Popup($env:VSWARM_Q, ${CONFIRM_TIMEOUT}, $env:VSWARM_T, 4 + 48 + 256) -eq 6) { 'allow' }`],
      { env: { ...process.env, VSWARM_Q: question, VSWARM_T: title }, timeoutMs: (CONFIRM_TIMEOUT + 5) * 1000 }).catch(() => ({ code: 1, out: "" }));
    return r.code === 0 && (r.out ?? "").trim() === "allow";
  }
  if (process.platform === "darwin") {
    const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    const out = await run(["osascript", "-e", `display dialog ${q(question)} buttons {"Refuse", "Allow"} default button "Refuse" cancel button "Refuse" with title ${q(title)} giving up after ${CONFIRM_TIMEOUT}`], (CONFIRM_TIMEOUT + 5) * 1000);
    return !!out && out.includes("button returned:Allow") && !out.includes("gave up:true");
  }
  const askpass = process.env.SSH_ASKPASS;
  if (askpass && existsSync(askpass)) {
    const r = await exec([askpass, question], { env: { ...process.env, SSH_ASKPASS_PROMPT: "confirm" }, timeoutMs: (CONFIRM_TIMEOUT + 5) * 1000 }).catch(() => ({ code: 1 }));
    return r.code === 0;
  }
  if (Bun.which("zenity")) {
    const r = await exec(["zenity", "--question", `--title=${title}`, `--text=${question}`, `--timeout=${CONFIRM_TIMEOUT}`], { timeoutMs: (CONFIRM_TIMEOUT + 5) * 1000 }).catch(() => ({ code: 1 }));
    return r.code === 0;
  }
  return false;
}

/**
 * For the audit log: who the signature was for, as far as the request says. The host's name comes from the check
 * ssh ran just before (`agent check` records which name each host key belongs to); the request itself has only the key.
 */
function target(f: SignedFor, conn: Conn, names: Record<string, string> = {}): string {
  const parts: string[] = [];
  const hk = f.hostKey ?? conn.hostKey;
  const name = hk && Object.hasOwn(names, hk) ? names[hk] : undefined;
  if (f.kind === "userauth") parts.push(`ssh login as ${f.user}${name ? ` to ${name}` : ""}`, `alg ${f.alg}`);
  else if (f.kind === "sshsig") parts.push(`ssh-keygen -Y sign, namespace ${f.namespace}`);
  else parts.push("other data");
  if (hk) parts.push(`host key ${hk}`);
  if (conn.forwarded) parts.push("through a forwarded agent");
  return parts.join(" · ");
}

export async function startAgent(opt: AgentOptions): Promise<Agent> {
  const say = opt.log ?? ((t: string) => line(t));
  // On Windows a socket path names the pipe of its folder (tests, --sock); a pipe is taken as it is.
  const sock = !WIN ? resolve(opt.sock) : isPipe(opt.sock) ? opt.sock.replace(/\//g, "\\") : pipeFor(dirname(resolve(opt.sock)));
  // sun_path is 104 bytes on macOS, 108 on Linux.
  if (!WIN && Buffer.byteLength(sock) > 100) throw new Error(`the socket path is too long for a Unix socket: ${sock}`);
  if (!WIN) safeDir(dirname(sock));
  if (mayAnswer(sock)) {
    if (await listIdentities(sock, 2000)) throw new Error(`an agent already answers on ${sock}`);
    if (!WIN) rmSync(sock, { force: true });
  }
  const upstream = opt.upstream && !same(opt.upstream, sock) ? opt.upstream : undefined;
  const held = new Map<string, Held>();
  const hex = (b: Buffer) => b.toString("hex");
  let locked: { salt: Buffer; hash: Buffer } | undefined;

  // Protected keys, read again whenever the vault folder changes (protect, unprotect).
  let seen = "";
  const refresh = async () => {
    if (opt.vaults === false) return;
    const dir = agentPaths.keys();
    let stamp = "none";
    try {
      // Each vault's own time too: agent policy seals one again in place.
      stamp = [statSync(dir).mtimeMs, ...readdirSync(dir).sort().map((f) => `${f}@${statSync(join(dir, f)).mtimeMs}`)].join(":");
    } catch {}
    if (stamp === seen) return;
    seen = stamp;
    const vaults = listVaults();
    for (const [id, h] of held) if (h.vault && !vaults.some((x) => x.file === h.vault)) held.delete(id);
    if (!vaults.length) return;
    let wk: Buffer;
    try {
      wk = await wrapKey();
    } catch (e: any) {
      seen = "";
      return say(c.red(`vswarm agent: ${e?.message ?? e}`));
    }
    for (const { file, v } of vaults) {
      try {
        const inside = await openVault(v, wk);
        const key = keyFromWire(Buffer.from(inside.wire, "base64"));
        if (fingerprint(key.blob) !== v.fp) throw new Error("its key does not match its fingerprint");
        held.set(hex(key.blob), { key, fp: v.fp, vault: file, confirm: !!inside.confirm, policy: keyPolicyOf(inside) });
      } catch (e: any) {
        say(c.red(`vswarm agent: could not open ${file}: ${e?.message ?? e}`));
      }
    }
  };
  await refresh();

  const live = () => {
    const now = Date.now();
    for (const [id, h] of held) if (h.expires && h.expires <= now) held.delete(id);
    return [...held.values()];
  };

  // One check at a time: ssh asking for several signatures at once waits for the same verdict.
  let inflight: Promise<Verdict> | undefined;
  const takeVerdict = () =>
    (inflight ??= (opt.verdict ?? (() => verdictNow({ quiet: true, offline: opt.offline, ctx: opt.ctx, maxAge: opt.maxAge ?? AGENT_MAX_AGE })))().finally(() => {
      inflight = undefined;
    }));

  const told = new Map<string, number>();
  const tell = async (title: string, body: string) => {
    // The same refusal once a minute, not once per retry.
    const at = told.get(body) ?? 0;
    if (Date.now() - at < 60_000) return;
    told.set(body, Date.now());
    await (opt.notify ?? desktopNotify)(title, body).catch(() => {});
  };

  // An old audit log with unsealed lines, set aside on the way: said once, where the agent's output goes.
  const noted = (notice?: string) => void (notice && say(c.amber(`vswarm agent: the audit log: ${notice}`)));

  const refuse = async (h: Held, why: string, todo: string, what: string) => {
    say(`${c.red("vswarm agent: refused")} ${h.fp} ${c.dim(`· ${why} · ${what}`)}`);
    await appendAudit("refuse", h.fp, `${why} · ${what}`).then(noted, (e) => say(c.red(`vswarm agent: could not write the audit log: ${e?.message ?? e}`)));
    await tell("vswarm: ssh key refused", `${h.key.comment || h.fp}: ${why}. ${todo}`);
    return FAIL;
  };

  const signFor = async (conn: Conn, msg: Buffer, r: Reader): Promise<Buffer> => {
    const blob = Buffer.from(r.str());
    const data = Buffer.from(r.str());
    const flags = r.left >= 4 ? r.u32() : 0;
    await refresh();
    const h = live().find((x) => x.key.blob.equals(blob));
    if (!h) {
      // Not ours: your usual agent decides, as if vswarm were not here.
      if (locked || !upstream) return FAIL;
      return (await agentCall(upstream, msg, opt.upstreamSignTimeout ?? UPSTREAM_SIGN_TIMEOUT)) ?? FAIL;
    }
    const what = target(signedFor(data), conn, (opt.hostNames ?? hostNames)());
    if (locked) return refuse(h, "the agent is locked (ssh-add -x)", "Unlock it: ssh-add -X", what);
    let verdict: Verdict;
    try {
      verdict = await takeVerdict();
    } catch (e: any) {
      return refuse(h, `the check failed (${String(e?.message ?? e).slice(0, 120)})`, "See why: vswarm why", what);
    }
    if (verdict === "block") {
      const { lock } = await lockState().catch(() => ({ lock: undefined }));
      return lock
        ? refuse(h, `incident ${lock.incident} is open`, "Production keys stay locked until vswarm unlock (after vswarm respond)", what)
        : refuse(h, "this machine does not pass preflight", "See why: vswarm why", what);
    }
    if (verdict === "warn") {
      const global = await (opt.policy ?? (async () => (await readPolicy()).warn))().catch((): WarnPolicy => "refuse");
      if (effective(h.policy, global) === "refuse")
        return refuse(h, h.policy === "refuse" ? "preflight warns, and this key signs on PASS only" : "preflight warns, and the policy refuses WARN",
          `See why: vswarm why · ${h.policy === "refuse" ? `let this key sign on WARN: vswarm agent policy ${h.vault ? short(listVaults().find((x) => x.file === h.vault)?.v.path ?? h.fp) : h.fp} --allow-warn` : "let WARN through: vswarm policy warn allow"}`, what);
    }
    if (h.confirm && !(await (opt.confirm ?? askOnDesktop)(`Allow ${h.key.comment || h.fp} to sign? ${what}`))) return refuse(h, "not confirmed", "Answer Allow in the vswarm dialog to use this key", what);
    const sig = signWith(h.key, data, flags);
    // No signature leaves without its sealed line in the audit log: a key store that does not answer means no seal,
    // so no signature (the refusal says why; it cannot be logged either).
    try {
      noted(await appendAudit("sign", h.fp, `${verdict.toUpperCase()} · ${what}`));
    } catch (e: any) {
      return refuse(h, `its audit line could not be sealed and written (${String(e?.message ?? e).slice(0, 160)})`, "Unlock the login keychain or keyring, then try again; vswarm doctor shows where the key is", what);
    }
    say(`${c.green("vswarm agent: signed")} ${h.fp} ${c.dim(`· ${verdict.toUpperCase()} · ${what}`)}`);
    return new Writer().u8(MSG.SIGN_RESPONSE).str(sig).out();
  };

  const identities = async (): Promise<Buffer> => {
    if (locked) return new Writer().u8(MSG.IDENTITIES_ANSWER).u32(0).out();
    await refresh();
    const own = live();
    const list: Identity[] = own.map((h) => ({ blob: h.key.blob, comment: h.key.comment }));
    if (upstream) for (const i of (await listIdentities(upstream)) ?? []) if (!own.some((h) => h.key.blob.equals(i.blob))) list.push(i);
    const w = new Writer().u8(MSG.IDENTITIES_ANSWER).u32(list.length);
    for (const i of list) w.str(i.blob).str(i.comment);
    return w.out();
  };

  const add = (r: Reader, constrained: boolean): Buffer => {
    if (locked) return FAIL;
    const key = readPrivate(r);
    let life: number | undefined, confirm = false;
    while (constrained && r.left) {
      const t = r.u8();
      if (t === CONSTRAIN_LIFETIME) life = r.u32();
      else if (t === CONSTRAIN_CONFIRM) confirm = true;
      // Destination limits and other extensions are not understood here: refused, as OpenSSH refuses what it does not know.
      else return FAIL;
    }
    const id = hex(key.blob);
    // A protected key keeps its vault settings; adding it again changes nothing.
    if (held.get(id)?.vault) return OK;
    const h: Held = { key, fp: fingerprint(key.blob), confirm, policy: "inherit" };
    if (life) {
      h.expires = Date.now() + life * 1000;
      setTimeout(() => held.get(id) === h && held.delete(id), life * 1000).unref?.();
    }
    held.set(id, h);
    say(`vswarm agent: added ${h.fp} ${c.dim(key.comment)}${confirm ? c.dim(" · confirm on use") : ""}${life ? c.dim(` · for ${life}s`) : ""}`);
    return OK;
  };

  const handle = async (conn: Conn, msg: Buffer): Promise<Buffer> => {
    const r = new Reader(msg, 1);
    switch (msg[0]) {
      case MSG.REQUEST_IDENTITIES:
        return identities();
      case MSG.SIGN_REQUEST:
        return signFor(conn, msg, r);
      case MSG.ADD_IDENTITY:
      case MSG.ADD_ID_CONSTRAINED:
        return add(r, msg[0] === MSG.ADD_ID_CONSTRAINED);
      case MSG.REMOVE_IDENTITY: {
        if (locked) return FAIL;
        const id = hex(Buffer.from(r.str()));
        const h = held.get(id);
        // A key vswarm does not hold is your usual agent's: ssh-add -d removes it there, as it would without vswarm.
        if (!h) return upstream ? ((await agentCall(upstream, msg)) ?? FAIL) : FAIL;
        if (h.vault) return FAIL;
        held.delete(id);
        return OK;
      }
      case MSG.REMOVE_ALL_IDENTITIES:
        if (locked) return FAIL;
        for (const [id, h] of held) if (!h.vault) held.delete(id);
        // ssh-add -D empties your usual agent too. Protected keys stay: only unprotect takes them out of the vault.
        return upstream ? ((await agentCall(upstream, msg)) ?? FAIL) : OK;
      case MSG.LOCK: {
        if (locked) return FAIL;
        const salt = randomBytes(16);
        locked = { salt, hash: scryptSync(r.str(), salt, 32) };
        return OK;
      }
      case MSG.UNLOCK: {
        if (!locked) return FAIL;
        if (!timingSafeEqual(scryptSync(r.str(), locked.salt, 32), locked.hash)) {
          // As OpenSSH does: a wrong passphrase costs time.
          await Bun.sleep(1000);
          return FAIL;
        }
        locked = undefined;
        return OK;
      }
      case MSG.EXTENSION: {
        // No extensions are offered. session-bind is still read, for the audit log only.
        if (r.text() === "session-bind@openssh.com") {
          try {
            conn.hostKey = fingerprint(Buffer.from(r.str()));
            r.str();
            r.str();
            conn.forwarded = r.left ? r.u8() !== 0 : false;
          } catch {}
        }
        return FAIL;
      }
      default:
        return FAIL;
    }
  };

  const server = Bun.listen<Conn>({
    unix: sock,
    socket: {
      open(s) {
        s.data = { pending: [], chain: Promise.resolve() };
      },
      data(s, d) {
        const st = s.data;
        st.feed ??= framer(
          (m) => {
            const msg = Buffer.from(m);
            // One message at a time per connection, answered in order.
            st.chain = st.chain.then(() => handle(st, msg)).catch(() => FAIL).then((reply) => send(s as any, frame(reply)));
          },
          () => s.end(),
        );
        st.feed(d);
      },
      drain: (s) => drain(s as any),
      error() {},
    },
  });
  if (!WIN)
    try {
      chmodSync(sock, 0o600);
    } catch {}
  return {
    sock,
    held: () => live().map((h) => ({ fp: h.fp, comment: h.key.comment, vault: !!h.vault, confirm: h.confirm, policy: h.policy })),
    stop() {
      server.stop(true);
      if (!WIN) rmSync(sock, { force: true });
    },
  };
}

// ── running it: a LaunchAgent, a systemd user service or a Task Scheduler task, and IdentityAgent for the gated hosts

const LABEL = "dev.vswarm.agent";
export const WIN_AGENT_TASK = { path: "\\vswarm\\", name: "agent" };
/** The task itself lives in Task Scheduler; this copy of its definition is what status and the scan look at. */
const winTaskFile = () => join(agentPaths.dir(), "agent-task.xml");
/** The task's one action as Get-ScheduledTask reports it: conhost --headless keeps a console window from showing. */
export function winAgentAction(launcher: string): { execute: string; args: string } {
  if (/["\r\n]/.test(launcher)) throw new Error(`cannot schedule ${launcher}: it contains a double quote`);
  // By full path: Task Scheduler would otherwise look the name up.
  return { execute: join(process.env.SystemRoot ?? "C:\\Windows", "System32", "conhost.exe"), args: `--headless "${launcher}" agent run` };
}
const plistPath = (home = homedir()) => join(home, "Library/LaunchAgents", `${LABEL}.plist`);
const unitPath = (home = homedir()) => join(home, ".config/systemd/user/vswarm-agent.service");
const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
const unitWord = (s: string) => (/^[A-Za-z0-9_./-]+$/.test(s) ? s : `"${s.replace(/[\\"]/g, "\\$&").replace(/%/g, "%%")}"`);

export function agentJobFiles(launcher: string, home = homedir(), platform = process.platform, winUser?: string): Record<string, string> {
  if (platform === "win32") {
    // At your logon, as you, without a time limit, started again a minute after it stops (as KeepAlive and Restart do).
    const a = winAgentAction(launcher);
    const x = (v: string) => xml(v).replace(/"/g, "&quot;");
    // Your SID when known (an Azure AD account's DOMAIN\name may not resolve), else DOMAIN\name.
    const user = winUser ?? (process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}` : (process.env.USERNAME ?? ""));
    return {
      [winTaskFile()]: `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>vswarm agent: ssh keys that sign only while this machine passes</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>${x(user)}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>${x(a.execute)}</Command><Arguments>${x(a.args)}</Arguments></Exec></Actions>
</Task>
`,
    };
  }
  if (platform === "darwin")
    return {
      [plistPath(home)]: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${LABEL}</string>
<key>ProgramArguments</key><array><string>${xml(launcher)}</string><string>agent</string><string>run</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardErrorPath</key><string>${xml(agentPaths.log())}</string>
</dict></plist>
`,
    };
  return {
    [unitPath(home)]: `[Unit]\nDescription=vswarm agent: ssh keys that sign only while this machine passes\n\n[Service]\nExecStart=${unitWord(launcher)} agent run\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n`,
  };
}

export { AGENT_END, AGENT_START };

export interface AgentBlockOpt {
  /** How ssh starts vswarm for the check before a login; without it the block has no check (tests, old blocks). */
  launcher?: string[];
  /** Protected key files, named for these hosts so ssh offers them (it reads the .pub beside each). */
  keys?: string[];
  /** Keep ssh's password and keyboard-interactive logins for these hosts (agent on --allow-passwords). */
  allowPasswords?: boolean;
  /** Let ssh offer every key the agent has, not only the configured ones (agent on --all-keys). */
  allKeys?: boolean;
  /** Windows OpenSSH: Match exec and ProxyCommand run through cmd.exe. */
  win?: boolean;
}

/**
 * The ~/.ssh/config block: these hosts take their keys from vswarm agent. A convenience; the control is the key.
 *
 *   Match … !exec "vswarm agent check …"   before the login, the same decision the agent will make, said on the
 *                                          terminal with the way out; a refusal ends there (ProxyCommand exits)
 *   IdentityAgent                          the agent
 *   IdentityFile <key>                     each protected key by its own path: ssh reads <key>.pub, signs through
 *                                          the agent, and never meets a file it would call an unprotected private key
 *   IdentitiesOnly yes                     only those keys (and the host's own IdentityFile), not every agent key
 *   PasswordAuthentication no              a key the agent refuses ends in "Permission denied", not in a password
 *   KbdInteractiveAuthentication no        prompt that looks like a forgotten password
 */
export function agentSshBlock(patterns: string[], sock: string, opt: AgentBlockOpt = {}): string {
  const win = opt.win ?? WIN;
  const bad = patterns.find((p) => !/^[\w*?!.:\[\]-]+$/.test(p));
  if (bad !== undefined) throw new Error(`"${bad}" is not an ssh host pattern (letters, digits, . - * ? and !)`);
  // ssh expands % and ~ in IdentityAgent and IdentityFile, and the paths sit in double quotes.
  for (const p of [sock, ...(opt.keys ?? [])]) if (/["%\r\n]/.test(p)) throw new Error(`cannot put ${p} in ~/.ssh/config: it contains % or a double quote`);
  if (opt.launcher?.some((p) => /["\n]/.test(p))) throw new Error(`cannot put ${opt.launcher.join(" ")} in ~/.ssh/config: it contains a double quote`);
  const pats = patterns.join(",");
  // cmd.exe reads & | ( ) in the host name ssh puts in for %n: on Windows the names go to the check only when every
  // pattern is a plain name (so %n is one of them). Without them the check covers every protected key.
  const names = !win || patterns.every((p) => /^[\w.:-]+$/.test(p)) ? " --host %n --hostname %h --port %p" : "";
  const path = (p: string) => (win ? p.replace(/\\/g, "/") : p);
  return [
    AGENT_START,
    "# Hosts below take their keys from `vswarm agent`, which signs only while this machine passes. Remove with: vswarm agent off",
    ...(opt.launcher
      ? [
        `Match originalhost ${pats} !exec "${opt.launcher.map(win ? cmdWord : shq).join(" ")} agent check${names}"`,
        refusedLine(opt.launcher.map(win ? cmdWord : shq).join(" "), win ? "vswarm agent: not connecting: the machine did not pass" : "vswarm agent: not connecting (the reason is above)", win),
      ]
      : []),
    `Match originalhost ${pats}`,
    `    IdentityAgent "${sshAgentPath(sock)}"`,
    ...(opt.keys ?? []).map((k) => `    IdentityFile "${path(k)}"`),
    ...(opt.allKeys ? [] : ["    IdentitiesOnly yes"]),
    ...(opt.allowPasswords ? [] : ["    PasswordAuthentication no", "    KbdInteractiveAuthentication no"]),
    AGENT_END,
  ].join("\n");
}

/** Writes (or with null removes) the agent block at the top of an ssh config, keeping a backup. Returns whether it changed. */
export function setAgentBlock(cfgPath: string, block: string | null): { changed: boolean; backup?: string } {
  const old = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "";
  const rest = removeBlock(old, AGENT_START, AGENT_END).replace(/^\n+/, "").trimEnd();
  // ssh takes the first IdentityAgent it meets, so the block goes first (before a Host * from another agent).
  const next = block ? `${block}\n\n${rest}${rest ? "\n" : ""}` : rest ? `${rest}\n` : "";
  if (next === old) return { changed: false };
  let backup: string | undefined;
  if (old) writeFileSync((backup = `${cfgPath}.bak-vswarm-${Date.now()}`), old, { mode: 0o600 });
  mkdirSync(dirname(cfgPath), { recursive: true, mode: 0o700 });
  writeFileSync(cfgPath, next, { mode: 0o600 });
  if (block) recordManaged(block + "\n");
  return { changed: true, backup };
}

/** Host patterns of the ssh gate block, when there is one. */
export function gatedHosts(cfg: string): string[] {
  return blockHosts(cfg, GATE_START, GATE_END);
}

/** Host patterns of the agent block, when there is one. */
export function agentHosts(cfg: string): string[] {
  return blockHosts(cfg, AGENT_START, AGENT_END);
}

/** The fingerprints known_hosts lists for a host (plain or hashed names, [host]:port for another port). */
export function knownHostKeys(text: string, hostname: string, port = 22): string[] {
  const name = port === 22 ? hostname : `[${hostname}]:${port}`;
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.trim();
    if (!l || l.startsWith("#") || l.startsWith("@")) continue;
    const [hosts, , b64] = l.split(/\s+/);
    if (!hosts || !b64) continue;
    let hit = false;
    const hashed = /^\|1\|([^|]+)\|([^|]+)$/.exec(hosts);
    if (hashed) hit = createHmac("sha1", Buffer.from(hashed[1], "base64")).update(name).digest("base64") === hashed[2];
    else hit = listMatch(hosts.split(","), name);
    if (!hit) continue;
    try {
      out.push(fingerprint(Buffer.from(b64, "base64")));
    } catch {}
  }
  return [...new Set(out)];
}

/** Remembers which name a host's keys belong to, so the audit log can name the host a signature was for. */
function noteHost(host: string, hostname: string, port: number, home: string) {
  const fps = knownHostKeys(readText(join(home, ".ssh", "known_hosts")) ?? "", hostname, port);
  if (!fps.length) return;
  try {
    const j = readJson<Record<string, HostSeen>>(agentPaths.hosts()) ?? {};
    for (const fp of fps) j[fp] = { host, at: Date.now() };
    safeDir(agentPaths.dir());
    writeFileSync(`${agentPaths.hosts()}.tmp`, JSON.stringify(j, null, 1) + "\n", { mode: 0o600 });
    renameSync(`${agentPaths.hosts()}.tmp`, agentPaths.hosts());
  } catch {}
}

export interface CheckAnswer {
  ok: boolean;
  why?: string;
  todo?: string;
  /** The protected keys the decision was about. */
  keys: string[];
}

/**
 * `vswarm agent check --host <name>`: what the agent would answer for a login to this host, before ssh asks it. ssh
 * runs this from the agent block (Match exec), so a refusal is said on the terminal, with the way out, instead of
 * ending in a password prompt. Only protected keys are its business; a host whose own IdentityFile names other keys
 * goes ahead, as those keys go to your usual agent untouched.
 */
export async function agentCheck(host: string, opt: { hostname?: string; port?: number; home?: string; verdict?: () => Promise<Verdict>; policy?: () => Promise<WarnPolicy>; answering?: () => Promise<boolean> } = {}): Promise<CheckAnswer> {
  const home = opt.home ?? homedir();
  // No host: Windows with wildcard patterns (see agentSshBlock); every protected key is then relevant.
  const view = host ? hostView(readText(join(home, ".ssh", "config")) ?? "", host, { home, withoutOwn: true }) : { identityFiles: [] as string[], hostname: undefined, port: undefined };
  // The agent block comes first in the file, so when ssh runs this, a HostName or Port further down is not applied
  // yet (%h is still the name, %p 22): what the config says for the host wins.
  if (host) noteHost(host, view.hostname ?? opt.hostname ?? host, view.port ?? opt.port ?? 22, home);
  const vaults = listVaults();
  if (!vaults.length) return { ok: true, keys: [] };
  const own = view.identityFiles.map((f) => f.replace(/\.pub$/, ""));
  const mine = vaults.filter((x) => own.includes(x.v.path));
  // The host names keys of its own and none is protected: not the agent's decision.
  if (own.length && !mine.length) return { ok: true, keys: [] };
  const relevant = mine.length ? mine : vaults;
  const keys = relevant.map((x) => x.v.path);
  const names = keys.map(short).join(", ");
  const answering = await (opt.answering ?? (async () => !!(await listIdentities(agentPaths.sock(), 1500))))();
  if (!answering) return { ok: false, keys, why: `vswarm agent is not running, and ${names} ${keys.length > 1 ? "are" : "is"} only there`, todo: "start it: vswarm agent on · vswarm doctor shows why it stopped" };
  const verdict = await (opt.verdict ?? (() => verdictNow({ quiet: true, silent: true, maxAge: AGENT_MAX_AGE })))();
  if (verdict === "block") {
    const { lock } = await lockState().catch(() => ({ lock: undefined }));
    return lock
      ? { ok: false, keys, why: `incident ${lock.incident} is open, so ${names} cannot sign`, todo: "vswarm unlock once the machine is clean (after vswarm respond)" }
      : { ok: false, keys, why: `this machine does not pass preflight, so ${names} cannot sign`, todo: "see why and how to fix it: vswarm why" };
  }
  if (verdict === "warn") {
    const global = await (opt.policy ?? (async () => (await readPolicy()).warn))();
    let wk: Buffer | undefined;
    try {
      wk = await wrapKey();
    } catch {}
    const pols = await Promise.all(relevant.map(async (x) => (wk ? keyPolicyOf(await openVault(x.v, wk).catch(() => ({}) as VaultInside)) : "refuse") as KeyPolicy));
    if (pols.every((p) => effective(p, global) === "refuse")) {
      const ownRefuse = relevant.filter((_, i) => pols[i] === "refuse").map((x) => short(x.v.path));
      return {
        ok: false, keys,
        why: ownRefuse.length ? `preflight warns, and ${ownRefuse.join(", ")} sign${ownRefuse.length > 1 ? "" : "s"} on PASS only` : "preflight warns, and the policy refuses WARN",
        todo: `see why: vswarm why · ${ownRefuse.length ? `let ${ownRefuse.length > 1 ? "them" : "it"} sign on WARN: ${ownRefuse.map((k) => `vswarm agent policy ${k} --allow-warn`).join(" ; ")}` : "let WARN through: vswarm policy warn allow"}`,
      };
    }
  }
  return { ok: true, keys };
}

/** For `vswarm why`: protected keys with a WARN setting of their own, one line each, with the way back to the policy. */
export async function keyOverrides(): Promise<string[]> {
  const vaults = listVaults();
  if (!vaults.length) return [];
  let wk: Buffer;
  try {
    wk = await wrapKey();
  } catch (e: any) {
    return [`protected keys: ${e?.message ?? e}`];
  }
  const out: string[] = [];
  for (const { v } of vaults) {
    const p = keyPolicyOf(await openVault(v, wk).catch(() => ({}) as VaultInside));
    if (p === "inherit") continue;
    out.push(`key ${short(v.path)} ${p === "allow" ? "signs on WARN" : "signs on PASS only"}, whatever the policy · follow the policy: vswarm agent policy ${short(v.path)} --inherit`);
  }
  return out;
}

const jobFile = (home: string) => (WIN ? winTaskFile() : process.platform === "darwin" ? plistPath(home) : unitPath(home));
export const agentInstalled = (home = homedir()) => existsSync(jobFile(home));

/**
 * The background job, as this vswarm sees it. The LaunchAgent or unit is the user's, whatever VSWARM_HOME says: one
 * that runs another vswarm's launcher is not this one's, and status says so instead of calling it installed.
 */
export function agentJob(home = homedir(), launcher = ownLauncher()): { installed: boolean; note?: string } {
  const file = jobFile(home);
  const text = readText(file);
  if (text === undefined) return { installed: false };
  if (!process.env.VSWARM_HOME) return { installed: true };
  const ours = text.includes(WIN ? xml(`"${launcher}"`).replace(/"/g, "&quot;") : process.platform === "darwin" ? `<string>${xml(launcher)}</string>` : unitWord(launcher));
  return ours ? { installed: true, note: `${short(file)}${GLOBAL_TAG()}` } : { installed: false, note: `${short(file)} runs another vswarm, not this VSWARM_HOME's${GLOBAL_TAG()}` };
}

async function serviceOn(launcher: string) {
  const sid = WIN ? /"(S-1-[0-9-]+)"/.exec((await run(["whoami", "/user", "/fo", "csv", "/nh"], 10_000)) ?? "")?.[1] : undefined;
  for (const [path, text] of Object.entries(agentJobFiles(launcher, homedir(), process.platform, sid))) {
    const first = !existsSync(path);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
    recordManagedFile(text);
    line(`${c.green("✔")} ${path.replace(homedir(), "~")}${c.dim(GLOBAL_TAG())}`);
    const note = first ? backgroundItemNote() : undefined;
    if (note) line(c.dim(`  ${note}`));
  }
  if (process.platform === "darwin") {
    const uid = process.getuid?.() ?? 501;
    const job = `gui/${uid}/${LABEL}`;
    await run(["launchctl", "bootout", job], 10_000);
    // bootout returns before launchd has let go of the job, and a bootstrap in that window fails (error 5) and
    // leaves no agent at all: wait for the old job to go, and try the bootstrap again while it is still going.
    for (let i = 0; i < 25 && (await run(["launchctl", "print", job], 5_000)) !== undefined; i++) await Bun.sleep(200);
    for (let i = 0; i < 5 && (await run(["launchctl", "bootstrap", `gui/${uid}`, plistPath()], 10_000)) === undefined; i++) await Bun.sleep(500);
  } else if (WIN) {
    const a = winAgentAction(launcher);
    recordManagedFile(`${a.execute} ${a.args}`);
    await winTaskStop();
    const r = await ps(`Register-ScheduledTask ${WIN_TASK_ARGS} -Xml ([IO.File]::ReadAllText($env:VSWARM_TASK_XML)) -Force | Out-Null; Start-ScheduledTask ${WIN_TASK_ARGS}`, { VSWARM_TASK_XML: winTaskFile() });
    if (r.code !== 0) throw new Error(`could not register the scheduled task: ${r.err.trim().split("\n")[0] || `exit ${r.code}`}`);
  } else {
    await run(["systemctl", "--user", "daemon-reload"], 10_000);
    await run(["systemctl", "--user", "enable", "--now", "vswarm-agent.service"], 10_000);
  }
  // Report a start that did not happen, instead of a login refused later for "agent is not running".
  for (let i = 0; i < 25; i++) {
    if (await listIdentities(agentPaths.sock(), 1000)) return;
    await Bun.sleep(200);
  }
  line(`${c.red("✖")} vswarm agent did not start ${c.dim(`· ${short(agentPaths.dir())}/agent.log says why · try again: vswarm agent on`)}`);
}

const WIN_TASK_ARGS = `-TaskPath '${WIN_AGENT_TASK.path}' -TaskName '${WIN_AGENT_TASK.name}'`;

/** PowerShell with its inputs in environment variables: nothing from a path is parsed as code. */
const ps = (script: string, env: Record<string, string> = {}) =>
  exec([powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], { env: { ...process.env, ...env }, timeoutMs: 30_000 });

/**
 * Stops the task and waits until its agent no longer answers, so the next one can own the pipe. Stopping the task
 * ends what it started; an agent that still answers after that (started by hand, or left over) is ended by its
 * command line, which names this vswarm's cli.ts.
 */
async function winTaskStop() {
  await ps(`Stop-ScheduledTask ${WIN_TASK_ARGS} -ErrorAction SilentlyContinue`);
  const gone = async () => {
    for (let i = 0; i < 25; i++) {
      if (!(await listIdentities(agentPaths.sock(), 500))) return true;
      await Bun.sleep(200);
    }
    return false;
  };
  if (await gone()) return;
  const { CLI } = await import("../setup");
  await ps(`Get-CimInstance Win32_Process -Filter "Name = 'bun.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($env:VSWARM_CLI) -and $_.CommandLine -match ' agent run' -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`, { VSWARM_CLI: CLI });
  await gone();
}

export async function agentOff(home = homedir()): Promise<string[]> {
  const gone: string[] = [];
  if (WIN) {
    await winTaskStop();
    const r = await ps(`$t = Get-ScheduledTask ${WIN_TASK_ARGS} -ErrorAction SilentlyContinue; if ($t) { $t | Unregister-ScheduledTask -Confirm:$false; 'gone' }`);
    if (r.out.includes("gone")) gone.push(`Task Scheduler ${WIN_AGENT_TASK.path}${WIN_AGENT_TASK.name}`);
    if (existsSync(winTaskFile())) (rmSync(winTaskFile()), gone.push(winTaskFile()));
  } else if (process.platform === "darwin") {
    await run(["launchctl", "bootout", `gui/${process.getuid?.() ?? 501}/${LABEL}`], 10_000);
    if (existsSync(plistPath(home))) (rmSync(plistPath(home)), gone.push(plistPath(home)));
  } else {
    await run(["systemctl", "--user", "disable", "--now", "vswarm-agent.service"], 10_000);
    if (existsSync(unitPath(home))) (rmSync(unitPath(home)), gone.push(unitPath(home)));
    await run(["systemctl", "--user", "daemon-reload"], 10_000);
  }
  const cfg = join(home, ".ssh", "config");
  if (existsSync(cfg) && readFileSync(cfg, "utf8").includes(AGENT_START) && setAgentBlock(cfg, null).changed) gone.push(`the IdentityAgent block in ${cfg}`);
  return gone;
}

/** For doctor: how the agent stands, one line each. */
export async function agentDoctor(): Promise<{ level: "ok" | "warn" | "bad" | "off"; text: string; detail?: string }[]> {
  const vaults = listVaults();
  const job = agentJob();
  const installed = job.installed;
  const answering = mayAnswer(agentPaths.sock()) ? await listIdentities(agentPaths.sock(), 2000) : undefined;
  const out: { level: "ok" | "warn" | "bad" | "off"; text: string; detail?: string }[] = [];
  if (!installed && !vaults.length) return [{ level: "off", text: t("cli.agentDoc.off"), detail: `vswarm agent protect <key> · vswarm agent on${job.note ? ` · ${job.note}` : ""}` }];
  if (answering) out.push({ level: "ok", text: t("cli.agentDoc.running"), detail: `${agentPaths.sock()} · ${t("cli.agentDoc.keys", { n: vaults.length })}` });
  else out.push({ level: vaults.length ? "bad" : "warn", text: t("cli.agentDoc.down"), detail: vaults.length ? t("cli.agentDoc.downKeys", { n: vaults.length }) : "vswarm agent on" });
  if (vaults.length) {
    try {
      await wrapKey();
    } catch (e: any) {
      out.push({ level: "bad", text: t("cli.agentDoc.cannotOpen"), detail: String(e?.message ?? e) });
    }
  }
  // An IdentityFile that names a .pub: ssh reads it as the private key whenever the agent is not used.
  const cfgText = readText(join(homedir(), ".ssh", "config")) ?? "";
  const named = new Set(blocks(cfgText).flatMap((b) => b.options.filter((o) => o.key === "identityfile").map((o) => expandPath(o.value))));
  for (const { v } of vaults)
    if (named.has(`${v.path}.pub`))
      out.push({ level: "warn", text: `~/.ssh/config names ${short(v.path)}.pub as an IdentityFile`, detail: `ssh reads it as a private key when the agent is not used ("UNPROTECTED PRIVATE KEY FILE"); write IdentityFile ${short(v.path)}, and ssh finds the .pub beside it` });
  // A block written by 2.7 or earlier: no check before each login, so a refusal still ends in a password prompt, and
  // the running agent is the old code until agent on restarts it.
  if (cfgText.includes(AGENT_START) && !cfgText.includes("agent check"))
    out.push({ level: "warn", text: "the agent's block in ~/.ssh/config is from an older vswarm", detail: "vswarm agent on refreshes it and restarts the agent, so the shared WARN policy and the clear refusal apply" });
  for (const l of leftOnDisk()) out.push({ level: "warn", text: `a file is still at ${short(l.path)}, though that key is in the vault`, detail: `protect did not finish removing it · vswarm agent protect ${short(l.path)} finishes` });
  const audit = await readAudit();
  if (audit.notice) out.push({ level: "warn", text: "the agent's audit log started again", detail: audit.notice });
  if (audit.why) out.push({ level: "bad", text: `the agent's audit log ${audit.why}`, detail: `${agentPaths.dir()} · treat this machine as suspect: vswarm respond` });
  return out;
}

/** For uninstall: the service and config block go; --purge is refused while keys are protected (it would delete them). */
export async function agentUninstall(purge: boolean): Promise<string[]> {
  const vaults = listVaults();
  if (purge && vaults.length)
    throw new Error(`${vaults.length} ssh key${vaults.length > 1 ? "s are" : " is"} protected by vswarm agent; --purge would delete ${vaults.length > 1 ? "them" : "it"}. Put ${vaults.length > 1 ? "them" : "it"} back first: ${vaults.map((x) => `vswarm agent unprotect ${x.v.path}`).join(" ; ")}`);
  const cfg = join(homedir(), ".ssh", "config");
  const routed = existsSync(cfg) && readFileSync(cfg, "utf8").includes(AGENT_START);
  const gone = agentInstalled() || routed ? await agentOff() : [];
  if (purge) await (await activeStore()).store.remove(WRAP_NAME).catch(() => {});
  return gone;
}

// ── the command

export interface AgentCommandOpt {
  confirm: boolean;
  /** WARN signs with this protected key (protect, policy). */
  allowWarn: boolean;
  /** WARN refuses with this protected key (protect, policy). */
  strict: boolean;
  /** policy: the key follows the shared policy again (vswarm policy). */
  inherit?: boolean;
  global: boolean;
  upstream?: string;
  /** Seconds the upstream agent may take over a signature (agent on). */
  upstreamTimeout?: number;
  life?: number;
  /** agent on: keep password logins for the routed hosts; offer every agent key, not only the configured ones. */
  allowPasswords?: boolean;
  allKeys?: boolean;
  /** protect: go on although the machine's verdict would make the key refuse; skip the test logins. */
  anyway?: boolean;
  noVerify?: boolean;
  /** protect: hosts to test the key on, besides those ~/.ssh/config names it for. check: the host ssh connects to. */
  host?: string;
  hostname?: string;
  port?: number;
  ask: (q: string, o?: { secret?: boolean }) => Promise<string>;
  /** A yes/no question (default no). */
  yes?: (q: string, def?: boolean) => Promise<boolean>;
}

interface AgentConfig {
  upstream?: string;
  /** Seconds; see UPSTREAM_SIGN_TIMEOUT. */
  upstreamTimeout?: number;
  /** agent on --allow-passwords / --all-keys, kept for the next agent on (protect runs it too). */
  allowPasswords?: boolean;
  allKeys?: boolean;
}

const short = (p: string) => p.replace(homedir(), "~");

/** Said once, the first time a LaunchAgent is installed: macOS announces it, and that is this. */
export function backgroundItemNote(platform = process.platform): string | undefined {
  return platform === "darwin" ? t("cli.bg.mac") : undefined;
}

/**
 * Routes `hosts` to the agent (or keeps the hosts already routed when none are given), with the check before each
 * login and every protected key named. Starts the service when `service` is set. Returns the hosts routed.
 */
export async function agentOn(hosts: string[], opt: { home?: string; launcher?: string[]; service?: boolean; allowPasswords?: boolean; allKeys?: boolean; say?: (t: string) => void } = {}): Promise<{ hosts: string[]; backup?: string; changed: boolean }> {
  const say = opt.say ?? line;
  const home = opt.home ?? homedir();
  const cfgPath = join(home, ".ssh", "config");
  const cfg = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "";
  const saved: AgentConfig = { ...readJson<AgentConfig>(agentPaths.config()) };
  const flags = { allowPasswords: opt.allowPasswords ?? saved.allowPasswords, allKeys: opt.allKeys ?? saved.allKeys };
  if (opt.allowPasswords !== undefined || opt.allKeys !== undefined) {
    safeDir(agentPaths.dir());
    writeFileSync(agentPaths.config(), JSON.stringify({ ...saved, ...flags }, null, 1) + "\n", { mode: 0o600 });
  }
  const want = [...new Set(hosts.length ? hosts : agentHosts(cfg).length ? agentHosts(cfg) : gatedHosts(cfg))];
  if (!want.length) return { hosts: [], changed: false };
  const keys = listVaults().map((x) => x.v.path);
  const r = setAgentBlock(cfgPath, agentSshBlock(want, agentPaths.sock(), { launcher: opt.launcher, keys, ...flags }));
  if (r.changed) say(`${c.green("✔")} ${want.join(", ")} take their keys from vswarm agent ${c.dim(`(${short(cfgPath)}: IdentityAgent, ${keys.length} protected key${keys.length === 1 ? "" : "s"}, a check before each login${flags.allowPasswords ? "" : ", no password prompts"})`)}`);
  return { hosts: want, backup: r.backup, changed: r.changed };
}

// ── protect, with proof first

export interface ProtectDeps {
  home: string;
  /** The ssh config protect reads (default <home>/.ssh/config). */
  cfgPath?: string;
  /** Extra ssh options for every test login (tests: a throwaway known_hosts). */
  sshOpts?: string[];
  verdict?: () => Promise<Verdict>;
  policy?: () => Promise<WarnPolicy>;
  /** Routes the hosts and starts the agent (default: agent on, with the service); returns the socket to test through. */
  agentOn?: (hosts: string[]) => Promise<string>;
  env?: Record<string, string | undefined>;
  say?: (t: string) => void;
  yes: (q: string, def?: boolean) => Promise<boolean>;
}

const exists = (p: string) => existsSync(p) && statSync(p).isFile();

/** What `ssh -G` says a host uses: identity files (as written, expanded), and the HostName and Port. */
export async function sshResolve(host: string, cfgPath: string, env?: Record<string, string | undefined>): Promise<{ identityFiles: string[]; hostname?: string; port?: number } | undefined> {
  const r = await exec(["ssh", "-G", "-F", cfgPath, host], { env, timeoutMs: 20_000 }).catch(() => undefined);
  if (!r || r.code !== 0) return;
  const kv = r.out.split("\n").map((l) => /^(\S+)\s+(.*)$/.exec(l.trim())).filter(Boolean) as RegExpExecArray[];
  return {
    identityFiles: kv.filter((m) => m[1] === "identityfile").map((m) => resolve(m[2].replace(/^~(?=\/)/, homedir()))),
    hostname: kv.find((m) => m[1] === "hostname")?.[2],
    port: Number(kv.find((m) => m[1] === "port")?.[2]) || undefined,
  };
}

/** One test login: `true` on the host, with exactly this key (and through the agent at `agent`, when given). */
export async function testLogin(host: string, key: string, deps: Pick<ProtectDeps, "cfgPath" | "sshOpts" | "env" | "home">, agent?: string): Promise<{ ok: boolean; refused: boolean; why: string }> {
  const encrypted = !agent && keyEncrypted(readText(key, 64_000) ?? "") === true;
  const cmd = [
    "ssh", "-F", deps.cfgPath ?? join(deps.home, ".ssh", "config"),
    // A key with a passphrase asks for it on this terminal; nothing else may ask: no server passwords.
    ...(encrypted ? ["-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"] : ["-o", "BatchMode=yes"]),
    "-o", `IdentityAgent=${agent ? sshAgentPath(agent) : "none"}`, "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
    ...(agent ? ["-o", `IdentityFile=${key}`] : ["-i", key]),
    ...(deps.sshOpts ?? []), host, "true",
  ];
  const r = await exec(cmd, { env: deps.env, timeoutMs: 60_000, tty: encrypted }).catch((e: any) => ({ code: 255, out: "", err: String(e?.message ?? e) }));
  const err = (r.err ?? "").trim().split("\n").filter((l) => !/^(Warning: Permanently added|vswarm)/.test(l)).at(-1) ?? "";
  return { ok: r.code === 0, refused: /Permission denied/.test(r.err ?? ""), why: r.code === 0 ? "" : err || `ssh exit ${r.code}` };
}

/**
 * `vswarm agent protect <key>`, the whole of it: the machine is checked first; the hosts that use the key are found
 * and the key is tried on them while its file is still on disk; only then is it moved into the vault; then the hosts
 * are routed to the agent and tried again through it. Nothing is removed until a host accepted the key, unless
 * --no-verify. The test logins are your own logins to your own hosts, made only here, when you run protect.
 */
export async function protectFlow(file: string, opt: { confirm?: boolean; policy?: KeyPolicy; anyway?: boolean; noVerify?: boolean; hosts?: string[] }, deps: ProtectDeps): Promise<Protected | undefined> {
  const say = deps.say ?? line;
  const path = resolve(file);
  const cfgPath = deps.cfgPath ?? join(deps.home, ".ssh", "config");
  if (listVaults().some((x) => x.v.path === path)) return protect(file, { confirm: opt.confirm, policy: opt.policy, env: deps.env });
  if (!exists(path)) throw new Error(`no key file at ${path}`);
  if (path.endsWith(".pub")) throw new Error(`${path} is a public key; name the private key file`);

  // 1 · the machine: a key that would refuse to sign right away is not worth taking off the disk.
  say(`${c.bold(`1  ${t("cli.protect.s1")}`)} ${c.dim(`· ${t("cli.protect.s1sub")}`)}`);
  const verdict = await (deps.verdict ?? (() => verdictNow({ quiet: true, fresh: true })))();
  const global = await (deps.policy ?? (async () => (await readPolicy()).warn))();
  const keyPol = opt.policy ?? "inherit";
  const refuses = verdict === "block" || (verdict === "warn" && effective(keyPol, global) === "refuse");
  if (refuses) {
    const why = verdict === "block" ? t("cli.protect.whyBlock") : t("cli.protect.whyWarn", { by: keyPol === "refuse" ? "--strict" : t("cli.protect.thePolicy") });
    if (!opt.anyway) {
      say(c.amber(`  ! ${t("cli.protect.wouldRefuse", { why })}`));
      say(c.dim(`  ${t("cli.protect.anyway", { key: short(path) })}`));
      return;
    }
    say(c.amber(`  ! ${t("cli.protect.goingOn", { why })}`));
  } else say(`  ${c.green("✔")} ${t(verdict === "pass" ? "cli.protect.wouldSign" : "cli.protect.wouldSignWarn")}`);

  // 2 · the hosts that use it, as ssh itself resolves each Host.
  say(`\n${c.bold(`2  ${t("cli.protect.s2")}`)} ${c.dim(`· ${t("cli.protect.s2sub", { file: short(cfgPath) })}`)}`);
  const text = readText(cfgPath) ?? "";
  const { gate, agent } = ownHosts(text);
  const production = [...gate, ...agent].filter(literal);
  const candidates = [...new Set([...namedHosts(text), ...production, ...(opt.hosts ?? [])])];
  const hosts: string[] = [];
  for (const h of candidates) {
    const g = await sshResolve(h, cfgPath, deps.env);
    if (!g) continue;
    // ssh -G lists the default keys for a host that names none: those count only for the hosts you named or gated,
    // never for every Host in the file (github.com is not yours to test against).
    const explicit = hostView(text, h, { home: deps.home, withoutOwn: true }).identityFiles;
    const named = explicit.some((f) => f === path || f === `${path}.pub`);
    if (explicit.includes(`${path}.pub`))
      say(c.amber(`  ! ${t("cli.protect.namesPub", { host: h, key: short(path) })}`));
    if (named || ((production.includes(h) || opt.hosts?.includes(h)) && g.identityFiles.includes(path))) hosts.push(h);
  }
  if (hosts.length) say(`  ${hosts.join(", ")}`);
  else say(c.dim(`  ${t(opt.hosts?.length ? "cli.protect.noHostsGiven" : "cli.protect.noHosts", { file: short(cfgPath), key: short(path) })}`));

  // 3 · try it while the file is still here.
  say(`\n${c.bold(`3  ${t("cli.protect.s3")}`)} ${c.dim(`· ${t("cli.protect.s3sub")}`)}`);
  const accepted: string[] = [];
  if (opt.noVerify) say(c.dim(`  ${t("cli.protect.skipped")}`));
  for (const h of opt.noVerify ? [] : hosts) {
    let tl = await testLogin(h, path, { ...deps, cfgPath });
    if (!tl.ok && tl.refused) {
      say(c.amber(`  ! ${t("cli.protect.refused", { host: h })}`));
      const g = await sshResolve(h, cfgPath, deps.env);
      // A key the server already takes, to put this one next to it.
      let other: string | undefined;
      for (const k of (g?.identityFiles ?? []).filter((k) => k !== path && exists(k)))
        if ((await testLogin(h, k, { ...deps, cfgPath })).ok) {
          other = k;
          break;
        }
      const copy = ["ssh-copy-id", "-F", cfgPath, "-o", "IdentityAgent=none", "-o", `IdentityFile=${other ?? "<a key the server already accepts>"}`, ...(deps.sshOpts ?? []), "-i", `${path}.pub`, h];
      if (other && (await deps.yes(t("cli.protect.copyAsk", { key: short(path), host: h, other: short(other), cmd: copy.join(" ") }), false))) {
        const r = await exec(copy, { env: deps.env, tty: true, timeoutMs: 120_000 }).catch(() => ({ code: 1 }));
        if (r.code === 0) tl = await testLogin(h, path, { ...deps, cfgPath });
      } else say(c.dim(`  ${t("cli.protect.toAdd", { cmd: copy.map((w) => (/\s/.test(w) ? shq(w) : w)).join(" ") })}`));
    }
    if (tl.ok) {
      accepted.push(h);
      say(`  ${c.green("✔")} ${t("cli.protect.accepts", { host: h })}`);
    } else if (!tl.refused) say(c.amber(`  ! ${h}: ${tl.why}`));
  }
  if (!opt.noVerify && !accepted.length) {
    say(c.amber(`\n  ! ${t("cli.protect.noneAccepted", { key: short(path) })}`));
    say(c.dim(`  ${t("cli.protect.nameHost", { key: short(path) })}`));
    return;
  }

  // 4 · into the vault, the hosts to the agent, and the same login again through it.
  say(`\n${c.bold(`4  ${t("cli.protect.s4")}`)} ${c.dim(`· ${t("cli.protect.s4sub")}`)}`);
  const r = await protect(file, { confirm: opt.confirm, policy: opt.policy, env: deps.env });
  const routed = accepted.length ? accepted : hosts;
  if (routed.length && deps.agentOn) {
    const sock = await deps.agentOn(routed);
    for (const h of accepted) {
      // The agent reads its vault folder again on each request; a moment for it to start, the first time.
      let tl = await testLogin(h, path, { ...deps, cfgPath }, sock);
      for (let i = 0; i < 10 && !tl.ok && !tl.refused; i++) (await Bun.sleep(500), (tl = await testLogin(h, path, { ...deps, cfgPath }, sock)));
      if (tl.ok) say(`  ${c.green("✔")} ${t("cli.protect.acceptsAgent", { host: h })}`);
      else say(c.red(`  ✖ ${t("cli.protect.agentFailed", { host: h, why: tl.why, key: short(path) })}`));
    }
  }
  return r;
}


/**
 * `vswarm agent protect <key>` and `vswarm setup`'s offer for each production key: protectFlow, then what came of it,
 * with the recovery code shown once. `deps` replaces parts of the real thing (tests: a throwaway sshd and agent).
 * True when the key is in the vault.
 */
export async function protectKey(file: string, opt: Parameters<typeof protectFlow>[1], deps: Partial<ProtectDeps> & Pick<ProtectDeps, "yes">): Promise<boolean> {
  const sock = agentPaths.sock();
  const path = resolve(file);
  const say = deps.say ?? line;
  const launcher = ownLauncher();
  const r = await protectFlow(file, opt, {
    home: homedir(),
    agentOn: async (hosts) => {
      (await import("../setup")).ensureLauncher((t) => say(t));
      if (!agentInstalled() || !(await listIdentities(sock, 1500))) {
        safeDir(agentPaths.dir());
        await serviceOn(launcher);
      }
      await agentOn([...new Set([...agentHosts(readText(join(homedir(), ".ssh", "config")) ?? ""), ...hosts])], { launcher: [launcher] });
      return sock;
    },
    ...deps,
  });
  if (!r) return false;
  if (r.finished) {
    say(`${c.green("✔")} ${t("cli.protect.finished", { key: short(path) })} ${c.dim(r.fp)}`);
    return true;
  }
  const how = opt.policy === "allow" ? t("cli.protect.signsWarn") : opt.policy === "refuse" ? t("cli.protect.signsPass") : t("cli.protect.follows");
  say(`${c.green("✔")} ${t("cli.protect.inVault", { key: short(path) })} ${c.dim(`${r.fp} · ${how}`)}`);
  if (!r.left) say(`${c.green("✔")} ${t(r.pubWritten ? "cli.protect.removedPubWritten" : "cli.protect.removedPubStays", { key: short(path) })}`);
  say(`${c.green("✔")} ${t("cli.protect.backup", { file: short(r.backup) })}`);
  say(`\n      ${c.bold(r.code)}\n`);
  say(c.amber(`  ${t("cli.protect.codeWhere")}`));
  if (r.left) say(c.amber(`  ! ${t("cli.protect.left", { why: r.left, key: short(path) })}`));
  say(c.dim(`  ${t("cli.protect.restore", { backup: short(r.backup), key: short(path) })}`));
  const up = resolveUpstream();
  const there = up ? await listIdentities(up, 3000) : undefined;
  if (there?.some((i) => fingerprint(i.blob) === r.fp)) say(c.amber(`  ! ${t("cli.protect.alsoLoaded", { key: short(path) })}`));
  if (!deps.agentOn && !(await listIdentities(sock, 2000))) say(c.dim(`  ${t("cli.protect.nextOn")}`));
  say(c.dim(`  ${t("cli.protect.copies")}`));
  return true;
}

export async function agentCommand(action: string, args: string[], opt: AgentCommandOpt) {
  const sock = agentPaths.sock();
  if (action === "run") {
    const t = readJson<AgentConfig>(agentPaths.config())?.upstreamTimeout;
    // Task Scheduler keeps no output (launchd and systemd do): on Windows the agent writes its log itself.
    const say = WIN ? (s: string) => { try { appendFileSync(agentPaths.log(), s.replace(/\x1b\[[0-9;]*m/g, "") + "\n"); } catch {} } : (s: string) => line(s);
    const a = await startAgent({ sock, log: say, upstream: resolveUpstream(), upstreamSignTimeout: Number.isInteger(t) && t! > 0 ? t! * 1000 : undefined });
    const up = resolveUpstream();
    say(`vswarm agent listening on ${a.sock} · ${a.held().length} protected key${a.held().length === 1 ? "" : "s"} · ${up ? `other keys from ${up}` : "no upstream agent"}`);
    const stop = () => {
      a.stop();
      process.exit(0);
    };
    process.on("SIGTERM", stop);
    process.on("SIGINT", stop);
    return new Promise<never>(() => {});
  }

  if (action === "check") {
    // Run by ssh (Match exec in the agent block): exit 0 lets the login go on, anything else ends it with the reason.
    // Windows leaves the names out when a pattern has wildcards (see agentSshBlock).
    const host = opt.host ?? args[0] ?? "";
    if (!host && !WIN) throw new Error("usage: vswarm agent check --host <name> [--hostname <address>] [--port <n>]   (ssh runs this from the agent block)");
    const r = await agentCheck(host, { hostname: opt.hostname, port: opt.port });
    if (r.ok) return;
    line(`${c.red("✖ vswarm agent:")} ${host ? `ssh to ${host}` : "ssh"} refused: ${r.why}`);
    if (r.todo) line(`  ${c.cyan("→")} ${r.todo}`);
    await appendAudit("refuse", r.keys.map((k) => listVaults().find((x) => x.v.path === k)?.v.fp ?? k).join(","), `${r.why} · ssh${host ? ` to ${host}` : ""}, stopped before connecting`).catch(() => {});
    process.exitCode = 1;
    return;
  }

  if (action === "on") {
    const launcher = (await import("../setup")).ensureLauncher((t) => line(t));
    if (opt.upstream !== undefined || opt.upstreamTimeout !== undefined) {
      if (opt.upstream !== undefined && opt.upstream !== "none" && same(opt.upstream, sock)) throw new Error("--upstream names this agent itself");
      safeDir(agentPaths.dir());
      const cfg: AgentConfig = { ...readJson<AgentConfig>(agentPaths.config()) };
      if (opt.upstream !== undefined) cfg.upstream = opt.upstream;
      if (opt.upstreamTimeout !== undefined) cfg.upstreamTimeout = opt.upstreamTimeout;
      writeFileSync(agentPaths.config(), JSON.stringify(cfg, null, 1) + "\n", { mode: 0o600 });
    }
    safeDir(agentPaths.dir());
    await serviceOn(launcher);
    const cfgPath = join(homedir(), ".ssh", "config");
    const r = opt.global ? { hosts: [] as string[] } : await agentOn(args, { launcher: [launcher], allowPasswords: opt.allowPasswords || undefined, allKeys: opt.allKeys || undefined });
    if (r.hosts.length) {
      if (!("changed" in r) || !r.changed) line(`${c.green("✔")} ${r.hosts.join(", ")} take their keys from vswarm agent ${c.dim(`(already in ${short(cfgPath)})`)}`);
      if ("backup" in r && r.backup) line(c.dim(`  backup ${r.backup}`));
      const cfg = readJson<AgentConfig>(agentPaths.config()) ?? {};
      if (!cfg.allowPasswords) line(c.dim("  a key the agent refuses ends in \"Permission denied\" for these hosts, never a password prompt · hosts that need a password: agent on --allow-passwords"));
      if (!cfg.allKeys) line(c.dim("  ssh offers only the protected keys and each host's own IdentityFile · keys that live only in another agent: agent on --all-keys"));
    } else {
      line(c.dim(`  ${opt.global ? "" : "no host patterns given and no ssh gate to take them from; "}to send every ssh client through the agent, in your shell's rc file:`));
      line(WIN ? `    [Environment]::SetEnvironmentVariable('SSH_AUTH_SOCK', '${sock}', 'User')   ${c.dim("(PowerShell, once; new terminals use it)")}` : `    export SSH_AUTH_SOCK=${JSON.stringify(sock)}`);
      line(c.dim(`  or per host in ~/.ssh/config:  IdentityAgent "${sshAgentPath(sock)}"`));
    }
    line(c.dim(`  keys it does not hold go to ${resolveUpstream() ?? "no other agent (none found in SSH_AUTH_SOCK)"} · vswarm agent status · vswarm agent off`));
    if (!listVaults().length) line(c.dim("  next: vswarm agent protect ~/.ssh/<production key>"));
    return;
  }

  if (action === "off") {
    await (await import("./human")).weaken("agent", ["off"]);
    for (const g of await agentOff()) line(`${c.green("✔")} removed ${short(g)}`);
    const n = listVaults().length;
    if (n) line(c.amber(`  ${n} protected key${n > 1 ? "s stay" : " stays"} in the vault and cannot sign until vswarm agent on · put ${n > 1 ? "them" : "it"} back: vswarm agent unprotect <key>`));
    return;
  }

  if (action === "status") {
    const ids = mayAnswer(sock) ? await listIdentities(sock, 2000) : undefined;
    const job = agentJob();
    line(ids ? `${c.green("●")} agent running ${c.dim(sock)}` : `${c.dim("○")} agent not running ${c.dim(job.installed ? "(installed; see " + agentPaths.log() + ")" : "· vswarm agent on")}`);
    if (job.note) line(c.dim(`  ${job.note}`));
    line(c.dim(`  other keys from: ${resolveUpstream() ?? "none"}`));
    const cfgPath = join(homedir(), ".ssh", "config");
    const cfgText = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "";
    const block = cfgText.match(blockRegex(AGENT_START, AGENT_END))?.[0];
    const hosts = agentHosts(cfgText);
    const elsewhere = block && !block.includes(`"${sshAgentPath(sock)}"`) ? " (to another vswarm's agent)" : "";
    line(c.dim(`  hosts routed here by ~/.ssh/config${GLOBAL_TAG()}: ${hosts.length ? hosts.join(", ") + elsewhere : "none"}`));
    const global = (await readPolicy()).warn;
    line(c.dim(`  policy: WARN ${global === "allow" ? "allowed" : "refused"} · vswarm policy`));
    const vaults = listVaults();
    if (!vaults.length) line(c.dim("  no protected keys · vswarm agent protect <key file>"));
    let wk: Buffer | undefined;
    try {
      if (vaults.length) wk = await wrapKey();
    } catch {}
    for (const { v } of vaults) {
      const inside = wk ? await openVault(v, wk).catch(() => undefined) : undefined;
      const kp = inside ? keyPolicyOf(inside) : undefined;
      const policy = inside ? `${kp === "inherit" ? `follows the policy (WARN ${global === "allow" ? "signs" : "refuses"})` : kp === "allow" ? "WARN signs (this key)" : "PASS only (this key)"}${inside.confirm ? " · confirm on use" : ""}` : "cannot be opened";
      line(`  ${c.cyan("key")} ${v.fp} ${c.dim(`${v.type} · ${v.comment} · ${policy} · was ${short(v.path)}`)}`);
      if (existsSync(v.path)) line(c.amber(`      ! a file is still at ${short(v.path)}: protect did not finish removing it · vswarm agent protect ${short(v.path)} finishes`));
    }
    if (ids) for (const i of ids.filter((i) => !vaults.some((x) => x.v.fp === fingerprint(i.blob)))) line(`  ${c.dim("    ")} ${fingerprint(i.blob)} ${c.dim(i.comment)}`);
    return;
  }

  if (action === "add") {
    const file = args[0];
    if (!file) throw new Error("usage: vswarm agent add <key file> [--confirm] [--life seconds]");
    if (!(await listIdentities(sock, 2000))) throw new Error("the agent is not running: vswarm agent on (or vswarm agent run in another terminal)");
    const cmd = ["ssh-add", ...(opt.confirm ? ["-c"] : []), ...(opt.life ? ["-t", String(opt.life)] : []), file];
    const p = Bun.spawn(cmd, { env: { ...process.env, SSH_AUTH_SOCK: sock }, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
    process.exitCode = await p.exited;
    if (!process.exitCode) line(c.dim("  held in memory until the agent restarts; it signs only while this machine passes · to keep it off the disk: vswarm agent protect"));
    return;
  }

  if (action === "protect") {
    const file = args[0];
    if (!file) throw new Error("usage: vswarm agent protect <key file> [--confirm] [--allow-warn | --strict] [--host a,b] [--anyway] [--no-verify]");
    const policy: KeyPolicy | undefined = opt.allowWarn ? "allow" : opt.strict ? "refuse" : undefined;
    if (!(await protectKey(file, { confirm: opt.confirm, policy, anyway: opt.anyway, noVerify: opt.noVerify, hosts: opt.host?.split(",").filter(Boolean) }, { yes: opt.yes ?? (async () => false) }))) process.exitCode = 1;
    return;
  }

  if (action === "policy") {
    const given = [opt.allowWarn, opt.strict, opt.inherit].filter(Boolean).length;
    if (!args[0] || given !== 1) throw new Error("usage: vswarm agent policy <key file | SHA256:fingerprint> --allow-warn | --strict | --inherit");
    const p: KeyPolicy = opt.allowWarn ? "allow" : opt.strict ? "refuse" : "inherit";
    if (p === "allow") await (await import("./human")).weaken("agent", ["policy", args[0], "--allow-warn"]);
    const r = await setKeyPolicy(args[0], p);
    line(`${c.green("✔")} ${short(r.path)} ${c.dim(r.fp)} ${p === "allow" ? "signs on PASS and WARN" : p === "refuse" ? "signs on PASS only; WARN refuses" : `follows the policy (WARN ${(await readPolicy()).warn === "allow" ? "signs" : "refuses"}; vswarm policy)`}`);
    return;
  }

  if (action === "prune") {
    const cfgPath = join(homedir(), ".ssh", "config");
    const { pruneHosts } = await import("./probe");
    const keep = await pruneHosts(agentHosts(readText(cfgPath) ?? ""), { cfgText: readText(cfgPath) ?? "", ask: opt.yes ?? (async () => false), what: "agent" });
    if (keep) await agentOn(keep, { launcher: [ownLauncher()] });
    return;
  }

  if (action === "unprotect") {
    if (!args[0]) throw new Error("usage: vswarm agent unprotect <key file | SHA256:fingerprint>");
    await (await import("./human")).weaken("agent", ["unprotect", args[0]]);
    const r = await unprotect(args[0]);
    line(`${c.green("✔")} ${short(r.path)} is back on disk ${c.dim(`${r.fp} · it no longer needs vswarm, and nothing checks the machine before it is used`)}`);
    return;
  }

  if (action === "restore") {
    if (!args[0]) throw new Error("usage: vswarm agent restore <key file>.vswarm-backup");
    const code = await opt.ask("recovery code:", { secret: true });
    if (!code) throw new Error("no recovery code given");
    const r = restore(args[0], code);
    line(`${c.green("✔")} ${short(r.path)} restored ${c.dim(r.fp)}`);
    if (listVaults().some((x) => x.v.fp === r.fp)) line(c.dim(`  the vault still holds it too; drop it with: vswarm agent unprotect ${r.fp}   (after moving ${short(r.path)} aside, or it refuses)`));
    return;
  }

  if (action === "log") {
    const { entries, why, notice } = await readAudit();
    if (notice) line(c.amber(`  ${notice}`));
    if (why) line(c.red(`  the audit log ${why}`));
    if (!entries.length) return line("no signatures yet");
    const word = (e: string) => (e === "sign" ? c.green("signed ") : e === "refuse" ? c.red("refused") : c.amber("restart"));
    for (const e of entries.slice(-30)) line(`  ${c.dim(new Date(e.at).toLocaleString())}  ${word(e.event)}  ${e.incident ?? ""}  ${c.dim(e.reason ?? "")}`);
    return;
  }

  throw new Error("usage: vswarm agent on [host patterns…] [--global] [--upstream path|none] [--upstream-timeout s] [--allow-passwords] [--all-keys] | off | status | protect <key> [--confirm] [--allow-warn | --strict] [--host a,b] [--anyway] [--no-verify] | policy <key> --allow-warn|--strict|--inherit | unprotect <key> | restore <backup> | add <key> [--confirm] [--life s] | prune | log | run");
}

/** For vswarm ui: each protected key's signing policy by fingerprint, read as agent status reads it; empty when the vault cannot be opened. */
export async function keyPolicies(): Promise<Record<string, { allowWarn: boolean; confirm: boolean }>> {
  const out: Record<string, { allowWarn: boolean; confirm: boolean }> = {};
  const vaults = listVaults();
  const wk = vaults.length ? await wrapKey().catch(() => undefined) : undefined;
  for (const { v } of wk ? vaults : []) {
    const inside = await openVault(v, wk).catch(() => undefined);
    if (inside) out[v.fp] = { allowWarn: inside.allowWarn === true, confirm: !!inside.confirm };
  }
  return out;
}
