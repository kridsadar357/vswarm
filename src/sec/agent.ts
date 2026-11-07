// `vswarm agent`: an SSH agent that holds your production keys and signs only while this machine passes.
//
// The ssh gate in ~/.ssh/config is advice to one client: `ssh -F /dev/null`, an IP address instead of the host name,
// VS Code Remote, a GUI client, paramiko or libssh2 never read it. The agent moves the control to the key. Once
// `vswarm agent protect ~/.ssh/prod_key` has run, that key exists only inside the agent's vault, and every signature
// with it is decided at the moment it is asked for: the sealed recent verdict, or a fresh quiet check, exactly as
// preflight decides (an open incident always blocks). Whatever program asks, by whatever route, gets
// SSH_AGENT_FAILURE from a machine that does not pass, and the refusal is logged and shown.
//
//   ~/.vswarm/agent/            0700, owned by you
//     agent.sock                the agent (draft-miller-ssh-agent), 0600
//     keys/<id>.json            protected keys: AES-256-GCM, the wrapping key in the Keychain / Secret Service / DPAPI
//     config.json               the upstream agent, when you named one (agent on --upstream)
//   ~/.vswarm/sec/audit.log     every signature and refusal, sealed and chained like the incident log
//   <key>.vswarm-backup         the original key file, encrypted with a recovery code printed once
//
// Keys the agent does not hold are passed to your usual agent (upstream) untouched, so git and other ssh keep
// working through the same socket. What this does not stop: a program running as you can ask the agent to sign while
// the machine passes, and could read the agent's memory. See docs/guide.md, "vswarm agent".

import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { HOME, paths } from "../home";
import { exec, readJson, run, type Ctx } from "./ctx";
import { verdictNow } from "./gate";
import { c, line } from "./print";
import { notify as desktopNotify } from "./schedule";
import { keyFromWire, fingerprint, parsePublicLine, publicLine, readPrivate, Reader, signedFor, signWith, Writer, type SignedFor, type SshKey } from "./sshkey";
import { appendAudit, blockRegex, keyStore, lockState, readAudit, recordManaged, recordManagedFile, removeBlock } from "./store";
import type { Verdict } from "./types";

export const agentPaths = {
  dir: () => process.env.VSWARM_AGENT_DIR ?? join(HOME, "agent"),
  sock: () => join(agentPaths.dir(), "agent.sock"),
  keys: () => join(agentPaths.dir(), "keys"),
  config: () => join(agentPaths.dir(), "config.json"),
  log: () => join(agentPaths.dir(), "agent.log"),
};

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
  const s = keyStore();
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
  strict: boolean;
}

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
  const sock = join(dir, "s");
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
  code: string;
  pubWritten: boolean;
}

/**
 * Moves a private key into the vault: read (by ssh-add), encrypted at rest, a backup encrypted with a recovery code,
 * both checked by opening them again, and only then the key file overwritten and removed. Its .pub stays (or is
 * written), so ssh still knows which agent key an IdentityFile means.
 */
export async function protect(keyfile: string, opt: { confirm?: boolean; strict?: boolean; env?: Record<string, string | undefined> } = {}): Promise<Protected> {
  const path = resolve(keyfile);
  if (!existsSync(path)) throw new Error(`no key file at ${path}`);
  const st = lstatSync(path);
  if (!st.isFile()) throw new Error(`${path} is not a plain file${st.isSymbolicLink() ? " (a symlink: protect the file it points to)" : ""}`);
  if (path.endsWith(".pub")) throw new Error(`${path} is a public key; name the private key file`);
  if (listVaults().some((x) => x.v.path === path)) throw new Error(`${path} is already protected · vswarm agent status`);
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
  const inside: VaultInside = { wire: k.wire.toString("base64"), original: original.toString("base64"), confirm: !!opt.confirm, strict: !!opt.strict };
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
  shred(path);
  return { fp, vault: file, backup, code, pubWritten };
}

/** Puts a protected key file back where it was, byte for byte, and removes its vault and backup. */
export async function unprotect(target: string): Promise<{ path: string; fp: string }> {
  const full = resolve(target);
  const hit = listVaults().find((x) => x.v.fp === target || x.v.path === full || x.v.path === full.replace(/\.pub$/, ""));
  if (!hit) throw new Error(`${target} is not a protected key · vswarm agent status lists them`);
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
  /** WARN refuses too (otherwise WARN signs, as preflight lets WARN through). */
  strict: boolean;
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
  ctx?: Ctx;
  offline?: boolean;
  notify?: (title: string, body: string) => Promise<void>;
  /** Asks you whether to allow one signature with a confirm-on-use key. */
  confirm?: (question: string) => Promise<boolean>;
  /** Load protected keys from the vault (default true). */
  vaults?: boolean;
  log?: (text: string) => void;
}

export interface Agent {
  sock: string;
  held(): { fp: string; comment: string; vault: boolean; confirm: boolean; strict: boolean }[];
  stop(): void;
}

/** Whether `p` names the same socket as `q`. */
const same = (p: string, q: string) => resolve(p) === resolve(q);

/** Your usual agent: the one configured with agent on --upstream, else $SSH_AUTH_SOCK, never this agent itself. */
export function resolveUpstream(env: Record<string, string | undefined> = process.env, own = agentPaths.sock()): string | undefined {
  const cfg = readJson<{ upstream?: string }>(agentPaths.config());
  const v = env.VSWARM_AGENT_UPSTREAM ?? cfg?.upstream ?? env.SSH_AUTH_SOCK;
  if (!v || v === "none" || same(v, own)) return;
  return v;
}

/** The socket's folder: made 0700 if missing, and refused when someone else owns it or others may enter it. */
function safeDir(dir: string) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = statSync(dir);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) throw new Error(`${dir} belongs to another user; the agent will not listen there`);
  if (st.mode & 0o077) throw new Error(`${dir} can be entered by other users (mode ${(st.mode & 0o777).toString(8)}); chmod 700 it`);
}

const CONFIRM_TIMEOUT = 30;

/** Asks on the desktop: a dialog on macOS, SSH_ASKPASS or zenity on Linux. No way to ask means no. */
export async function askOnDesktop(question: string): Promise<boolean> {
  if (process.platform === "darwin") {
    const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    const out = await run(["osascript", "-e", `display dialog ${q(question)} buttons {"Refuse", "Allow"} default button "Refuse" cancel button "Refuse" with title "vswarm agent" giving up after ${CONFIRM_TIMEOUT}`], (CONFIRM_TIMEOUT + 5) * 1000);
    return !!out && out.includes("button returned:Allow") && !out.includes("gave up:true");
  }
  const askpass = process.env.SSH_ASKPASS;
  if (askpass && existsSync(askpass)) {
    const r = await exec([askpass, question], { env: { ...process.env, SSH_ASKPASS_PROMPT: "confirm" }, timeoutMs: (CONFIRM_TIMEOUT + 5) * 1000 }).catch(() => ({ code: 1 }));
    return r.code === 0;
  }
  if (Bun.which("zenity")) {
    const r = await exec(["zenity", "--question", "--title=vswarm agent", `--text=${question}`, `--timeout=${CONFIRM_TIMEOUT}`], { timeoutMs: (CONFIRM_TIMEOUT + 5) * 1000 }).catch(() => ({ code: 1 }));
    return r.code === 0;
  }
  return false;
}

/** For the audit log: who the signature was for, as far as the request says. */
function target(f: SignedFor, conn: Conn): string {
  const parts: string[] = [];
  if (f.kind === "userauth") parts.push(`ssh login as ${f.user}`, `alg ${f.alg}`);
  else if (f.kind === "sshsig") parts.push(`ssh-keygen -Y sign, namespace ${f.namespace}`);
  else parts.push("other data");
  const hk = f.hostKey ?? conn.hostKey;
  if (hk) parts.push(`host key ${hk}`);
  if (conn.forwarded) parts.push("through a forwarded agent");
  return parts.join(" · ");
}

export async function startAgent(opt: AgentOptions): Promise<Agent> {
  if (process.platform === "win32") throw new Error("vswarm agent is not on Windows yet");
  const say = opt.log ?? ((t: string) => line(t));
  const sock = resolve(opt.sock);
  // sun_path is 104 bytes on macOS, 108 on Linux.
  if (Buffer.byteLength(sock) > 100) throw new Error(`the socket path is too long for a Unix socket: ${sock}`);
  safeDir(dirname(sock));
  if (existsSync(sock)) {
    if (await listIdentities(sock, 2000)) throw new Error(`an agent already answers on ${sock}`);
    rmSync(sock, { force: true });
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
      stamp = `${statSync(dir).mtimeMs}:${readdirSync(dir).length}`;
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
        held.set(hex(key.blob), { key, fp: v.fp, vault: file, confirm: !!inside.confirm, strict: !!inside.strict });
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
    (inflight ??= (opt.verdict ?? (() => verdictNow({ quiet: true, offline: opt.offline, ctx: opt.ctx })))().finally(() => {
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

  const refuse = async (h: Held, why: string, todo: string, what: string) => {
    say(`${c.red("vswarm agent: refused")} ${h.fp} ${c.dim(`· ${why} · ${what}`)}`);
    await appendAudit("refuse", h.fp, `${why} · ${what}`).catch((e) => say(c.red(`vswarm agent: could not write the audit log: ${e?.message ?? e}`)));
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
      return (await agentCall(upstream, msg)) ?? FAIL;
    }
    const what = target(signedFor(data), conn);
    if (locked) return refuse(h, "the agent is locked (ssh-add -x)", "Unlock it: ssh-add -X", what);
    let verdict: Verdict;
    try {
      verdict = await takeVerdict();
    } catch (e: any) {
      return refuse(h, `the check failed (${String(e?.message ?? e).slice(0, 120)})`, "Run: vswarm preflight --fresh", what);
    }
    if (verdict === "block") {
      const { lock } = await lockState().catch(() => ({ lock: undefined }));
      return lock
        ? refuse(h, `incident ${lock.incident} is open`, "Production keys stay locked until vswarm unlock (after vswarm respond)", what)
        : refuse(h, "this machine does not pass preflight", "See why: vswarm preflight --fresh", what);
    }
    if (verdict === "warn" && h.strict) return refuse(h, "preflight warns and this key is strict", "Fix or accept the findings: vswarm preflight --fresh", what);
    if (h.confirm && !(await (opt.confirm ?? askOnDesktop)(`Allow ${h.key.comment || h.fp} to sign? ${what}`))) return refuse(h, "not confirmed", "Answer Allow in the vswarm dialog to use this key", what);
    const sig = signWith(h.key, data, flags);
    // No signature leaves without its line in the audit log.
    try {
      await appendAudit("sign", h.fp, `${verdict.toUpperCase()} · ${what}`);
    } catch (e: any) {
      return refuse(h, `the audit log could not be written (${String(e?.message ?? e).slice(0, 120)})`, "Run: vswarm doctor", what);
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
    const h: Held = { key, fp: fingerprint(key.blob), confirm, strict: false };
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
        if (!h || h.vault) return FAIL;
        held.delete(id);
        return OK;
      }
      case MSG.REMOVE_ALL_IDENTITIES:
        if (locked) return FAIL;
        for (const [id, h] of held) if (!h.vault) held.delete(id);
        return OK;
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
  try {
    chmodSync(sock, 0o600);
  } catch {}
  return {
    sock,
    held: () => live().map((h) => ({ fp: h.fp, comment: h.key.comment, vault: !!h.vault, confirm: h.confirm, strict: h.strict })),
    stop() {
      server.stop(true);
      rmSync(sock, { force: true });
    },
  };
}

// ── running it: a LaunchAgent or a systemd user service, and IdentityAgent for the gated hosts

const LABEL = "dev.vswarm.agent";
const plistPath = (home = homedir()) => join(home, "Library/LaunchAgents", `${LABEL}.plist`);
const unitPath = (home = homedir()) => join(home, ".config/systemd/user/vswarm-agent.service");
const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
const unitWord = (s: string) => (/^[A-Za-z0-9_./-]+$/.test(s) ? s : `"${s.replace(/[\\"]/g, "\\$&").replace(/%/g, "%%")}"`);

export function agentJobFiles(launcher: string, home = homedir(), platform = process.platform): Record<string, string> {
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

export const AGENT_START = "# >>> vswarm agent >>>";
export const AGENT_END = "# <<< vswarm agent <<<";

/** The ~/.ssh/config block: these hosts take their keys from vswarm agent. A convenience; the control is the key. */
export function agentSshBlock(patterns: string[], sock: string): string {
  const bad = patterns.find((p) => !/^[\w*?!.:\[\]-]+$/.test(p));
  if (bad !== undefined) throw new Error(`"${bad}" is not an ssh host pattern (letters, digits, . - * ? and !)`);
  // ssh expands % and ~ in IdentityAgent, and the path sits in double quotes.
  if (/["%\r\n]/.test(sock)) throw new Error(`cannot put ${sock} in ~/.ssh/config: it contains % or a double quote`);
  return [
    AGENT_START,
    "# Hosts below take their keys from `vswarm agent`, which signs only while this machine passes. Remove with: vswarm agent off",
    `Match originalhost ${patterns.join(",")}`,
    `    IdentityAgent "${sock}"`,
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
  return /Match originalhost (\S+) !exec "[^"]* (?:preflight|cert) --quiet/.exec(cfg)?.[1].split(",") ?? [];
}

export const agentInstalled = (home = homedir()) => existsSync(process.platform === "darwin" ? plistPath(home) : unitPath(home));

async function serviceOn(launcher: string) {
  for (const [path, text] of Object.entries(agentJobFiles(launcher))) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
    recordManagedFile(text);
    line(`${c.green("✔")} ${path.replace(homedir(), "~")}`);
  }
  if (process.platform === "darwin") {
    const uid = process.getuid?.() ?? 501;
    await run(["launchctl", "bootout", `gui/${uid}/${LABEL}`], 10_000);
    await run(["launchctl", "bootstrap", `gui/${uid}`, plistPath()], 10_000);
  } else {
    await run(["systemctl", "--user", "daemon-reload"], 10_000);
    await run(["systemctl", "--user", "enable", "--now", "vswarm-agent.service"], 10_000);
  }
}

export async function agentOff(home = homedir()): Promise<string[]> {
  const gone: string[] = [];
  if (process.platform === "darwin") {
    await run(["launchctl", "bootout", `gui/${process.getuid?.() ?? 501}/${LABEL}`], 10_000);
    if (existsSync(plistPath(home))) (rmSync(plistPath(home)), gone.push(plistPath(home)));
  } else if (process.platform !== "win32") {
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
  if (process.platform === "win32") return [];
  const vaults = listVaults();
  const installed = agentInstalled();
  const answering = existsSync(agentPaths.sock()) ? await listIdentities(agentPaths.sock(), 2000) : undefined;
  const out: { level: "ok" | "warn" | "bad" | "off"; text: string; detail?: string }[] = [];
  if (!installed && !vaults.length) return [{ level: "off", text: "ssh agent off", detail: "vswarm agent protect <key> · vswarm agent on" }];
  if (answering) out.push({ level: "ok", text: "ssh agent running", detail: `${agentPaths.sock()} · ${vaults.length} protected key${vaults.length === 1 ? "" : "s"}` });
  else out.push({ level: vaults.length ? "bad" : "warn", text: "ssh agent not answering", detail: vaults.length ? `${vaults.length} protected key${vaults.length === 1 ? "" : "s"} cannot sign until it runs: vswarm agent on` : "vswarm agent on" });
  if (vaults.length) {
    try {
      await wrapKey();
    } catch (e: any) {
      out.push({ level: "bad", text: "protected ssh keys cannot be opened", detail: String(e?.message ?? e) });
    }
  }
  const audit = await readAudit();
  if (audit.why) out.push({ level: "bad", text: `the agent's audit log ${audit.why}`, detail: `${agentPaths.dir()} · treat this machine as suspect: vswarm respond` });
  return out;
}

/** For uninstall: the service and config block go; --purge is refused while keys are protected (it would delete them). */
export async function agentUninstall(purge: boolean): Promise<string[]> {
  if (process.platform === "win32") return [];
  const vaults = listVaults();
  if (purge && vaults.length)
    throw new Error(`${vaults.length} ssh key${vaults.length > 1 ? "s are" : " is"} protected by vswarm agent; --purge would delete ${vaults.length > 1 ? "them" : "it"}. Put ${vaults.length > 1 ? "them" : "it"} back first: ${vaults.map((x) => `vswarm agent unprotect ${x.v.path}`).join(" ; ")}`);
  const cfg = join(homedir(), ".ssh", "config");
  const routed = existsSync(cfg) && readFileSync(cfg, "utf8").includes(AGENT_START);
  const gone = agentInstalled() || routed ? await agentOff() : [];
  if (purge) await keyStore().remove(WRAP_NAME).catch(() => {});
  return gone;
}

// ── the command

export interface AgentCommandOpt {
  confirm: boolean;
  strict: boolean;
  global: boolean;
  upstream?: string;
  life?: number;
  ask: (q: string, o?: { secret?: boolean }) => Promise<string>;
}

const short = (p: string) => p.replace(homedir(), "~");

export async function agentCommand(action: string, args: string[], opt: AgentCommandOpt) {
  const sock = agentPaths.sock();
  if (action === "run") {
    const a = await startAgent({ sock, upstream: resolveUpstream() });
    const up = resolveUpstream();
    line(`vswarm agent listening on ${a.sock} · ${a.held().length} protected key${a.held().length === 1 ? "" : "s"} · ${up ? `other keys from ${up}` : "no upstream agent"}`);
    const stop = () => {
      a.stop();
      process.exit(0);
    };
    process.on("SIGTERM", stop);
    process.on("SIGINT", stop);
    return new Promise<never>(() => {});
  }

  if (action === "on") {
    const launcher = join(paths.bin(), "vswarm");
    if (!existsSync(launcher)) throw new Error("install the launcher first: vswarm install");
    if (opt.upstream !== undefined) {
      if (opt.upstream !== "none" && same(opt.upstream, sock)) throw new Error("--upstream names this agent itself");
      safeDir(agentPaths.dir());
      writeFileSync(agentPaths.config(), JSON.stringify({ upstream: opt.upstream }, null, 1) + "\n", { mode: 0o600 });
    }
    safeDir(agentPaths.dir());
    await serviceOn(launcher);
    const cfgPath = join(homedir(), ".ssh", "config");
    const cfg = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "";
    const hosts = args.length ? args : gatedHosts(cfg);
    if (!opt.global && hosts.length) {
      const r = setAgentBlock(cfgPath, agentSshBlock(hosts, sock));
      line(`${c.green("✔")} ${hosts.join(", ")} take their keys from vswarm agent ${c.dim(`(IdentityAgent in ${short(cfgPath)})`)}`);
      if (r.backup) line(c.dim(`  backup ${r.backup}`));
    } else {
      line(c.dim(`  ${opt.global ? "" : "no host patterns given and no ssh gate to take them from; "}to send every ssh client through the agent, in your shell's rc file:`));
      line(`    export SSH_AUTH_SOCK=${JSON.stringify(sock)}`);
      line(c.dim(`  or per host in ~/.ssh/config:  IdentityAgent "${sock}"`));
    }
    line(c.dim(`  keys it does not hold go to ${resolveUpstream() ?? "no other agent (none found in SSH_AUTH_SOCK)"} · vswarm agent status · vswarm agent off`));
    if (!listVaults().length) line(c.dim("  next: vswarm agent protect ~/.ssh/<production key>"));
    return;
  }

  if (action === "off") {
    for (const g of await agentOff()) line(`${c.green("✔")} removed ${short(g)}`);
    const n = listVaults().length;
    if (n) line(c.amber(`  ${n} protected key${n > 1 ? "s stay" : " stays"} in the vault and cannot sign until vswarm agent on · put ${n > 1 ? "them" : "it"} back: vswarm agent unprotect <key>`));
    return;
  }

  if (action === "status") {
    const ids = existsSync(sock) ? await listIdentities(sock, 2000) : undefined;
    line(ids ? `${c.green("●")} agent running ${c.dim(sock)}` : `${c.dim("○")} agent not running ${c.dim(agentInstalled() ? "(installed; see " + agentPaths.log() + ")" : "· vswarm agent on")}`);
    line(c.dim(`  other keys from: ${resolveUpstream() ?? "none"}`));
    const cfgPath = join(homedir(), ".ssh", "config");
    const block = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8").match(blockRegex(AGENT_START, AGENT_END))?.[0] : undefined;
    const hosts = /Match originalhost (\S+)/.exec(block ?? "")?.[1];
    line(c.dim(`  hosts routed here by ~/.ssh/config: ${hosts ?? "none"}`));
    const vaults = listVaults();
    if (!vaults.length) line(c.dim("  no protected keys · vswarm agent protect <key file>"));
    for (const { v } of vaults) line(`  ${c.cyan("key")} ${v.fp} ${c.dim(`${v.type} · ${v.comment} · was ${short(v.path)}`)}`);
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
    if (!file) throw new Error("usage: vswarm agent protect <key file> [--confirm] [--strict]");
    line(c.dim("  ssh-add reads the key; if it has a passphrase, type it at ssh's prompt"));
    const r = await protect(file, { confirm: opt.confirm, strict: opt.strict });
    const path = resolve(file);
    line(`${c.green("✔")} ${short(path)} is now in the vault ${c.dim(`${r.fp} · ${short(r.vault)}`)}`);
    line(`${c.green("✔")} the key file was overwritten and removed; ${short(path)}.pub ${r.pubWritten ? "was written" : "stays"} so ssh can name it`);
    line(`${c.green("✔")} backup ${short(r.backup)}, encrypted with this recovery code (shown once; keep it off this machine):`);
    line(`\n      ${c.bold(r.code)}\n`);
    line(c.dim(`  restore with it: vswarm agent restore ${short(r.backup)}   ·   put the key back normally: vswarm agent unprotect ${short(path)}`));
    const up = resolveUpstream();
    const there = up ? await listIdentities(up, 3000) : undefined;
    if (there?.some((i) => fingerprint(i.blob) === r.fp)) line(c.amber(`  ! this key is also loaded in your usual agent, where nothing checks the machine: ssh-add -d ${short(path)}.pub`));
    if (!(await listIdentities(sock, 2000))) line(c.dim("  next: vswarm agent on"));
    line(c.dim("  copies of the key elsewhere (other machines, backups, a password manager) are not covered: remove them, or rotate the key"));
    return;
  }

  if (action === "unprotect") {
    if (!args[0]) throw new Error("usage: vswarm agent unprotect <key file | SHA256:fingerprint>");
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
    const { entries, why } = await readAudit();
    if (why) line(c.red(`  the audit log ${why}`));
    if (!entries.length) return line("no signatures yet");
    for (const e of entries.slice(-30)) line(`  ${c.dim(new Date(e.at).toLocaleString())}  ${e.event === "sign" ? c.green("signed ") : c.red("refused")}  ${e.incident ?? ""}  ${c.dim(e.reason ?? "")}`);
    return;
  }

  throw new Error("usage: vswarm agent on [host patterns…] [--global] [--upstream path|none] | off | status | protect <key> [--confirm] [--strict] | unprotect <key> | restore <backup> | add <key> [--confirm] [--life s] | log | run");
}
