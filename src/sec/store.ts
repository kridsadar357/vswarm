// What vswarm keeps on this machine, all under ~/.vswarm/sec with owner-only permissions:
//   baseline.json   the machine as it was when you said it was clean
//   last.json       the most recent scan, and the verdict preflight reuses for a short while
//   accepted.json   findings you reviewed and accepted
//   lock            present while an incident is open; preflight blocks until `vswarm unlock`
//   incidents.log   every lock and unlock, each entry sealed and chained to the one before
//   audit.log       every signature `vswarm agent` made or refused, sealed and chained the same way
//   incidents/<id>/ evidence, quarantine and reports of one incident
//   osv-cache.json  answers from the known-malicious database
//   policy.json     whether WARN is let through (vswarm policy), for every gate and the agent alike
//   *.seal          the seal of the file of the same name (see seal.ts); keystore.json says where the key is, and is
//                   checked against the system's own store (chooseStore)
//
// Sealed files are trusted only with a matching seal. A cached verdict without one is never reused, a lock without one
// still blocks, and a lock file that was deleted is still open while the incident log says so. While the key store does
// not answer nothing can be verified, so the log cannot prove an incident was closed: one it ever opened counts as open
// until the store answers again. No entry is ever written to a log without its seal. Malware running as you can read
// the key too: this catches a hand-edited or forged file, not a program that imitates vswarm.

import { createHash, randomBytes } from "node:crypto";
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "../home";
import { readJson, readText, reEscape } from "./ctx";
import { entryMac, fallbackDir, fileStore, platformStore, sameHex, sealOf, storeOfKind, type KeyKind, type KeyStore } from "./seal";
import type { Finding, Scan, Verdict } from "./types";

export const SEC = () => process.env.VSWARM_SEC_DIR ?? join(HOME, "sec");

export const files = {
  baseline: () => join(SEC(), "baseline.json"),
  last: () => join(SEC(), "last.json"),
  accepted: () => join(SEC(), "accepted.json"),
  lock: () => join(SEC(), "lock"),
  log: () => join(SEC(), "incidents.log"),
  audit: () => join(SEC(), "audit.log"),
  incidents: () => join(SEC(), "incidents"),
  osv: () => join(SEC(), "osv-cache.json"),
  managed: () => join(SEC(), "managed.json"),
  keystore: () => join(SEC(), "keystore.json"),
  policy: () => join(SEC(), "policy.json"),
};

export function ensureSec(): string {
  if (!existsSync(SEC())) mkdirSync(SEC(), { recursive: true, mode: 0o700 });
  try {
    chmodSync(SEC(), 0o700);
  } catch {}
  return SEC();
}

export function writePrivate(path: string, data: unknown) {
  ensureSec();
  writeFileSync(path, typeof data === "string" ? data : JSON.stringify(data, null, 1), { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {}
}

const read = readJson;

// ── the sealing key

let injected: KeyStore | undefined;
/** Tests hand in a store of their own (a temp file); undefined goes back to the normal choice. */
export function useKeyStore(s?: KeyStore) {
  injected = s;
  stores = undefined;
  keys.clear();
}

let stores: { recorded?: KeyKind; platform: KeyStore; file: KeyStore } | undefined;
/** Tests: what keystore.json records, the system's own store and the file store, as the real home would have them. */
export function useStores(s?: { recorded?: KeyKind; platform: KeyStore; file: KeyStore }) {
  injected = undefined;
  stores = s;
  keys.clear();
}

/**
 * The store for this state folder. A state folder moved with VSWARM_SEC_DIR (tests, selftest, a scratch scan) keeps
 * its key in a file beside it, so nothing but the real ~/.vswarm ever touches the Keychain, Secret Service or DPAPI.
 * Otherwise the machine keeps the store it started with (keystore.json), or takes this system's own.
 */
export function keyStore(): KeyStore {
  if (injected) return injected;
  if (stores) return stores.recorded && stores.recorded !== stores.platform.kind ? stores.file : stores.platform;
  if (process.env.VSWARM_KEYSTORE?.startsWith("file:")) return fileStore(process.env.VSWARM_KEYSTORE.slice(5));
  if (process.env.VSWARM_SEC_DIR) return fileStore(join(SEC(), "keys"));
  const kind = recordedKind();
  return kind ? storeOfKind(kind) : platformStore();
}

const recordedKind = (): KeyKind | undefined => {
  const kind = read<{ kind?: KeyKind }>(files.keystore())?.kind;
  return kind && ["keychain", "secret-service", "dpapi", "file"].includes(kind) ? kind : undefined;
};

/** The name, in the system's own store, under which vswarm notes the kind of store it chose. */
export const KIND_NAME = "store-kind";

export interface StoreChoice {
  store: KeyStore;
  /** keystore.json points somewhere vswarm did not move the key: a finding, and the system's own store is used. */
  tampered?: string;
}

/**
 * The store to use, given the kind keystore.json records and the system's own store. keystore.json carries no seal (it
 * says where the key is), so a change of kind is checked against the system store itself: vswarm moves to a file only
 * when the system store would not keep the key, and then leaves no key there and notes "file" when it can. A
 * keystore.json that says "file" while the system store holds vswarm's key, or notes another kind, was not changed by
 * vswarm: that is reported, and the system store is used. When the system store does not answer, the file is used and
 * nothing can be said either way.
 */
export async function chooseStore(recorded: KeyKind | undefined, platform: KeyStore, ofKind: (k: KeyKind) => KeyStore): Promise<StoreChoice> {
  if (!recorded || recorded === platform.kind) return { store: platform };
  if (recorded !== "file" || platform.kind === "file") return { store: ofKind(recorded) };
  let noted: string | undefined, key: string | undefined;
  try {
    noted = await platform.get(KIND_NAME);
    if (noted !== "file") key = await platform.get("state-key");
  } catch {
    return { store: ofKind("file") };
  }
  if (noted === "file" || (!noted && !key)) return { store: ofKind("file") };
  return {
    store: platform,
    tampered: `keystore.json says the sealing key is in a plain file, but ${platform.where} ${noted ? `notes that vswarm chose ${noted}` : "holds vswarm's key"}: vswarm did not make that change`,
  };
}

/** The store this process uses, with keystore.json checked as above. */
export async function activeStore(): Promise<StoreChoice> {
  if (injected) return { store: injected };
  if (stores) return chooseStore(stores.recorded, stores.platform, (k) => (k === "file" ? stores!.file : stores!.platform));
  if (process.env.VSWARM_KEYSTORE?.startsWith("file:") || process.env.VSWARM_SEC_DIR) return { store: keyStore() };
  return chooseStore(recordedKind(), platformStore(), storeOfKind);
}

export interface KeyState {
  key?: Buffer;
  store: KeyStore;
  /** Why there is no key: the store is there but did not answer. State is then read unverified, and the check says so. */
  error?: string;
  /** keystore.json was changed to another kind of store outside vswarm (see chooseStore). */
  tampered?: string;
}

// A key that was read is kept for the process. A store that did not answer (a Keychain still locked when launchd
// started the agent, a keyring not up yet) is asked again after a short wait, doubling up to a minute, so a
// long-running agent or watch recovers on its own.
const RETRY_FIRST = 1000, RETRY_MAX = 60_000;
interface KeySlot {
  p: Promise<KeyState>;
  wait: number;
  /** Set once the attempt failed: when to ask the store again. */
  retryAt?: number;
}
const keys = new Map<string, KeySlot>();

/** The key, once per process and store. The first time on a machine it is made, and files from before seals existed are adopted. */
export async function stateKey(): Promise<KeyState> {
  const choice = await activeStore();
  const store = choice.store;
  const id = `${store.kind}:${store.where}`;
  const had = keys.get(id);
  if (had && (had.retryAt === undefined || Date.now() < had.retryAt)) return had.p;
  const slot: KeySlot = { p: loadKey(store).then((k) => (choice.tampered ? { ...k, tampered: choice.tampered } : k)), wait: had ? Math.min(had.wait * 2, RETRY_MAX) : RETRY_FIRST };
  keys.set(id, slot);
  const k = await slot.p;
  if (!k.key) slot.retryAt = Date.now() + slot.wait;
  return k;
}

const sealPath = (f: string) => `${f}.seal`;
// Sealed files, adopted once when a machine that never had seals gets its key (the MCP pins are written by mcp.ts).
const SEALED = () => [files.baseline(), files.accepted(), files.last(), files.lock(), join(SEC(), "mcp-tools.json")];

async function loadKey(store: KeyStore): Promise<KeyState> {
  let hex: string | undefined;
  try {
    hex = await store.get("state-key");
  } catch (e: any) {
    return { store, error: String(e?.message ?? e) };
  }
  if (hex && /^[0-9a-f]{64}$/.test(hex)) return { key: Buffer.from(hex, "hex"), store };
  // No key yet. Files sealed before, or an incident log, mean the key was lost or removed: nothing is adopted then,
  // so those files stay untrusted. A machine that never had seals adopts what it has (upgrading from 2.5).
  const fresh = !SEALED().some((f) => existsSync(sealPath(f))) && !existsSync(files.log());
  const made = randomBytes(32).toString("hex");
  let used = store;
  try {
    await store.set("state-key", made);
    if ((await store.get("state-key")) !== made) throw new Error("the key read back is not the one written");
  } catch (e: any) {
    if (store.kind === "file") return { store, error: String(e?.message ?? e) };
    // The system's store would not take it: an owner-only file instead, and doctor says so. No key is left in the
    // system store, and "file" is noted there when it takes that, so this move is told apart from a hand edit.
    used = stores?.file ?? fileStore(fallbackDir());
    try {
      await used.set("state-key", made);
    } catch (e2: any) {
      return { store, error: String(e2?.message ?? e2) };
    }
    await store.remove("state-key").catch(() => {});
    await store.set(KIND_NAME, "file").catch(() => {});
  }
  if (used === store && store.kind !== "file") await store.set(KIND_NAME, store.kind).catch(() => {});
  if (!process.env.VSWARM_SEC_DIR && !injected && !stores) writePrivate(files.keystore(), { kind: used.kind, at: Date.now() });
  const key = Buffer.from(made, "hex");
  if (fresh) {
    // last.json is only a cache: dropped, so the first gate after the upgrade checks afresh instead of doubting it.
    rmSync(files.last(), { force: true });
    for (const f of SEALED()) if (existsSync(f)) writeSeal(key, f, readFileSync(f));
    const lock = read<Lock>(files.lock());
    if (existsSync(files.lock())) await appendEntry({ key, store: used }, "lock", lock?.incident ?? "unknown", lock?.reason ?? "open before seals existed");
  }
  return { key, store: used };
}

function writeSeal(key: Buffer, path: string, data: string | Buffer) {
  writePrivate(sealPath(path), `v1 ${sealOf(key, path, data)}\n`);
}

/** Writes a state file and its seal. Without a key the file is written unsealed, and reads of it say so. */
export async function writeSealed(path: string, data: unknown) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 1);
  // The key first: making it the first time adopts (and clears) older files, which must not include this write.
  const k = await stateKey();
  writePrivate(path, text);
  if (k.key) writeSeal(k.key, path, text);
  else rmSync(sealPath(path), { force: true });
}

export interface Sealed<T> {
  value?: T;
  /** Why the file is not to be trusted, when it exists and its seal does not match. */
  untrusted?: string;
  /** The key could not be read, so nothing could be checked (untrusted says why). */
  nokey?: boolean;
}

/** A state file and whether its seal matches. A missing file is {}. */
export async function readSealed<T>(path: string): Promise<Sealed<T>> {
  if (!existsSync(path)) return {};
  const raw = readText(path, 256_000_000);
  let value: T | undefined;
  try {
    value = raw === undefined ? undefined : JSON.parse(raw);
  } catch {}
  if (raw === undefined) return { untrusted: "cannot be read" };
  const k = await stateKey();
  if (!k.key) return { value, untrusted: `could not be checked: vswarm could not read its sealing key (${k.error})`, nokey: true };
  const seal = /^v1 ([0-9a-f]{64})\s*$/.exec(readText(sealPath(path)) ?? "")?.[1];
  if (!seal) return { value, untrusted: "has no seal: it was written or replaced outside vswarm" };
  if (!sameHex(seal, sealOf(k.key, path, raw))) return { value, untrusted: "was changed outside vswarm: its seal does not match" };
  return { value };
}

/** Only a value whose seal matches. */
const trusted = async <T>(path: string) => {
  const r = await readSealed<T>(path);
  return r.untrusted ? undefined : r.value;
};

export const readBaseline = () => readSealed<Scan>(files.baseline());
export const loadBaseline = () => trusted<Scan>(files.baseline());
export const saveBaseline = (s: Scan) => writeSealed(files.baseline(), s);

export interface Last {
  scan: Scan;
  findings: Finding[];
  verdict: Verdict;
  at: number;
}
export const readLast = () => readSealed<Last>(files.last());
export const loadLast = () => trusted<Last>(files.last());
export const saveLast = (l: Last) => writeSealed(files.last(), l);
/** Whether accepted findings or the baseline changed after a moment (the last scan's time). */
export const decisionsSince = (at: number) =>
  [files.accepted(), files.baseline()].some((f) => {
    try {
      return statSync(f).mtimeMs > at;
    } catch {
      return false;
    }
  });

export interface Accepted {
  [findingId: string]: { at: number; title: string };
}
export const readAccepted = () => readSealed<Accepted>(files.accepted());
/** Accepted findings; a list whose seal does not match accepts nothing. */
export const loadAccepted = async () => (await trusted<Accepted>(files.accepted())) ?? {};
export const saveAccepted = (a: Accepted) => writeSealed(files.accepted(), a);

// ── the lock and the incident log

export interface Lock {
  incident: string;
  at: number;
  reason: string;
}

export interface LogEntry {
  n: number;
  at: number;
  event: "lock" | "unlock" | "reset" | "sign" | "refuse";
  incident?: string;
  reason?: string;
  prev: string;
  mac: string;
}

/** A chained log and the name its last entry is kept under in the key store. */
interface Chain {
  file: string;
  head: string;
}
const INCIDENTS = (): Chain => ({ file: files.log(), head: "log-head" });
const AUDIT = (): Chain => ({ file: files.audit(), head: "audit-head" });

export interface LogRead {
  entries: LogEntry[];
  /** Why the log cannot be trusted, when it cannot (changed, cut short, deleted). */
  why?: string;
  /** Said by the one read that found entries without a seal and set them aside (see setAsideUnsealed). */
  notice?: string;
}

const entryOk = (e: unknown): e is LogEntry => !!e && typeof e === "object" && typeof (e as LogEntry).n === "number" && typeof (e as LogEntry).prev === "string" && typeof (e as LogEntry).mac === "string";

/** The incident log, and why it cannot be trusted when it cannot (changed, cut short, deleted). */
export async function readLog(k?: KeyState, chain = INCIDENTS()): Promise<LogRead> {
  k ??= await stateKey();
  const text = existsSync(chain.file) ? readText(chain.file, 64_000_000) : "";
  if (text === undefined) return { entries: [], why: "cannot be read" };
  const entries: LogEntry[] = [];
  let why: string | undefined;
  for (const l of text.split("\n")) {
    if (!l.trim()) continue;
    try {
      entries.push(JSON.parse(l));
    } catch {
      why ??= "has a line that is not vswarm's";
    }
  }
  if (!k.key) return { entries, why };
  // Each entry carries the MAC of the one before it. An entry with an empty MAC is one vswarm 2.6 and older wrote
  // while the key store did not answer; it proves nothing and is counted, not verified.
  let prev = "";
  let unsealed = 0;
  let lastSealed: LogEntry | undefined;
  entries.forEach((e, i) => {
    if (why) return;
    if (!entryOk(e) || e.n !== i + 1 || e.prev !== prev || (e.mac !== "" && !sameHex(e.mac, entryMac(k!.key!, e)))) return void (why = `was changed outside vswarm (entry ${i + 1})`);
    if (e.mac === "") unsealed++;
    else lastSealed = e;
    prev = e.mac;
  });
  // The last sealed entry is also kept in the key store, so a log cut short or deleted does not look like a shorter, valid one.
  let head: string | undefined;
  try {
    head = await k.store.get(chain.head);
  } catch {}
  if (!why && head && head !== `${lastSealed?.n}:${lastSealed?.mac}`) why = entries.length ? "was cut short or rewritten" : "was deleted";
  if (!why && !head && lastSealed) why = "does not match the record vswarm keeps of it";
  if (!why && unsealed) return setAsideUnsealed(k, chain, text, entries, unsealed);
  return { entries, why };
}

/**
 * A log whose sealed entries all verify, with entries in it that carry no seal (vswarm 2.6 and older wrote those while
 * the key store did not answer; 2.7 never does). They are not taken as valid, and the log is not called tampered
 * either: it is set aside whole, and a new chain starts with a sealed entry that says so, once. For the incident log
 * the new chain stays closed only if the old one was: an unsealed lock still counts (the safe way), an unsealed unlock
 * or reset does not, so an incident open by either count stays open.
 */
async function setAsideUnsealed(k: KeyState, chain: Chain, text: string, entries: LogEntry[], unsealed: number): Promise<LogRead> {
  // Another vswarm process got here first: read what it left.
  if (readText(chain.file, 64_000_000) !== text) return readLog(k, chain);
  const aside = `${chain.file}.unsealed-${Date.now()}`;
  renameSync(chain.file, aside);
  await k.store.remove(chain.head).catch(() => {});
  const notice = `${unsealed} entr${unsealed === 1 ? "y" : "ies"} written while the key store was unavailable (by vswarm 2.6 or older, without a seal) ${unsealed === 1 ? "was" : "were"} set aside in ${aside}; a new log starts here`;
  await appendEntry(k, "reset", undefined, notice, chain);
  if (chain.head === INCIDENTS().head) {
    let open: LogEntry | undefined;
    for (const e of entries) {
      if (e.event === "lock") open = e;
      else if (e.mac !== "" && (e.event === "unlock" || e.event === "reset")) open = undefined;
    }
    if (open) await appendEntry(k, "lock", open.incident, `still open: ${open.reason ?? ""}`.slice(0, 300), chain);
  }
  return { ...(await readLog(k, chain)), notice };
}

/** Appends one sealed entry. Without the key nothing is written: an entry without its seal would break the chain for good. */
async function appendEntry(k: KeyState, event: LogEntry["event"], incident?: string, reason?: string, chain = INCIDENTS()): Promise<string | undefined> {
  if (!k.key) throw new Error(`the entry could not be sealed: vswarm could not read its sealing key (${k.error ?? "no key"})`);
  const { entries, notice } = await readLog(k, chain);
  const prevMac = entries.at(-1)?.mac ?? "";
  const e: Omit<LogEntry, "mac"> = { n: entries.length + 1, at: Date.now(), event, incident, reason: reason?.slice(0, 300), prev: typeof prevMac === "string" ? prevMac : "" };
  const mac = entryMac(k.key, e);
  ensureSec();
  appendFileSync(chain.file, JSON.stringify({ ...e, mac }) + "\n", { mode: 0o600 });
  await k.store.set(chain.head, `${e.n}:${mac}`);
  return notice;
}

// One append at a time: two signatures at once must not both take the same place in the chain.
let auditQueue: Promise<unknown> = Promise.resolve();

/**
 * One line in the audit log of `vswarm agent`: a signature made or refused, and on what grounds. Rejects when the line
 * cannot be sealed (the key store does not answer), and then nothing is written. Resolves to a notice when an old log
 * with unsealed entries was set aside on the way.
 */
export function appendAudit(event: "sign" | "refuse", key: string, reason: string): Promise<string | undefined> {
  const next = auditQueue.then(async () => appendEntry(await stateKey(), event, key, reason, AUDIT()));
  auditQueue = next.catch(() => {});
  return next;
}

/** The audit log, and why it cannot be trusted when it cannot. */
export const readAudit = async () => readLog(await stateKey(), AUDIT());

export interface LockState {
  lock?: Lock;
  /** Why the machine counts as locked although nobody may have meant it to (tampering, a deleted lock file). */
  why?: string;
}

/**
 * Whether an incident is open: a lock file (trusted or not: a lock that cannot be verified still blocks), or an
 * incident log that says so, or one that was tampered with. Without the key the log proves nothing, an unlock least
 * of all: an incident it ever opened counts as open until the key store answers. Never "open" without a reason the
 * user can act on.
 */
export async function lockState(): Promise<LockState> {
  const k = await stateKey();
  if (existsSync(files.lock())) {
    const r = await readSealed<Lock>(files.lock());
    const ok = r.value && typeof r.value.incident === "string";
    // A lock file that cannot be read still means an incident is open: the gate must not fail open.
    const lock = ok ? r.value! : { incident: "unknown", at: 0, reason: "the lock file is unreadable" };
    return { lock, why: r.untrusted && !r.nokey && ok ? `the lock file ${r.untrusted}` : undefined };
  }
  const log = await readLog(k);
  const last = log.entries.filter((e) => e && (e.event === "lock" || e.event === "unlock" || e.event === "reset")).at(-1);
  if (log.why) {
    const open = log.entries.filter((e) => e?.event === "lock").at(-1);
    return { lock: { incident: open?.incident ?? "unknown", at: open?.at ?? 0, reason: `vswarm's incident log ${log.why}` }, why: `vswarm's incident log ${log.why}` };
  }
  if (!k.key) {
    const open = log.entries.filter((e) => e?.event === "lock").at(-1);
    if (open) {
      const why = `vswarm cannot read its sealing key (${k.error ?? "no key"}), so its incident log cannot show that incident ${open.incident ?? "unknown"} was closed; it counts as open until the key store answers`;
      return { lock: { incident: open.incident ?? "unknown", at: open.at ?? 0, reason: why }, why };
    }
    return {};
  }
  if (last?.event === "lock")
    return { lock: { incident: last.incident ?? "unknown", at: last.at, reason: last.reason ?? "" }, why: "the lock file is gone, but the incident log says this incident is still open" };
  return {};
}

export const loadLock = async () => (await lockState()).lock;

/**
 * Opens an incident: the lock file, and a sealed entry in the log that outlives it. Without the key the lock file is
 * still written (unsealed, it blocks all the same) and the log is left alone; `unsealed` says why.
 */
export async function setLock(l: Lock): Promise<{ unsealed?: string }> {
  await writeSealed(files.lock(), l);
  const k = await stateKey();
  if (!k.key) return { unsealed: `vswarm could not read its sealing key (${k.error ?? "no key"}): the lock file holds the incident open, and the incident log has no entry for it` };
  await appendEntry(k, "lock", l.incident, l.reason);
  return {};
}

/** Closes the incident. Refuses while the log does not verify, unless `reset`: then the old log is kept aside and a new one starts. */
export async function clearLock(incident: string, opt: { reset?: boolean } = {}): Promise<{ kept?: string }> {
  const k = await stateKey();
  // An unlock that cannot be sealed would not count (see lockState): refused before anything is removed.
  if (!k.key) throw new Error(`vswarm cannot read its sealing key (${k.error ?? "no key"}), so it cannot record the unlock; unlock the login keychain (macOS) or keyring (Linux) and try again`);
  const log = await readLog(k);
  let kept: string | undefined;
  if (log.why) {
    if (!opt.reset) throw new Error(`vswarm's incident log ${log.why}`);
    if (existsSync(files.log())) renameSync(files.log(), (kept = `${files.log()}.broken-${Date.now()}`));
    await k.store.remove("log-head").catch(() => {});
    rmSync(files.lock(), { force: true });
    rmSync(sealPath(files.lock()), { force: true });
    await appendEntry(k, "reset", incident, "unlock --force after the log did not verify");
    return { kept };
  }
  rmSync(files.lock(), { force: true });
  rmSync(sealPath(files.lock()), { force: true });
  await appendEntry(k, "unlock", incident);
  return { kept };
}

/** For uninstall --purge: the key and the log head leave with the data, or a reinstall would find a log that is "deleted". */
export async function forgetKey() {
  const s = (await activeStore()).store;
  for (const name of ["state-key", "log-head", "audit-head", KIND_NAME]) await s.remove(name).catch(() => {});
  keys.clear();
}

/** The block between two marker lines, with the newline before it, as setBlock, the ssh gate and canaries write them. */
export function blockRegex(start: string, end: string): RegExp {
  return new RegExp(`\\n?${reEscape(start)}[\\s\\S]*?${reEscape(end)}\\n?`, "g");
}

export function removeBlock(text: string, start: string, end: string): string {
  return text.replace(blockRegex(start, end), "\n").replace(/\n{3,}/g, "\n\n");
}

// Blocks vswarm writes into your files (PATH in ~/.zshrc, the ssh gate, the install guard, canaries). Their hashes
// are kept so a scan does not report vswarm's own lines as a change. A block that differs by one character from what
// vswarm wrote is not recognised, and is checked like any other line.
// Line endings do not count: an editor on Windows may turn the block's \n into \r\n.
const BLOCK = /# >>> vswarm[^\r\n]*>>>\r?\n[\s\S]*?# <<< vswarm[^\r\n]*<<<(\r?\n)?/g;
const blockHash = (b: string) => createHash("sha256").update(b.replace(/\r\n/g, "\n").trim()).digest("hex");

export function recordManaged(text: string) {
  const m = read<Record<string, number>>(files.managed()) ?? {};
  for (const b of text.match(BLOCK) ?? []) m[blockHash(b)] = Date.now();
  writePrivate(files.managed(), m);
}

export function stripManaged(text: string): string {
  const m = read<Record<string, number>>(files.managed()) ?? {};
  return text.replace(BLOCK, (b) => (m[blockHash(b)] ? "" : b));
}

/** Whole files vswarm writes (its own background job). Recognised by their exact content. */
export function recordManagedFile(text: string) {
  const m = read<Record<string, number>>(files.managed()) ?? {};
  m[`file:${createHash("sha256").update(text).digest("hex")}`] = Date.now();
  writePrivate(files.managed(), m);
}

export function isManagedFile(sha256hex: string | undefined): boolean {
  if (!sha256hex) return false;
  return Boolean((read<Record<string, number>>(files.managed()) ?? {})[`file:${sha256hex}`]);
}
