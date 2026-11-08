// One WARN policy for every gate and the agent; findings by number (ok, fix, why); SSH keys judged one by one; report
// output on stdout. State folders, homes and keys are temp folders of their own; the CLI runs with HOME pointed there.
import { describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { helpRow, reportsTo } from "../src/cli";
import type { Ctx } from "../src/sec/ctx";
import { acceptedBefore, check } from "../src/sec/engine";
import { backupDir, fixFor, removeLines } from "../src/sec/fix";
import { gateVerdict } from "../src/sec/gate";
import { effective, policyLine, readPolicy, savePolicy } from "../src/sec/policy";
import { numbers } from "../src/sec/print";
import { secrets } from "../src/sec/secrets";
import { files, loadAccepted, saveLast } from "../src/sec/store";
import type { Finding, Scan, Verdict } from "../src/sec/types";
import { completion } from "../src/setup";

const WIN = process.platform === "win32";
const CLI = join(import.meta.dir, "../src/cli.ts");
const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-pol-${tag}-`));
const ctxFor = (home: string): Ctx => ({ home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined });

async function withSec<T>(fn: (sec: string) => Promise<T>): Promise<T> {
  const prev = process.env.VSWARM_SEC_DIR;
  const sec = tmp("sec");
  process.env.VSWARM_SEC_DIR = sec;
  try {
    return await fn(sec);
  } finally {
    if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
    else process.env.VSWARM_SEC_DIR = prev;
  }
}

/** The CLI with its state, HOME and VSWARM_HOME in temp folders; stdin closed. */
async function vswarm(dirs: { sec: string; home?: string }, ...a: string[]) {
  const home = dirs.home ?? tmp("home");
  const env = { ...process.env, NO_COLOR: "1", VSWARM_SEC_DIR: dirs.sec, HOME: home, USERPROFILE: home, VSWARM_HOME: join(home, ".vswarm") };
  const p = Bun.spawn([process.execPath, CLI, ...a], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { code, out, err };
}

const warnLast = (findings: Finding[] = [{ id: "x", rule: "x", severity: "medium", title: "a warning", detail: [] }]) =>
  saveLast({ verdict: "warn", findings, at: Date.now(), scan: {} as Scan });

describe("one WARN policy", () => {
  test("allow by default; refuse when set; a policy file edited by hand counts as refuse and is reported", () => withSec(async (sec) => {
    expect(await readPolicy()).toEqual({ warn: "allow", set: false });
    await savePolicy("refuse");
    expect(await readPolicy()).toEqual({ warn: "refuse", set: true });
    expect(policyLine(await readPolicy())).toContain("WARN is refused");
    await savePolicy("allow");
    // Changed outside vswarm: the seal no longer matches, so it can only make vswarm stricter.
    writeFileSync(files.policy(), JSON.stringify({ warn: "allow", at: 1 }));
    const p = await readPolicy();
    expect(p.warn).toBe("refuse");
    expect(p.untrusted).toContain("changed outside vswarm");
    const r = await check(ctxFor(tmp("home")), { offline: true });
    expect(r.findings.find((f) => f.id === "vswarm-state:policy")?.severity).toBe("medium");
    expect(effective("inherit", "refuse")).toBe("refuse");
    expect(effective("allow", "refuse")).toBe("allow");
    expect(effective(undefined, "allow")).toBe("allow");
    expect(existsSync(sec)).toBe(true);
  }));

  test("the gates: BLOCK refuses, WARN as the policy says (or --strict), with the way out on stderr", () => withSec(async () => {
    await warnLast();
    expect(await gateVerdict({ quiet: true })).toMatchObject({ verdict: "warn", allowed: true, code: 0 });
    expect(await gateVerdict({ quiet: true, strict: true })).toMatchObject({ allowed: false, code: 2 });
    await savePolicy("refuse");
    expect(await gateVerdict({ quiet: true })).toMatchObject({ verdict: "warn", allowed: false, code: 2 });
    await saveLast({ verdict: "block", findings: [], at: Date.now(), scan: {} as Scan });
    expect(await gateVerdict({ quiet: true })).toMatchObject({ verdict: "block", allowed: false, code: 3 });
  }));

  test.skipIf(WIN)("preflight --then: a WARN the policy refuses runs nothing, says why on stderr, exit 2; --json gives the decision as data", async () => {
    const sec = tmp("sec");
    const prev = process.env.VSWARM_SEC_DIR;
    process.env.VSWARM_SEC_DIR = sec;
    try {
      await warnLast();
      await savePolicy("refuse");
    } finally {
      process.env.VSWARM_SEC_DIR = prev;
    }
    const ran = await vswarm({ sec }, "preflight", "--quiet", "--then", "echo", "RAN");
    expect(ran.code).toBe(2);
    expect(ran.out).toBe("");
    expect(ran.err).toContain("WARN refused by policy");
    expect(ran.err).toContain("vswarm why");
    expect(ran.err).toContain("vswarm policy warn allow");
    const j = await vswarm({ sec }, "preflight", "--json");
    expect(j.code).toBe(2);
    const data = JSON.parse(j.out);
    expect(data).toMatchObject({ verdict: "warn", allowed: false, code: 2, policy: { warn: "refuse", set: true } });
    expect(data.findings[0].title).toBe("a warning");
    expect((await vswarm({ sec }, "preflight", "--json", "--then", "echo")).err).toContain("use one");
    // vswarm policy shows and sets it, on stdout.
    expect((await vswarm({ sec }, "policy")).out).toContain("WARN is refused");
    expect((await vswarm({ sec }, "policy", "warn", "allow")).out).toContain("WARN is allowed");
    expect((await vswarm({ sec }, "preflight", "--quiet", "--then", "echo", "RAN")).out).toBe("RAN\n");
    expect((await vswarm({ sec }, "policy", "warn", "maybe")).code).toBe(4);
  }, 60_000);
});

describe("findings by number", () => {
  test("numbers follow the check as saved; the printed finding says how to accept it", () => {
    const fs: Finding[] = [{ id: "a", rule: "r", severity: "high", title: "A", detail: [] }, { id: "b", rule: "r", severity: "low", title: "B", detail: [] }];
    expect([...numbers(fs)]).toEqual([["a", 1], ["b", 2]]);
  });

  test.skipIf(WIN)("vswarm ok <n> accepts finding n of the last check; ids still work; a number that is not there is an error", async () => {
    const sec = tmp("sec");
    const prev = process.env.VSWARM_SEC_DIR;
    process.env.VSWARM_SEC_DIR = sec;
    const fs: Finding[] = [
      { id: "tool-exec:x:1", rule: "tool-exec-new", severity: "medium", title: "first", detail: [] },
      { id: "bin:y", rule: "new-bin", severity: "medium", title: "second", detail: [] },
      { id: "malicious:npm:evil@1", rule: "malicious", severity: "critical", title: "evil", detail: [] },
    ];
    try {
      await saveLast({ verdict: "warn", findings: fs, at: Date.now(), scan: {} as Scan });
    } finally {
      process.env.VSWARM_SEC_DIR = prev;
    }
    expect((await vswarm({ sec }, "ok", "2")).err).toContain("accepted: second");
    expect((await vswarm({ sec }, "accept", "tool-exec:x:1")).err).toContain("accepted: first");
    expect((await vswarm({ sec }, "ok", "3")).err).toContain("cannot be accepted");
    const bad = await vswarm({ sec }, "ok", "9");
    expect(bad.code).toBe(4);
    expect(bad.err).toContain("no finding 9");
    process.env.VSWARM_SEC_DIR = sec;
    try {
      expect(Object.keys(await loadAccepted()).sort()).toEqual(["bin:y", "tool-exec:x:1"]);
    } finally {
      process.env.VSWARM_SEC_DIR = prev;
    }
    expect((await vswarm({ sec }, "ok", "--list")).out).toContain("second");
    // fix: a finding with no automatic fix gets the steps; one past the end is an error.
    const f1 = await vswarm({ sec }, "fix", "1");
    expect(f1.err).toContain("no automatic fix");
    expect(f1.err).toContain("vswarm ok 1");
    expect((await vswarm({ sec }, "fix", "7")).err).toContain("there is no 7");
  }, 60_000);

  test("fix plans: the production key goes to agent protect (or ssh-keygen -p), another key to ssh-keygen -p, an unsafe source loses its lines", async () => {
    const home = tmp("home");
    const prod: Finding = { id: "secret:ssh:prod", rule: "secret", severity: "medium", title: "k", detail: [], meta: { file: join(home, ".ssh/prod"), production: true } };
    // A temp home is a Windows path on Windows, so it is judged with that system's quoting.
    const p = fixFor(prod, { n: 1, self: ["vswarm"], home, platform: process.platform === "win32" ? "win32" : "darwin" });
    expect(p.exact).toEqual([`vswarm agent protect ${join(home, ".ssh/prod")}`]);
    expect(p.instead?.exact).toEqual([`ssh-keygen -p -f ${join(home, ".ssh/prod")}`]);
    expect(fixFor(prod, { n: 1, self: ["vswarm"], home, platform: "win32" }).exact[0]).toContain("ssh-keygen -p");
    // On Windows the command is shown as PowerShell takes it: a backslash path as it is, double quotes around a space.
    const winKey: Finding = { ...prod, meta: { file: "C:\\Users\\a b\\.ssh\\k", production: false } };
    expect(fixFor(winKey, { n: 1, self: ["vswarm"], platform: "win32" }).exact).toEqual(['ssh-keygen -p -f "C:\\Users\\a b\\.ssh\\k"']);
    expect(fixFor({ ...winKey, meta: { file: "C:\\k\\id", production: false } }, { n: 1, self: ["vswarm"], platform: "win32" }).exact).toEqual(["ssh-keygen -p -f C:\\k\\id"]);
    expect(fixFor({ ...prod, meta: { file: join(home, ".ssh/me"), production: false } }, { n: 1, self: ["vswarm"], home }).exact[0]).toBe(`ssh-keygen -p -f ${join(home, ".ssh/me")}`);
    const npmrc = join(home, ".npmrc");
    writeFileSync(npmrc, "registry=http://198.51.100.7/npm/\nsave-exact=true\n");
    const src: Finding = { id: "pkg-source:.npmrc:x", rule: "pkg-source", severity: "medium", title: "src", detail: [], item: { kind: "tool-config", id: ".npmrc", name: ".npmrc", path: npmrc }, meta: { lines: ["registry=http://198.51.100.7/npm/"] } };
    const plan = fixFor(src, { n: 2, self: ["vswarm"], home });
    expect(plan.exact).toEqual(["- registry=http://198.51.100.7/npm/"]);
    await withSec(async () => {
      expect(await plan.run!()).toContain("removed 1 line from");
      expect(readFileSync(npmrc, "utf8")).toBe("save-exact=true\n");
      expect(existsSync(backupDir())).toBe(true);
      expect(await plan.run!()).toContain("nothing removed");
    });
    expect(fixFor({ id: "x", rule: "launch-new", severity: "high", title: "t", detail: [], fix: "remove it" }, { n: 3, self: ["vswarm"] }).manual).toEqual(["remove it", "or, if it is expected: vswarm ok 3"]);
  });

  test("removeLines takes out whole lines only, and says which were not there", () => {
    const f = join(tmp("rl"), "rc");
    writeFileSync(f, "a\r\n  curl x | sh  \r\nb\r\n");
    expect(removeLines(f, ["curl x | sh", "gone"])).toEqual({ removed: 1, missing: ["gone"] });
    expect(readFileSync(f, "utf8")).toBe("a\r\nb\r\n");
  });
});

describe.skipIf(WIN)("SSH keys without a passphrase, one by one", () => {
  const BARE = (() => {
    // An OpenSSH key header with cipher "none": no key material, only what keyEncrypted reads.
    const w = (s: Buffer) => Buffer.concat([Buffer.alloc(4), s]).fill(0, 0, 0);
    const str = (s: string) => {
      const b = Buffer.from(s);
      const n = Buffer.alloc(4);
      n.writeUInt32BE(b.length);
      return Buffer.concat([n, b]);
    };
    void w;
    const body = Buffer.concat([Buffer.from("openssh-key-v1\0"), str("none"), str("none"), str("")]);
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${body.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----\n`;
  })();

  const homeWith = (cfg: string, keys: string[]) => {
    const home = tmp("home");
    mkdirSync(join(home, ".ssh"));
    for (const k of keys) {
      writeFileSync(join(home, ".ssh", k), BARE);
      chmodSync(join(home, ".ssh", k), 0o600);
    }
    writeFileSync(join(home, ".ssh", "config"), cfg);
    return home;
  };
  const GATE = `# >>> vswarm gate >>>\nMatch originalhost prod-*,db1 !exec "/v/vswarm preflight --quiet --host %h"\n    ProxyCommand /bin/sh -c 'exit 1'\n# <<< vswarm gate <<<\n\n`;

  test("a key the gated hosts use is MED; a personal key is LOW, so a dev machine can pass", async () => {
    const home = homeWith(`${GATE}Host prod-web\n    IdentityFile ~/.ssh/prod\nHost github.com\n    IdentityFile ~/.ssh/personal\n`, ["prod", "personal"]);
    const fs = (await secrets(ctxFor(home))).filter((f) => f.id.startsWith("secret:ssh:"));
    expect(fs.map((f) => [f.id, f.severity, f.meta?.production])).toEqual([["secret:ssh:personal", "low", false], ["secret:ssh:prod", "medium", true]]);
    expect(fs[1].title).toContain("used for production hosts");
    expect(fs[0].fix).toContain("ssh-keygen -p -f ~/.ssh/personal");
  });

  test("a gated host that names no key uses ssh's defaults; without a gate every key is LOW", async () => {
    const gated = homeWith(`${GATE}Host db1\n    HostName 10.0.0.9\n`, ["id_ed25519", "other"]);
    expect((await secrets(ctxFor(gated))).filter((f) => f.id.startsWith("secret:ssh:")).map((f) => [f.id, f.severity])).toEqual([["secret:ssh:id_ed25519", "medium"], ["secret:ssh:other", "low"]]);
    const plain = homeWith("Host db1\n    IdentityFile ~/.ssh/id_ed25519\n", ["id_ed25519"]);
    expect((await secrets(ctxFor(plain))).filter((f) => f.id.startsWith("secret:ssh:")).map((f) => f.severity)).toEqual(["low"]);
  });

  test("a key accepted under 2.7's one finding for all keys stays accepted", () => {
    expect(acceptedBefore({ "secret:ssh:a,b": {} }, "secret:ssh:b")).toBe(true);
    expect(acceptedBefore({ "secret:ssh:a,b": {} }, "secret:ssh:c")).toBe(false);
    expect(acceptedBefore({ "secret:ssh:a": {} }, "secret:ssh:b")).toBe(false);
  });
});

describe("output where it belongs", () => {
  test("reports to stdout, gates and actions to stderr", () => {
    expect(reportsTo("scan", [])).toBe(true);
    expect(reportsTo("why", [])).toBe(true);
    expect(reportsTo("preflight", [])).toBe(true);
    expect(reportsTo("preflight", ["--quiet"])).toBe(false);
    expect(reportsTo("preflight", ["--then", "aws"])).toBe(false);
    expect(reportsTo("preflight", ["--json"])).toBe(false);
    expect(reportsTo("accept", ["--list"])).toBe(true);
    expect(reportsTo("accept", ["3"])).toBe(false);
    expect(reportsTo("agent", ["status"])).toBe(true);
    expect(reportsTo("agent", ["protect", "k"])).toBe(false);
    expect(reportsTo("respond", [])).toBe(false);
    expect(reportsTo("pkg", ["check", "npm", "x"])).toBe(true);
    expect(reportsTo("pkg", ["npm", "install"])).toBe(false);
  });

  test.skipIf(WIN)("vswarm secrets > file keeps the report; vswarm why ends with the policy line", async () => {
    const sec = tmp("sec");
    const home = tmp("home");
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".git-credentials"), "https://me:ghp_notarealtokennotarealtoken00000000@github.com\n");
    const s = await vswarm({ sec, home }, "secrets");
    expect(s.out).toContain(".git-credentials");
    expect(s.err).toBe("");
    const w = await vswarm({ sec, home }, "why", "--offline");
    expect(w.out).toContain("▼ vswarm why");
    expect(w.out).toMatch(/accept\s+vswarm ok \d+/);
    expect(w.out).toContain("policy: WARN is allowed (the default)");
  }, 120_000);

  test("the help table: a long command gets its description on the next line, long descriptions wrap", () => {
    const short = helpRow("vswarm scan", "everything", 80, 20);
    expect(short.gap).toBe(" ".repeat(20 - "vswarm scan".length + 2));
    const long = helpRow("vswarm guard on [--ignore-scripts] [--sandbox] [--strict]", "a b c", 80, 20);
    expect(long.gap.startsWith("\n")).toBe(true);
    const wrapped = helpRow("x", "word ".repeat(30).trim(), 60, 20);
    expect(wrapped.desc.length).toBeGreaterThan(1);
    expect(wrapped.desc.every((l) => l.length <= 60 - 24 || !l.includes(" "))).toBe(true);
  });

  test("completions know watch, team, try and the new commands", () => {
    for (const sh of ["bash", "zsh"]) {
      const t = completion(sh);
      for (const w of ["watch)", "team)", "try)", "why", "policy", "fix", "ok"]) expect(t).toContain(w);
    }
  });
});

void (null as unknown as Verdict);
