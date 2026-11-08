// vswarm setup, driven with scripted answers: a fake home (test/ui-fixture), its state, agent folder and sealing key
// in temp folders, a throwaway sshd on 127.0.0.1 and throwaway keys. The background watch, the install guard and the
// AI tool inspection are stand-ins that only record that they were asked for: nothing is installed on this machine.
// The gate and agent protect are the real ones, on the fake home's ssh config. SSH_AUTH_SOCK is removed for the file.
import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listVaults, protectKey, startAgent, type Agent } from "../src/sec/agent";
import type { Ctx } from "../src/sec/ctx";
import { check } from "../src/sec/engine";
import { fixCommand } from "../src/sec/fix";
import { readPolicy, savePolicy } from "../src/sec/policy";
import { GATE_START } from "../src/sec/sshblocks";
import { files, loadAccepted, loadBaseline, useKeyStore } from "../src/sec/store";
import { gate } from "../src/setup";
import { keysOf, pickHosts, runSetup, type SetupDeps } from "../src/wizard";
import { reset } from "./isolate";
import { fakeMachine, plant, type FakeMachine } from "./ui-fixture";

const WIN = process.platform === "win32";
const SSHD = existsSync("/usr/sbin/sshd");
const savedSock = process.env.SSH_AUTH_SOCK;
delete process.env.SSH_AUTH_SOCK;
afterAll(() => {
  if (savedSock !== undefined) process.env.SSH_AUTH_SOCK = savedSock;
  reset("VSWARM_SEC_DIR");
  reset("VSWARM_AGENT_DIR");
  useKeyStore(undefined);
});

const envNoAgent = () => {
  const e: Record<string, string | undefined> = { ...process.env };
  delete e.SSH_AUTH_SOCK;
  return e;
};

async function sh(cmd: string[]) {
  const p = Bun.spawn(cmd, { env: envNoAgent(), stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { out, err, code };
}

async function keygen(dir: string, name: string) {
  const f = join(dir, name);
  expect((await sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", `test-${name}`, "-f", f])).code).toBe(0);
  return f;
}

/** What the wizard writes to stderr, while fn runs. */
async function captured<T>(fn: () => Promise<T>): Promise<{ r: T; out: string }> {
  const write = process.stderr.write.bind(process.stderr);
  let out = "";
  (process.stderr as any).write = (s: string | Uint8Array) => ((out += typeof s === "string" ? s : Buffer.from(s).toString()), true);
  try {
    return { r: await fn(), out };
  } finally {
    (process.stderr as any).write = write;
  }
}

/** Answers by the question: a list of [pattern, answer]; a question nobody scripted fails the test. */
function script(rules: [RegExp, string | boolean][]) {
  const asked: string[] = [];
  const answer = (q: string) => {
    asked.push(q);
    const r = rules.find(([re]) => re.test(q));
    if (!r) throw new Error(`unscripted question: ${q}`);
    return r[1];
  };
  return {
    asked,
    ask: async (q: string) => String(answer(q)),
    yes: async (q: string) => answer(q) === true,
  };
}

interface Rig {
  m: FakeMachine;
  key: string;
  protectCfg: string;
  calls: string[];
  deps: (s: ReturnType<typeof script>, over?: Partial<SetupDeps>) => SetupDeps;
  stop: () => void;
}

/** A fake machine with an ssh config naming prod-test (a throwaway sshd that accepts `key`) and github.com. */
async function rig(opt: { sshd?: boolean; plantCases?: string[] } = {}): Promise<Rig> {
  const root = mkdtempSync(join(tmpdir(), "vs-setup-"));
  const m = await fakeMachine(root, { windows: false });
  // A machine setup has never seen: no starting point yet (the fixture takes one), so only what is always wrong shows.
  rmSync(files.baseline(), { force: true });
  if (opt.plantCases?.length) plant(m, ...opt.plantCases);
  mkdirSync(join(m.home, ".ssh"), { recursive: true });
  const key = await keygen(join(m.home, ".ssh"), "prod_ed25519");
  let port = 9;
  const srv = join(root, "sshd");
  if (opt.sshd) {
    mkdirSync(srv);
    await keygen(srv, "host_key");
    writeFileSync(join(srv, "authorized_keys"), readFileSync(`${key}.pub`));
    port = 20000 + Math.floor(Math.random() * 20000);
    writeFileSync(join(srv, "config"), [
      `Port ${port}`, "ListenAddress 127.0.0.1", `HostKey ${join(srv, "host_key")}`, `PidFile ${join(srv, "pid")}`, "UsePAM no", "StrictModes no",
      "PasswordAuthentication no", "KbdInteractiveAuthentication no", `AuthorizedKeysFile ${join(srv, "authorized_keys")}`,
    ].join("\n") + "\n");
    expect((await sh(["/usr/sbin/sshd", "-f", join(srv, "config"), "-E", join(srv, "log")])).code).toBe(0);
    for (let i = 0; i < 30 && !existsSync(join(srv, "pid")); i++) await Bun.sleep(100);
  }
  const hosts = `Host prod-test\n    HostName 127.0.0.1\n    Port ${port}\n    IdentityFile ${key}\nHost github.com\n    User git\n`;
  writeFileSync(join(m.home, ".ssh", "config"), hosts);
  // agent protect's test logins read a copy without the gate block: its Match exec would run a real preflight.
  const protectCfg = join(root, "ssh_config");
  writeFileSync(protectCfg, hosts);
  const calls: string[] = [];
  let agent: Agent | undefined;
  let watch = false, guard = false, inspected = false;
  const ctx: Ctx = m.ctx;
  const deps = (s: ReturnType<typeof script>, over: Partial<SetupDeps> = {}): SetupDeps => ({
    home: m.home, platform: process.platform, interactive: true, auto: false, ask: s.ask, yes: s.yes,
    check: () => check(ctx, { offline: true }),
    watch: { on: () => watch, enable: async () => void (calls.push("watch"), (watch = true)) },
    guard: { on: async () => guard, enable: async () => void (calls.push("guard"), (guard = true)) },
    uninspected: async (r) => (inspected ? [] : r.scan.items.filter((i) => i.kind === "mcp").slice(0, 1)),
    inspect: async (servers) => void (calls.push(`inspect`, ...servers.map((x) => x.name)), (inspected = true)),
    gate: async (patterns) => (calls.push(`gate ${patterns.join(",")}`), gate(["ssh", ...patterns], m.home)),
    protect: (k) => protectKey(k, {}, {
      home: m.home, cfgPath: protectCfg, env: envNoAgent(), yes: s.yes,
      sshOpts: ["-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"],
      verdict: async () => "pass", policy: async () => "allow",
      agentOn: async () => {
        agent ??= await startAgent({ sock: join(m.agent, "agent.sock"), ctx, offline: true, notify: async () => {}, confirm: async () => false, log: () => {}, verdict: async () => "pass", policy: async () => "allow" });
        return agent.sock;
      },
    }),
    vaulted: () => listVaults().map((x) => x.v.path),
    fix: async (f, n) => void (await fixCommand(f, n, { self: ["vswarm"], yes: s.yes })),
    policy: { read: readPolicy, save: async (w) => void (await savePolicy(w)) },
    ...over,
  });
  const stop = () => {
    agent?.stop();
    try {
      process.kill(Number(readFileSync(join(srv, "pid"), "utf8")));
    } catch {}
    rmSync(root, { recursive: true, force: true });
  };
  return { m, key, protectCfg, calls, deps, stop };
}

describe("vswarm setup: the pieces", () => {
  test("hosts by number or name; what matches nothing is said, not guessed", () => {
    expect(pickHosts("2 prod-a 9 nope prod-a", ["prod-a", "prod-b"])).toEqual({ picked: ["prod-b", "prod-a"], unknown: ["9", "nope"] });
    expect(pickHosts("", ["a"])).toEqual({ picked: [], unknown: [] });
  });

  test.skipIf(WIN)("the keys production hosts log in with: their IdentityFile, or ssh's default keys that exist", async () => {
    const home = mkdtempSync(join(tmpdir(), "vs-setup-keys-"));
    try {
      mkdirSync(join(home, ".ssh"));
      const named = await keygen(join(home, ".ssh"), "deploy");
      const dflt = await keygen(join(home, ".ssh"), "id_ed25519");
      writeFileSync(join(home, ".ssh", "config"), `Host prod-a\n    IdentityFile ~/.ssh/deploy\nHost prod-b\n    HostName 10.0.0.2\n`);
      expect([...keysOf(home, ["prod-a", "prod-b", "prod-*"])]).toEqual([[named, ["prod-a"]], [dflt, ["prod-b"]]]);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});

describe.skipIf(WIN)("vswarm setup: one guided path", () => {
  test("without a terminal it prints the plan and changes nothing", async () => {
    const r = await rig();
    try {
      const s = script([]);
      const { r: code, out } = await captured(() => runSetup(r.deps(s, { interactive: false })));
      expect(code).toBe(0);
      expect(out).toContain("What vswarm setup would do here");
      expect(out).toContain("nothing was changed");
      expect(s.asked).toEqual([]);
      expect(r.calls).toEqual([]);
      expect(await loadBaseline()).toBeUndefined();
      expect(readFileSync(join(r.m.home, ".ssh", "config"), "utf8")).not.toContain(GATE_START);
    } finally {
      r.stop();
    }
  }, 60_000);

  test.skipIf(!SSHD)("every step answered: a finding marked as mine, the starting point, watch, guard, inspect, a production door and its key in the vault, the policy; then again: only what is missing", async () => {
    const r = await rig({ sshd: true, plantCases: ["Remote MCP server over plain http"] });
    try {
      let firstFinding = true;
      const s = script([
        [/^Finding \d+/, "o"],
        [/clean starting point/, true],
        [/Watch this computer/, true],
        [/Check package installs/, true],
        [/Inspect the 1 AI tool server/, true],
        [/Which of these are production/, "1 nope"],
        [/Put ~?.*prod_ed25519 in the key safe/, true],
        [/should production still work/, true],
      ]);
      const ask = s.ask;
      s.ask = async (q) => (/^Finding/.test(q) && !firstFinding ? (s.asked.push(q), "") : ((firstFinding = !/^Finding/.test(q) && firstFinding), ask(q)));
      const { r: code, out } = await captured(() => runSetup(r.deps(s)));
      expect(code).toBe(0);
      // 1 · the finding, in plain words, marked as mine.
      expect(out).toContain("An AI tool in Cursor talks over an unencrypted connection");
      expect(Object.values(await loadAccepted()).some((a) => /tickets/.test(a.title))).toBe(true);
      // 2 · the starting point.
      expect(await loadBaseline()).toBeDefined();
      // 3 · watch, guard and the inspection were asked for (stand-ins here).
      expect(r.calls).toEqual(["watch", "guard", "inspect", expect.any(String), "gate prod-test"]);
      // 4 · the door, written by vswarm gate ssh; a name not in the list is said and left out.
      const cfg = readFileSync(join(r.m.home, ".ssh", "config"), "utf8");
      expect(cfg).toContain(GATE_START);
      expect(cfg).toContain("Match originalhost prod-test ");
      expect(out).toContain("not in the list, left out: nope");
      // The key: tried on the server first, then into the vault, and the recovery code shown once.
      expect(out).toContain("prod-test accepts it");
      expect(out).toContain("prod-test accepts it through vswarm agent");
      expect(out).toContain("recovery code");
      expect(out).toContain("password manager");
      expect(existsSync(r.key)).toBe(false);
      expect(listVaults().map((x) => x.v.path)).toEqual([r.key]);
      // 5 · the policy, set.
      expect(await readPolicy()).toMatchObject({ warn: "allow", set: true });
      expect(out).toContain("vswarm ui");
      expect(out).toContain("vswarm uninstall");

      // Again: what is on is said, and nothing done twice.
      const again = script([[/^Finding \d+/, ""], [/Any more production servers/, ""]]);
      r.calls.length = 0;
      const second = await captured(() => runSetup(r.deps(again)));
      expect(second.out).toContain("Already set up");
      expect(second.out).toContain("already have a starting point");
      expect(second.out).toContain("background watch is on");
      expect(second.out).toContain("doors (gates) stay as they are: prod-test");
      expect(again.asked.filter((q) => !/^Finding|Any more production/.test(q))).toEqual([]);
      expect(r.calls).toEqual([]);
    } finally {
      r.stop();
    }
  }, 120_000);

  test("--yes: the recommended answers, said as they are taken; no production hosts picked and no key moved", async () => {
    const r = await rig();
    try {
      const s = script([]);
      const { out } = await captured(() => runSetup(r.deps(s, { auto: true })));
      expect(s.asked).toEqual([]);
      expect(out).toContain("(--yes)");
      expect(await loadBaseline()).toBeDefined();
      expect(r.calls.slice(0, 2)).toEqual(["watch", "guard"]);
      expect(r.calls.some((c) => c.startsWith("gate"))).toBe(false);
      expect(existsSync(r.key)).toBe(true);
      expect((await readPolicy()).set).toBe(false);
      expect(out).toContain("which servers are production is yours to say");
    } finally {
      r.stop();
    }
  }, 60_000);

  test("the starting point is refused over a serious finding nobody marked as theirs, as vswarm baseline refuses it", async () => {
    const r = await rig({ plantCases: ["MCP server added to Cursor that downloads and runs a script"] });
    try {
      const s = script([]);
      const { out } = await captured(() => runSetup(r.deps(s, { auto: true })));
      expect(out).toContain("Not recorded");
      expect(out).toContain("vswarm baseline --accept-high");
      expect(await loadBaseline()).toBeUndefined();
    } finally {
      r.stop();
    }
  }, 60_000);

  test("in Thai: the same steps in Thai, command names as they are typed", async () => {
    const r = await rig();
    const prev = process.env.VSWARM_LANG;
    process.env.VSWARM_LANG = "th";
    try {
      const s = script([]);
      // macOS's words, whichever system runs the test: the notice is said before anything is turned on.
      const { out } = await captured(() => runSetup(r.deps(s, { interactive: false, platform: "darwin" })));
      expect(out).toContain("สิ่งที่ vswarm setup จะทำในเครื่องนี้");
      expect(out).toContain("vswarm setup --yes");
      expect(out).toContain("Background Items Added: vswarm");
    } finally {
      process.env.VSWARM_LANG = prev;
      r.stop();
    }
  }, 60_000);
});
