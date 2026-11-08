// Reading ~/.ssh/config without running it, and whether the hosts behind the gate are still there. The only network
// connections here go to 127.0.0.1 ports this test opens and closes; names resolve through stand-ins, never DNS.
import { describe, expect, test } from "bun:test";
import { homedir } from "node:os";
import { join } from "node:path";
import { dead, lastUsed, probeAll, probeHost, probeText, pruneHosts } from "../src/sec/probe";
import { blocks, expandPath, globMatch, hostView, listMatch, literal, namedHosts, ownHosts, productionKeys } from "../src/sec/sshconfig";
import { hostHealth } from "../src/setup";

const CFG = `# >>> vswarm agent >>>
Match originalhost prod-*,db1 !exec "/v/vswarm agent check --host %n --hostname %h --port %p"
    ProxyCommand /bin/sh -c 'exit 1'
Match originalhost prod-*,db1
    IdentityAgent "/a/agent.sock"
    IdentityFile "/h/.ssh/everything"
# <<< vswarm agent <<<

# >>> vswarm gate >>>
Match originalhost prod-*,db1,10.0.0.7 !exec "/v/vswarm preflight --quiet --host %h"
    ProxyCommand /bin/sh -c 'exit 1'
# <<< vswarm gate <<<

Host db1
    HostName 192.0.2.10
    Port 2222
    IdentityFile ~/.ssh/db
Host prod-web prod-api
    IdentityFile=~/.ssh/prod
    User deploy
Host * !bastion
    ServerAliveInterval 30
Match user root exec "true"
    IdentityFile ~/.ssh/root
`;

describe("ssh config, read without running it", () => {
  test("patterns: * and ?, case-insensitive; a negation that matches wins", () => {
    expect(globMatch("prod-*", "PROD-web")).toBe(true);
    expect(globMatch("db?", "db12")).toBe(false);
    expect(listMatch(["*", "!bastion"], "bastion")).toBe(false);
    expect(listMatch(["*", "!bastion"], "db1")).toBe(true);
    expect(literal("db1") && literal("10.0.0.7") && !literal("prod-*") && !literal("!x")).toBe(true);
  });

  test("a host's view: first value wins, IdentityFile adds up, vswarm's own blocks left out on request, Match with other criteria skipped", () => {
    const home = "/h";
    expect(hostView(CFG, "db1", { home, withoutOwn: true })).toEqual({ identityFiles: ["/h/.ssh/db"], hostname: "192.0.2.10", port: 2222, skipped: 1 });
    expect(hostView(CFG, "db1", { home }).identityFiles).toEqual(["/h/.ssh/everything", "/h/.ssh/db"]);
    expect(hostView(CFG, "prod-api", { home, withoutOwn: true })).toMatchObject({ identityFiles: ["/h/.ssh/prod"], user: "deploy" });
    expect(namedHosts(CFG)).toEqual(["db1", "prod-web", "prod-api"]);
    expect(ownHosts(CFG)).toEqual({ agent: ["prod-*", "db1"], gate: ["prod-*", "db1", "10.0.0.7"] });
    expect(blocks("Host a\n  IdentityFile \"/p q/k\"\n")[1].options).toEqual([{ key: "identityfile", value: "/p q/k" }]);
    expect(expandPath("~/.ssh/k", "/h")).toBe("/h/.ssh/k");
    expect(expandPath("k", "/h")).toBe("/h/.ssh/k");
    expect(expandPath("%d/x", "/h")).toBe("/h/x");
  });

  test("production keys: those the gated hosts name, and ssh's defaults for a gated host that names none", () => {
    const keys = productionKeys(CFG, "/h");
    expect(keys.has("/h/.ssh/db")).toBe(true);
    expect(keys.has("/h/.ssh/prod")).toBe(true);
    // 10.0.0.7 has no Host block: it logs in with the default keys.
    expect(keys.has("/h/.ssh/id_ed25519")).toBe(true);
    expect(keys.has("/h/.ssh/root")).toBe(false);
    expect(keys.has("/h/.ssh/everything")).toBe(false);
    expect(productionKeys("Host db1\n  IdentityFile ~/.ssh/db\n", "/h").size).toBe(0);
  });
});

describe("hosts that no longer answer", () => {
  test("DNS, then the ssh port, 2 seconds each: an open port answers, a closed one refuses, a name that does not resolve is said", async () => {
    const open = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {}, open() {} } });
    const closed = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
    const closedPort = closed.port;
    closed.stop(true);
    try {
      const a = await probeHost("local", { hostname: "127.0.0.1", port: open.port });
      expect(a).toMatchObject({ tcp: "open", addresses: ["127.0.0.1"] });
      expect(dead(a)).toBe(false);
      const b = await probeHost("gone", { hostname: "127.0.0.1", port: closedPort });
      expect(b.tcp).toBe("refused");
      expect(dead(b)).toBe(true);
      expect(probeText(b)).toContain("refuses the connection");
      const c = await probeHost("old-db.example.invalid", { resolve: async () => Promise.reject(Object.assign(new Error("x"), { code: "ENOTFOUND" })) });
      expect(c.dns).toBe("no such name (DNS)");
      expect(c.tcp).toBe("skipped");
      // A name server that never answers, and an address that never answers: each gives up at the limit.
      const t0 = Date.now();
      const slow = await probeHost("slow", { timeoutMs: 300, resolve: () => new Promise(() => {}) });
      expect(slow.dns).toContain("no DNS answer");
      const quiet = await probeHost("quiet", { hostname: "192.0.2.1", timeoutMs: 300, connect: () => new Promise(() => {}) });
      expect(quiet.tcp).toBe("timeout");
      const hang = await probeHost("hang", { hostname: "192.0.2.1", timeoutMs: 300, connect: async (_ip, _p, ms) => (await Bun.sleep(ms), "timeout") });
      expect(hang.tcp).toBe("timeout");
      expect(Date.now() - t0).toBeLessThan(3000);
    } finally {
      open.stop(true);
    }
  });

  test("all at once, each at the HostName and Port the config gives it; patterns are not probed", async () => {
    const seen: string[] = [];
    const ps = await probeAll(["prod-*", "db1", "10.0.0.7"], CFG, { connect: async (ip, port) => (seen.push(`${ip}:${port}`), ip === "192.0.2.10" ? "open" : "timeout") });
    expect(ps.map((p) => [p.host, p.target, p.port, p.tcp])).toEqual([["db1", "192.0.2.10", 2222, "open"], ["10.0.0.7", "10.0.0.7", 22, "timeout"]]);
    expect(seen.sort()).toEqual(["10.0.0.7:22", "192.0.2.10:2222"]);
  });

  test("when the agent last signed a login to a host, from the audit log", () => {
    const day = 86_400_000;
    const e = [
      { at: Date.now() - 40 * day, event: "sign", reason: "WARN · ssh login as root to db1 · alg ssh-ed25519" },
      { at: Date.now() - 3 * day, event: "sign", reason: "PASS · ssh login as root to db1 · alg ssh-ed25519" },
      { at: Date.now(), event: "refuse", reason: "x · ssh login as root to 10.0.0.7 · alg ssh-ed25519" },
      { at: Date.now(), event: "sign", reason: "PASS · ssh login as root to db10 · alg ssh-ed25519" },
    ];
    expect(lastUsed(["db1", "10.0.0.7", "db"], e)).toEqual({ db1: 3, "10.0.0.7": undefined, db: undefined });
  });

  test("doctor and gate status: one line per host, with when it was last used; prune offers only dead hosts, and only removes what you confirm", async () => {
    const deps = { connect: async (ip: string) => (ip === "192.0.2.10" ? ("open" as const) : ("refused" as const)) };
    const lines = (await hostHealth(CFG, deps)).join("\n");
    expect(lines).toContain("db1");
    expect(lines).toContain("192.0.2.10:2222 answers");
    expect(lines).toContain("10.0.0.7:22 refuses the connection");
    expect(lines).toContain("vswarm gate ssh --prune");
    const asked: string[] = [];
    const keep = await pruneHosts(["prod-*", "db1", "10.0.0.7"], { cfgText: CFG, what: "gate", deps, say: () => {}, ask: async (q) => (asked.push(q), true) });
    expect(asked).toEqual(["10.0.0.7: 10.0.0.7:22 refuses the connection. Remove it from the ssh gate?"]);
    expect(keep).toEqual(["prod-*", "db1"]);
    expect(await pruneHosts(["prod-*", "10.0.0.7"], { cfgText: CFG, what: "agent", deps, say: () => {}, ask: async () => false })).toBeUndefined();
    expect(await hostHealth("Host x\n")).toEqual([]);
  });

  test("probes run where they are asked for only: preflight and scans have none", async () => {
    const src = await Bun.file(join(import.meta.dir, "../src/sec/gate.ts")).text();
    const eng = await Bun.file(join(import.meta.dir, "../src/sec/engine.ts")).text();
    expect(src.includes("probe") || eng.includes("probe")).toBe(false);
    expect(homedir()).toBeTruthy();
  });
});
