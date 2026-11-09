// When vswarm itself cannot run (its folder removed, Bun moved), what it put in your files must not lock you out with
// the wrong reason: ssh says vswarm cannot run (not that the machine failed), installs go ahead with a warning, and
// the launcher says what moved. Everything here runs in temp folders; ssh is only pointed at a config file of its own.
import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentSshBlock } from "../src/sec/agent";
import { guardBlock } from "../src/sec/pkg";
import { recordManaged, stripManaged } from "../src/sec/store";
import { CLI, launcherText, refreshSshBlocks, sshGate } from "../src/setup";
import { VERSION } from "../src/home";

const WIN = process.platform === "win32";
const tmp = (p: string) => mkdtempSync(join(tmpdir(), `vs-lockout-${p}-`));

/** A stand-in launcher: answers --version, and gives `code` for anything else. */
const fakeLauncher = (path: string, code: number) =>
  writeFileSync(path, `#!/bin/sh\n[ "$1" = --version ] && { echo 9.9.9; exit 0; }\nexit ${code}\n`, { mode: 0o755 });

async function ssh(cfg: string, host: string) {
  const p = Bun.spawn(["ssh", "-F", cfg, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", host, "true"], { stdout: "pipe", stderr: "pipe" });
  const [code, err] = await Promise.all([p.exited, new Response(p.stderr).text()]);
  return { code, err };
}

describe.skipIf(WIN || !Bun.which("ssh"))("ssh blocks: refused for the right reason", () => {
  for (const kind of ["gate", "agent"] as const) {
    test(`${kind}: a missing launcher says vswarm cannot run; a refusing one says the machine did not pass`, async () => {
      const d = join(tmp(kind), "O'Brien dir");
      mkdirSync(d);
      const launcher = join(d, "vswarm");
      const block = kind === "gate" ? sshGate(["vs-lockout-test"], [launcher], { win: false }) : agentSshBlock(["vs-lockout-test"], join(d, "agent.sock"), { launcher: [launcher], win: false });
      const cfg = join(d, "config");
      writeFileSync(cfg, block + "\n", { mode: 0o600 });

      const gone = await ssh(cfg, "vs-lockout-test");
      expect(gone.code).not.toBe(0);
      expect(gone.err).toContain("vswarm itself cannot run");
      expect(gone.err).not.toContain("did not pass");

      fakeLauncher(launcher, 3);
      const refused = await ssh(cfg, "vs-lockout-test");
      expect(refused.code).not.toBe(0);
      expect(refused.err).toContain("not connecting");
      expect(refused.err).not.toContain("cannot run");
    }, 30_000);
  }

  test("a launcher path with $, ` or \\ is refused rather than written into a shell line", () => {
    expect(() => sshGate(["prod"], ["/a$b/vswarm"], { win: false })).toThrow("$");
    expect(() => agentSshBlock(["prod"], "/s", { launcher: ["/a`b/vswarm"], win: false })).toThrow("$");
  });
});

describe.skipIf(WIN)("install guard: vswarm gone, installs go ahead with a warning", () => {
  async function npm(rc: string, d: string) {
    const out: Record<string, { code: number; err: string; log: string }> = {};
    for (const sh of [["zsh", "-f"], ["bash", "--norc", "--noprofile"]]) {
      if (!Bun.which(sh[0])) continue;
      writeFileSync(join(d, "log"), "");
      const p = Bun.spawn([...sh, "-c", `. "${rc}"; npm install left-pad`], { cwd: d, env: { PATH: `${d}/bin:/usr/bin:/bin`, HOME: d }, stdout: "pipe", stderr: "pipe" });
      const [code, err] = await Promise.all([p.exited, new Response(p.stderr).text()]);
      out[sh[0]] = { code, err, log: readFileSync(join(d, "log"), "utf8") };
    }
    return Object.values(out);
  }

  test("missing launcher: npm runs, and says it was not checked", async () => {
    const d = tmp("guard");
    mkdirSync(join(d, "bin"));
    writeFileSync(join(d, "bin", "npm"), `#!/bin/sh\necho "npm $*" >> "${d}/log"\n`, { mode: 0o755 });
    const launcher = join(d, "vswarm");
    const rc = join(d, "rc");
    writeFileSync(rc, guardBlock(launcher));
    for (const r of await npm(rc, d)) {
      expect(r).toMatchObject({ code: 0, log: "npm install left-pad\n" });
      expect(r.err).toContain("vswarm cannot run, so this install was not checked");
    }
    // vswarm there and refusing: npm does not run.
    fakeLauncher(launcher, 3);
    for (const r of await npm(rc, d)) expect(r).toMatchObject({ code: 3, log: "" });
    // vswarm there, and 127 from the check itself (the tool was not found): passed on, not taken for "vswarm gone".
    fakeLauncher(launcher, 127);
    for (const r of await npm(rc, d)) expect(r).toMatchObject({ code: 127, log: "" });
  }, 30_000);
});

describe.skipIf(WIN)("the launcher", () => {
  test("runs vswarm, or says Bun or vswarm moved and exits 127", async () => {
    const d = tmp("launcher");
    const ok = join(d, "ok"), noBun = join(d, "no-bun"), noCli = join(d, "no-cli");
    writeFileSync(ok, launcherText(process.execPath, CLI, false), { mode: 0o755 });
    writeFileSync(noBun, launcherText(join(d, "gone", "bun"), CLI, false), { mode: 0o755 });
    writeFileSync(noCli, launcherText(process.execPath, join(d, "gone", "cli.ts"), false), { mode: 0o755 });
    const run = async (f: string) => {
      const p = Bun.spawn([f, "--version"], { stdout: "pipe", stderr: "pipe" });
      return { code: await p.exited, out: (await new Response(p.stdout).text()).trim(), err: await new Response(p.stderr).text() };
    };
    expect(await run(ok)).toMatchObject({ code: 0, out: VERSION });
    for (const f of [noBun, noCli]) {
      const r = await run(f);
      expect(r.code).toBe(127);
      expect(r.err).toContain("no longer where it was installed");
    }
    expect(launcherText("C:\\b\\bun.exe", "C:\\v\\cli.ts", true)).toContain("exit /b 127");
  });
});

describe("after an update: the old refusal line in vswarm's own blocks is replaced", () => {
  const OLD_GATE = `# >>> vswarm gate >>>\n# Hosts below connect only after \`vswarm preflight\` passes. Remove with: vswarm gate remove\nMatch originalhost prod-* !exec "/v/vswarm preflight --quiet --host %h"\n    ProxyCommand /bin/sh -c 'echo "vswarm: not connecting: this machine did not pass preflight (the reason is above) · vswarm why" >&2; exit 1'\n# <<< vswarm gate <<<`;

  test("a block vswarm wrote is refreshed, with a backup, and is still recognised as vswarm's own", () => {
    const d = tmp("refresh");
    const cfg = join(d, "config");
    recordManaged(OLD_GATE + "\n");
    writeFileSync(cfg, `${OLD_GATE}\n\nHost db\n    HostName 10.0.0.5\n`);
    expect(refreshSshBlocks(cfg)).toBe(true);
    const now = readFileSync(cfg, "utf8");
    expect(now).toContain(`ProxyCommand /bin/sh -c "if /v/vswarm --version >/dev/null 2>&1; then echo 'vswarm: not connecting: this machine did not pass preflight (the reason is above) · vswarm why' >&2;`);
    expect(now).toContain("Host db\n    HostName 10.0.0.5\n");
    expect(stripManaged(now)).not.toContain("vswarm gate");
    expect(readdirSync(d).some((f) => f.startsWith("config.bak-vswarm-"))).toBe(true);
    // Already up to date: nothing to do.
    expect(refreshSshBlocks(cfg)).toBe(false);
  });

  test("the agent block too, keeping its keys and options", () => {
    const d = tmp("refresh-agent");
    const cfg = join(d, "config");
    const old = `# >>> vswarm agent >>>\n# Hosts below take their keys from \`vswarm agent\`, which signs only while this machine passes. Remove with: vswarm agent off\nMatch originalhost orca-prod !exec "/v/vswarm agent check --host %n --hostname %h --port %p"\n    ProxyCommand /bin/sh -c 'echo "vswarm agent: not connecting (the reason is above) · vswarm why" >&2; exit 1'\nMatch originalhost orca-prod\n    IdentityAgent "/h/.vswarm/agent/agent.sock"\n    IdentityFile "/h/.ssh/prod"\n    IdentitiesOnly yes\n# <<< vswarm agent <<<`;
    recordManaged(old + "\n");
    writeFileSync(cfg, `${old}\n\nHost orca-prod\n    HostName 192.0.2.10\n`);
    expect(refreshSshBlocks(cfg)).toBe(true);
    const now = readFileSync(cfg, "utf8");
    expect(now).toBe(old.replace(/    ProxyCommand .*\n/, agentSshBlock(["orca-prod"], "/h/.vswarm/agent/agent.sock", { launcher: ["/v/vswarm"], win: false }).split("\n").find((l) => l.includes("ProxyCommand"))! + "\n") + "\n\nHost orca-prod\n    HostName 192.0.2.10\n");
    expect(stripManaged(now)).not.toContain("vswarm agent >>>");
  });

  test("a block someone edited is left as it is", () => {
    const d = tmp("edited");
    const cfg = join(d, "config");
    const edited = OLD_GATE.replace("prod-*", "prod-*,db");
    writeFileSync(cfg, edited + "\n");
    expect(refreshSshBlocks(cfg)).toBe(false);
    expect(readFileSync(cfg, "utf8")).toBe(edited + "\n");
    expect(existsSync(join(d, "missing"))).toBe(false);
  });
});

describe.skipIf(WIN)("respond stops only the program the check found", () => {
  test("a process number now running something else is not taken for it", async () => {
    const { runsProgram } = await import("../src/sec/respond");
    expect(await runsProgram(process.pid, process.execPath)).toBe(true);
    expect(await runsProgram(process.pid, "/bin/ls")).toBe(false);
    expect(await runsProgram(1, "/sbin/launchd")).toBe(false);
    expect(await runsProgram(2 ** 22 + 7, process.execPath)).toBe(false);
  });
});
