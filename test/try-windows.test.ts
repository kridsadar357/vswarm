// vswarm try on Windows: the command line it builds (everywhere), and the AppContainer sandbox itself (on the
// Windows CI runner only: it grants the sandbox read access to the runner's toolchains and, as the runner's
// administrator, a loopback exemption, which a developer's own machine should not get from a test).
import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { makeBox, observe } from "../src/sec/try";
import { containerSid, loopbackExempt, winArg, winCommandLine, winEnv } from "../src/sec/try/windows";

const RUNNER = process.platform === "win32" && !!process.env.GITHUB_ACTIONS;

describe("vswarm try on Windows: the command line", () => {
  test("arguments are quoted as the C runtime splits them", () => {
    expect(winArg("plain")).toBe("plain");
    expect(winArg("two words")).toBe('"two words"');
    expect(winArg('say "hi"')).toBe('"say \\"hi\\""');
    expect(winArg("C:\\dir with space\\")).toBe('"C:\\dir with space\\\\"');
    expect(winArg("")).toBe('""');
  });

  test("a .cmd runs through cmd.exe, and an argument cmd.exe would read is refused", () => {
    const which = (c: string) => (c === "npm" ? "C:\\Program Files\\nodejs\\npm.cmd" : c === "node" ? "C:\\Program Files\\nodejs\\node.exe" : null);
    expect(winCommandLine(["node", "-e", "1+1"], which)).toBe('"C:\\Program Files\\nodejs\\node.exe" -e 1+1');
    expect(winCommandLine(["npm", "install"], which)).toMatch(/cmd\.exe"? \/d \/s \/c ""C:\\Program Files\\nodejs\\npm\.cmd" install"$/);
    expect(() => winCommandLine(["npm", "run", "x&calc"], which)).toThrow("cmd.exe");
  });
});

describe.skipIf(!RUNNER)("vswarm try on Windows: the AppContainer", () => {
  const secret = join(homedir(), "vswarm-try-secret.txt");

  test("the code runs in its box, with a fake profile; your profile, the network and what it leaves running are closed off", async () => {
    writeFileSync(secret, "not for the sandbox");
    // A toolchain's programs are open to the sandbox; the login beside them is not.
    const cargo = join(homedir(), ".cargo");
    mkdirSync(join(cargo, "bin"), { recursive: true });
    writeFileSync(join(cargo, "credentials.toml"), '[registry]\ntoken = "not-a-real-token"\n');
    const box = makeBox("wintest-");
    try {
      // Reads your profile: refused. Writes its own work folder: fine. Its USERPROFILE is the box's.
      const read = await observe(box, ["cmd", "/c", "type", secret], { net: "none", timeoutMs: 60_000 });
      expect({ exit: read.exit === 0, out: read.output }).toMatchObject({ exit: false, out: expect.stringContaining("Access is denied") });
      const token = await observe(box, ["cmd", "/c", "type", join(cargo, "credentials.toml")], { net: "none", timeoutMs: 60_000 });
      expect({ exit: token.exit === 0, out: token.output }).toMatchObject({ exit: false, out: expect.stringContaining("Access is denied") });
      // Modify, not full control: the code cannot open its box to anyone else.
      const acl = await observe(box, ["icacls", ".", "/grant", "*S-1-1-0:F"], { net: "none", timeoutMs: 60_000 });
      expect({ exit: acl.exit === 0, out: acl.output }).toMatchObject({ exit: false });
      const write = await observe(box, ["cmd", "/c", "echo made> made.txt & echo %USERPROFILE%"], { net: "none", timeoutMs: 60_000 });
      expect({ exit: write.exit, out: write.output }).toMatchObject({ exit: 0 });
      expect(readFileSync(join(box.work, "made.txt"), "utf8").trim()).toBe("made");
      expect(write.output).toContain(box.home);
      // No network at all with --net none.
      const net = await observe(box, ["curl.exe", "-sS", "-m", "8", "--noproxy", "*", "https://example.com"], { net: "none", timeoutMs: 60_000 });
      expect(net.exit).not.toBe(0);
      // Node runs (Program Files is open to every app), and finds neither your profile nor your files.
      if (Bun.which("node")) {
        const n = await observe(box, ["node", "-e", `const fs=require("fs");let r;try{fs.readFileSync(${JSON.stringify(secret)});r="read"}catch(e){r=e.code}console.log(require("os").homedir()+" "+r)`], { net: "none", timeoutMs: 60_000 });
        expect({ exit: n.exit, out: n.output }).toMatchObject({ exit: 0, out: expect.stringContaining(`${box.home} EPERM`) });
      }
      // Something left running in the background is listed and stopped with the sandbox.
      const bg = await observe(box, ["cmd", "/c", "start /b cmd /d /c for /l %i in (0,0,1) do @rem"], { net: "none", timeoutMs: 60_000 });
      expect({ left: bg.left.map((l) => l.command), timedOut: bg.timedOut, out: bg.output }).toMatchObject({ left: expect.arrayContaining([expect.stringMatching(/cmd\.exe$/i)]), timedOut: false });
      expect(bg.runFindings.some((f) => f.id === "try:leftover")).toBe(true);
      // What Node cannot do in an AppContainer: make the named pipes its child processes talk through.
      if (Bun.which("node")) {
        writeFileSync(join(box.work, "pipe.js"), `require("net").createServer().listen("\\\\.\\pipe\\vs-test-" + process.pid).on("error", (e) => console.log("pipe " + e.code));\n`);
        expect((await observe(box, ["node", "pipe.js"], { net: "none", timeoutMs: 30_000 })).output).toContain("pipe EACCES");
      }
      // The box is closed to the sandbox again after each run.
      expect((Bun.spawnSync(["icacls", box.dir]).stdout.toString())).not.toContain(containerSid());
    } finally {
      rmSync(secret, { force: true });
      rmSync(join(cargo, "credentials.toml"), { force: true });
      rmSync(box.dir, { recursive: true, force: true });
    }
  }, 240_000);

  test("with the loopback exemption: only vswarm's proxy, which lets registries through and records the rest", async () => {
    const sid = containerSid();
    // The runner is an administrator; on a real machine vswarm try asks Windows for this once.
    Bun.spawnSync(["CheckNetIsolation.exe", "LoopbackExempt", "-a", `-p=${sid}`]);
    expect(await loopbackExempt(sid)).toBe(true);
    const box = makeBox("wintest-net-");
    try {
      const reg = await observe(box, ["curl.exe", "-sS", "--ssl-no-revoke", "-m", "20", "-o", "NUL", "-w", "%{http_code}", "https://registry.npmjs.org/"], { net: "registries", timeoutMs: 90_000 });
      expect(reg.output).toContain("200");
      // (--ssl-no-revoke: Windows' TLS checks revocation by fetching from the CA directly, which the sandbox cannot.)
      // Around the proxy: no internet of its own.
      const direct = await observe(box, ["curl.exe", "-sS", "-m", "8", "--noproxy", "*", "https://example.com"], { net: "registries", timeoutMs: 60_000 });
      expect(direct.exit).not.toBe(0);
      // Through the proxy, a host that is not a registry: refused, and recorded.
      const other = await observe(box, ["curl.exe", "-sS", "--ssl-no-revoke", "-m", "20", "https://example.com"], { net: "registries", timeoutMs: 60_000 });
      expect(other.exit).not.toBe(0);
      expect(JSON.stringify(other.runFindings)).toContain("example.com");
      expect(winEnv(box, 3128).HTTPS_PROXY).toBe("http://127.0.0.1:3128");
    } finally {
      Bun.spawnSync(["CheckNetIsolation.exe", "LoopbackExempt", "-d", `-p=${sid}`]);
      rmSync(box.dir, { recursive: true, force: true });
    }
  }, 240_000);

  test("the launcher reports a sandbox that could not start instead of running the code outside it", async () => {
    const box = makeBox("wintest-bad-");
    try {
      const r = await observe(box, ["C:\\no\\such\\program.exe"], { net: "none", timeoutMs: 30_000 });
      expect(r.exit).toBe(125);
      expect(r.output).toContain("the Windows sandbox did not start");
      expect(existsSync(join(box.dir, "sandbox.json"))).toBe(true);
    } finally {
      rmSync(box.dir, { recursive: true, force: true });
    }
  }, 60_000);
});
