// Command gates (cmdgate.ts), gcloud and az gates (cloudgate.ts), and the plain-text / stored-password findings
// (plaintext.ts). Every test works in temp folders: no real rc file, profile, gcloud or Azure folder is read or written.
import { describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addCmdGate, checkTool, cmdGateBlock, iniGet, CMDGATE_END, CMDGATE_START, decide, gateCmd, globMatch, loadCmdGates, mask, optValues, psCmdGateBlock,
  removeCmdGate, targets, uriHosts, type GateFiles,
} from "../src/sec/cmdgate";
import { cloudUninstall, executableOf, gateAz, gateGcloud, gatedCredential, gcloudHookOff, gcloudHookOn, gcloudHookStatus, iniSet, loadCloudGates, ungated, type CloudEnv } from "../src/sec/cloudgate";
import { myCnf, pgpassHosts, plainHosts, plaintext } from "../src/sec/plaintext";
import { readKept, setBlock } from "../src/setup";
import { recordManaged, saveLast, stripManaged } from "../src/sec/store";
import type { Ctx } from "../src/sec/ctx";
import type { Scan, Verdict } from "../src/sec/types";

const WIN = process.platform === "win32";
const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-gates-${tag}-`));
const CLI = join(import.meta.dir, "../src/cli.ts");
const at = (env: Record<string, string> = {}, home = "/nonexistent-home") => ({ env, home });
const hosts = (tool: string, ...args: string[]) => targets(tool, args, at()).hosts;
const ctxFor = (home: string): Ctx => ({ home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined });

async function withSec<T>(fn: (sec: string) => Promise<T> | T): Promise<T> {
  const prev = process.env.VSWARM_SEC_DIR;
  const prevGate = process.env.VSWARM_GATE_DIR;
  const sec = tmp("sec");
  process.env.VSWARM_SEC_DIR = sec;
  process.env.VSWARM_GATE_DIR = join(sec, "gate");
  try {
    return await fn(sec);
  } finally {
    if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
    else process.env.VSWARM_SEC_DIR = prev;
    if (prevGate === undefined) delete process.env.VSWARM_GATE_DIR;
    else process.env.VSWARM_GATE_DIR = prevGate;
  }
}

/** Console output of fn, so the commands' messages can be checked and do not clutter the test run. */
async function quiet(fn: () => Promise<unknown>): Promise<string> {
  const orig = console.log;
  let out = "";
  console.log = (...a: unknown[]) => void (out += a.join(" ") + "\n");
  try {
    await fn();
  } finally {
    console.log = orig;
  }
  return out;
}

describe("command gate: where a command connects", () => {
  test("telnet, ftp and nc: the first plain word, URIs and user@ dropped, nc -l connects nowhere", () => {
    expect(hosts("telnet", "-l", "admin", "Router.LAN", "23")).toEqual(["router.lan"]);
    expect(hosts("telnet", "telnet://sw1.example:2323")).toEqual(["sw1.example"]);
    expect(hosts("ftp", "-P", "2121", "files.example.com")).toEqual(["files.example.com"]);
    expect(hosts("ftp", "ftp://bob:hunter2@ftp.example.org/pub/x")).toEqual(["ftp.example.org"]);
    expect(hosts("ftp", "bob@ftp.example.org:pub/x")).toEqual(["ftp.example.org"]);
    expect(hosts("nc", "-w", "3", "10.0.0.5", "443")).toEqual(["10.0.0.5"]);
    expect(hosts("nc", "-lk", "8080")).toEqual([]);
    expect(hosts("ncat", "[2001:db8::1]:443")).toEqual(["2001:db8::1"]);
  });

  test("psql: -h, --host=, URIs with several hosts, host= conninfo, PGHOST, the local socket", () => {
    expect(hosts("psql", "-h", "db.prod.internal", "-U", "app", "orders")).toEqual(["db.prod.internal"]);
    expect(hosts("psql", "-hdb1.prod", "orders")).toEqual(["db1.prod"]);
    expect(hosts("psql", "--host=DB2.prod", "orders")).toEqual(["db2.prod"]);
    expect(hosts("psql", "postgres://app:s3cret@pg.prod.internal:5432/orders?sslmode=require")).toEqual(["pg.prod.internal"]);
    expect(hosts("psql", "postgresql://app@h1.prod:5432,h2.prod:5433/orders")).toEqual(["h1.prod", "h2.prod"]);
    expect(hosts("psql", "-d", "host=pg.prod port=5432 user=app password=s3cret dbname=orders")).toEqual(["pg.prod"]);
    expect(hosts("psql", "host='a.prod,b.prod' dbname=x")).toEqual(["a.prod", "b.prod"]);
    expect(hosts("psql", "postgresql:///orders")).toEqual(["localhost"]);
    expect(hosts("psql", "postgresql://%2Fvar%2Frun%2Fpostgresql/orders")).toEqual(["localhost"]);
    expect(hosts("psql", "orders")).toEqual(["localhost"]);
    expect(targets("psql", ["orders"], at({ PGHOST: "pg.env.prod" })).hosts).toEqual(["pg.env.prod"]);
    // pg_dump reads its host the same way.
    expect(hosts("pg_dump", "-h", "x.prod", "orders")).toEqual(["x.prod"]);
  });

  test("mysql, mongosh, redis-cli, sqlcmd", () => {
    expect(hosts("mysql", "-h", "my.prod", "-u", "root", "-pS3cret", "shop")).toEqual(["my.prod"]);
    expect(hosts("mysql", "--host=my2.prod", "-P", "3307")).toEqual(["my2.prod"]);
    expect(hosts("mysql", "-u", "root")).toEqual(["localhost"]);
    expect(targets("mysql", [], at({ MYSQL_HOST: "env.prod" })).hosts).toEqual(["env.prod"]);
    expect(hosts("mongosh", "mongodb+srv://u:p@cluster0.ab12.mongodb.net/shop")).toEqual(["cluster0.ab12.mongodb.net"]);
    expect(hosts("mongosh", "mongodb://u:p@m1.prod:27017,m2.prod:27017/shop?replicaSet=rs0")).toEqual(["m1.prod", "m2.prod"]);
    expect(hosts("mongosh", "--host", "rs0/m1.prod:27017,m2.prod")).toEqual(["m1.prod", "m2.prod"]);
    expect(hosts("mongosh", "10.1.2.3:27017/shop")).toEqual(["10.1.2.3"]);
    expect(hosts("mongosh", "-u", "admin", "shop")).toEqual(["localhost"]);
    expect(hosts("mongodump", "--uri=mongodb://u:p@md.prod/shop")).toEqual(["md.prod"]);
    expect(hosts("redis-cli", "-h", "cache.prod", "-a", "pass", "PING")).toEqual(["cache.prod"]);
    expect(hosts("redis-cli", "-u", "rediss://default:pw@cache2.prod:6380/0")).toEqual(["cache2.prod"]);
    expect(hosts("redis-cli")).toEqual(["localhost"]);
    expect(hosts("sqlcmd", "-S", "tcp:sql.prod,1433", "-U", "sa", "-P", "pw")).toEqual(["sql.prod"]);
    expect(hosts("sqlcmd", "-Ssql2.prod\\INST1")).toEqual(["sql2.prod"]);
    expect(hosts("sqlcmd", "-S", "np:\\\\sql3.prod\\pipe\\sql\\query")).toEqual(["sql3.prod"]);
    expect(hosts("sqlcmd", "-S", ".")).toEqual(["localhost"]);
    expect(targets("sqlcmd", [], at({ SQLCMDSERVER: "env-sql.prod" })).hosts).toEqual(["env-sql.prod"]);
  });

  test("gcloud and az: the configuration, project or subscription, from flags, environment or their own files", () => {
    const home = tmp("cloud");
    const g = join(home, ".config", "gcloud");
    mkdirSync(join(g, "configurations"), { recursive: true });
    writeFileSync(join(g, "active_config"), "prod\n");
    writeFileSync(join(g, "configurations", "config_prod"), "[core]\r\nproject = shop-prod\r\naccount = a@example.com\r\n");
    expect(targets("gcloud", ["compute", "instances", "list"], at({}, home)).hosts).toEqual(["prod", "shop-prod"]);
    expect(targets("gcloud", ["--project=other-prod", "run", "deploy"], at({}, home)).hosts).toEqual(["prod", "other-prod"]);
    expect(targets("gcloud", ["run", "deploy"], at({ CLOUDSDK_CORE_PROJECT: "envproj" }, home)).hosts).toEqual(["prod", "envproj"]);
    mkdirSync(join(home, ".azure"));
    writeFileSync(join(home, ".azure", "azureProfile.json"), "\uFEFF" + JSON.stringify({ subscriptions: [{ name: "Dev", id: "1111", isDefault: false }, { name: "Prod-Payments", id: "2222", isDefault: true }] }));
    expect(targets("az", ["vm", "list"], at({}, home)).hosts).toEqual(["prod-payments", "2222"]);
    expect(targets("az", ["vm", "list", "--subscription", "Dev"], at({}, home)).hosts).toEqual(["dev"]);
  });

  test("options and URIs never hand back a password", () => {
    expect(optValues(["-h", "a", "-hb", "--host=c", "--host", "d", "--", "-h", "e"], ["-h"], ["--host"])).toEqual(["a", "b", "c", "d"]);
    expect(uriHosts("postgres://user:pa:ss@h.example/db")).toEqual(["h.example"]);
    expect(uriHosts("not a uri")).toBeUndefined();
    const all = ["psql", "mysql", "mongosh", "redis-cli", "sqlcmd", "ftp", "telnet"].flatMap((t) =>
      targets(t, ["-pS3cretPW", "-a", "S3cretPW", "-P", "S3cretPW", "postgres://u:S3cretPW@h.prod/x", "mongodb://u:S3cretPW@m.prod/x", "ftp://u:S3cretPW@f.prod/"], at()).hosts);
    expect(all.join(" ")).not.toContain("S3cretPW");
    expect(mask("postgres://app:s3cret@pg.prod/orders")).toBe("postgres://app:•••@pg.prod/orders");
    expect(mask("ftp bob:hunter2@files.example")).toBe("ftp bob:•••@files.example");
    expect(mask("db.prod.internal")).toBe("db.prod.internal");
  });
});

describe("command gate: when it checks", () => {
  test("patterns like ssh's: * and ?, case-insensitive, ! excludes", () => {
    expect(globMatch("*.prod.internal", "DB.prod.internal")).toBe(true);
    expect(globMatch("db?.prod", "db1.prod")).toBe(true);
    expect(globMatch("*.prod", "prod")).toBe(false);
    expect(decide("psql", ["-h", "db.prod.internal"], ["*.prod.internal"], at())).toEqual({ check: true, host: "db.prod.internal", pattern: "*.prod.internal" });
    expect(decide("psql", ["-h", "localhost"], ["*.prod.internal"], at()).check).toBe(false);
    expect(decide("psql", ["-h", "canary.prod.internal"], ["*.prod.internal", "!canary.*"], at()).check).toBe(false);
    // No patterns: every run is checked.
    expect(decide("telnet", ["router.lan"], [], at())).toEqual({ check: true, host: "router.lan" });
    expect(decide("telnet", ["router.lan"], ["!router.lan"], at()).check).toBe(false);
  });

  test("an unknown tool: any argument matching counts, and the argument itself is never named", () => {
    const d = decide("mytool", ["--password", "prod-pass", "connect"], ["prod-*"], at());
    expect(d).toEqual({ check: true, pattern: "prod-*" });
    expect(decide("mytool", ["deploy", "--target", "ops@build.prod/x"], ["build.prod"], at())).toEqual({ check: true, pattern: "build.prod" });
    expect(decide("mytool", ["deploy", "staging"], ["prod-*"], at()).check).toBe(false);
  });

  test("names and patterns that would break the shell, or tools with a real gate, are refused", () => {
    for (const bad of ["ssh", "aws", "kubectl", "gcloud", "az", "command", "cd", "vswarm", "a b", "x;y", "$(id)", "-rf"]) expect(() => checkTool(bad)).toThrow();
    for (const good of ["telnet", "redis-cli", "pg_dump", "sqlcmd", "mytool2"]) expect(() => checkTool(good)).not.toThrow();
    return withSec(async () => {
      const where: GateFiles = { files: [join(tmp("rc"), ".zshrc")], body: (g) => cmdGateBlock("/v/vswarm", g) };
      await expect(addCmdGate("psql", ["prod'; rm -rf ~"], where)).rejects.toThrow("not a host pattern");
      await expect(gateCmd(["ssh", "prod-*"], where)).rejects.toThrow("vswarm gate ssh");
    });
  });
});

describe("command gate: the shell functions", () => {
  test.skipIf(WIN)("zsh and bash: BLOCK stops the real command, PASS runs it, `command` skips the gate", async () => {
    const d = join(tmp("sh"), "O'Brien dir");
    mkdirSync(d, { recursive: true });
    const log = join(d, "log");
    // A stand-in vswarm: exits 3 when the arguments name a blocked host, as cmdgate does on BLOCK.
    writeFileSync(join(d, "vswarm"), `#!/bin/sh\necho "vswarm $*" >> "${log}"\ncase "$*" in *blocked.prod*) exit 3;; esac\nexit 0\n`, { mode: 0o755 });
    for (const t of ["psql", "redis-cli", "telnet"]) writeFileSync(join(d, t), `#!/bin/sh\necho "${t} $*" >> "${log}"\n`, { mode: 0o755 });
    const block = cmdGateBlock(join(d, "vswarm"), { tools: { psql: { patterns: ["*.prod", "!canary.prod"], at: 0 }, "redis-cli": { patterns: [], at: 0 }, telnet: { patterns: [], at: 0 } } });
    expect(block.startsWith(CMDGATE_START) && block.endsWith(CMDGATE_END)).toBe(true);
    expect(block).toContain("function psql { ");
    expect(block).toContain("cmdgate psql '*.prod' '!canary.prod' -- \"$@\" || return $?; command psql \"$@\"; }");
    expect(block).toContain("Skip once: command <name>");
    const rc = join(d, "rc");
    writeFileSync(rc, block);
    for (const sh of [["zsh", "-f"], ["bash", "--norc", "--noprofile"]]) {
      if (!Bun.which(sh[0])) continue;
      expect(await Bun.spawn([...sh, "-n", rc], { stdout: "ignore", stderr: "ignore" }).exited).toBe(0);
      const run = async (cmd: string) => {
        writeFileSync(log, "");
        const p = Bun.spawn([...sh, "-c", `. "${rc}"; ${cmd}`], { cwd: d, env: { PATH: `${d}:/usr/bin:/bin`, HOME: d }, stdout: "pipe", stderr: "pipe" });
        const code = await p.exited;
        return { code, log: readFileSync(log, "utf8").trim().split("\n").filter(Boolean) };
      };
      expect(await run("psql -h blocked.prod orders")).toEqual({ code: 3, log: ["vswarm cmdgate psql *.prod !canary.prod -- -h blocked.prod orders"] });
      expect(await run("psql -h ok.prod 'with space'")).toEqual({ code: 0, log: ["vswarm cmdgate psql *.prod !canary.prod -- -h ok.prod with space", "psql -h ok.prod with space"] });
      expect(await run("redis-cli -h blocked.prod PING")).toEqual({ code: 3, log: ["vswarm cmdgate redis-cli -- -h blocked.prod PING"] });
      // The documented bypass goes straight to the real binary.
      expect(await run("command telnet blocked.prod")).toEqual({ code: 0, log: ["telnet blocked.prod"] });
    }
  });

  test.skipIf(WIN)("vswarm cmdgate: BLOCK names the host with any password masked, a host outside the patterns is not checked", async () => {
    const sec = tmp("cli-sec");
    const prev = process.env.VSWARM_SEC_DIR;
    process.env.VSWARM_SEC_DIR = sec;
    await saveLast({ verdict: "block" as Verdict, findings: [], at: Date.now(), scan: {} as Scan }).finally(() => {
      if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
      else process.env.VSWARM_SEC_DIR = prev;
    });
    const env = { ...process.env, VSWARM_SEC_DIR: sec, NO_COLOR: "1" };
    const run = async (...a: string[]) => {
      const p = Bun.spawn([process.execPath, CLI, "cmdgate", ...a], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
      const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
      return { out, err, code };
    };
    const blocked = await run("psql", "*.prod", "--", "postgres://app:S3cretPW@pg.prod/orders", "--host=x");
    expect(blocked.code).toBe(3);
    expect(blocked.err).toContain("psql to pg.prod stopped");
    expect(blocked.err).toContain("skip once: command psql");
    expect(blocked.err + blocked.out).not.toContain("S3cretPW");
    // Not a production host: the command runs, and the cached BLOCK is not even read.
    expect((await run("psql", "*.prod", "--", "-h", "localhost")).code).toBe(0);
    const unknown = await run("mytool", "prod-*", "--", "--password", "prod-S3cretPW");
    expect(unknown.code).toBe(3);
    expect(unknown.err).toContain("(matches prod-*)");
    expect(unknown.err).not.toContain("S3cretPW");
  }, 30_000);

  test("PowerShell: ASCII only, bun and the CLI by full path, the real program found as an application, patterns quoted", () => {
    const b = psCmdGateBlock("C:\\Users\\a b\\.bun\\bin\\bun.exe", "C:\\Users\\o'x\\vswarm\\src\\cli.ts", { tools: { psql: { patterns: ["*.prod", "it's"], at: 0 }, telnet: { patterns: [], at: 0 } } });
    expect(b.startsWith(CMDGATE_START) && b.endsWith(CMDGATE_END)).toBe(true);
    expect(b.replace(/C:\\[^']*/g, "")).toMatch(/^[\x00-\x7f]*$/);
    expect(b).toContain("Get-Command -Name $tool -CommandType Application -TotalCount 1");
    expect(b).toContain("& 'C:\\Users\\a b\\.bun\\bin\\bun.exe' 'C:\\Users\\o''x\\vswarm\\src\\cli.ts' cmdgate $tool @pats '--' @a");
    expect(b).toContain("if ($LASTEXITCODE -ne 0) { return }");
    expect(b).toContain("function psql { __vswarm_cmdgate psql @('*.prod', 'it''s') $args }");
    expect(b).toContain("function telnet { __vswarm_cmdgate telnet @() $args }");
    expect(b).toContain("Skip once: <name>.exe");
  });

  test("a profile keeps its encoding, and scans know vswarm's block, also after CRLF", () => withSec(() => {
    const d = tmp("ps");
    const block = psCmdGateBlock("C:\\b\\bun.exe", "C:\\a\\cli.ts", { tools: { mysql: { patterns: ["*.prod"], at: 0 } } });
    const f = join(d, "profile.ps1");
    const bytes = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("Set-Alias ll ls\r\n", "utf16le")]);
    writeFileSync(f, bytes);
    setBlock(f, block, CMDGATE_START, CMDGATE_END);
    const after = readKept(f)!;
    expect(after.enc).toBe("utf16le");
    expect(after.text).toContain("function mysql");
    expect(stripManaged(after.text).trimEnd()).toBe("Set-Alias ll ls");
    expect(stripManaged(after.text.replace(/\n/g, "\r\n")).replace(/\r/g, "").trimEnd()).toBe("Set-Alias ll ls");
    // Someone else's change inside the block makes it foreign again.
    expect(stripManaged(after.text.replace("@a\n", "@a; iex $x\n"))).toContain("iex");
    setBlock(f, null, CMDGATE_START, CMDGATE_END);
    expect(readKept(f)!.text.trimEnd()).toBe("Set-Alias ll ls");
    expect(readKept(f)!.enc).toBe("utf16le");
  }));

  test("gate cmd adds, lists and removes, and the last one removes the block", () => withSec(async () => {
    const home = tmp("home");
    const zsh = join(home, ".zshrc");
    const bash = join(home, ".bashrc");
    writeFileSync(zsh, "alias ll='ls -la'\n");
    writeFileSync(bash, "export EDITOR=vi\r\n");
    const where: GateFiles = { files: [zsh, bash], body: (g) => cmdGateBlock("/v/vswarm", g) };
    const said = await quiet(() => gateCmd(["psql", "*.prod"], where));
    expect(said).toContain(`a reminder you can bypass, not a control: ${process.platform === "win32" ? "psql.exe" : "command psql"}`);
    await quiet(() => gateCmd(["telnet"], where));
    expect(loadCmdGates().tools.psql.patterns).toEqual(["*.prod"]);
    for (const f of [zsh, bash]) {
      expect(readFileSync(f, "utf8")).toContain("function psql {");
      expect(readFileSync(f, "utf8")).toContain("function telnet {");
    }
    expect(stripManaged(readFileSync(zsh, "utf8")).trimEnd()).toBe("alias ll='ls -la'");
    expect(await quiet(() => gateCmd(["--list"], where))).toContain("psql");
    expect(await quiet(() => gateCmd(["mytool", "build.prod"], where))).toContain("does not know mytool's syntax");
    await quiet(() => gateCmd(["--off", "psql"], where));
    expect(readFileSync(zsh, "utf8")).not.toContain("function psql");
    expect(readFileSync(zsh, "utf8")).toContain("function telnet");
    await removeCmdGate(undefined, where);
    expect(readFileSync(zsh, "utf8").trimEnd()).toBe("alias ll='ls -la'");
    expect(readFileSync(bash, "utf8").trimEnd()).toBe("export EDITOR=vi");
    expect(Object.keys(loadCmdGates().tools)).toEqual([]);
  }));
});

describe("gcloud: the credential's command runs preflight", () => {
  const wif = (extra: Record<string, unknown> = {}) => ({
    type: "external_account",
    audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    token_url: "https://sts.googleapis.com/v1/token",
    credential_source: { executable: { command: "/opt/idp/get-token --audience prod", timeout_millis: 5000, output_file: "/tmp/cache.json", ...extra } },
  });

  test("INI edits keep everything else, line endings too", () => {
    const t = "[core]\r\nproject = shop\r\n# a comment\r\n\r\n[compute]\r\nzone = x\r\n";
    const on = iniSet(t, "auth", "credential_file_override", "/g/c.json");
    expect(on).toBe("[core]\r\nproject = shop\r\n# a comment\r\n\r\n[compute]\r\nzone = x\r\n\r\n[auth]\r\ncredential_file_override = /g/c.json\r\n");
    expect(iniGet(on, "auth", "credential_file_override")).toBe("/g/c.json");
    expect(iniSet(on, "auth", "credential_file_override", null)).toBe(t);
    const inSection = "[auth]\ndisable_credentials = false\n\n[core]\nproject = p\n";
    const set = iniSet(inSection, "auth", "credential_file_override", "/x");
    expect(set).toBe("[auth]\ndisable_credentials = false\ncredential_file_override = /x\n\n[core]\nproject = p\n");
    expect(iniSet(iniSet(set, "auth", "credential_file_override", "/y"), "auth", "credential_file_override", null)).toBe(inSection);
  });

  test("only an executable-sourced external account has a command to gate; the copy drops output_file", () => {
    expect(executableOf({ type: "authorized_user" }).why).toContain("user sign-in");
    expect(executableOf({ type: "service_account" }).why).toContain("service-account key");
    expect(executableOf({ type: "external_account", credential_source: { file: "/x" } }).why).toContain("from a file");
    const { cred, droppedCache } = gatedCredential(wif(), ["/Users/a b/.vswarm/bin/vswarm"]);
    expect(droppedCache).toBe(true);
    expect(cred.credential_source.executable.output_file).toBeUndefined();
    expect(cred.credential_source.executable.timeout_millis).toBe(30_000);
    expect(cred.credential_source.executable.command).toBe("'/Users/a b/.vswarm/bin/vswarm' preflight --quiet --then /opt/idp/get-token --audience prod");
    // Gating a gated credential does not nest.
    expect(ungated(cred.credential_source.executable.command)).toBe("/opt/idp/get-token --audience prod");
    expect(gatedCredential(cred, ["/v/vswarm"]).cred.credential_source.executable.command).toBe("/v/vswarm preflight --quiet --then /opt/idp/get-token --audience prod");
    expect(() => gatedCredential({ type: "authorized_user" }, ["/v"])).toThrow("user sign-in");
  });

  test.skipIf(WIN || !Bun.which("python3"))("google-auth's shlex.split reads the command as vswarm, preflight, then the original", async () => {
    const { cred } = gatedCredential(wif({ command: "/opt/idp/get token 'quoted arg'" }), ["C:\\Users\\o'x\\bun.exe", "C:\\v s\\cli.ts"]);
    const p = Bun.spawn(["python3", "-I", "-c", "import json,shlex,sys; print(json.dumps(shlex.split(sys.argv[1])))", cred.credential_source.executable.command], { stdout: "pipe" });
    expect(JSON.parse(await new Response(p.stdout).text())).toEqual(["C:\\Users\\o'x\\bun.exe", "C:\\v s\\cli.ts", "preflight", "--quiet", "--then", "/opt/idp/get", "token", "quoted arg"]);
  });

  test("on, adopt, status, off and uninstall in a temp CLOUDSDK_CONFIG", () => withSec(async (sec) => {
    const cfg = tmp("gcloud");
    mkdirSync(join(cfg, "configurations"));
    const file = join(cfg, "configurations", "config_prod");
    const original = "[core]\nproject = shop-prod\n";
    writeFileSync(file, original);
    const src = join(cfg, "wif.json");
    writeFileSync(src, JSON.stringify(wif()));
    const e: CloudEnv = { env: { CLOUDSDK_CONFIG: cfg }, home: "/nonexistent", launcher: ["/v/vswarm"], where: { files: [join(cfg, "rc")], body: (g) => cmdGateBlock("/v/vswarm", g) } };
    expect(() => gcloudHookOn("Prod", src, e)).toThrow("not a gcloud configuration name");
    expect(() => gcloudHookOn("nope", src, e)).toThrow("no gcloud configuration nope");
    const said = await quiet(() => gateGcloud(["prod", "--cred-file", src], e));
    expect(said).toContain("its token command runs vswarm preflight first");
    expect(said).toContain("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1");
    const gated = join(sec, "gate", "gcloud-prod.json");
    expect(iniGet(readFileSync(file, "utf8"), "auth", "credential_file_override")).toBe(gated);
    expect(JSON.parse(readFileSync(gated, "utf8")).credential_source.executable.command).toBe("/v/vswarm preflight --quiet --then /opt/idp/get-token --audience prod");
    expect(readFileSync(src, "utf8")).toBe(JSON.stringify(wif()));
    expect(gcloudHookStatus()).toEqual([{ name: "prod", ok: true, detail: `${file} · token command runs preflight first` }]);
    // Again, without --cred-file: the configuration's own (vswarm's) credential is adopted, not nested, and the
    // value from before vswarm is still what off restores.
    await quiet(() => gateGcloud(["prod"], e));
    expect(loadCloudGates().gcloud.prod.source).toBe(src);
    expect(loadCloudGates().gcloud.prod.previous).toBeUndefined();
    // Someone points the configuration elsewhere: status says so, off leaves their change alone.
    writeFileSync(file, iniSet(readFileSync(file, "utf8"), "auth", "credential_file_override", "/elsewhere.json"));
    expect(gcloudHookStatus()[0].ok).toBe(false);
    expect(gcloudHookOff("prod").note).toContain("left as it is");
    expect(existsSync(gated)).toBe(false);
    // A configuration that already used the WIF file is adopted, and gets it back on off.
    writeFileSync(file, iniSet(original, "auth", "credential_file_override", src));
    await quiet(() => gateGcloud(["prod"], e));
    expect(loadCloudGates().gcloud.prod.previous).toBe(src);
    expect(gcloudHookOff("prod").done).toBe(true);
    expect(iniGet(readFileSync(file, "utf8"), "auth", "credential_file_override")).toBe(src);
    // Without a hookable credential: the wrapper, said plainly.
    writeFileSync(file, original);
    const w = await quiet(() => gateGcloud(["prod", "shop-*"], e));
    expect(w).toContain("no credential hook for these, so this is the command wrapper");
    expect(loadCmdGates().tools.gcloud.patterns).toEqual(["prod", "shop-*"]);
    expect(readFileSync(join(cfg, "rc"), "utf8")).toContain("function gcloud {");
    // Uninstall: hooks restored, wrappers gone.
    writeFileSync(file, iniSet(original, "auth", "credential_file_override", src));
    await quiet(() => gateGcloud(["prod"], e));
    const gone = await cloudUninstall(e.where);
    expect(gone.join("\n")).toContain("gcloud configuration prod restored");
    expect(readFileSync(file, "utf8")).toBe(iniSet(original, "auth", "credential_file_override", src));
    expect(readFileSync(join(cfg, "rc"), "utf8")).not.toContain("vswarm cmdgate");
    expect(loadCloudGates().gcloud).toEqual({});
  }));

  test("az is the wrapper, and says so", () => withSec(async () => {
    const rc = join(tmp("az"), ".zshrc");
    const where: GateFiles = { files: [rc], body: (g) => cmdGateBlock("/v/vswarm", g) };
    const said = await quiet(() => gateAz(["Prod-*"], where));
    expect(said).toContain("az has no credential hook");
    expect(said).toContain("a reminder you can bypass, not a control");
    expect(readFileSync(rc, "utf8")).toContain("cmdgate az 'Prod-*' --");
    expect(await quiet(() => gateAz(["status"], where))).toContain("Prod-*");
    await quiet(() => gateAz(["--off"], where));
    expect(readFileSync(rc, "utf8")).not.toContain("cmdgate");
  }));
});

describe("plain-text protocols and stored database passwords", () => {
  test("hosts from command lines: only where a command starts, user and password parts dropped", () => {
    expect(plainHosts("alias r='telnet -l admin 10.0.0.1'")).toEqual([{ tool: "telnet", host: "10.0.0.1", inlinePassword: false }]);
    expect(plainHosts("sudo ftp ftp://u:pw@Files.example.com/x")).toEqual([{ tool: "ftp", host: "files.example.com", inlinePassword: true }]);
    expect(plainHosts("x; rsh me@box.example ls")).toEqual([{ tool: "rsh", host: "box.example", inlinePassword: false }]);
    for (const quietLine of ["brew install telnet inetutils", "man ftp", "telnet localhost 25", 'command telnet "$@"', "sftp host.example", "lftp host.example", "curl ftp://h.example/x", "echo telnet is old"])
      expect(plainHosts(quietLine)).toEqual([]);
  });

  test("password files: the host field only", () => {
    expect(pgpassHosts("localhost:5432:*:me:pw\n# c\npg.prod:5432:orders:app:p\\:w\nweird\\:host:1:*:*:x\n")).toEqual(["localhost", "pg.prod", "weird:host"]);
    expect(myCnf("[client]\nuser=me\npassword = s3cret\nhost=my.prod\n")).toEqual({ password: true, hosts: ["my.prod"] });
    expect(myCnf("[client]\nuser=me\n").password).toBe(false);
  });

  test.skipIf(WIN)("findings in a fake home: what they say, how severe, and never a value", () => withSec(() => {
    const h = tmp("home");
    mkdirSync(join(h, ".ssh"));
    writeFileSync(join(h, ".zshrc"), "alias sw1='telnet sw1.office.example'\nfunction nas { ftp nas.office.example; }\n# telnet old.example\n");
    writeFileSync(join(h, ".ssh/config"), "Host legacy\n  ProxyCommand telnet jump.office.example 23\n");
    writeFileSync(join(h, ".zsh_history"), ": 1700000000:0;telnet sw1.office.example\n: 1700000001:0;ftp ftp://bob:Hunter2Secret@files.example.org/\n: 1700000002:0;brew install telnet\n");
    writeFileSync(join(h, ".bash_history"), "telnet sw1.office.example 23\nls\n");
    writeFileSync(join(h, ".pgpass"), "pg.prod.internal:5432:orders:app:PgSecretValue\nlocalhost:5432:*:me:LocalPw\n", { mode: 0o644 });
    chmodSync(join(h, ".pgpass"), 0o644);
    writeFileSync(join(h, ".my.cnf"), "[client]\npassword=MySecretValue\nhost=my.prod\n", { mode: 0o600 });
    writeFileSync(join(h, ".mylogin.cnf"), Buffer.from([0, 1, 2, 3, 4, 5]));
    writeFileSync(join(h, ".mongoshrc.js"), "db = connect('mongodb://admin:MongoSecretValue@m1.prod:27017/shop')\n");
    mkdirSync(join(h, "Library/DBeaverData/workspace6/General/.dbeaver"), { recursive: true });
    writeFileSync(join(h, "Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json"), Buffer.from([9, 9, 9, 9]));
    const f = plaintext(ctxFor(h));
    const by = (s: string) => f.find((x) => x.id.includes(s))!;
    expect(by("plaintext:config").severity).toBe("low");
    expect(by("plaintext:config").detail.join("\n")).toContain("~/.zshrc: nas.office.example, sw1.office.example");
    expect(by("plaintext:config").detail.join("\n")).toContain("~/.ssh/config: jump.office.example");
    expect(by("plaintext:config").detail.join("\n")).not.toContain("old.example");
    expect(by("plaintext:history").severity).toBe("medium");
    expect(by("plaintext:history").title).toBe("Shell history shows 3 telnet/ftp/rsh/rlogin sessions to 2 hosts, 1 with a password in the command line");
    expect(by("plaintext:history").detail[0]).toBe("hosts: files.example.org (1), sw1.office.example (2)");
    expect(by("dbpass:pgpass").severity).toBe("medium");
    expect(by("dbpass:pgpass").title).toContain("readable by other users (mode 0644)");
    expect(by("dbpass:mycnf").severity).toBe("low");
    expect(by("dbpass:mylogin").severity).toBe("low");
    expect(by("dbpass:mongorc").detail[0]).toBe("hosts: m1.prod");
    expect(by("dbpass:dbeaver").severity).toBe("low");
    const all = JSON.stringify(f);
    for (const v of ["Hunter2Secret", "PgSecretValue", "LocalPw", "MySecretValue", "MongoSecretValue", "bob", "admin:"]) expect(all).not.toContain(v);
    // Nothing from these is medium or higher except an open password file and a password typed into a command line.
    expect(f.filter((x) => x.severity === "high" || x.severity === "critical")).toEqual([]);
  }));

  test.skipIf(WIN)("quiet cases: an empty home, a 0600 local .pgpass, vswarm's own wrapper, installing telnet", () => withSec(() => {
    const h = tmp("quiet");
    expect(plaintext(ctxFor(h))).toEqual([]);
    writeFileSync(join(h, ".pgpass"), "localhost:5432:*:me:pw\n127.0.0.1:5432:*:me:pw\n", { mode: 0o600 });
    chmodSync(join(h, ".pgpass"), 0o600);
    const block = cmdGateBlock("/v/vswarm", { tools: { telnet: { patterns: [], at: 0 }, ftp: { patterns: ["*.prod"], at: 0 } } }) + "\n";
    recordManaged(block);
    writeFileSync(join(h, ".zshrc"), `export EDITOR=vi\n${block}`);
    writeFileSync(join(h, ".zsh_history"), ": 1:0;brew install telnet\n: 2:0;man ftp\n: 3:0;telnet localhost 25\n");
    writeFileSync(join(h, ".my.cnf"), "[client]\nuser=me\n");
    const f = plaintext(ctxFor(h));
    expect(f.map((x) => `${x.severity} ${x.id.replace(/:[0-9a-f]{10}$/, "")}`)).toEqual(["info secret:dbpass:pgpass"]);
  }));
});
