// vswarm hook (src/sec/hook.ts): what Claude Code is told before a shell command runs, and how the hook goes in and
// out of its settings. The gate is a stand-in here; the settings file is in a temp folder.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classify, commandsOf, hookInstalled, installHook, onTool, removeHook } from "../src/sec/hook";
import { evaluate } from "../src/sec/rules";
import type { Finding, Scan } from "../src/sec/types";

const root = mkdtempSync(join(tmpdir(), "vs-hook-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("what a command line is", () => {
  test("the commands of a line, past VAR=x, sudo and env", () => {
    expect(commandsOf("cd x && FOO=1 sudo env ssh prod-db 'ls'; echo hi | tee y")).toEqual([["cd", "x"], ["ssh", "prod-db", "'ls'"], ["echo", "hi"], ["tee", "y"]]);
  });

  test("production: ssh, cloud CLIs, deploys; a gated tool; not git, not a plan, not a local rsync", () => {
    for (const l of ["ssh deploy@prod-db", "cd app && aws s3 ls", "kubectl get pods", "terraform apply -auto-approve", "vercel --prod", "fly deploy", "/usr/bin/scp a b:c", "rsync -a dist/ web:/srv", "echo $(ssh x uptime)"])
      expect(classify(l)?.kind).toBe("prod");
    expect(classify("psql -h db.prod.internal", ["psql"])?.kind).toBe("prod");
    for (const l of ["git push origin main", "terraform plan", "rsync -a src/ dst/", "npm test", "echo ssh is a word", "psql -h localhost"])
      expect(classify(l)).toBeUndefined();
  });

  test("weakening vswarm: its own commands, and its files or the ssh gate edited by hand; looking is fine", () => {
    for (const l of ["vswarm ok 3", "vswarm accept --all", "vswarm unlock", "vswarm policy warn allow", "vswarm gate remove", "vswarm gate aws prod --off", "vswarm guard off", "vswarm hook remove claude", "bun src/cli.ts ok 3", "bun ~/develop/vswarm/src/cli.ts policy warn allow", "sed -i '' '/vswarm gate/d' ~/.ssh/config", "rm -rf ~/.vswarm/sec", "echo x >> ~/.ssh/config"])
      expect(classify(l)?.kind).toBe("weaken");
    for (const l of ["vswarm why", "vswarm scan --json", "vswarm policy", "cat ~/.ssh/config", "ls ~/.vswarm", "vswarm gate status", "vswarm ok --list", "bun src/cli.ts accept --list"])
      expect(classify(l)?.kind).not.toBe("weaken");
  });

  test("by hand: writing into ~/.vswarm or the ssh config is caught; reading them, or copying out of them, is not", () => {
    const writes = [
      "cp evil ~/.vswarm/bin/vswarm", "mv ~/.vswarm/sec /tmp/x", "tee -a ~/.ssh/config < x", "printf x>~/.ssh/config", "echo y 2>> \"$HOME/.vswarm/sec/last.json\"",
      "dd if=x of=$HOME/.vswarm/sec/last.json", "chmod 777 ~/.vswarm/sec", "perl -pi -e s/a/b/ ~/.ssh/config", "rsync -a x/ /Users/u/.vswarm/app", "sudo rm ~/.ssh/config",
    ];
    for (const l of writes) expect([l, classify(l)?.kind]).toEqual([l, "weaken"]);
    const reads = [
      "cp -R ~/.vswarm/app /tmp/copy", "python3 -c 'print(open(\"/Users/u/.vswarm/x\").read())'", "git -C ~/.vswarm/app tag -l", "cat ~/.ssh/config | grep Host",
      "~/.vswarm/bin/vswarm version", "ls -la ~/.vswarm > /tmp/listing", "sed -n 1,5p ~/.ssh/config", "diff ~/.ssh/config /tmp/old 2>&1", "rm -rf /tmp/vswarm-test",
    ];
    for (const l of reads) expect([l, classify(l)?.kind]).toEqual([l, undefined]);
  });
});

describe("the answer Claude Code gets", () => {
  const ev = (command: string, tool = "Bash") => ({ hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
  const passing = { gate: async () => ({ allowed: true }), reason: async () => "unused" };
  const failing = { gate: async () => ({ allowed: false }), reason: async (c: string) => `vswarm refuses: BLOCK (${c})` };

  test("production while the machine does not pass: deny, with the reason and a line for the agent", async () => {
    const r: any = await onTool(ev("ssh prod-db"), failing);
    expect(r.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(r.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r.hookSpecificOutput.permissionDecisionReason).toContain("vswarm refuses: BLOCK (ssh prod-db)");
    expect(r.hookSpecificOutput.permissionDecisionReason).toContain("If you are an AI agent");
  });

  test("production while it passes, and anything else: nothing, so the agent's own permissions decide; never allow", async () => {
    expect(await onTool(ev("ssh prod-db"), passing)).toBeUndefined();
    expect(await onTool(ev("npm test"), failing)).toBeUndefined();
    expect(await onTool(ev("ssh prod-db", "Read"), failing)).toBeUndefined();
    expect(await onTool({}, failing)).toBeUndefined();
  });

  test("weakening vswarm: deny (an ask can be answered for the person in auto mode), whatever the verdict, without running a check", async () => {
    let checked = false;
    const r: any = await onTool(ev("vswarm ok --all"), { gate: async () => ((checked = true), { allowed: true }), reason: async () => "" });
    expect(r.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r.hookSpecificOutput.permissionDecisionReason).toContain("in their own terminal");
    expect(checked).toBe(false);
  });
});

describe("in and out of Claude Code's settings", () => {
  test("added once beside what is there, taken out again leaving the rest as it was", () => {
    const f = join(root, "settings.json");
    const before = { model: "opus", hooks: { PreToolUse: [{ matcher: "Edit", hooks: [{ type: "command", command: "my-linter" }] }], Stop: [{ hooks: [{ type: "command", command: "say done" }] }] } };
    writeFileSync(f, JSON.stringify(before));
    const copies: string[] = [];
    const backup = (x: string) => (copies.push(x), `${x}.bak`);
    expect(installHook(["/Users/a b/.vswarm/bin/vswarm"], f, backup).changed).toBe(true);
    expect(hookInstalled(f)).toBe(true);
    expect(installHook(["/Users/a b/.vswarm/bin/vswarm"], f, backup).changed).toBe(false);
    const j = JSON.parse(readFileSync(f, "utf8"));
    expect(j.model).toBe("opus");
    expect(j.hooks.Stop).toEqual(before.hooks.Stop);
    expect(j.hooks.PreToolUse).toHaveLength(2);
    expect(j.hooks.PreToolUse[1]).toEqual({ matcher: "Bash", hooks: [{ type: "command", command: "'/Users/a b/.vswarm/bin/vswarm' hook claude", timeout: 60 }] });
    expect(removeHook(f, backup).changed).toBe(true);
    expect(JSON.parse(readFileSync(f, "utf8"))).toEqual(before);
    expect(hookInstalled(f)).toBe(false);
    expect(copies).toHaveLength(2);
  });

  test("a vswarm hook with another command (an older install) is replaced, not added twice", () => {
    const f = join(root, "older.json");
    writeFileSync(f, JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/Users/u/.vswarm/bin/vswarm hook claude" }] }] } }));
    expect(installHook(["/opt/bun", "/src/vswarm/src/cli.ts"], f).changed).toBe(true);
    const pre = JSON.parse(readFileSync(f, "utf8")).hooks.PreToolUse;
    expect(pre).toHaveLength(1);
    expect(pre[0].hooks[0].command).toBe("/opt/bun /src/vswarm/src/cli.ts hook claude");
    expect(installHook(["/opt/bun", "/src/vswarm/src/cli.ts"], f).changed).toBe(false);
  });

  test("a settings file that is not JSON is left alone", () => {
    const f = join(root, "broken.json");
    writeFileSync(f, "{ not json");
    expect(() => installHook(["vswarm"], f)).toThrow("not valid JSON");
    expect(readFileSync(f, "utf8")).toBe("{ not json");
  });
});

describe("the rule: an agent free to run anything, and production keys without a passphrase", () => {
  const scanWith = (perm: Record<string, unknown>): Scan => ({
    version: 1, host: "h", user: "u", home: "/home/u", at: 0, gaps: {}, texts: {},
    items: [{ kind: "agent-perm", id: "/home/u/.claude/settings.json", name: "claude-code:.claude settings.json", source: "claude-code", path: "/home/u/.claude/settings.json", meta: perm as any }],
  } as unknown as Scan);
  const prodKey: Finding = { id: "secret:ssh:prod_ed25519", rule: "secret", severity: "medium", title: "SSH private key without a passphrase", detail: [], meta: { file: "/home/u/.ssh/prod_ed25519", production: true } };
  const devKey: Finding = { ...prodKey, id: "secret:ssh:dev", meta: { file: "/home/u/.ssh/dev", production: false } };

  test("both: one finding naming the agent and the key", async () => {
    const fs = await evaluate({ scan: scanWith({ bypass: true }), malicious: [], secrets: [prodKey] });
    const f = fs.find((x) => x.rule === "agent-prod");
    expect(f?.severity).toBe("medium");
    expect(f?.title).toContain("claude-code:.claude settings.json");
    expect(f?.detail).toContain("~/.ssh/prod_ed25519");
  });

  test("either alone, or only a key that is not for production: not this finding", async () => {
    expect((await evaluate({ scan: scanWith({ bypass: false }), malicious: [], secrets: [prodKey] })).some((x) => x.rule === "agent-prod")).toBe(false);
    expect((await evaluate({ scan: scanWith({ wide: "Bash" }), malicious: [], secrets: [devKey] })).some((x) => x.rule === "agent-prod")).toBe(false);
    expect((await evaluate({ scan: scanWith({ wide: "Bash" }), malicious: [], secrets: [prodKey] })).some((x) => x.rule === "agent-prod")).toBe(true);
  });
});

describe("vswarm hook claude as a program", () => {
  const run = async (event: unknown) => {
    const p = Bun.spawn(["bun", join(import.meta.dir, "../src/cli.ts"), "hook", "claude"], { stdin: "pipe", stdout: "pipe", stderr: "pipe", env: { ...process.env } });
    p.stdin.write(JSON.stringify(event));
    p.stdin.end();
    const out = await new Response(p.stdout).text();
    return { code: await p.exited, out };
  };

  test("says nothing about an ordinary command, and denies a weakening one, on stdout only", async () => {
    expect(await run({ tool_name: "Bash", tool_input: { command: "npm test" } })).toEqual({ code: 0, out: "" });
    const r = await run({ tool_name: "Bash", tool_input: { command: "vswarm unlock" } });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).hookSpecificOutput.permissionDecision).toBe("deny");
    expect((await run("not an event")).out).toBe("");
  });
});
