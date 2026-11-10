#!/usr/bin/env bun
// vswarm — check your own machine before it touches production.

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { VERSION } from "./home";
import { readJson, realCtx, redact } from "./sec/ctx";
import { check } from "./sec/engine";
import { c, dateOf, line, numbers, summary, toStdout, wrap } from "./sec/print";
import { writeReport } from "./sec/report";
import { respond } from "./sec/respond";
import { selftest } from "./sec/selftest";
import { clearLock, files, loadAccepted, loadBaseline, loadLast, lockState, readLog, saveAccepted } from "./sec/store";
import { RANK, type Finding } from "./sec/types";
import { ask, banner, COMMANDS, completion, doctor, gate, guard, install, trust, uninstall, update, yes } from "./setup";
import { baselineCommand, fixable, heldLines, okCommand, secretsCommand, selfCommand, whyCommand } from "./commands";
import { t, useWindowsUtf8, type Key } from "./i18n";
import { pkgCheckCommand, pkgCommand } from "./sec/pkg";
import { shot } from "./shot";
import { canaryCommand } from "./sec/canary";
import { homedir } from "node:os";
import { gateVerdict } from "./sec/gate";
import { caCommand, certCommand } from "./sec/cert";
import { cleanTries, listTries, tryIt, type Net } from "./sec/try";

/** The team policy this machine follows, for reports (none until vswarm team join). */
const teamLabel = async (): Promise<{ name: string; serial: number } | undefined> => {
  const { policy } = await (await import("./sec/team")).loadPolicy();
  return policy ? { name: policy.name, serial: policy.serial } : undefined;
};

/** Where vswarm's own options end: what follows `--` or `--then` belongs to the command being wrapped. */
function own(args: string[]): number {
  const i = args.findIndex((a) => a === "--" || a === "--then");
  return i < 0 ? args.length : i;
}

function flag(args: string[], ...names: string[]): string | undefined {
  for (const name of names) {
    const i = args.indexOf(name);
    if (i >= 0 && i < own(args)) return args.splice(i, 2)[1];
  }
}

function has(args: string[], ...names: string[]): boolean {
  let found = false;
  for (const name of names) {
    const i = args.indexOf(name);
    if (i >= 0 && i < own(args)) {
      args.splice(i, 1);
      found = true;
    }
  }
  return found;
}

/** `--opt=value` becomes `--opt value`, for vswarm's own options only; the wrapped command's arguments are left as typed. */
function splitEquals(args: string[]) {
  for (let i = 0; i < own(args); i++) {
    const m = /^(--[\w-]+)=([\s\S]*)$/.exec(args[i]);
    if (m) args.splice(i, 1, m[1], m[2]);
  }
}

/** After a command took its options, anything left that looks like one is a typo, not something to pass along silently. */
function noMoreOptions(cmd: string, args: string[], known: string[] = []) {
  const bad = args.slice(0, own(args)).find((a) => /^-./.test(a) && !known.includes(a));
  if (bad) throw new Error(t("cli.err.unknownOption", { opt: bad, cmd }));
}

/** Commands that need a Unix shell, ssh config, launchd/systemd or a sandbox; Windows gets them in a later phase. */
const NOT_ON_WINDOWS = new Set(["ca", "cert", "canary", "shot"]);
export const notOnWindows = (cmd: string) => t("cli.err.notOnWindows", { cmd });

/**
 * Whether this command line prints a report (to stdout, so it can be kept) rather than a gate's or an action's
 * messages (stderr). preflight is a report only on its own: with --quiet or --then it is a gate.
 */
export function reportsTo(cmd: string, args: string[]): boolean {
  if (["scan", "diff", "check", "secrets", "agents", "why", "policy"].includes(cmd)) return true;
  if (cmd === "preflight") return !args.some((a) => a === "--quiet" || a === "-q" || a === "--then" || a === "--json");
  if (cmd === "pkg") return args[0] === "check";
  if (cmd === "accept" || cmd === "ok" || cmd === "try") return args.includes("--list");
  if (["agent", "watch", "team", "ca"].includes(cmd)) return args[0] === undefined || ["status", "log"].includes(args[0]);
  if (cmd === "canary" || cmd === "feed") return args[0] === undefined || args[0] === "list";
  if (cmd === "lang") return args[0] === undefined;
  return false;
}

/** Findings for JSON output: the facts a fix needs (meta) stay in vswarm's own files. */
const forJson = (fs: Finding[]) => fs.map(({ meta: _m, ...f }) => f);

/**
 * One row of the help table: the command in a column as wide as the longest that fits, the description beside it,
 * wrapped to the terminal (Thai by its width on screen); a command longer than the column gets its description on
 * the next line instead.
 */
export function helpRow(cmd: string, desc: string, width = process.stdout.columns || Number(process.env.COLUMNS) || 100, col = 44): { cmd: string; gap: string; desc: string[]; pad: string } {
  const indent = 2 + col + 2;
  const room = Math.max(30, width - indent);
  const wrapped = wrap(desc, room);
  const pad = " ".repeat(indent);
  // Too long for the column: the description starts on the next line, under the others.
  if (cmd.length > col) return { cmd, gap: `\n${pad}`, desc: wrapped, pad };
  return { cmd, gap: " ".repeat(col - cmd.length + 2), desc: wrapped, pad };
}

/** The help, under four plain headings; the commands stay as they are typed, the words are in the language in use. */
export const HELP: [Key, [string, Key][]][] = [
  ["cli.help.h.everyday", [
    ["vswarm setup", "cli.help.setup"],
    ["vswarm scan [--all] [--details] [--json]", "cli.help.scan"],
    ["vswarm diff", "cli.help.diff"],
    ["vswarm ui", "cli.help.ui"],
    ["vswarm watch on", "cli.help.watch"],
    ["vswarm secrets", "cli.help.secrets"],
    ["vswarm agents", "cli.help.agents"],
    ["vswarm mcp", "cli.help.mcp"],
    ["vswarm hook install claude · remove · status", "cli.help.hook"],
    ["vswarm guard on [--ignore-scripts] [--sandbox] [--strict]", "cli.help.guard"],
    ["vswarm pkg check npm|pip <name>[@v] [--sandbox]", "cli.help.pkgCheck"],
    ["vswarm try <folder|git URL|zip> [-- cmd]", "cli.help.try"],
    ["vswarm lang th|en|auto", "cli.help.lang"],
  ]],
  ["cli.help.h.found", [
    ["vswarm why [n]", "cli.help.why"],
    ["vswarm fix <n>", "cli.help.fix"],
    ["vswarm ok <n…> | <id…> | --all", "cli.help.ok"],
    ["vswarm ok --list · --remove <id>", "cli.help.okList"],
    ["vswarm baseline", "cli.help.baseline"],
    ["vswarm respond", "cli.help.respond"],
    ["vswarm report [incident]", "cli.help.report"],
    ["vswarm unlock", "cli.help.unlock"],
  ]],
  ["cli.help.h.production", [
    ["vswarm preflight [--quiet] [--strict] [--json]", "cli.help.preflight"],
    ["vswarm preflight --then <command…>", "cli.help.then"],
    ['vswarm gate ssh "prod-*" "*.internal"', "cli.help.gateSsh"],
    ["vswarm gate status · gate ssh --prune", "cli.help.gateStatus"],
    ["vswarm gate aws <profile…> · --off", "cli.help.gateAws"],
    ["vswarm gate kube <context…> · --off", "cli.help.gateKube"],
    ["vswarm gate gcloud <configuration> · gate az", "cli.help.gateGcloud"],
    ['vswarm gate cmd psql "*.prod.internal"', "cli.help.gateCmd"],
    ["vswarm agent protect <key> · agent on", "cli.help.agent"],
    ["vswarm policy [warn allow|refuse]", "cli.help.policy"],
  ]],
  ["cli.help.h.advanced", [
    ["vswarm agents --inspect [--show] [--timeout s]", "cli.help.inspect"],
    ["vswarm pkg npm install <name>", "cli.help.pkg"],
    ["vswarm try … --net registries · --localhost", "cli.help.tryNet"],
    ["vswarm try --list · --clean", "cli.help.tryList"],
    ["vswarm ca init · ca server <account>", "cli.help.ca"],
    ['vswarm cert · gate ssh --cert "prod-*"', "cli.help.cert"],
    ["vswarm canary plant aws|dns|env · list", "cli.help.canary"],
    ["vswarm report --json [--sign key] [--out dir]", "cli.help.reportJson"],
    ["vswarm report --html [--out file]", "cli.help.reportHtml"],
    ["vswarm feed add <https url> [--token-env VAR]", "cli.help.feed"],
    ["vswarm feed update · list · remove <name>", "cli.help.feedUpdate"],
    ["vswarm team join <git url> [--fingerprint fp]", "cli.help.teamJoin"],
    ["vswarm team sync · status · leave", "cli.help.teamSync"],
    ["vswarm selftest", "cli.help.selftest"],
    ["vswarm doctor · install · update · uninstall", "cli.help.doctor"],
    ["vswarm trust", "cli.help.trust"],
  ]],
];

function usage() {
  banner(t("cli.help.tagline"));
  const row = (cmd: string, desc: string) => {
    // Laid out first, coloured after: the escape codes must not count as width.
    const r = helpRow(cmd, desc);
    console.log(`  ${c.cyan(r.cmd)}${r.gap}${r.desc.map(c.dim).join(`\n${r.pad}`)}`);
  };
  HELP.forEach(([head, rows], i) => {
    console.log(`${i ? "\n" : ""}  ${c.bold(t(head))}`);
    for (const [cmd, key] of rows) row(cmd, t(key));
  });
  console.log(`\n  ${c.bold(t("cli.help.byHand"))} ${c.dim(t("cli.help.byHandSub"))}`);
  console.log(c.dim("    ~/.aws/config     credential_process = vswarm preflight --quiet --then aws configure export-credentials --profile <sso profile> --format process"));
  console.log(c.dim("    kubeconfig user   exec: { command: vswarm, args: [preflight, --quiet, --then, kubelogin, get-token, …] }"));
  // The two notes wrap at the width; the lines above are config to copy and stay whole.
  const note = (s: string, paint: (x: string) => string) => console.log(`\n${wrap(s, (process.stdout.columns || Number(process.env.COLUMNS) || 100) - 2).map((l) => `  ${paint(l)}`).join("\n")}`);
  if (process.platform === "win32") note(t("cli.help.windows"), c.amber);
  note(t("cli.help.privacy"), c.dim);
  console.log();
}

export async function main() {
  const [cmd = "help", ...args] = process.argv.slice(2);
  // Thai (and every other word that is not ASCII) on a Windows console: UTF-8 for this run (src/i18n).
  useWindowsUtf8();
  // What follows --then (preflight) or -- (try) belongs to the other command; vswarm's own flags stop there.
  const tailAt = args.indexOf(cmd === "preflight" ? "--then" : cmd === "try" ? "--" : "\0");
  const tail = tailAt >= 0 ? args.splice(tailAt + 1) : [];
  // pkg hands everything after the tool name to that tool, `=` and all.
  if (cmd !== "pkg" && cmd !== "cmdgate") splitEquals(args);
  // The report is what these print: to stdout, so it can be kept (vswarm scan > scan.txt). Gates, questions and
  // progress stay on stderr. Decided before the options are taken off the list.
  if (reportsTo(cmd, args)) toStdout();
  const offline = has(args, "--offline");
  const json = has(args, "--json");
  if (process.platform === "win32" && NOT_ON_WINDOWS.has(cmd)) throw new Error(notOnWindows(cmd));
  // After an update, once: what the old version's update could not do (setup.ts). Not on the paths ssh and installs
  // wait for.
  if (!["preflight", "agent", "cert", "pkg", "cmdgate", "mcp", "hook", "complete", "__complete"].includes(cmd)) (await import("./setup")).afterUpdate();

  switch (cmd) {
    case "scan":
    case "diff":
    case "check": {
      const all = has(args, "--all");
      const details = has(args, "--details");
      noMoreOptions(cmd, args);
      const r = await check(realCtx(), { offline });
      // Numbered as the check was saved, so vswarm ok <n> and fix <n> mean the finding shown with n.
      const numbered = numbers(r.findings);
      if (cmd === "diff") r.findings = r.findings.filter((f) => f.rule !== "secret");
      const { readPolicy } = await import("./sec/policy");
      if (json) console.log(JSON.stringify({ verdict: r.verdict, findings: forJson(r.findings), notes: r.notes, items: r.scan.items.length, ms: r.ms }, null, 2));
      else {
        const canFix = await fixable();
        summary(r, { all, details, title: cmd === "check" ? "scan" : cmd, numbered, policy: (await readPolicy()).warn, fixable: (f) => canFix(f, numbered.get(f.id)!), held: await heldLines(r.verdict) });
      }
      process.exitCode = r.verdict === "block" ? 3 : 0;
      return;
    }

    case "baseline": {
      const auto = has(args, "--yes", "-y");
      const acceptHigh = has(args, "--accept-high");
      noMoreOptions(cmd, args);
      // A baseline over HIGH or CRIT findings makes them normal from now on: never by default, never silently.
      if ((await baselineCommand({ auto, acceptHigh, offline, yes })) === "refused") process.exitCode = 3;
      return;
    }

    case "setup": {
      const auto = has(args, "--yes", "-y");
      noMoreOptions(cmd, args);
      process.exitCode = await (await import("./wizard")).setupCommand({ auto, offline });
      return;
    }

    case "lang": {
      noMoreOptions(cmd, args);
      const { langCommand } = await import("./i18n/command");
      return langCommand(args);
    }

    case "agents": {
      // What AI agents on this machine may start or run on their own.
      const { agents } = await import("./sec/collect/agents");
      const timeout = Number(flag(args, "--timeout") ?? 90);
      if (!(timeout > 0)) throw new Error("--timeout takes a number of seconds");
      const inspectOpt = { sandbox: !has(args, "--no-sandbox"), show: has(args, "--show"), timeoutMs: timeout * 1000 };
      const doInspect = has(args, "--inspect");
      noMoreOptions(cmd, args);
      const list = await agents(realCtx());
      if (doInspect) {
        // No sandbox on Windows yet: --inspect starts the servers only when you say they may run as you (--no-sandbox).
        if (process.platform === "win32" && inspectOpt.sandbox) throw new Error("vswarm agents --inspect with the sandbox is not on Windows yet; use it inside WSL, or --inspect --no-sandbox to start each server as your agent would, with your access");
        const { inspectAll } = await import("./sec/mcp");
        process.exitCode = await inspectAll(list.filter((i) => i.kind === "mcp"), inspectOpt);
        return;
      }
      line(`${c.violet("▼ vswarm agents")} ${c.dim(`· ${t("cli.agents.sub")}`)}`);
      if (!list.length) line(`  ${c.green("✔")} ${t("cli.agents.none")}`);
      const short = (p?: string) => (p ?? "").replace(homedir(), "~");
      for (const [kind, title] of [["mcp", t("cli.agents.mcp")], ["agent-hook", t("cli.agents.hooks")], ["agent-perm", t("cli.agents.perms")], ["agent-plugin", t("cli.agents.plugins")]] as const) {
        const xs = list.filter((i) => i.kind === kind);
        if (!xs.length) continue;
        line(`\n  ${c.bold(title)}`);
        for (const i of xs) {
          if (kind === "agent-perm") line(`    ${i.meta?.bypass ? c.amber("bypass") : c.green("asks  ")}  ${i.name}${i.meta?.wide ? c.dim(`  allows ${i.meta.wide}`) : ""}`);
          else if (kind === "agent-plugin") line(`    ${i.name} ${c.dim(String(i.source))}`);
          else line(`    ${c.cyan(String(i.source).padEnd(26))} ${i.name.replace(`${i.source} `, "")}\n      ${c.dim(redact(String(i.meta?.command ?? i.meta?.url ?? short(i.path))).slice(0, 140))}${i.meta?.secrets ? c.amber(`  token in plain text: ${i.meta.secrets}`) : ""}${i.meta?.disabled ? c.dim("  (disabled)") : ""}`);
        }
      }
      line(c.dim(`\n  ${t("cli.agents.after")}`));
      return;
    }

    case "secrets": {
      noMoreOptions(cmd, args);
      return secretsCommand();
    }

    case "mcp": {
      // For AI agents: read-only tools and a question for the person (src/sec/serve.ts). Typed at a terminal, how to add it.
      noMoreOptions(cmd, args);
      if (args.length) throw new Error("usage: vswarm mcp (an AI agent starts it; it takes no arguments)");
      if (process.stdin.isTTY) return line(t("cli.mcp.howto"));
      return (await import("./sec/serve")).serve();
    }

    case "preflight": {
      const quiet = has(args, "--quiet", "-q");
      const strict = has(args, "--strict");
      const fresh = has(args, "--fresh");
      const maxAge = Number(flag(args, "--max-age") ?? 120) * 1000;
      flag(args, "--host"); // accepted for ssh's %h; the check is about this machine, whatever the host
      noMoreOptions(cmd, args);
      const then = args.includes("--then") ? tail : [];
      if (json && then.length) throw new Error("preflight --json prints the verdict on stdout, and --then hands stdout to the command; use one");
      // --json: the same decision, as data on stdout; the human lines (a BLOCK's findings) stay on stderr.
      const g = await gateVerdict({ fresh, quiet: quiet || json, offline, maxAge, strict });
      if (json) {
        const last = await loadLast();
        const { lock } = await lockState();
        console.log(JSON.stringify({
          verdict: g.verdict, allowed: g.allowed, code: g.code, policy: { warn: g.policy.warn, set: g.policy.set, ...(g.policy.untrusted ? { untrusted: g.policy.untrusted } : {}) },
          ...(lock ? { incident: lock.incident } : {}), at: last?.at, findings: forJson(last?.findings ?? []),
        }, null, 2));
        process.exitCode = g.code;
        return;
      }
      if (!g.allowed) {
        process.exitCode = g.code;
        return;
      }
      if (then.length) {
        const p = Bun.spawn(then, { stdin: "inherit", stdout: "inherit", stderr: "inherit" });
        process.exitCode = await p.exited;
      }
      return;
    }

    case "why": {
      // preflight --fresh, with the way out under each finding and the policy at the end; `why <n>`: that one only.
      noMoreOptions(cmd, args);
      const n = args[0] === undefined ? undefined : Number(args[0]);
      if (n !== undefined && (!Number.isInteger(n) || n < 1 || args.length !== 1)) throw new Error(t("cli.err.whyUsage"));
      process.exitCode = await whyCommand({ offline, n });
      return;
    }

    case "policy": {
      const { readPolicy, savePolicy, policyLine } = await import("./sec/policy");
      noMoreOptions(cmd, args);
      const [what, value] = args;
      if (what === undefined) return line(policyLine(await readPolicy()));
      if (what !== "warn" || (value !== "allow" && value !== "refuse")) throw new Error(t("cli.err.policyUsage"));
      if (value === "allow") await (await import("./sec/human")).weaken("policy", ["warn", "allow"]);
      await savePolicy(value);
      line(`${c.green("✔")} ${policyLine(await readPolicy())}`);
      if (value === "refuse") line(c.dim(`  ${t("cli.policy.nowRefuse")}`));
      return;
    }

    case "fix": {
      noMoreOptions(cmd, args);
      const n = Number(args[0]);
      if (!Number.isInteger(n) || n < 1 || args.length !== 1) throw new Error(t("cli.err.fixUsage"));
      const last = await loadLast();
      if (!last) throw new Error(t("cli.err.scanFirst"));
      const f = last.findings[n - 1];
      if (!f) throw new Error(t("cli.err.noNumber", { n, count: last.findings.length }));
      const { fixCommand } = await import("./sec/fix");
      process.exitCode = await fixCommand(f, n, { self: await selfCommand(), yes });
      return;
    }

    case "ok":
    case "accept": {
      const acc = await loadAccepted();
      const list = has(args, "--list");
      const rm = flag(args, "--remove");
      const all = has(args, "--all");
      noMoreOptions(cmd, args);
      if (list) {
        const ids = Object.entries(acc);
        if (!ids.length) return line(t("cli.ok.none"));
        for (const [id, a] of ids) line(`  ${c.dim(dateOf(a.at))}  ${a.title}\n      ${c.dim(id)}`);
        line(c.dim(`  ${t("cli.ok.undo")}`));
        return;
      }
      if (rm) {
        if (!acc[rm]) throw new Error(t("cli.err.notAccepted", { id: rm }));
        delete acc[rm];
        await saveAccepted(acc);
        return line(`${c.green("✔")} ${t("cli.ok.removed", { id: rm })}`);
      }
      return okCommand(args, all);
    }

    case "respond": {
      const auto = has(args, "--yes", "-y");
      const force = has(args, "--force");
      noMoreOptions(cmd, args);
      const r = await check(realCtx(), { offline });
      if (!force && !r.findings.some((f) => RANK[f.severity] >= RANK.medium)) {
        summary(r, { title: "respond" });
        return line(c.dim(`  ${t("cli.respond.nothing")}`));
      }
      await respond(realCtx(), r, (q) => yes(q, false), { yes: auto });
      return;
    }

    case "report": {
      const html = has(args, "--html");
      const out = flag(args, "--out");
      const key = flag(args, "--sign");
      noMoreOptions(cmd, args);
      if (html) {
        // A static snapshot of the dashboard for a team: no server, no actions, credentials masked (src/ui/report.ts).
        if (json || key) throw new Error("--html makes a page of its own; leave out --json and --sign");
        line(`${c.green("✔")} ${await (await import("./ui/report")).htmlReport({ out, offline })}`);
        return;
      }
      if (json || out || key) {
        // This machine's state for a server that decides (docs/server-side.md); a fresh check, never the cached one.
        const { posture, signReport, writePosture } = await import("./sec/report");
        const r = await check(realCtx(), { offline });
        const text = JSON.stringify(posture(r, await teamLabel()), null, 2) + "\n";
        const sig = key ? await signReport(text, key) : undefined;
        if (out) for (const w of writePosture(out, text, sig)) line(`${c.green("✔")} ${w}`);
        // Signed on stdout: the exact bytes that were signed, and the signature, in one envelope.
        else process.stdout.write(sig ? JSON.stringify({ report: text, signature: sig }, null, 2) + "\n" : text);
        process.exitCode = r.verdict === "block" ? 3 : 0;
        return;
      }
      const dir = files.incidents();
      const id = args[0] ?? (existsSync(dir) ? readdirSync(dir).sort().at(-1) : undefined);
      if (!id) throw new Error(t("cli.err.noIncidents"));
      const inc = readJson(join(dir, id, "incident.json"));
      if (!inc) throw new Error(`no incident ${id} in ${dir}`);
      for (const w of writeReport(inc)) line(`${c.green("✔")} ${w}`);
      return;
    }

    case "unlock": {
      const force = has(args, "--force");
      noMoreOptions(cmd, args);
      const { lock, why } = await lockState();
      if (!lock) return line(t("cli.unlock.none"));
      if (why) line(c.amber(`  ${why}`));
      const base = await loadBaseline();
      if ((!base || base.at < lock.at) && !force) {
        return line(c.amber(t("cli.unlock.oldBaseline", { incident: lock.incident })));
      }
      const log = await readLog();
      if (log.why && !force) {
        process.exitCode = 3;
        return line(c.amber(t("cli.unlock.log", { why: log.why })));
      }
      await (await import("./sec/human")).weaken("unlock", force ? ["--force"] : []);
      const r = await clearLock(lock.incident, { reset: !!log.why });
      if (r.kept) line(c.dim(`  ${t("cli.unlock.kept", { file: r.kept })}`));
      return line(`${c.green("✔")} ${t("cli.unlock.done", { incident: lock.incident })}`);
    }

    case "gate":
      noMoreOptions(cmd, args, ["--cert", "--team", "--off", "--list", "--cred-file", "--wrapper", "--prune", "--all"]);
      return gate(args);

    case "cmdgate": {
      // vswarm cmdgate <tool> [patterns…] -- <the tool's arguments>; the functions vswarm gate cmd writes call this.
      const dash = args.indexOf("--");
      const [tool, ...patterns] = dash >= 0 ? args.slice(0, dash) : args;
      if (!tool) throw new Error("usage: vswarm cmdgate <tool> [host patterns…] -- <arguments>   (written by vswarm gate cmd)");
      process.exitCode = await (await import("./sec/cmdgate")).cmdgateRun(tool, patterns, dash >= 0 ? args.slice(dash + 1) : []);
      return;
    }

    case "guard":
      noMoreOptions(cmd, args, ["--ignore-scripts", "--sandbox", "--strict"]);
      return guard(args);

    case "hook": {
      // Claude Code's PreToolUse hook (src/sec/hook.ts): `hook claude` answers on stdout; install, remove, status.
      noMoreOptions(cmd, args);
      return (await import("./sec/hook")).hookCommand(args);
    }

    case "feed": {
      const { feedCommand } = await import("./sec/feed");
      const action = args.shift() ?? "list";
      const opt = { fingerprint: flag(args, "--fingerprint"), tokenEnv: flag(args, "--token-env"), key: flag(args, "--key"), yes: has(args, "--yes", "-y"), ask: yes };
      noMoreOptions(cmd, args, ["--all"]);
      return feedCommand(action, args, opt);
    }

    case "team": {
      const { teamCommand } = await import("./sec/team");
      const action = args.shift() ?? "status";
      const opt = { fingerprint: flag(args, "--fingerprint"), key: flag(args, "--key"), yes: has(args, "--yes", "-y"), ask: yes };
      noMoreOptions(cmd, args);
      return teamCommand(action, args, opt);
    }

    case "watch": {
      const { watchCommand } = await import("./sec/schedule");
      const action = args.shift() ?? "status";
      const every = Number(flag(args, "--every") ?? 60);
      if (!Number.isInteger(every) || every < 1) throw new Error(t("cli.err.every"));
      noMoreOptions(cmd, args);
      return watchCommand(action, { every });
    }

    case "pkg": {
      // vswarm pkg [--run] [--strict] <tool> [--] <the tool's arguments>; the shell wrapper calls this before every install.
      // With --run (guard on --ignore-scripts / --sandbox) vswarm also runs the install itself.
      // --deep reads the contents of the whole tree, not only named packages and those with install scripts.
      let run = false, strict = false, deep = false;
      for (let a = args[0]; a === "--run" || a === "--strict" || a === "--deep"; a = args[0]) (args.shift(), a === "--run" ? (run = true) : a === "--strict" ? (strict = true) : (deep = true));
      const tool = args.shift();
      if (!tool) throw new Error("usage: vswarm pkg [--strict] [--deep] npm|pnpm|yarn|bun|npx|bunx|pip|pip3|uv|uvx|pipx|brew [--] <arguments>   e.g. vswarm pkg npm install axois");
      // vswarm pkg check npm|pip <name>[@version]: read a package without installing it.
      if (tool === "check") {
        const sandbox = has(args, "--sandbox");
        deep = has(args, "--deep") || deep;
        strict = has(args, "--strict") || strict;
        const [eco, spec] = args.splice(0, 2);
        noMoreOptions("pkg check", args);
        process.exitCode = await pkgCheckCommand(eco, spec, { offline, deep, sandbox, json, strict });
        return;
      }
      if (args[0] === "--") args.shift();
      if (process.env.VSWARM_GUARD === "off") {
        // Off for this command: no check, but the install the wrapper handed over still runs.
        if (run && Bun.which(tool)) process.exitCode = await Bun.spawn([Bun.which(tool)!, ...args], { stdin: "inherit", stdout: "inherit", stderr: "inherit" }).exited;
        return;
      }
      process.exitCode = await pkgCommand(tool, args, { offline, strict, run, deep, ask: yes });
      return;
    }

    case "ca": {
      const action = args.shift() ?? "status";
      const opt = { principals: flag(args, "--principal")?.split(","), ttl: flag(args, "--ttl"), sk: has(args, "--sk"), noPassphrase: has(args, "--no-passphrase") };
      noMoreOptions(cmd, args);
      return caCommand(action, args, opt);
    }

    case "agent": {
      // The ssh agent that signs with protected keys only while this machine passes (src/sec/agent.ts).
      const { agentCommand } = await import("./sec/agent");
      const action = args.shift() ?? "status";
      const life = flag(args, "--life");
      const upTimeout = flag(args, "--upstream-timeout");
      // --strict is the default for protected keys since 2.7; it is still accepted, and `agent policy` takes it.
      const port = flag(args, "--port");
      const opt = {
        confirm: has(args, "--confirm"), allowWarn: has(args, "--allow-warn"), strict: has(args, "--strict"), inherit: has(args, "--inherit"), global: has(args, "--global"), upstream: flag(args, "--upstream"),
        upstreamTimeout: upTimeout === undefined ? undefined : Number(upTimeout), life: life === undefined ? undefined : Number(life), ask, yes,
        allowPasswords: has(args, "--allow-passwords"), allKeys: has(args, "--all-keys"), anyway: has(args, "--anyway"), noVerify: has(args, "--no-verify"),
        host: flag(args, "--host"), hostname: flag(args, "--hostname"), port: port === undefined ? undefined : Number(port),
      };
      if (opt.life !== undefined && !(Number.isInteger(opt.life) && opt.life > 0)) throw new Error("--life takes a whole number of seconds");
      if (opt.upstreamTimeout !== undefined && !(Number.isInteger(opt.upstreamTimeout) && opt.upstreamTimeout > 0 && opt.upstreamTimeout <= 600)) throw new Error("--upstream-timeout takes a whole number of seconds, at most 600");
      if (opt.allowWarn && opt.strict) throw new Error("--allow-warn and --strict say opposite things; give one");
      noMoreOptions(cmd, args);
      return agentCommand(action, args, opt);
    }

    case "canary": {
      const action = args.shift() ?? "list";
      const opt = { ask, profile: flag(args, "--profile"), alias: flag(args, "--alias") };
      noMoreOptions(cmd, args);
      return canaryCommand(action, args, opt);
    }

    case "cert": {
      const opt = { quiet: has(args, "--quiet", "-q"), fresh: has(args, "--fresh"), offline, host: flag(args, "--host") };
      noMoreOptions(cmd, args);
      process.exitCode = await certCommand(opt);
      return;
    }

    case "try": {
      const list = has(args, "--list");
      const cleanAt = args.indexOf("--clean");
      // --clean on its own removes every try; --clean <id> one of them.
      const clean = cleanAt >= 0 && cleanAt < own(args) ? { id: args.splice(cleanAt, 2)[1] } : undefined;
      const net = (flag(args, "--net") ?? "none") as Net;
      const auto = has(args, "--yes", "-y");
      const localhost = has(args, "--localhost");
      noMoreOptions(cmd, args);
      if (list) {
        const all = listTries();
        if (!all.length) return line(t("cli.try.none"));
        for (const x of all) line(`  ${x.verdict === "block" ? c.red("●") : x.verdict === "warn" ? c.amber("●") : c.green("●")} ${x.id}  ${c.dim(x.source ?? "")}`);
        return;
      }
      if (clean) return line(`${c.green("✔")} removed ${cleanTries(clean.id)} tr${clean.id ? "y" : "ies"}`);
      if (!["none", "registries", "all"].includes(net)) throw new Error("--net is none, registries or all");
      const dash = args.indexOf("--");
      const command = dash >= 0 ? tail : [];
      const source = (dash >= 0 ? args.slice(0, dash) : args)[0];
      if (!source) throw new Error('usage: vswarm try <folder | git URL | archive | file> [--net none|registries|all] [--localhost] [-- command …]');
      const r = await tryIt(source, command, { net, ask: (q) => yes(q, true), yes: auto, localhost });
      process.exitCode = r.verdict === "block" ? 3 : 0;
      return;
    }

    case "selftest": {
      const all = has(args, "--all");
      noMoreOptions(cmd, args);
      const r = await selftest();
      if (json) {
        console.log(JSON.stringify({ ...r, falseAlarms: r.falseAlarms.map((f) => ({ rule: f.rule, severity: f.severity, title: f.title })) }, null, 2));
        process.exitCode = r.caught === r.total && !r.falseAlarms.length ? 0 : 1;
        return;
      }
      banner("selftest");
      console.log(c.dim("  fake home in a temp folder · harmless stand-ins for real attack steps, each planted alone · this machine is not touched\n"));
      for (const [t, x] of Object.entries(r.techniques)) {
        const mark = x.caught === x.total && !x.alarms ? c.green("✔") : c.red("✖");
        console.log(`  ${mark} ${t.padEnd(40)} ${c.dim(`${x.total ? `caught ${x.caught}/${x.total}` : "no cases here"}${x.benign ? ` · false alarms ${x.alarms}/${x.benign} benign` : ""}`)}`);
        for (const k of r.cases.filter((k) => k.technique === t && !k.skipped && (all || !k.caught)))
          console.log(`      ${k.caught ? c.green("✔") : c.red("✖")} ${k.name} ${c.dim(k.severity ? `(${k.severity}, needs ${k.min}+)` : "(missed)")}`);
        for (const b of r.benign.filter((b) => b.technique === t && (all || !b.ok)))
          console.log(`      ${b.ok ? c.green("✔") : c.red("✖")} benign: ${b.name} ${c.dim(b.severity ? `(${b.severity}${b.when === "change" ? `, may be ${b.max} at most` : ""})` : "(quiet)")}`);
      }
      const skipped = r.cases.filter((k) => k.skipped).length;
      const quiet = r.benign.filter((b) => b.ok).length;
      console.log(`\n  ${c.bold(`detected ${r.caught}/${r.total}`)} ${c.dim(`(${Math.round((r.caught / r.total) * 100)}%)${skipped ? ` · ${skipped} not on this system` : ""} · benign look-alikes quiet ${quiet}/${r.benign.length} · false alarms ${r.falseAlarms.length} · ${r.ms} ms`)}`);
      for (const f of r.falseAlarms) console.log(`    ${c.amber("!")} ${f.severity}: ${f.title}`);
      console.log(c.dim(`\n  This measures the cases in src/sec/selftest-cases.ts, not every possible attack. Add cases there · --all lists each one.\n`));
      process.exitCode = r.caught === r.total && !r.falseAlarms.length ? 0 : 1;
      return;
    }

    case "shot": {
      const target = args.shift();
      if (!target) throw new Error("usage: vswarm shot <localhost URL or file> [--out shot.png] [--size 1280x800] [--wait ms]");
      const out = flag(args, "--out", "-o") ?? "shot.png";
      const opt = { size: flag(args, "--size"), wait: Number(flag(args, "--wait") ?? 5000) };
      noMoreOptions(cmd, args);
      console.log(await shot(target, out, opt));
      return;
    }

    case "ui": {
      // A local page in plain words: 127.0.0.1 only, a one-time key per run (src/ui/server.ts).
      const open = !has(args, "--no-open");
      noMoreOptions(cmd, args);
      return (await import("./ui/server")).uiCommand({ open, offline });
    }

    case "doctor":
      noMoreOptions(cmd, args);
      banner("doctor");
      if (!(await doctor())) process.exitCode = 1;
      return;
    case "install":
      noMoreOptions(cmd, args, ["--yes", "-y", "--no-path", "--path"]);
      return install(args);
    case "uninstall":
      noMoreOptions(cmd, args, ["--purge"]);
      return uninstall(args);
    case "update":
    case "upgrade":
      noMoreOptions(cmd, args, ["--unsigned"]);
      return update(args);
    case "trust":
      noMoreOptions(cmd, args);
      return trust(args);
    case "completions":
      noMoreOptions(cmd, args);
      process.stdout.write(completion(args[0] ?? "zsh"));
      return;
    case "version":
    case "--version":
    case "-v":
      console.log(VERSION);
      return;
    case "help":
    case "--help":
    case "-h":
      return usage();
    default: {
      const near = COMMANDS.map(([n]) => n).find((n) => n.startsWith(cmd.slice(0, 2)));
      throw new Error(t(near ? "cli.err.unknownNear" : "cli.err.unknown", { cmd, near }));
    }
  }
}

// Run as a program only: tests import helpRow and reportsTo from here.
if (import.meta.main)
  main().catch((err) => {
    console.error(`${c.red("✖")} ${err.message ?? err}`);
    process.exit(4);
  });
