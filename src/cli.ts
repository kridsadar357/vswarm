#!/usr/bin/env bun
// vswarm — check your own machine before it touches production.

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { VERSION } from "./home";
import { readJson, realCtx, redact } from "./sec/ctx";
import { check, STATE_RULE } from "./sec/engine";
import { c, finding as printFinding, line, summary } from "./sec/print";
import { writeReport } from "./sec/report";
import { respond } from "./sec/respond";
import { forBaseline } from "./sec/scan";
import { secrets as findSecrets } from "./sec/secrets";
import { selftest } from "./sec/selftest";
import { clearLock, files, loadAccepted, loadBaseline, loadLast, lockState, readLog, saveAccepted, saveBaseline } from "./sec/store";
import { RANK } from "./sec/types";
import { ask, banner, COMMANDS, completion, doctor, gate, guard, install, trust, uninstall, update, yes } from "./setup";
import { pkgCommand } from "./sec/pkg";
import { shot } from "./shot";
import { canaryCommand } from "./sec/canary";
import { homedir } from "node:os";
import { verdictNow } from "./sec/gate";
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
  if (bad) throw new Error(`unknown option ${bad} for vswarm ${cmd} · vswarm help`);
}

/** Commands that need a Unix shell, ssh config, launchd/systemd or a sandbox; Windows gets them in a later phase. */
const NOT_ON_WINDOWS = new Set(["try", "ca", "cert", "canary", "shot"]);

function usage() {
  banner("check your machine before it touches production");
  const row = (cmd: string, desc: string) => console.log(`  ${c.cyan(cmd.padEnd(46))}${c.dim(desc)}`);
  console.log(`  ${c.bold("check")}`);
  row("vswarm scan [--all] [--json]", "everything that can run code, persist or hold access");
  row("vswarm baseline", "record this machine as clean (after a scan you trust)");
  row("vswarm diff", "only what changed since the baseline");
  row("vswarm watch on", "check every hour in the background, notify on anything new");
  row("vswarm secrets", "long-lived credentials on this machine (never prints values)");
  row("vswarm agents", "MCP servers, hooks and permissions of AI coding agents");
  row("vswarm agents --inspect [--show] [--timeout s]", "start each MCP server sandboxed, read its tools for hidden instructions");
  console.log(`\n  ${c.bold("gate production access")}`);
  row("vswarm preflight [--quiet] [--strict]", "PASS / WARN / BLOCK; exit 3 on BLOCK");
  row("vswarm preflight --then <command…>", "run the command only if this machine passes");
  row('vswarm gate ssh "prod-*" "*.internal"', "ssh to these hosts only after preflight passes");
  row("vswarm ca init · ca server <account>", "a CA for short-lived SSH certificates");
  row("vswarm canary plant aws|dns|env · list", "decoy credentials that alert you when used");
  row('vswarm cert · gate ssh --cert "prod-*"', "15-minute certificate, only when preflight passes");
  row("vswarm accept <id…> | --all | --list", "mark reviewed findings as expected");
  console.log(`\n  ${c.bold("before you install")}`);
  row("vswarm guard on [--ignore-scripts] [--sandbox] [--strict]", "npm, pip, brew … ask vswarm before installing");
  row("vswarm pkg npm install <name>", "check by hand: malicious, look-alike, brand new, scripts");
  console.log(`\n  ${c.bold("run code you do not trust")}`);
  row("vswarm try <folder|git URL|zip> [-- cmd]", "in a sandbox: no secrets, no network; reports what it tried");
  row("vswarm try … --net registries", "allow package registries only (npm install, pip install)");
  row("vswarm try … --localhost", "let it reach services on your own localhost (a dev server, a database)");
  row("vswarm try --list · --clean", "earlier tries");
  console.log(`\n  ${c.bold("when something is wrong")}`);
  row("vswarm respond", "lock, evidence, credential checklist, quarantine, report");
  row("vswarm report [incident]", "write the incident report again");
  row("vswarm report --json [--sign key] [--out dir]", "this machine's state for a server that decides (signed with an SSH key)");
  row("vswarm unlock", "close the incident once the machine is clean");
  console.log(`\n  ${c.bold("team")}`);
  row("vswarm team join <git url> [--fingerprint fp]", "follow a signed team policy (accepted findings, allowlists, required checks)");
  row("vswarm team sync · status · leave", "fetch it again (signature checked) · what this machine lacks");
  console.log(`\n  ${c.bold("trust, but verify")}`);
  row("vswarm selftest", "plant fake threats in a sandbox home, print the detection rate");
  row("vswarm doctor · install · update · uninstall", "set-up (update: signed releases once published, main until then)");
  row("vswarm trust", "release keys this machine accepts updates from");
  console.log(`\n  ${c.bold("gates for other tools")}`);
  console.log(c.dim("    ~/.aws/config     credential_process = vswarm preflight --quiet --then aws configure export-credentials --profile prod-sso --format process"));
  console.log(c.dim("    kubeconfig user   exec: { command: vswarm, args: [preflight, --quiet, --then, kubelogin, get-token, …] }"));
  if (process.platform === "win32") console.log(c.amber("\n  Windows preview: try and agents --inspect need the sandbox, and ca, cert, canary and shot are not here yet;\n  use those inside WSL. Everything else works."));
  console.log(c.dim("\n  Local-first, no telemetry. Only package names and versions go to api.osv.dev for the known-malicious check (--offline skips it).\n"));
}

async function main() {
  const [cmd = "help", ...args] = process.argv.slice(2);
  // What follows --then (preflight) or -- (try) belongs to the other command; vswarm's own flags stop there.
  const tailAt = args.indexOf(cmd === "preflight" ? "--then" : cmd === "try" ? "--" : "\0");
  const tail = tailAt >= 0 ? args.splice(tailAt + 1) : [];
  // pkg hands everything after the tool name to that tool, `=` and all.
  if (cmd !== "pkg") splitEquals(args);
  const offline = has(args, "--offline");
  const json = has(args, "--json");
  if (process.platform === "win32" && NOT_ON_WINDOWS.has(cmd)) throw new Error(`vswarm ${cmd} is not on Windows yet ; use it inside WSL`);

  switch (cmd) {
    case "scan":
    case "diff":
    case "check": {
      const all = has(args, "--all");
      noMoreOptions(cmd, args);
      const r = await check(realCtx(), { offline });
      if (cmd === "diff") r.findings = r.findings.filter((f) => f.rule !== "secret");
      if (json) console.log(JSON.stringify({ verdict: r.verdict, findings: r.findings, notes: r.notes, items: r.scan.items.length, ms: r.ms }, null, 2));
      else summary(r, { all, title: cmd });
      process.exitCode = r.verdict === "block" ? 3 : 0;
      return;
    }

    case "baseline": {
      const auto = has(args, "--yes", "-y");
      noMoreOptions(cmd, args);
      const r = await check(realCtx(), { offline });
      summary(r, { title: "baseline check" });
      // During an incident this is the step that records the cleaned machine; vswarm unlock needs it.
      if (r.lock) line(c.amber(`\n  Incident ${r.lock.incident} is open. Record a baseline only once the machine is clean (best: reinstalled) and credentials are rotated.`));
      const serious = r.findings.filter((f) => RANK[f.severity] >= RANK.high);
      if (serious.length) line(c.red(`\n  ${serious.length} serious finding${serious.length > 1 ? "s" : ""} above. A baseline taken now treats them as normal.`));
      const count = r.scan.items.filter((i) => i.kind !== "proc" && i.kind !== "conn").length;
      if (!auto) line("");
      const ok = auto || (await yes(`Record this machine (${count} items) as the clean baseline?`, !serious.length));
      if (!ok) return line(c.dim("  not recorded"));
      await saveBaseline(forBaseline(r.scan));
      line(`  ${c.green("✔")} baseline recorded ${c.dim(files.baseline())}`);
      line(c.dim("  From now on, scan and preflight report what changes from this point."));
      return;
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
        if (process.platform === "win32") throw new Error("vswarm agents --inspect is not on Windows yet (it needs the sandbox); use it inside WSL");
        const { inspectAll } = await import("./sec/mcp");
        process.exitCode = await inspectAll(list.filter((i) => i.kind === "mcp"), inspectOpt);
        return;
      }
      line(`${c.violet("▼ vswarm agents")} ${c.dim("· MCP servers, hooks and permissions of AI coding agents on this machine")}`);
      if (!list.length) line(`  ${c.green("✔")} no agent settings found`);
      const short = (p?: string) => (p ?? "").replace(homedir(), "~");
      for (const [kind, title] of [["mcp", "MCP servers"], ["agent-hook", "hooks (run on their own)"], ["agent-perm", "permissions"], ["agent-plugin", "plugins"]] as const) {
        const xs = list.filter((i) => i.kind === kind);
        if (!xs.length) continue;
        line(`\n  ${c.bold(title)}`);
        for (const i of xs) {
          if (kind === "agent-perm") line(`    ${i.meta?.bypass ? c.amber("bypass") : c.green("asks  ")}  ${i.name}${i.meta?.wide ? c.dim(`  allows ${i.meta.wide}`) : ""}`);
          else if (kind === "agent-plugin") line(`    ${i.name} ${c.dim(String(i.source))}`);
          else line(`    ${c.cyan(String(i.source).padEnd(26))} ${i.name.replace(`${i.source} `, "")}\n      ${c.dim(redact(String(i.meta?.command ?? i.meta?.url ?? short(i.path))).slice(0, 140))}${i.meta?.secrets ? c.amber(`  token in plain text: ${i.meta.secrets}`) : ""}`);
        }
      }
      line(c.dim("\n  Changes from your baseline show up in vswarm diff and block or warn in preflight."));
      return;
    }

    case "secrets": {
      noMoreOptions(cmd, args);
      const f = await findSecrets(realCtx());
      line(`${c.violet("▼ vswarm secrets")} ${c.dim("· where long-lived credentials live on this machine · values are never read out")}`);
      if (!f.length) line(`  ${c.green("✔")} none found in the usual places`);
      for (const x of f) printFinding(x);
      return;
    }

    case "preflight": {
      const quiet = has(args, "--quiet", "-q");
      const strict = has(args, "--strict");
      const fresh = has(args, "--fresh");
      const maxAge = Number(flag(args, "--max-age") ?? 120) * 1000;
      flag(args, "--host"); // accepted for ssh's %h; the check is about this machine, whatever the host
      noMoreOptions(cmd, args);
      const then = args.includes("--then") ? tail : [];
      const verdict = await verdictNow({ fresh, quiet, offline, maxAge });
      if (verdict === "block" || (strict && verdict === "warn")) {
        process.exitCode = verdict === "block" ? 3 : 2;
        return;
      }
      if (then.length) {
        const p = Bun.spawn(then, { stdin: "inherit", stdout: "inherit", stderr: "inherit" });
        process.exitCode = await p.exited;
      }
      return;
    }

    case "accept": {
      const acc = await loadAccepted();
      const list = has(args, "--list");
      const rm = flag(args, "--remove");
      const all = has(args, "--all");
      noMoreOptions(cmd, args);
      if (list) {
        const ids = Object.entries(acc);
        if (!ids.length) return line("nothing accepted");
        for (const [id, a] of ids) line(`  ${c.dim(new Date(a.at).toLocaleDateString())}  ${a.title}\n      ${c.dim(id)}`);
        return;
      }
      if (rm) {
        if (!acc[rm]) throw new Error(`${rm} is not an accepted finding · vswarm accept --list`);
        delete acc[rm];
        await saveAccepted(acc);
        return line(`${c.green("✔")} no longer accepted: ${rm}`);
      }
      // Only ids from a check vswarm itself wrote: a forged last.json must not name what gets accepted.
      const last = await loadLast();
      if (!last) throw new Error("run vswarm scan first");
      const pick = all ? last.findings : last.findings.filter((f) => args.includes(f.id));
      if (!pick.length) throw new Error("name finding ids (shown under each finding), or --all");
      for (const f of pick) {
        if (f.rule === "malicious") {
          line(`  ${c.red("✖")} a known-malicious package cannot be accepted: ${f.title}`);
          continue;
        }
        if (f.rule === STATE_RULE) {
          line(`  ${c.red("✖")} cannot be accepted, it is about vswarm's own files: ${f.title} · ${f.fix ?? ""}`);
          continue;
        }
        acc[f.id] = { at: Date.now(), title: f.title };
        line(`  ${c.green("✔")} accepted: ${f.title}`);
      }
      await saveAccepted(acc);
      return;
    }

    case "respond": {
      const auto = has(args, "--yes", "-y");
      const force = has(args, "--force");
      noMoreOptions(cmd, args);
      const r = await check(realCtx(), { offline });
      if (!force && !r.findings.some((f) => RANK[f.severity] >= RANK.medium)) {
        summary(r, { title: "respond" });
        return line(c.dim("  nothing to respond to · vswarm respond --force opens an incident anyway"));
      }
      await respond(realCtx(), r, (q) => yes(q, false), { yes: auto });
      return;
    }

    case "report": {
      const out = flag(args, "--out");
      const key = flag(args, "--sign");
      noMoreOptions(cmd, args);
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
      if (!id) throw new Error("no incidents yet");
      const inc = readJson(join(dir, id, "incident.json"));
      if (!inc) throw new Error(`no incident ${id} in ${dir}`);
      for (const w of writeReport(inc)) line(`${c.green("✔")} ${w}`);
      return;
    }

    case "unlock": {
      const force = has(args, "--force");
      noMoreOptions(cmd, args);
      const { lock, why } = await lockState();
      if (!lock) return line("no incident is open");
      if (why) line(c.amber(`  ${why}`));
      const base = await loadBaseline();
      if ((!base || base.at < lock.at) && !force) {
        return line(c.amber(`The baseline is older than incident ${lock.incident}. On the cleaned machine run vswarm baseline first (or unlock --force).`));
      }
      const log = await readLog();
      if (log.why && !force) {
        process.exitCode = 3;
        return line(c.amber(`vswarm's incident log ${log.why}. If you did not touch ~/.vswarm, treat this machine as compromised (vswarm respond).\n` +
          `If you know why (you restored a backup, or removed files by hand): vswarm unlock --force starts a new log and keeps the old one.`));
      }
      const r = await clearLock(lock.incident, { reset: !!log.why });
      if (r.kept) line(c.dim(`  the old log is kept as ${r.kept}`));
      return line(`${c.green("✔")} incident ${lock.incident} closed · preflight allows production access again`);
    }

    case "gate":
      noMoreOptions(cmd, args, ["--cert", "--team"]);
      return gate(args);

    case "guard":
      noMoreOptions(cmd, args, ["--ignore-scripts", "--sandbox", "--strict"]);
      return guard(args);

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
      if (!Number.isInteger(every) || every < 1) throw new Error("--every takes a whole number of minutes");
      noMoreOptions(cmd, args);
      return watchCommand(action, { every });
    }

    case "pkg": {
      // vswarm pkg [--run] [--strict] <tool> [--] <the tool's arguments>; the shell wrapper calls this before every install.
      // With --run (guard on --ignore-scripts / --sandbox) vswarm also runs the install itself.
      let run = false, strict = false;
      while (args[0] === "--run" || args[0] === "--strict") (args.shift() === "--run" ? (run = true) : (strict = true));
      const tool = args.shift();
      if (!tool) throw new Error("usage: vswarm pkg [--strict] npm|pnpm|yarn|bun|npx|bunx|pip|pip3|uv|uvx|pipx|brew [--] <arguments>   e.g. vswarm pkg npm install axois");
      if (args[0] === "--") args.shift();
      if (process.env.VSWARM_GUARD === "off") {
        // Off for this command: no check, but the install the wrapper handed over still runs.
        if (run && Bun.which(tool)) process.exitCode = await Bun.spawn([Bun.which(tool)!, ...args], { stdin: "inherit", stdout: "inherit", stderr: "inherit" }).exited;
        return;
      }
      process.exitCode = await pkgCommand(tool, args, { offline, strict, run, ask: yes });
      return;
    }

    case "ca": {
      const action = args.shift() ?? "status";
      const opt = { principals: flag(args, "--principal")?.split(","), ttl: flag(args, "--ttl"), sk: has(args, "--sk"), noPassphrase: has(args, "--no-passphrase") };
      noMoreOptions(cmd, args);
      return caCommand(action, args, opt);
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
        if (!all.length) return line("no tries yet");
        for (const t of all) line(`  ${t.verdict === "block" ? c.red("●") : t.verdict === "warn" ? c.amber("●") : c.green("●")} ${t.id}  ${c.dim(t.source ?? "")}`);
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
      noMoreOptions(cmd, args);
      banner("selftest");
      console.log(c.dim("  fake home in a temp folder · harmless stand-ins for real attack steps · this machine is not touched\n"));
      const r = await selftest();
      for (const x of r.cases) {
        console.log(`  ${x.caught ? c.green("✔") : c.red("✖")} ${x.name} ${c.dim(x.severity ? `(${x.severity}, needs ${x.min}+)` : "(missed)")}`);
        console.log(`      ${c.dim(x.like)}`);
      }
      console.log(`\n  ${c.bold(`detected ${r.caught}/${r.total}`)} ${c.dim(`(${Math.round((r.caught / r.total) * 100)}%) · false alarms on the clean parts: ${r.falseAlarms.length} · ${r.ms} ms`)}`);
      for (const f of r.falseAlarms) console.log(`    ${c.amber("!")} ${f.title}`);
      console.log(c.dim("\n  This measures the cases in src/sec/selftest.ts, not every possible attack. Add cases there.\n"));
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

    case "doctor":
      noMoreOptions(cmd, args);
      banner("doctor");
      if (!(await doctor())) process.exitCode = 1;
      return;
    case "install":
      noMoreOptions(cmd, args, ["--yes", "-y", "--no-path"]);
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
      throw new Error(`unknown command "${cmd}"${near ? ` · did you mean: vswarm ${near}` : ""} · vswarm help`);
    }
  }
}

main().catch((err) => {
  console.error(`${c.red("✖")} ${err.message ?? err}`);
  process.exit(4);
});
