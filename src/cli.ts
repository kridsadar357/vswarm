#!/usr/bin/env bun
// vswarm — check your own machine before it touches production.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { VERSION } from "./home";
import { realCtx } from "./sec/ctx";
import { check } from "./sec/engine";
import { c, finding as printFinding, line, summary, VERDICT } from "./sec/print";
import { writeReport } from "./sec/report";
import { respond } from "./sec/respond";
import { forBaseline } from "./sec/scan";
import { secrets as findSecrets } from "./sec/secrets";
import { selftest } from "./sec/selftest";
import { clearLock, files, loadAccepted, loadBaseline, loadLast, loadLock, saveAccepted, saveBaseline } from "./sec/store";
import { RANK, type Finding, type Verdict } from "./sec/types";
import { ask, banner, canAsk, COMMANDS, completion, doctor, gate, install, uninstall, update } from "./setup";
import { shot } from "./shot";

function flag(args: string[], ...names: string[]): string | undefined {
  for (const name of names) {
    const i = args.indexOf(name);
    if (i >= 0) return args.splice(i, 2)[1];
  }
}

function has(args: string[], ...names: string[]): boolean {
  let found = false;
  for (const name of names) {
    const i = args.indexOf(name);
    if (i >= 0) {
      args.splice(i, 1);
      found = true;
    }
  }
  return found;
}

const yes = async (q: string, def = false) => {
  if (!canAsk()) return def;
  const a = (await ask(`${q} ${c.dim(def ? "[Y/n]" : "[y/N]")}`)).toLowerCase();
  return a ? a.startsWith("y") : def;
};

function usage() {
  banner("check your machine before it touches production");
  const row = (cmd: string, desc: string) => console.log(`  ${c.cyan(cmd.padEnd(40))}${c.dim(desc)}`);
  console.log(`  ${c.bold("check")}`);
  row("vswarm scan [--all] [--json]", "everything that can run code, persist or hold access");
  row("vswarm baseline", "record this machine as clean (after a scan you trust)");
  row("vswarm diff", "only what changed since the baseline");
  row("vswarm secrets", "long-lived credentials on this machine (never prints values)");
  console.log(`\n  ${c.bold("gate production access")}`);
  row("vswarm preflight [--quiet] [--strict]", "PASS / WARN / BLOCK; exit 3 on BLOCK");
  row("vswarm preflight --then <command…>", "run the command only if this machine passes");
  row('vswarm gate ssh "prod-*" "*.internal"', "ssh to these hosts only after preflight passes");
  row("vswarm accept <id…> | --all | --list", "mark reviewed findings as expected");
  console.log(`\n  ${c.bold("when something is wrong")}`);
  row("vswarm respond", "lock, evidence, credential checklist, quarantine, report");
  row("vswarm report [incident]", "write the incident report again");
  row("vswarm unlock", "close the incident once the machine is clean");
  console.log(`\n  ${c.bold("trust, but verify")}`);
  row("vswarm selftest", "plant fake threats in a sandbox home, print the detection rate");
  row("vswarm doctor · install · update · uninstall", "set-up");
  console.log(`\n  ${c.bold("gates for other tools")}`);
  console.log(c.dim("    ~/.aws/config     credential_process = vswarm preflight --quiet --then aws configure export-credentials --profile prod-sso --format process"));
  console.log(c.dim("    kubeconfig user   exec: { command: vswarm, args: [preflight, --quiet, --then, kubelogin, get-token, …] }"));
  console.log(c.dim("\n  Local-first, no telemetry. Only package names and versions go to api.osv.dev for the known-malicious check (--offline skips it).\n"));
}

async function main() {
  const [cmd = "help", ...args] = process.argv.slice(2);
  const offline = has(args, "--offline");
  const json = has(args, "--json");

  switch (cmd) {
    case "scan":
    case "diff":
    case "check": {
      const r = await check(realCtx(), { offline });
      if (cmd === "diff") r.findings = r.findings.filter((f) => f.rule !== "secret");
      if (json) console.log(JSON.stringify({ verdict: r.verdict, findings: r.findings, notes: r.notes, items: r.scan.items.length, ms: r.ms }, null, 2));
      else summary(r, { all: has(args, "--all"), title: cmd });
      process.exitCode = r.verdict === "block" ? 3 : 0;
      return;
    }

    case "baseline": {
      const auto = has(args, "--yes", "-y");
      const r = await check(realCtx(), { offline });
      summary(r, { title: "baseline check" });
      if (r.lock) throw new Error(`incident ${r.lock.incident} is open; clean the machine, then record a baseline and vswarm unlock`);
      const serious = r.findings.filter((f) => RANK[f.severity] >= RANK.high);
      if (serious.length) line(c.red(`\n  ${serious.length} serious finding${serious.length > 1 ? "s" : ""} above. A baseline taken now treats them as normal.`));
      const count = r.scan.items.filter((i) => i.kind !== "proc" && i.kind !== "conn").length;
      const ok = auto || (await yes(`\n  Record this machine (${count} items) as the clean baseline?`, !serious.length));
      if (!ok) return line(c.dim("  not recorded"));
      saveBaseline(forBaseline(r.scan));
      line(`  ${c.green("✔")} baseline recorded ${c.dim(files.baseline())}`);
      line(c.dim("  From now on, scan and preflight report what changes from this point."));
      return;
    }

    case "secrets": {
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
      const thenAt = args.indexOf("--then");
      const then = thenAt >= 0 ? args.slice(thenAt + 1) : [];
      // ssh and kubectl call this on every connection, so a verdict from the last couple of minutes is reused.
      const last = loadLast();
      const lock = loadLock();
      let verdict: Verdict;
      let findings: Finding[];
      const cached = !fresh && !lock && last !== undefined && Date.now() - last.at < maxAge;
      if (cached) {
        verdict = last!.verdict;
        findings = last!.findings;
        if (verdict !== "pass") {
          const n = findings.filter((f) => RANK[f.severity] >= RANK.medium).length;
          line(`${VERDICT[verdict]} ${c.dim(`vswarm preflight · ${n} finding${n === 1 ? "" : "s"} · details: vswarm preflight --fresh`)}`);
        }
      } else {
        // In the quiet gate the known-malicious lookup uses its cache, so a slow network never delays a login.
        const r = await check(realCtx(), { offline: offline || quiet });
        verdict = r.verdict;
        if (!quiet || verdict === "block") summary(r, { title: "preflight" });
        else if (verdict === "warn") {
          const n = r.findings.filter((f) => RANK[f.severity] >= RANK.medium).length;
          line(`${VERDICT.warn} ${c.dim(`vswarm preflight · ${n} finding${n === 1 ? "" : "s"} · details: vswarm preflight --fresh`)}`);
        }
      }
      if (lock) verdict = "block";
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
      const acc = loadAccepted();
      if (has(args, "--list")) {
        const ids = Object.entries(acc);
        if (!ids.length) return line("nothing accepted");
        for (const [id, a] of ids) line(`  ${c.dim(new Date(a.at).toLocaleDateString())}  ${a.title}\n      ${c.dim(id)}`);
        return;
      }
      const rm = flag(args, "--remove");
      if (rm) {
        delete acc[rm];
        saveAccepted(acc);
        return line(`${c.green("✔")} no longer accepted: ${rm}`);
      }
      const last = loadLast();
      if (!last) throw new Error("run vswarm scan first");
      const pick = has(args, "--all") ? last.findings : last.findings.filter((f) => args.includes(f.id));
      if (!pick.length) throw new Error("name finding ids (shown under each finding), or --all");
      for (const f of pick) {
        if (f.rule === "malicious") {
          line(`  ${c.red("✖")} a known-malicious package cannot be accepted: ${f.title}`);
          continue;
        }
        acc[f.id] = { at: Date.now(), title: f.title };
        line(`  ${c.green("✔")} accepted: ${f.title}`);
      }
      saveAccepted(acc);
      return;
    }

    case "respond": {
      const auto = has(args, "--yes", "-y");
      const force = has(args, "--force");
      const r = await check(realCtx(), { offline });
      if (!force && !r.findings.some((f) => RANK[f.severity] >= RANK.medium)) {
        summary(r, { title: "respond" });
        return line(c.dim("  nothing to respond to · vswarm respond --force opens an incident anyway"));
      }
      await respond(realCtx(), r, (q) => yes(q, false), { yes: auto });
      return;
    }

    case "report": {
      const dir = files.incidents();
      const id = args[0] ?? (existsSync(dir) ? readdirSync(dir).sort().at(-1) : undefined);
      if (!id) throw new Error("no incidents yet");
      const inc = JSON.parse(readFileSync(join(dir, id, "incident.json"), "utf8"));
      for (const w of writeReport(inc)) line(`${c.green("✔")} ${w}`);
      return;
    }

    case "unlock": {
      const lock = loadLock();
      if (!lock) return line("no incident is open");
      const base = loadBaseline();
      if ((!base || base.at < lock.at) && !has(args, "--force")) {
        return line(c.amber(`The baseline is older than incident ${lock.incident}. On the cleaned machine run vswarm baseline first (or unlock --force).`));
      }
      clearLock();
      return line(`${c.green("✔")} incident ${lock.incident} closed · preflight allows production access again`);
    }

    case "gate":
      return gate(args);

    case "selftest": {
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
      console.log(await shot(target, flag(args, "--out", "-o") ?? "shot.png", { size: flag(args, "--size"), wait: Number(flag(args, "--wait") ?? 5000) }));
      return;
    }

    case "doctor":
      banner("doctor");
      if (!(await doctor())) process.exitCode = 1;
      return;
    case "install":
      return install(args);
    case "uninstall":
      return uninstall(args);
    case "update":
    case "upgrade":
      return update();
    case "completions":
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
