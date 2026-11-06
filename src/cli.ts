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
import { ask, banner, canAsk, COMMANDS, completion, doctor, gate, guard, install, uninstall, update } from "./setup";
import { checkInstall, plan } from "./sec/pkg";
import { shot } from "./shot";
import { loadCanaries, plantAws, plantDns, plantEnv, removeCanary } from "./sec/canary";
import { homedir } from "node:os";
import { verdictNow } from "./sec/gate";
import { caFiles, caInit, certInfo, issue, loadCaConfig, serverSetup } from "./sec/cert";
import { cleanTries, listTries, tryIt, type Net } from "./sec/try";

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
  row("vswarm ca init · ca server <account>", "a CA for short-lived SSH certificates");
  row("vswarm canary plant aws|dns|env · list", "decoy credentials that alert you when used");
  row('vswarm cert · gate ssh --cert "prod-*"', "15-minute certificate, only when preflight passes");
  row("vswarm accept <id…> | --all | --list", "mark reviewed findings as expected");
  console.log(`\n  ${c.bold("before you install")}`);
  row("vswarm guard on", "npm, pip, brew … ask vswarm before installing");
  row("vswarm pkg npm install <name>", "check by hand: malicious, look-alike, brand new, scripts");
  console.log(`\n  ${c.bold("run code you do not trust")}`);
  row("vswarm try <folder|git URL|zip> [-- cmd]", "in a sandbox: no secrets, no network; reports what it tried");
  row("vswarm try … --net registries", "allow package registries only (npm install, pip install)");
  row("vswarm try --list · --clean", "earlier tries");
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

    case "guard":
      return guard(args);

    case "pkg": {
      // vswarm pkg <tool> [--] <the tool's arguments>; the shell wrapper calls this before every install.
      const tool = args.shift();
      if (!tool) throw new Error("usage: vswarm pkg npm|pnpm|yarn|bun|npx|bunx|pip|pip3|uv|uvx|pipx|brew [--] <arguments>   e.g. vswarm pkg npm install axois");
      if (args[0] === "--") args.shift();
      if (process.env.VSWARM_GUARD === "off") return;
      const p = plan(tool, args);
      if (p.skip) return;
      const r = await checkInstall(p, { offline });
      const quietPass = !r.findings.some((f) => f.severity !== "info") && !r.notes.length;
      if (quietPass) {
        if (process.stderr.isTTY) line(c.dim(`vswarm ✔ ${p.wants.length > 1 ? `${p.wants.length} packages` : p.from} checked · ${r.ms} ms`));
        return;
      }
      line(`${c.violet("▼ vswarm")} checked ${p.from.startsWith(tool) ? p.from : `${tool} ${p.from}`} ${c.dim(`· ${r.ms} ms`)}`);
      for (const f of r.findings.filter((x) => x.severity !== "info")) printFinding({ ...f, id: "" }, f.severity !== "low");
      for (const n of r.notes) line(c.dim(`  · ${n}`));
      if (r.verdict !== "block") {
        if (r.findings.length) line(c.dim(`  ${VERDICT[r.verdict]} · going ahead`));
        return;
      }
      if (await yes(`${c.red("Stop here.")} Install anyway?`, false)) return line(c.dim("  going ahead, as you said"));
      line(c.dim(`  not installed · skip vswarm once with: command ${tool} …`));
      process.exitCode = 3;
      return;
    }

    case "ca": {
      const action = args.shift() ?? "status";
      if (action === "init") {
        const principals = flag(args, "--principal")?.split(",");
        const ttl = flag(args, "--ttl");
        const sk = has(args, "--sk");
        const noPass = has(args, "--no-passphrase");
        line(c.dim(sk ? "  touch your security key when it blinks" : "  choose a CA passphrase; vswarm asks for it each time it signs a certificate"));
        const cfg = await caInit({ sk, noPassphrase: noPass, principals, ttl });
        line(`${c.green("✔")} CA created ${c.dim(caFiles.key())} · principals ${cfg.principals.join(",")} · certificates last ${cfg.ttl}`);
        line(c.dim(`  next: vswarm ca server <account>   (commands to make a server trust this CA)`));
        return;
      }
      if (action === "server") {
        if (!existsSync(caFiles.pub())) throw new Error("no CA yet: vswarm ca init");
        console.log(serverSetup(args[0] ?? "root", loadCaConfig()));
        return;
      }
      if (action === "status") {
        if (!existsSync(caFiles.key())) return line("no CA yet · vswarm ca init");
        const cfg = loadCaConfig();
        const info = await certInfo();
        line(`CA ${c.dim(caFiles.key())} · principals ${cfg.principals.join(",")} · ttl ${cfg.ttl}`);
        line(info.valid ? `${c.green("●")} certificate valid for ${Math.floor((info.left ?? 0) / 60)} min more · ${c.dim(info.id ?? "")}` : `${c.dim("○")} no valid certificate · vswarm cert`);
        return;
      }
      throw new Error("usage: vswarm ca init [--sk] [--principal a,b] [--ttl 15m] | ca server <account> | ca status");
    }

    case "canary": {
      const action = args.shift() ?? "list";
      if (action === "list") {
        const list = loadCanaries();
        if (!list.length) return line(`no canaries yet · ${c.dim("vswarm canary plant aws|dns|env")}`);
        for (const k of list) line(`  ${c.amber("◆")} ${k.id}  ${k.kind.padEnd(4)} ${k.label.padEnd(22)} ${c.dim(k.where.replace(homedir(), "~"))}  ${c.dim(k.token)}`);
        line(c.dim("\n  Never use these yourself: any use sends you an alert. Remove one with vswarm canary remove <id>."));
        return;
      }
      if (action === "remove") {
        for (const k of removeCanary(args[0] ?? "")) line(`${c.green("✔")} removed ${k.kind} canary ${k.label} from ${k.where.replace(homedir(), "~")}`);
        return;
      }
      if (action !== "plant") throw new Error("usage: vswarm canary plant aws|dns|env … | canary list | canary remove <id|all>");
      const kind = args.shift();
      line(c.dim("  Make the token at https://canarytokens.org with your e-mail (free, by Thinkst). vswarm only plants it."));
      let k;
      if (kind === "aws" || kind === "env") {
        const dir = kind === "env" ? args.shift() : undefined;
        if (kind === "env" && !dir) throw new Error("usage: vswarm canary plant env <folder>");
        const keyId = (await ask("Canary AWS access key id (AKIA…):")).trim();
        const secret = (await ask("Canary AWS secret access key:", { secret: true })).trim();
        k = kind === "aws" ? plantAws(keyId, secret, { profile: flag(args, "--profile") }) : plantEnv(dir!, keyId, secret);
      } else if (kind === "dns") {
        const host = args.shift() ?? (await ask("DNS token hostname (…canarytokens.com):")).trim();
        k = plantDns(host, { alias: flag(args, "--alias") });
      } else throw new Error("usage: vswarm canary plant aws [--profile name] | dns <token-host> [--alias name] | env <folder>");
      line(`${c.green("✔")} planted ${k.kind} canary ${c.bold(k.label)} in ${k.where.replace(homedir(), "~")} ${c.dim(`(id ${k.id})`)}`);
      line(c.dim(k.kind === "dns" ? `  test it once: dscacheutil -q host -a name ${k.token}  → you should get an e-mail` : `  test it once: aws sts get-caller-identity --profile ${k.label.replace(/[\[\]]/g, "")}  → you should get an e-mail`));
      return;
    }

    case "cert": {
      const quiet = has(args, "--quiet", "-q");
      const host = flag(args, "--host");
      const verdict = await verdictNow({ fresh: has(args, "--fresh"), quiet, offline });
      if (verdict === "block") {
        line(c.red("vswarm: no certificate for a machine that does not pass preflight"));
        process.exitCode = 3;
        return;
      }
      const r = await issue({ host });
      if (!quiet || !r.reused) line(`${c.green("✔")} ${r.reused ? "certificate still valid" : "certificate issued"} for ${Math.floor((r.info.left ?? 0) / 60)} min · ${c.dim(r.info.principals.join(","))}`);
      return;
    }

    case "try": {
      if (has(args, "--list")) {
        const all = listTries();
        if (!all.length) return line("no tries yet");
        for (const t of all) line(`  ${t.verdict === "block" ? c.red("●") : t.verdict === "warn" ? c.amber("●") : c.green("●")} ${t.id}  ${c.dim(t.source ?? "")}`);
        return;
      }
      const cleanAt = args.indexOf("--clean");
      if (cleanAt >= 0) {
        const id = args[cleanAt + 1];
        return line(`${c.green("✔")} removed ${cleanTries(id)} tr${id ? "y" : "ies"}`);
      }
      const net = (flag(args, "--net") ?? "none") as Net;
      if (!["none", "registries", "all"].includes(net)) throw new Error("--net is none, registries or all");
      const auto = has(args, "--yes", "-y");
      const dash = args.indexOf("--");
      const command = dash >= 0 ? args.slice(dash + 1) : [];
      const source = (dash >= 0 ? args.slice(0, dash) : args)[0];
      if (!source) throw new Error('usage: vswarm try <folder | git URL | archive | file> [--net none|registries|all] [-- command …]');
      const r = await tryIt(source, command, { net, ask: (q) => yes(q, true), yes: auto });
      process.exitCode = r.verdict === "block" ? 3 : 0;
      return;
    }

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
