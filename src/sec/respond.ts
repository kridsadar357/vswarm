// `vswarm respond`: what to do once a check says BLOCK. Five steps, each one shown before it happens:
//   1 lock      preflight refuses production access from this machine until `vswarm unlock`
//   2 evidence  copies of the suspicious files with hashes, plus processes, connections and login jobs
//   3 rotate    a checklist of every credential this machine held, to rotate from a different, clean device
//   4 contain   unload and quarantine login jobs and programs, strip added startup lines (each one asked)
//   5 report    a report for your team and drafts for the package registries (you send them; nothing is sent)

import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileHash, run, type Ctx } from "./ctx";
import type { Check } from "./engine";
import { writeReport } from "./report";
import { files, setLock, writePrivate } from "./store";
import type { Finding } from "./types";
import { RANK } from "./types";
import { c, finding as printFinding, line } from "./print";

export interface Incident {
  id: string;
  dir: string;
  at: number;
  host: string;
  user: string;
  findings: Finding[];
  evidence: { path: string; sha256?: string; size?: number; mtime?: number; copy?: string; note?: string }[];
  actions: { at: number; what: string; done: boolean; detail?: string }[];
  credentials: string[];
}

function stamp(t = Date.now()) {
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

/** Every place on the machine that held a credential worth rotating, whether or not a finding named it. */
export function credentialChecklist(ctx: Ctx, findings: Finding[]): string[] {
  const h = ctx.home;
  const out: string[] = [];
  const has = (rel: string) => existsSync(join(h, rel));
  if (has(".ssh")) out.push("SSH keys in ~/.ssh: make new keys, put the new public keys on servers, remove the old ones from every authorized_keys");
  if (has(".aws")) out.push("AWS: deactivate and delete access keys used on this machine; revoke SSO sessions (IAM Identity Center → active sessions)");
  if (has(".kube")) out.push("Kubernetes: revoke tokens and certificates in ~/.kube/config; rotate service-account tokens it could reach");
  if (has(".config/gcloud")) out.push("Google Cloud: gcloud auth revoke --all; delete service-account keys used here");
  if (has(".azure")) out.push("Azure: az logout; revoke refresh tokens for this user");
  if (has(".config/gh") || has(".git-credentials")) out.push("GitHub: revoke personal access tokens and OAuth apps; sign out all sessions; check SSH and deploy keys on your repos");
  if (has(".docker")) out.push("Container registries: change passwords / tokens used by docker login");
  if (has(".npmrc") || has(".pypirc")) out.push("Package registries: revoke npm / PyPI publish tokens; check recent publishes of your packages");
  out.push("Browsers: sign out of every session (Google, GitHub, cloud consoles, Slack); session cookies can be copied");
  out.push("Password manager: change the master password from another device; review recent logins");
  out.push("Chat and email: sign out other sessions; warn colleagues not to trust messages sent from your accounts during the incident window");
  for (const f of findings.filter((x) => x.rule === "secret")) out.push(`Named by the scan: ${f.title}`);
  return out;
}

async function collectEvidence(inc: Incident) {
  const ev = join(inc.dir, "evidence");
  const copies = join(ev, "files");
  mkdirSync(copies, { recursive: true, mode: 0o700 });
  const paths = new Set<string>();
  for (const f of inc.findings) {
    const p = f.item?.path;
    if (p && existsSync(p) && statSync(p).isFile()) paths.add(p);
    const prog = String(f.item?.meta?.program ?? "").split(" ").find((x) => x.startsWith("/") && existsSync(x));
    if (prog && statSync(prog).isFile()) paths.add(prog);
  }
  for (const p of paths) {
    try {
      const st = statSync(p);
      const sha = st.size < 200_000_000 ? fileHash(p) : undefined;
      const copy = sha ? join(copies, `${sha.slice(0, 16)}-${basename(p)}`) : undefined;
      if (copy) copyFileSync(p, copy);
      inc.evidence.push({ path: p, sha256: sha, size: st.size, mtime: st.mtimeMs, copy });
    } catch (e: any) {
      inc.evidence.push({ path: p, note: `could not copy: ${e.message ?? e}` });
    }
  }
  // The moment's state: what ran, what talked to whom, what launchd had loaded.
  const snap: [string, string[]][] = [
    ["processes.txt", ["ps", "-axww", "-o", "pid,ppid,user,lstart,command"]],
    ["connections.txt", ["lsof", "-nP", "-i"]],
    ["launchctl.txt", ["launchctl", "list"]],
  ];
  for (const [name, cmd] of snap) {
    const out = await run(cmd, 20_000);
    if (out !== undefined) {
      writeFileSync(join(ev, name), out, { mode: 0o600 });
      inc.evidence.push({ path: `(${cmd.join(" ")})`, sha256: fileHash(join(ev, name)), copy: join(ev, name) });
    }
  }
  const manifest = inc.evidence.map((e) => `${e.sha256 ?? "-".repeat(64)}  ${e.path}`).join("\n") + "\n";
  writeFileSync(join(ev, "MANIFEST.sha256"), manifest, { mode: 0o600 });
}

type Ask = (q: string) => Promise<boolean>;

/** Containment steps for one finding, as (description, action) pairs. Nothing runs unless the user says yes. */
function containment(f: Finding, ctx: Ctx, inc: Incident): { what: string; act?: () => Promise<string>; manual?: string }[] {
  const i = f.item;
  const quarantine = join(inc.dir, "quarantine");
  const moveAway = async (p: string) => {
    mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    const dest = join(quarantine, `${Date.now()}-${basename(p)}`);
    renameSync(p, dest);
    return `moved ${p} → ${dest}`;
  };
  if (!i) return [];
  switch (i.kind) {
    case "launch": {
      if (i.source !== "user") return [{ what: `unload system job ${i.name}`, manual: `sudo launchctl bootout system "${i.path}" && sudo mv "${i.path}" "${quarantine}/"` }];
      const uid = process.getuid?.() ?? 501;
      return [{
        what: `unload login job ${i.name} and move its plist to quarantine`,
        act: async () => {
          await run(["launchctl", "bootout", `gui/${uid}`, i.path!], 10_000);
          return moveAway(i.path!);
        },
      }];
    }
    case "bin":
    case "proc":
    case "conn":
      if (!i.path || !existsSync(i.path)) return [];
      return [
        ...(i.kind !== "bin" && i.meta?.pid ? [{ what: `stop process ${i.meta.pid} (${i.name})`, act: async () => ((await run(["kill", "-9", String(i.meta!.pid)])) !== undefined ? `killed ${i.meta!.pid}` : "kill failed") }] : []),
        { what: `move ${i.path} to quarantine`, act: () => moveAway(i.path!) },
      ];
    case "rc":
    case "ssh":
    case "cron": {
      const added = f.detail.filter((d) => d.startsWith("+ ")).map((d) => d.slice(2));
      if (!added.length || !i.path) return [];
      return [{
        what: `remove the ${added.length} added line${added.length > 1 ? "s" : ""} from ${i.path} (a copy is kept in the evidence)`,
        act: async () => {
          const text = readFileSync(i.path!, "utf8");
          copyFileSync(i.path!, join(inc.dir, "evidence", `${basename(i.path!)}.before-cleanup`));
          const kept = text.split("\n").filter((l) => !added.includes(l.trim())).join("\n");
          writeFileSync(i.path!, kept);
          return `removed ${added.length} line(s) from ${i.path}`;
        },
      }];
    }
    case "brew-tap": {
      const formulas = f.detail.find((d) => d.startsWith("installed from it:"))?.replace("installed from it: ", "").split(", ").map((x) => x.split(" ")[0]) ?? [];
      return [{ what: `uninstall ${formulas.join(", ") || "its packages"} and untap ${i.name}`, manual: `${formulas.map((x) => `brew uninstall ${x}`).join(" && ")}${formulas.length ? " && " : ""}brew untap ${i.name}` }];
    }
    case "brew":
      return [{ what: `uninstall ${i.name}`, manual: `brew uninstall ${i.name}` }];
    case "npm":
      return [{ what: `uninstall global npm package ${i.name}`, manual: i.source === "bun-global" ? `bun remove -g ${i.name}` : `npm uninstall -g ${i.name}` }];
    case "pip":
      return [{ what: `uninstall Python package ${i.name}`, manual: `python3 -m pip uninstall ${i.name}` }];
    case "browser-ext":
    case "editor-ext":
      return [{ what: `remove ${i.name} from ${i.source}`, manual: `remove it in ${i.source}'s extension settings` }];
  }
  return [];
}

export async function respond(ctx: Ctx, check: Check, ask: Ask, opt: { yes?: boolean } = {}): Promise<Incident> {
  const serious = check.findings.filter((f) => RANK[f.severity] >= RANK.medium);
  const id = stamp();
  const dir = join(files.incidents(), id);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const inc: Incident = { id, dir, at: Date.now(), host: check.scan.host, user: check.scan.user, findings: serious, evidence: [], actions: [], credentials: [] };
  const log = (what: string, done: boolean, detail?: string) => inc.actions.push({ at: Date.now(), what, done, detail });

  line(`${c.violet("▼ vswarm respond")} ${c.dim(`incident ${id} · ${dir}`)}`);
  for (const f of serious) printFinding(f, false);

  line(`\n${c.bold("1  lock")}`);
  setLock({ incident: id, at: Date.now(), reason: serious[0]?.title ?? "manual" });
  log("locked production access from this machine (preflight blocks)", true);
  line(`  ${c.green("✔")} preflight now blocks production access from this machine until ${c.cyan("vswarm unlock")}`);
  line(`  ${c.dim("if a finding is critical, also disconnect from the network (Wi-Fi off) before going on")}`);

  line(`\n${c.bold("2  evidence")}`);
  await collectEvidence(inc);
  log(`collected ${inc.evidence.length} evidence items with SHA-256`, true);
  line(`  ${c.green("✔")} ${inc.evidence.length} items with SHA-256 in ${join(dir, "evidence")}`);

  line(`\n${c.bold("3  rotate credentials")} ${c.dim("— from a different, clean device, not this one")}`);
  inc.credentials = credentialChecklist(ctx, check.findings);
  for (const cr of inc.credentials) line(`  ☐ ${cr}`);
  log("wrote the credential rotation checklist", true);

  line(`\n${c.bold("4  contain")}`);
  if (serious.some((f) => f.severity === "critical")) {
    line(`  ${c.red("!")} a critical finding means the machine should be erased and reinstalled; the steps below only buy time`);
  }
  let any = false;
  for (const f of serious) {
    for (const step of containment(f, ctx, inc)) {
      any = true;
      if (step.manual) {
        line(`  ☐ ${step.what}\n      ${c.cyan(step.manual)}`);
        log(step.what, false, step.manual);
        continue;
      }
      // Changing the machine is never automatic: --yes skips the questions by skipping these steps.
      if (!opt.yes && step.act && (await ask(`${step.what}?`))) {
        try {
          const r = await step.act();
          line(`  ${c.green("✔")} ${r}`);
          log(step.what, true, r);
        } catch (e: any) {
          line(`  ${c.red("✖")} ${e.message ?? e}`);
          log(step.what, false, String(e.message ?? e));
        }
      } else {
        line(`  ☐ ${step.what} ${c.dim("(skipped)")}`);
        log(step.what, false, "skipped");
      }
    }
  }
  if (!any) line(`  ${c.dim("nothing to contain automatically for these findings")}`);

  line(`\n${c.bold("5  report")}`);
  const written = writeReport(inc);
  for (const w of written) line(`  ${c.green("✔")} ${w}`);
  writePrivate(join(dir, "incident.json"), inc);
  line(`\n${c.dim("When the machine is clean (best: reinstalled) and credentials are rotated:")}`);
  line(`  ${c.cyan("vswarm baseline")} ${c.dim("then")} ${c.cyan("vswarm unlock")}`);
  return inc;
}
