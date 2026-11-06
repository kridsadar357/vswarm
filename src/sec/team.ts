// `vswarm team`: a small shared policy for a team, kept in a git repository the team controls and signed with an SSH
// key, the same allowed_signers mechanism as vswarm's releases. No server: each machine pulls the repository.
//
//   vswarm-team.json       the policy (below)
//   vswarm-team.json.sig   ssh-keygen -Y sign -n vswarm-team over it
//   allowed_signers        who may sign it: <principal> namespaces="vswarm-team" <ssh public key>
//
// `team join` pins allowed_signers on first use, after you confirm its fingerprints (or name one with --fingerprint).
// From then on `team sync` accepts only a policy signed by a pinned key, refuses a repository whose signers changed,
// and refuses a policy older (lower serial) than the one it has. The policy kept on this machine is sealed like
// vswarm's other state files.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "../home";
import { exec, readText, type Ctx } from "./ctx";
import { allowNames, normName } from "./intel";
import { readSealed, SEC, writeSealed } from "./store";
import type { Finding } from "./types";
import { fingerprints } from "./update";

// A state folder moved with VSWARM_SEC_DIR (tests, scratch runs) keeps its team policy beside it, like its key.
export const TEAM = () => process.env.VSWARM_TEAM_DIR ?? (process.env.VSWARM_SEC_DIR ? join(SEC(), "team") : join(HOME, "team"));
export const NAMESPACE = "vswarm-team";
const POLICY = "vswarm-team.json";

const paths = {
  repo: () => join(TEAM(), "repo"),
  signers: () => join(TEAM(), "allowed_signers"),
  policy: () => join(TEAM(), "policy.json"),
  remote: () => join(TEAM(), "remote.json"),
};

export interface Policy {
  "vswarm-team": 1;
  name: string;
  /** Goes up with every change; a machine never moves to a lower one (a replayed old policy). */
  serial: number;
  /** Finding ids the team expects (exact, or ending in * for a prefix). Known-malicious packages and vswarm's own state never match. */
  accept?: string[];
  /** Package names that are the team's own and never look-alikes (exact, or ending in *). */
  allow?: { npm?: string[]; pip?: string[] };
  /** What every machine should have; a missing one is a WARN in scan and preflight. */
  require?: { baseline?: boolean; baselineMaxDays?: number; watch?: boolean; guard?: boolean; guardIgnoreScripts?: boolean };
  /** Hosts the ssh gate should cover: `vswarm gate ssh --team` uses them, and status says what is missing. */
  gate?: { ssh?: string[] };
}

/** The policy's shape, checked before anything of it is used. Throws with what is wrong. */
export function parsePolicy(text: string): Policy {
  let p: any;
  try {
    p = JSON.parse(text);
  } catch {
    throw new Error(`${POLICY} is not valid JSON`);
  }
  const list = (v: unknown, what: string) => {
    if (v === undefined) return;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || !x || x.length > 300)) throw new Error(`${what} must be a list of strings`);
  };
  if (p?.["vswarm-team"] !== 1) throw new Error(`${POLICY} must say "vswarm-team": 1`);
  if (typeof p.name !== "string" || !/^[\w .@-]{1,80}$/.test(p.name)) throw new Error("name must be a short plain name");
  if (!Number.isInteger(p.serial) || p.serial < 1) throw new Error("serial must be a whole number, 1 or more");
  list(p.accept, "accept");
  list(p.allow?.npm, "allow.npm");
  list(p.allow?.pip, "allow.pip");
  list(p.gate?.ssh, "gate.ssh");
  if (p.gate?.ssh?.some((x: string) => !/^[\w*?!.:\[\]-]+$/.test(x))) throw new Error("gate.ssh holds something that is not an ssh host pattern");
  const r = p.require ?? {};
  for (const k of ["baseline", "watch", "guard", "guardIgnoreScripts"]) if (r[k] !== undefined && typeof r[k] !== "boolean") throw new Error(`require.${k} must be true or false`);
  if (r.baselineMaxDays !== undefined && !(Number.isInteger(r.baselineMaxDays) && r.baselineMaxDays > 0)) throw new Error("require.baselineMaxDays must be a whole number of days");
  return p as Policy;
}

/** `prefix*` or an exact match. */
export const matches = (patterns: string[] | undefined, value: string) => (patterns ?? []).some((p) => (p.endsWith("*") ? value.startsWith(p.slice(0, -1)) : value === p));

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
/** allowed_signers compared by their keys, not by comments or spacing. */
const signerSet = (text: string) => text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => l.replace(/\s+/g, " ")).sort().join("\n");

async function git(args: string[], cwd?: string) {
  // No hooks, no submodules, no LFS filters: fetching a policy must not run anything.
  const r = await exec(["git", "-c", "core.hooksPath=/dev/null", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false", ...args], { cwd, env: { ...process.env, GIT_TERMINAL_PROMPT: "0" }, timeoutMs: 120_000 });
  if (r.code !== 0) throw new Error(`git ${args[0]}: ${r.err.trim().split("\n")[0] || `exit ${r.code}`}`);
  return r.out;
}

/** Verifies dir/vswarm-team.json against its .sig with the signers in `signers`. Returns who signed it. */
export async function verifyPolicy(dir: string, signers: string): Promise<string> {
  const file = join(dir, POLICY), sig = `${file}.sig`;
  if (!existsSync(file)) throw new Error(`no ${POLICY} in the team repository`);
  if (!existsSync(sig)) throw new Error(`${POLICY} is not signed (no ${POLICY}.sig); vswarm uses only a signed policy`);
  const who = await exec(["ssh-keygen", "-Y", "find-principals", "-s", sig, "-f", signers]);
  const principal = who.out.trim().split("\n")[0];
  if (who.code !== 0 || !principal) throw new Error(`${POLICY} is not signed by a key in the team's pinned allowed_signers`);
  const p = Bun.spawn(["ssh-keygen", "-Y", "verify", "-f", signers, "-I", principal, "-n", NAMESPACE, "-s", sig], { stdin: Bun.file(file), stdout: "pipe", stderr: "pipe" });
  const [err, code] = await Promise.all([new Response(p.stderr).text(), p.exited]);
  if (code !== 0) throw new Error(`the signature on ${POLICY} does not verify: ${err.trim().split("\n")[0] || `exit ${code}`}`);
  return principal;
}

export interface Joined {
  policy: Policy;
  signer: string;
  keys: { who: string; fp: string }[];
}

/**
 * First contact: clone, read the signers the repository lists, and pin them only after `confirm` (the caller asks
 * you, or checks --fingerprint). Nothing is kept unless the policy verifies against them.
 */
export async function teamJoin(url: string, confirm: (keys: { who: string; fp: string }[]) => Promise<boolean>): Promise<Joined> {
  if (existsSync(paths.signers())) throw new Error("this machine already follows a team policy; vswarm team leave first, or vswarm team sync");
  mkdirSync(TEAM(), { recursive: true, mode: 0o700 });
  rmSync(paths.repo(), { recursive: true, force: true });
  try {
    await git(["clone", "--quiet", "--depth", "1", "--no-recurse-submodules", url, paths.repo()]);
    const shipped = readText(join(paths.repo(), "allowed_signers"));
    if (!shipped || !signerSet(shipped)) throw new Error("the team repository lists no signers (allowed_signers)");
    const candidate = join(TEAM(), "allowed_signers.candidate");
    writeFileSync(candidate, shipped, { mode: 0o600 });
    const keys = await fingerprints(candidate);
    if (!keys.length) throw new Error("allowed_signers in the team repository holds no usable key");
    try {
      if (!(await confirm(keys))) throw new Error("not joined: the signing keys were not confirmed");
      const signer = await verifyPolicy(paths.repo(), candidate);
      const policy = parsePolicy(readFileSync(join(paths.repo(), POLICY), "utf8"));
      writeFileSync(paths.signers(), shipped, { mode: 0o600 });
      await keep(policy, url);
      return { policy, signer, keys };
    } finally {
      rmSync(candidate, { force: true });
    }
  } catch (e) {
    rmSync(paths.repo(), { recursive: true, force: true });
    throw e;
  }
}

async function keep(policy: Policy, url: string) {
  await writeSealed(paths.policy(), policy);
  writeFileSync(paths.remote(), JSON.stringify({ url, syncedAt: Date.now() }, null, 1), { mode: 0o600 });
}

/** Pulls the repository and takes its policy only if it is signed by a pinned key, its signers are the pinned ones, and its serial did not go back. */
export async function teamSync(): Promise<{ policy: Policy; previous?: number; signer: string }> {
  if (!existsSync(paths.signers())) throw new Error("this machine follows no team policy yet: vswarm team join <git url>");
  const url = JSON.parse(readFileSync(paths.remote(), "utf8")).url as string;
  if (!existsSync(join(paths.repo(), ".git"))) await git(["clone", "--quiet", "--depth", "1", "--no-recurse-submodules", url, paths.repo()]);
  await git(["-C", paths.repo(), "fetch", "--quiet", "--depth", "1", "origin"]);
  await git(["-C", paths.repo(), "reset", "--quiet", "--hard", "FETCH_HEAD"]);
  const pinned = readFileSync(paths.signers(), "utf8");
  const shipped = readText(join(paths.repo(), "allowed_signers")) ?? "";
  // A new signer is a decision for people, not for a pull: like a changed release key, it needs a deliberate re-join.
  if (sha(signerSet(shipped)) !== sha(signerSet(pinned)))
    throw new Error("the team repository now lists different signers than the ones pinned here; check with your team, then vswarm team leave && vswarm team join <url>");
  const signer = await verifyPolicy(paths.repo(), paths.signers());
  const policy = parsePolicy(readFileSync(join(paths.repo(), POLICY), "utf8"));
  const prev = (await loadPolicy()).policy;
  if (prev && policy.serial < prev.serial) throw new Error(`the policy in the repository (serial ${policy.serial}) is older than the one here (${prev.serial}); refusing to go back`);
  await keep(policy, url);
  return { policy, previous: prev?.serial, signer };
}

export function teamLeave() {
  rmSync(TEAM(), { recursive: true, force: true });
}

/** The policy this machine follows, as last synced; one changed outside vswarm is not used. */
export async function loadPolicy(): Promise<{ policy?: Policy; untrusted?: string }> {
  if (!existsSync(paths.policy())) return {};
  const r = await readSealed<Policy>(paths.policy());
  if (r.untrusted && !r.nokey) return { untrusted: r.untrusted };
  try {
    return { policy: parsePolicy(JSON.stringify(r.value)) };
  } catch (e: any) {
    return { untrusted: `is not a valid policy (${e.message})` };
  }
}

export function teamInfo(): { url?: string; syncedAt?: number } {
  try {
    return JSON.parse(readFileSync(paths.remote(), "utf8"));
  } catch {
    return {};
  }
}

/** The team's own package names stop being look-alikes, in scans and in the install guard alike. */
export function applyAllow(p?: Policy) {
  allowNames((kind, name) => matches(kind === "pip" ? p?.allow?.pip?.map((x) => normName("pip", x)) : p?.allow?.npm, name));
}

/** What the policy requires that this machine does not have, as WARN findings. */
export async function requirements(p: Policy, ctx: Ctx, baselineAt?: number): Promise<Finding[]> {
  const out: Finding[] = [];
  const r = p.require ?? {};
  const add = (id: string, title: string, fix: string) => out.push({ id: `team:${id}`, rule: "team-require", severity: "medium", title: `Team ${p.name}: ${title}`, detail: [`policy serial ${p.serial}`], fix });
  if ((r.baseline || r.baselineMaxDays) && baselineAt === undefined) add("baseline", "every machine keeps a baseline, and this one has none", "On a machine you trust: vswarm baseline");
  else if (r.baselineMaxDays && baselineAt !== undefined && Date.now() - baselineAt > r.baselineMaxDays * 86_400_000)
    add("baseline-age", `the baseline should be at most ${r.baselineMaxDays} days old`, "Review vswarm diff, then vswarm baseline");
  if (r.watch) {
    const { watchInstalled } = await import("./schedule");
    if (!watchInstalled(ctx.home)) add("watch", "the background watch should be on", "vswarm watch on");
  }
  const want = p.gate?.ssh ?? [];
  if (want.length) {
    const cfg = readText(join(ctx.home, ".ssh", "config")) ?? "";
    const line = /# >>> vswarm gate >>>[\s\S]*?Match originalhost (\S+)/.exec(cfg)?.[1]?.split(",") ?? [];
    const missing = want.filter((h) => !line.includes(h));
    if (missing.length) add("gate", `ssh to ${missing.join(", ")} should go through the gate`, "vswarm gate ssh --team");
  }
  return out;
}

// ── vswarm team join | sync | status | leave | sign

/** Signs a policy file for the team repository (maintainers): checks its shape first, then ssh-keygen -Y sign. */
export async function signPolicy(file: string, key: string): Promise<string> {
  parsePolicy(readFileSync(file, "utf8"));
  // On the terminal: a key with a passphrase asks for it there.
  const r = await exec(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", NAMESPACE, file], { tty: true });
  if (r.code !== 0 || !existsSync(`${file}.sig`)) throw new Error(`could not sign ${file} with ${key}`);
  return `${file}.sig`;
}

export async function teamCommand(action: string, args: string[], opt: { fingerprint?: string; yes?: boolean; key?: string; ask: (q: string, def?: boolean) => Promise<boolean> }) {
  const { c, line } = await import("./print");
  const show = (p: Policy) => {
    if (p.accept?.length) line(`  ${c.dim(`accepts ${p.accept.length} finding pattern${p.accept.length > 1 ? "s" : ""} team-wide`)}`);
    const allowed = (p.allow?.npm?.length ?? 0) + (p.allow?.pip?.length ?? 0);
    if (allowed) line(`  ${c.dim(`${allowed} package name pattern${allowed > 1 ? "s" : ""} of the team's own, never look-alikes`)}`);
    if (p.gate?.ssh?.length) line(`  ${c.dim(`gate: ${p.gate.ssh.join(", ")} (vswarm gate ssh --team)`)}`);
  };
  if (action === "join") {
    const url = args[0];
    if (!url) throw new Error("usage: vswarm team join <git url> [--fingerprint SHA256:…] [--yes]");
    const j = await teamJoin(url, async (keys) => {
      line(`${c.violet("▼ vswarm team join")} ${c.dim(url)}`);
      for (const k of keys) line(`  signing key ${c.bold(k.fp)} ${c.dim(k.who)}`);
      if (opt.fingerprint) {
        const hit = keys.some((k) => k.fp === opt.fingerprint);
        if (!hit) line(c.red(`  none of these is ${opt.fingerprint}`));
        return hit;
      }
      if (opt.yes) return true;
      line(c.dim("  Compare these with what your team published through another channel (chat, wiki, in person)."));
      return opt.ask("Trust these keys for this team's policy from now on?", false);
    });
    line(`${c.green("✔")} joined ${j.policy.name} (serial ${j.policy.serial}), signed by ${j.signer}`);
    show(j.policy);
    line(c.dim("  vswarm team sync fetches changes; only a policy signed by these keys is taken"));
    return;
  }
  if (action === "sync") {
    const r = await teamSync();
    line(`${c.green("✔")} ${r.policy.name} serial ${r.policy.serial}${r.previous === r.policy.serial ? " (no change)" : r.previous !== undefined ? ` (was ${r.previous})` : ""}, signed by ${r.signer}`);
    show(r.policy);
    return;
  }
  if (action === "leave") {
    teamLeave();
    line(`${c.green("✔")} this machine follows no team policy now`);
    return;
  }
  if (action === "sign") {
    if (!args[0] || !opt.key) throw new Error("usage: vswarm team sign vswarm-team.json --key ~/.ssh/team_signing_key");
    line(`${c.green("✔")} ${await signPolicy(args[0], opt.key)}`);
    return;
  }
  if (action === "status") {
    const l = await loadPolicy();
    if (l.untrusted) {
      line(c.red(`  the team policy on this machine ${l.untrusted}; vswarm team sync fetches the signed one`));
      return;
    }
    if (!l.policy) return line(`  ${c.dim("·")} no team policy · vswarm team join <git url>`);
    const info = teamInfo();
    line(`${c.violet("▼ vswarm team")} ${l.policy.name} ${c.dim(`· serial ${l.policy.serial} · ${info.url ?? ""} · synced ${info.syncedAt ? new Date(info.syncedAt).toLocaleString() : "?"}`)}`);
    for (const k of await fingerprints(paths.signers())) line(`  ${c.dim(`signing key ${k.fp} ${k.who}`)}`);
    show(l.policy);
    const { realCtx } = await import("./ctx");
    const { loadBaseline } = await import("./store");
    const missing = await requirements(l.policy, realCtx(), (await loadBaseline())?.at);
    const r = l.policy.require ?? {};
    if (r.guard || r.guardIgnoreScripts) {
      const { guardOn } = await import("../setup");
      const { loadGuardConfig } = await import("./pkg");
      if (!(await guardOn())) missing.push({ id: "team:guard", rule: "team-require", severity: "medium", title: "the install guard should be on", detail: [], fix: "vswarm guard on" });
      else if (r.guardIgnoreScripts && !loadGuardConfig().ignoreScripts)
        missing.push({ id: "team:guard-scripts", rule: "team-require", severity: "medium", title: "installs should run with their scripts off", detail: [], fix: "vswarm guard on --ignore-scripts" });
    }
    if (!missing.length) line(`  ${c.green("✔")} this machine has what the policy requires`);
    for (const f of missing) line(`  ${c.amber("!")} ${f.title.replace(`Team ${l.policy.name}: `, "")} ${c.dim(`· ${f.fix}`)}`);
    return;
  }
  throw new Error("usage: vswarm team join <git url> | sync | status | leave | sign <file> --key <key>");
}
