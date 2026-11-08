// gcloud and az: gate the credential where the tool lets a command produce it, a wrapper only where it does not.
//
// gcloud: an external-account credential (workload identity federation) can take its subject token from a command,
// `credential_source.executable.command`: the analogue of aws `credential_process`. `vswarm gate gcloud <configuration>`
// writes a copy of that credential whose command is `vswarm preflight --quiet --then <the original command>` and points
// the configuration's `auth/credential_file_override` at it (the property google-github-actions/auth sets through
// CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE; gcloud reads the file on every run). gcloud then asks vswarm each time it
// needs a new token, from any shell, script or program that runs gcloud with that configuration. The copy has no
// `output_file`: a cached token there would be used without running the command. gcloud runs executables only with
// GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1 in its environment.
//
// User accounts (gcloud auth login) and service-account keys have no such hook: for them `gate gcloud` falls back to
// the command wrapper (cmdgate.ts), matching the configuration or project a command acts on, and says so.
//
// az: the Azure CLI signs in through MSAL and keeps its tokens in ~/.azure; it has no setting that runs a command for a
// credential. `vswarm gate az` is the command wrapper, matching the subscription, and says that plainly.

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, sep } from "node:path";
import { HOME } from "../home";
import { backupCopy, backupDir } from "./fix";
import { readJson, readText } from "./ctx";
import { addCmdGate, gcloudDir, honest, iniGet, loadCmdGates, realGateFiles, removeCmdGate, type GateFiles } from "./cmdgate";
import { c } from "./print";
import { SEC, writePrivate } from "./store";
import type { AwsHook } from "./awsgate";
import type { KubeHook } from "./kubegate";

export interface GcloudHook {
  /** The configuration file vswarm changed. */
  file: string;
  /** auth/credential_file_override before vswarm set it, restored on off. */
  previous?: string;
  /** The gated copy of the credential. */
  cred: string;
  /** The credential it was made from. */
  source: string;
  /** A copy of the configuration file from before, in ~/.vswarm/backups (removed with the hook). */
  backup?: string;
  at: number;
}

export interface CloudGates {
  gcloud: Record<string, GcloudHook>;
  /** aws profiles whose credential_process runs preflight (awsgate.ts), by the profile vswarm changed. */
  aws: Record<string, AwsHook>;
  /** kubeconfig users whose exec plugin runs preflight (kubegate.ts), by user name. */
  kube: Record<string, KubeHook>;
}

const stateFile = () => join(SEC(), "cloudgate.json");
export const loadCloudGates = (): CloudGates => {
  const s = readJson<CloudGates>(stateFile());
  const map = (v: unknown): any => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
  return { gcloud: map(s?.gcloud), aws: map(s?.aws), kube: map(s?.kube) };
};
export const saveCloudGates = (s: CloudGates) => writePrivate(stateFile(), s);

/**
 * Removes a backup vswarm made for a hook that is gone, once no other hook still names it: one in ~/.vswarm/backups,
 * or one an older vswarm wrote beside the file (`<file>.bak-vswarm-<time>`). Anything else is left alone.
 */
export function pruneBackup(backup: string | undefined, file: string, state: CloudGates = loadCloudGates()) {
  if (!backup) return;
  const ours = backup.startsWith(backupDir() + sep) || backup === `${file}.bak-vswarm-${/\.bak-vswarm-(\d+)$/.exec(backup)?.[1]}`;
  const named = [...Object.values(state.aws), ...Object.values(state.kube), ...Object.values(state.gcloud)].some((h) => h.backup === backup);
  if (ours && !named) rmSync(backup, { force: true });
}

/** Where vswarm keeps gated credentials. */
export const gateDir = () => process.env.VSWARM_GATE_DIR ?? join(HOME, "gate");

// ── INI, as gcloud's configuration files are written

/** Sets (or with null removes) key in [section], keeping every other line, comment and line ending as it was. */
export function iniSet(text: string, section: string, key: string, value: string | null): string {
  const nl = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.length ? text.split(/\r?\n/) : [];
  // A trailing newline leaves an empty last element; it comes back on join.
  const trailing = lines.length && lines[lines.length - 1] === "";
  if (trailing) lines.pop();
  let start = -1;
  let end = lines.length;
  for (let i = 0; i < lines.length; i++) {
    const s = /^\s*\[([^\]]+)\]\s*$/.exec(lines[i]);
    if (!s) continue;
    if (start >= 0) {
      end = i;
      break;
    }
    if (s[1].trim() === section) start = i;
  }
  const isKey = (l: string) => new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*[=:]`).test(l);
  if (start < 0) {
    if (value === null) return text;
    // Before the new section, one blank line if the file has content.
    const add = [...(lines.length && lines[lines.length - 1].trim() ? [""] : []), `[${section}]`, `${key} = ${value}`];
    return [...lines, ...add].join(nl) + nl;
  }
  const at = lines.findIndex((l, i) => i > start && i < end && isKey(l));
  if (value === null) {
    if (at < 0) return text;
    lines.splice(at, 1);
    end--;
    // A section left with nothing in it goes too, with the blank line that set it apart.
    if (!lines.slice(start + 1, end).some((l) => l.trim())) {
      lines.splice(start, end - start);
      if (start > 0 && !lines[start - 1].trim() && (start === lines.length || /^\s*\[/.test(lines[start]) || !lines[start].trim())) lines.splice(start - 1, 1);
    }
  } else if (at >= 0) lines[at] = `${key} = ${value}`;
  else {
    // After the section's last non-blank line.
    let ins = end;
    while (ins - 1 > start && !lines[ins - 1].trim()) ins--;
    lines.splice(ins, 0, `${key} = ${value}`);
  }
  return lines.length ? lines.join(nl) + (trailing || value !== null ? nl : "") : "";
}

// ── the gated credential

/** One word for Python's shlex.split, which google-auth uses on the command: single quotes keep backslashes too. */
const sq = (s: string) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'"'"'`)}'`);

const PREFIX = (launcher: string[]) => `${launcher.map(sq).join(" ")} preflight --quiet --then `;

/** The command of an executable-sourced external account, or why there is none. */
export function executableOf(cred: any): { command?: string; why?: string } {
  if (!cred || typeof cred !== "object") return { why: "is not JSON" };
  if (cred.type === "authorized_user") return { why: "is a user sign-in (gcloud auth login), which has no command to put a check in front of" };
  if (cred.type === "service_account") return { why: "is a service-account key, which has no command to put a check in front of" };
  if (cred.type !== "external_account") return { why: `is of type ${String(cred.type ?? "unknown")}, not an external account` };
  const cmd = cred.credential_source?.executable?.command;
  if (typeof cmd !== "string" || !cmd.trim()) {
    const kind = cred.credential_source?.file ? "a file" : cred.credential_source?.url ? "a URL" : cred.credential_source?.environment_id ? "the cloud it runs on" : "no command";
    return { why: `takes its token from ${kind}, not from a command` };
  }
  return { command: cmd.trim() };
}

/** The original command inside a credential vswarm already gated, so gating twice does not nest. */
export function ungated(command: string): string {
  const m = /^(?:\S+|'[^']*')(?:\s+(?:\S+|'[^']*'))*?\s+preflight\s+--quiet\s+--then\s+([\s\S]+)$/.exec(command);
  return m && /vswarm|cli\.ts/.test(command.slice(0, command.length - m[1].length)) ? m[1] : command;
}

/** A copy of an external-account credential whose command runs preflight first; output_file is dropped. */
export function gatedCredential(cred: any, launcher: string[]): { cred: any; droppedCache: boolean } {
  const ex = executableOf(cred);
  if (!ex.command) throw new Error(`this credential ${ex.why}`);
  const copy = JSON.parse(JSON.stringify(cred));
  const exe = copy.credential_source.executable;
  const droppedCache = exe.output_file !== undefined;
  delete exe.output_file;
  exe.command = PREFIX(launcher) + ungated(ex.command);
  // Room for a fresh check (about 0.2 s, up to 3 s when a known-malicious lookup is slow) on top of the command.
  if (typeof exe.timeout_millis === "number" && exe.timeout_millis < 30_000) exe.timeout_millis = 30_000;
  return { cred: copy, droppedCache };
}

const CONFIG_NAME = /^[a-z][-a-z0-9]*$/;

export interface CloudEnv {
  env: Record<string, string | undefined>;
  home: string;
  /** How vswarm is started from gcloud: the launcher, or bun and the CLI. */
  launcher: string[];
  /** The rc files / profiles for the wrapper fallback. */
  where?: GateFiles;
}

export async function realEnv(): Promise<CloudEnv> {
  const { CLI, launcherPath } = await import("../setup");
  const win = process.platform === "win32";
  // On Windows bun and the CLI by full path: Python starts vswarm.cmd through cmd.exe, which would read the arguments.
  return { env: process.env, home: homedir(), launcher: win || !existsSync(launcherPath()) ? [process.execPath, CLI] : [launcherPath()] };
}

const configFile = (e: CloudEnv, name: string) => join(gcloudDir(e), "configurations", `config_${name}`);

/** Hooks one gcloud configuration. Returns what was done, for the caller to print. */
export function gcloudHookOn(name: string, credFile: string | undefined, e: CloudEnv): { hook: GcloudHook; droppedCache: boolean; adopted: boolean } {
  if (!CONFIG_NAME.test(name)) throw new Error(`"${name}" is not a gcloud configuration name (lower-case letters, digits and -)`);
  const file = configFile(e, name);
  const text = readText(file);
  if (text === undefined) throw new Error(`no gcloud configuration ${name} (${file}); create it with gcloud config configurations create ${name}`);
  const state = loadCloudGates();
  const ours = state.gcloud[name];
  const current = iniGet(text, "auth", "credential_file_override");
  const own = (p?: string) => !!p && (p === ours?.cred || p.startsWith(gateDir()));
  // The credential to gate: the one named, else the one the configuration already overrides with (adopted).
  const source = credFile ?? (own(current) ? ours?.source : current);
  if (!source) throw new Error(`configuration ${name} has no credential file vswarm can hook; name one with --cred-file <external-account.json>`);
  const cred = readJson(source);
  if (cred === undefined) throw new Error(`cannot read ${source}`);
  const { cred: gated, droppedCache } = gatedCredential(cred, e.launcher);
  mkdirSync(gateDir(), { recursive: true, mode: 0o700 });
  const out = join(gateDir(), `gcloud-${name}.json`);
  writeFileSync(out, JSON.stringify(gated, null, 2) + "\n", { mode: 0o600 });
  // The copy goes to ~/.vswarm/backups: gcloud reads every config_<name> file in configurations/, a backup there too.
  const backup = ours?.backup && existsSync(ours.backup) ? ours.backup : backupCopy(file, "gcloud");
  writeFileSync(file, iniSet(text, "auth", "credential_file_override", out));
  const hook: GcloudHook = { file, previous: own(current) ? ours?.previous : current, cred: out, source, backup, at: Date.now() };
  state.gcloud[name] = hook;
  saveCloudGates(state);
  return { hook, droppedCache, adopted: !credFile };
}

/** Restores one configuration as it was. Returns what happened, for the caller to print. */
export function gcloudHookOff(name: string): { done: boolean; note?: string } {
  const state = loadCloudGates();
  const h = state.gcloud[name];
  if (!h) return { done: false };
  const text = readText(h.file);
  let note: string | undefined;
  if (text !== undefined) {
    const current = iniGet(text, "auth", "credential_file_override");
    if (current === h.cred) writeFileSync(h.file, iniSet(text, "auth", "credential_file_override", h.previous ?? null));
    else note = `${h.file} no longer points at vswarm's credential (now ${current ?? "nothing"}); left as it is`;
  }
  rmSync(h.cred, { force: true });
  delete state.gcloud[name];
  saveCloudGates(state);
  pruneBackup(h.backup, h.file, state);
  // Copies older vswarm versions left in configurations/, where gcloud took each for a configuration of its own.
  try {
    for (const f of readdirSync(dirname(h.file))) if (new RegExp(`^${basename(h.file).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.bak-vswarm-\\d+$`).test(f)) rmSync(join(dirname(h.file), f), { force: true });
  } catch {}
  return { done: true, note };
}

/** Each hooked configuration and whether it is still in place. */
export function gcloudHookStatus(): { name: string; ok: boolean; detail: string }[] {
  return Object.entries(loadCloudGates().gcloud).map(([name, h]) => {
    const current = iniGet(readText(h.file) ?? "", "auth", "credential_file_override");
    const cred = readJson(h.cred);
    const inPlace = current === h.cred && typeof cred?.credential_source?.executable?.command === "string" && /preflight --quiet --then/.test(cred.credential_source.executable.command);
    return { name, ok: inPlace, detail: inPlace ? `${h.file} · token command runs preflight first` : current !== h.cred ? `${h.file} no longer points at ${h.cred}` : `${h.cred} was changed: its command does not run preflight` };
  });
}

export const ok = (t: string, d = "") => console.log(`  ${c.green("✔")} ${t}${d ? "  " + c.dim(d) : ""}`);
export const warn = (t: string, d = "") => console.log(`  ${c.amber("!")} ${t}${d ? "  " + c.dim(d) : ""}`);
export const note = (t: string) => console.log(`  ${c.dim(t)}`);

/** vswarm gate gcloud <configuration|project patterns…> [--cred-file f] [--wrapper] | --off [name] | (status) */
export async function gateGcloud(args: string[], e?: CloudEnv) {
  e ??= await realEnv();
  const take = (f: string) => {
    const i = args.indexOf(f);
    return i >= 0 ? (args.splice(i, 1), true) : false;
  };
  const credAt = args.indexOf("--cred-file");
  const credFile = credAt >= 0 ? args.splice(credAt, 2)[1] : undefined;
  if (credAt >= 0 && !credFile) throw new Error("--cred-file takes the path of an external-account credential (JSON)");
  const off = take("--off");
  const wrapper = take("--wrapper");
  const where = () => e!.where ?? realGateFiles(!off);
  if (off) {
    if (!args.length) {
      for (const n of Object.keys(loadCloudGates().gcloud)) report(n, gcloudHookOff(n));
      const r = await removeCmdGate("gcloud", await where());
      if (r.removed.length) ok("gcloud wrapper removed", r.changed.join(", "));
      return;
    }
    for (const n of args) {
      const r = gcloudHookOff(n);
      if (r.done) report(n, r);
      const g = loadCmdGates().tools.gcloud;
      if (g?.patterns.includes(n)) {
        const rest = g.patterns.filter((p) => p !== n);
        if (rest.length) await addCmdGate("gcloud", rest, await where());
        else await removeCmdGate("gcloud", await where());
        ok(`gcloud wrapper no longer matches ${n}`);
      } else if (!r.done) note(`${n}: no vswarm gate`);
    }
    return;
  }
  if ((!args.length && !wrapper) || (args.length === 1 && args[0] === "status")) return gcloudStatus();
  if (credFile && args.length !== 1) throw new Error("--cred-file hooks one configuration: vswarm gate gcloud <configuration> --cred-file <file>");
  // A configuration with a credential vswarm can hook gets the hook; anything else gets the wrapper, said plainly.
  if (!wrapper) {
    const hookable = (name: string): string | undefined => {
      if (!CONFIG_NAME.test(name)) return;
      const text = readText(configFile(e!, name));
      if (text === undefined) return;
      const cur = iniGet(text, "auth", "credential_file_override");
      const known = loadCloudGates().gcloud[name];
      const src = credFile ?? (cur && cur === known?.cred ? known.source : cur);
      return src && executableOf(readJson(src)).command ? src : undefined;
    };
    if (credFile || (args.length === 1 && hookable(args[0]))) {
      const r = gcloudHookOn(args[0], credFile, e);
      ok(`gcloud configuration ${args[0]}: its token command runs vswarm preflight first`, r.hook.file);
      note(`credential ${r.hook.cred} (made from ${r.hook.source}${r.adopted ? ", the file this configuration used" : ""})`);
      note("gcloud asks for a new token about once an hour, from any shell or program, so the check runs then; a BLOCK means no new token");
      if (r.droppedCache) note("output_file was left out of the copy: a token cached there would be used without the check");
      if (e.env.GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES !== "1")
        warn("gcloud runs a credential's command only with GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1", "set it where gcloud runs, e.g. export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1 in your shell rc");
      note(`turn off: vswarm gate gcloud --off ${args[0]}`);
      return;
    }
  }
  const w = await where();
  const changed = await addCmdGate("gcloud", args, w);
  warn("gcloud: no credential hook for these, so this is the command wrapper", "user sign-ins and service-account keys give gcloud no command to run for a token");
  ok(`gcloud checks preflight when it acts on ${args.join(", ")} (configuration or project)`, changed.length ? changed.join(", ") : "already in place");
  honest("gcloud");
  note("a real hook: sign in through workload identity federation with an executable source, then vswarm gate gcloud <configuration> --cred-file <its config>");
}

function report(name: string, r: { done: boolean; note?: string }) {
  if (!r.done) return;
  ok(`gcloud configuration ${name} restored`);
  if (r.note) warn(r.note);
}

function gcloudStatus() {
  const hooks = gcloudHookStatus();
  for (const h of hooks) (h.ok ? ok : warn)(`gcloud configuration ${h.name}: credential hook`, h.detail);
  const w = loadCmdGates().tools.gcloud;
  if (w) ok("gcloud wrapper", `${w.patterns.join(", ") || "every run"} · a reminder you can bypass`);
  if (!hooks.length && !w) note("no gcloud gate · vswarm gate gcloud <configuration> [--cred-file <external-account.json>]");
}

/** vswarm gate az [subscription patterns…] | --off | (status) */
export async function gateAz(args: string[], where?: GateFiles) {
  const offAt = args.indexOf("--off");
  if (offAt >= 0) {
    args.splice(offAt, 1);
    const r = await removeCmdGate("az", where ?? (await realGateFiles(false)));
    if (r.removed.length) ok("az wrapper removed", r.changed.join(", "));
    else note("az is not gated");
    return;
  }
  // No arguments is status, as for every other gate; `gate az --all` wraps every run.
  const allAt = args.indexOf("--all");
  const every = allAt >= 0;
  if (every) args.splice(allAt, 1);
  if ((!args.length && !every) || (args.length === 1 && args[0] === "status")) {
    const g = loadCmdGates().tools.az;
    return g ? ok("az wrapper", `${g.patterns.join(", ") || "every run"} · a reminder you can bypass`) : note('az is not gated · vswarm gate az "<subscription name or id>" … (or --all for every run)');
  }
  const w = where ?? (await realGateFiles(true));
  const changed = await addCmdGate("az", args, w);
  warn("az has no credential hook: the Azure CLI signs in through MSAL and keeps its tokens in ~/.azure, and runs no command for a credential", "so this is the command wrapper");
  ok(`az checks preflight ${args.length ? `when it acts on subscription ${args.join(", ")}` : "every time it runs"}`, changed.length ? changed.join(", ") : "already in place");
  honest("az");
  note("programs that call az themselves (Terraform, the Azure SDK's AzureCliCredential) are not checked");
}

/** For doctor: one line per cloud and command gate. */
export async function cloudDoctor(e?: CloudEnv): Promise<{ level: "ok" | "warn" | "off"; text: string; detail?: string }[]> {
  const out: { level: "ok" | "warn" | "off"; text: string; detail?: string }[] = [];
  // aws profiles and kubectl users whose credential runs preflight (awsgate.ts, kubegate.ts)
  const { awsStatus } = await import("./awsgate");
  const { kubeStatus } = await import("./kubegate");
  const aws = awsStatus(e ?? (await realEnv()));
  for (const h of aws) out.push({ level: h.ok ? "ok" : "warn", text: `aws gate on profile ${h.name}`, detail: h.detail });
  if (!aws.length) out.push({ level: "off", text: "no aws gate", detail: "vswarm gate aws <profile>" });
  const kube = kubeStatus();
  for (const h of kube) out.push({ level: h.ok ? "ok" : "warn", text: `kubectl gate on user ${h.name}`, detail: h.detail });
  if (!kube.length) out.push({ level: "off", text: "no kubectl gate", detail: "vswarm gate kube <context>" });
  for (const h of gcloudHookStatus()) out.push({ level: h.ok ? "ok" : "warn", text: `gcloud gate on configuration ${h.name}`, detail: h.detail });
  const tools = Object.keys(loadCmdGates().tools).sort();
  if (tools.length) {
    const { readKept } = await import("../setup");
    const w = await realGateFiles(false).catch(() => undefined);
    const present = w ? w.files.some((f) => (readKept(f)?.text ?? "").includes("# >>> vswarm cmdgate >>>")) : false;
    out.push(present ? { level: "ok", text: `command gates: ${tools.join(", ")}`, detail: "reminders you can bypass, not controls" } : { level: "warn", text: `command gates listed (${tools.join(", ")}) but not in your shell files`, detail: "vswarm gate cmd <name> writes them again" });
  } else out.push({ level: "off", text: "no command gates", detail: "vswarm gate cmd psql \"*.prod.internal\"" });
  return out;
}

/** For uninstall: every command gate and aws, kubectl and gcloud hook removed. Returns what changed. */
export async function cloudUninstall(where?: GateFiles): Promise<string[]> {
  const done: string[] = [];
  done.push(...(await import("./awsgate")).awsUninstall(), ...(await import("./kubegate")).kubeUninstall());
  for (const n of Object.keys(loadCloudGates().gcloud)) if (gcloudHookOff(n).done) done.push(`gcloud configuration ${n} restored`);
  if (Object.keys(loadCmdGates().tools).length || where) {
    const w = where ?? (await realGateFiles(false));
    const r = await removeCmdGate(undefined, w);
    for (const f of r.changed) done.push(`command gates removed from ${f}`);
  }
  // Nothing left to gate: the folder of gated credentials goes too, if vswarm made it and it is empty.
  try {
    if (existsSync(gateDir()) && !readdirSync(gateDir()).length) rmSync(gateDir(), { recursive: true });
  } catch {}
  return done;
}
