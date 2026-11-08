// aws: the credential a profile hands out runs vswarm preflight first.
//
// `vswarm gate aws <profile…>` changes ~/.aws/config (or AWS_CONFIG_FILE) so that the profile's credentials come from
// `credential_process = vswarm preflight --quiet --then <what produced them before>`. The AWS CLI and the SDKs run that
// command whenever they need credentials for the profile, from any shell, script or program; a BLOCK means none.
//
//   credential_process   the command is wrapped where it stands
//   IAM Identity Center  (sso_session / sso_start_url …) the SSO settings move to a companion profile,
//                        [profile vswarm-src-<name>], and the profile's credential_process becomes
//                        `aws configure export-credentials --profile vswarm-src-<name> --format process` behind
//                        preflight. The profile cannot ask itself: that would run its own credential_process again.
//                        Settings move rather than stay, because the SDKs try SSO before credential_process.
//   role_arn + source_profile   the role is assumed with the source profile's credentials, so the source is gated
//   static keys          (aws_access_key_id in ~/.aws/credentials or the config) are refused: the SDKs read them
//                        before credential_process and send them without running anything, so nothing can stand in
//                        front of them. Move the profile to IAM Identity Center or a credential_process first.
//
// The file is edited line by line: every other line, comment, blank line and line ending stays as it was. vswarm keeps
// a backup, the profile's section before and after, and the exact lines it took out and put in, so --off puts the
// bytes back, and a section edited since (aws configure set …) gets only vswarm's lines swapped back.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readText } from "./ctx";
import { loadCloudGates, note, ok, pruneBackup, realEnv, saveCloudGates, ungated, warn, type CloudEnv } from "./cloudgate";
import { backupCopy } from "./fix";

export interface AwsHook {
  /** The config file vswarm changed (~/.aws/config or AWS_CONFIG_FILE). */
  file: string;
  /** A copy of that file from before the first change. */
  backup: string;
  kind: "sso" | "process";
  /** The profiles named on the command line that this gate covers: the profile itself, or roles it is the source of. */
  for: string[];
  /** The profile's section before vswarm changed it and as vswarm wrote it, exactly. */
  original: string;
  written: string;
  /** Lines vswarm took out of the section and put in, exactly (line endings included). */
  removed: string[];
  /** Where each removed line stood in the section (0 is the header), so they go back in their places. */
  removedAt?: number[];
  added: string[];
  /** [profile vswarm-src-<name>] as vswarm wrote it (SSO profiles). */
  companion?: string;
  at: number;
}

export const COMPANION_PREFIX = "vswarm-src-";
const companionOf = (p: string) => COMPANION_PREFIX + p;
const SSO_KEYS = new Set(["sso_session", "sso_start_url", "sso_region", "sso_account_id", "sso_role_name", "sso_registration_scopes"]);

export const awsFiles = (e: CloudEnv) => ({
  config: e.env.AWS_CONFIG_FILE || join(e.home, ".aws", "config"),
  credentials: e.env.AWS_SHARED_CREDENTIALS_FILE || join(e.home, ".aws", "credentials"),
});

// ── INI sections, as the AWS CLI reads them

/** Lines with their line endings, so a file put back together is the same bytes. */
export const linesOf = (t: string) => t.match(/[^\n]*\n|[^\n]+$/g) ?? [];
const bare = (l: string) => l.replace(/\r?\n$/, "");

interface Section {
  /** The profile it is: [default] and [profile x] in the config, [x] in the credentials file. Other sections: none. */
  profile?: string;
  /** First line (the header) and one past the last. */
  start: number;
  end: number;
}

export function sections(lines: string[], credentials: boolean): Section[] {
  const out: Section[] = [];
  for (let i = 0; i < lines.length; i++) {
    const h = /^\s*\[\s*([^\]]*?)\s*\]\s*(?:[#;].*)?$/.exec(bare(lines[i]));
    if (!h) continue;
    if (out.length) out[out.length - 1].end = i;
    const name = h[1];
    const profile = credentials ? name : name === "default" ? "default" : /^profile\s+(.+)$/.exec(name)?.[1].trim();
    out.push({ profile, start: i, end: lines.length });
  }
  return out;
}

/** Keys of a section: the top-level `key = value` lines (indented lines are a nested value's, like s3 = …). */
function keys(lines: string[], s: Section): Map<string, { value: string; at: number }> {
  const out = new Map<string, { value: string; at: number }>();
  for (let i = s.start + 1; i < s.end; i++) {
    const kv = /^([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$/.exec(bare(lines[i]));
    if (kv && !out.has(kv[1])) out.set(kv[1], { value: kv[2], at: i });
  }
  return out;
}

const find = (lines: string[], credentials: boolean, profile: string) => sections(lines, credentials).find((s) => s.profile === profile);
const textOf = (lines: string[], s: Section) => lines.slice(s.start, s.end).join("");

// ── what to gate

export type AwsPlan = { profile: string; kind: "sso" | "process" | "gated"; chain: string[] };

/**
 * Which profile to change for `profile`, and how; throws with the reason when it cannot be gated. A role
 * (role_arn + source_profile) is gated at its source, followed to the end of the chain.
 */
export function awsPlan(profile: string, config: string, credentials: string, chain: string[] = []): AwsPlan {
  const where = chain.length ? ` (the source of ${chain.join(" → ")})` : "";
  if (profile.startsWith(COMPANION_PREFIX)) throw new Error(`${profile} is the profile vswarm keeps a gated profile's SSO settings in; gate the profile itself`);
  const cl = linesOf(config), kl = linesOf(credentials);
  const cs = find(cl, false, profile), ks = find(kl, true, profile);
  if (!cs && !ks) throw new Error(`no profile ${profile}${where} in ~/.aws/config`);
  const c = cs ? keys(cl, cs) : new Map();
  const k = ks ? keys(kl, ks) : new Map();
  if (k.has("aws_access_key_id") || c.has("aws_access_key_id"))
    throw new Error(`${profile}${where} uses static access keys (in ${k.has("aws_access_key_id") ? "~/.aws/credentials" : "~/.aws/config"}). aws reads those before any credential_process and sends them without running anything, so no check can stand in front of them. Move the profile to IAM Identity Center (aws configure sso) or a credential_process, delete the keys, then gate it`);
  if (c.has("role_arn")) {
    const src = c.get("source_profile")?.value;
    if (src) {
      if (src === profile || chain.includes(src)) throw new Error(`${profile}${where} is part of a source_profile loop (${[...chain, profile, src].join(" → ")})`);
      if (chain.length >= 8) throw new Error(`the source_profile chain from ${chain[0]} is too long to follow`);
      return awsPlan(src, config, credentials, [...chain, profile]);
    }
    if (c.has("web_identity_token_file")) throw new Error(`${profile}${where} assumes its role with a web identity token read from a file, which runs no command to gate`);
    const cred = c.get("credential_source")?.value;
    throw new Error(`${profile}${where} assumes its role with ${cred ? `credentials from ${cred} (the environment or the machine it runs on)` : "no source profile"}, which runs no command to gate`);
  }
  const sso = [...c.keys()].some((x) => SSO_KEYS.has(x));
  const cp = c.get("credential_process")?.value;
  if (cp !== undefined) {
    if (sso) throw new Error(`${profile}${where} has both SSO settings and a credential_process; aws uses SSO first. Keep one, then gate it`);
    return { profile, kind: ungated(cp) !== cp ? "gated" : "process", chain };
  }
  if (sso) {
    if (find(cl, false, companionOf(profile))) throw new Error(`there is already a [profile ${companionOf(profile)}] in ~/.aws/config that vswarm did not write; rename or remove it first`);
    if (!c.has("sso_session") && !c.has("sso_start_url")) throw new Error(`${profile}${where} has SSO settings without sso_session or sso_start_url`);
    return { profile, kind: "sso", chain };
  }
  throw new Error(`${profile}${where} has no credential source in ~/.aws/config: aws then takes credentials from the environment, an instance role or a container, none of which runs a command to gate`);
}

// ── writing it

/**
 * One word for the command line credential_process is split into: botocore splits it like a POSIX shell (and the JS
 * SDK hands it to one), on Windows like the C runtime does, where double quotes group and backslashes stay.
 */
export function awsWord(s: string, win = process.platform === "win32"): string {
  if (/^[A-Za-z0-9_@%+=:,./\\-]+$/.test(s) && !(!win && s.includes("\\"))) return s;
  if (win) {
    if (s.includes('"')) throw new Error(`cannot put ${s} in credential_process: it contains a double quote`);
    return `"${s}"`;
  }
  return `'${s.replace(/'/g, `'"'"'`)}'`;
}

const prefix = (launcher: string[], win?: boolean) => `${launcher.map((w) => awsWord(w, win)).join(" ")} preflight --quiet --then `;

/** The config text with `profile` gated, and what to record. Throws if `plan` does not fit the text any more. */
export function awsGateText(config: string, plan: AwsPlan, launcher: string[], win?: boolean): { text: string; hook: Pick<AwsHook, "kind" | "original" | "written" | "removed" | "removedAt" | "added" | "companion"> } {
  if (plan.kind === "gated") throw new Error(`${plan.profile} already runs vswarm preflight`);
  const lines = linesOf(config);
  const s = find(lines, false, plan.profile);
  if (!s) throw new Error(`no profile ${plan.profile} in ~/.aws/config`);
  const eol = (lines[s.start].match(/\r?\n$/) ?? ["\n"])[0];
  const withEol = (l: string) => (/\n$/.test(l) ? l : l + eol);
  const original = textOf(lines, s);
  const body = lines.slice(s.start, s.end);
  const k = keys(lines, s);
  let removed: string[], removedAt: number[], added: string[], companion: string | undefined;
  if (plan.kind === "process") {
    const at = k.get("credential_process")!.at - s.start;
    removed = [body[at]];
    removedAt = [at];
    added = [withEol(`credential_process = ${prefix(launcher, win)}${k.get("credential_process")!.value}`)];
    body.splice(at, 1, ...added);
  } else {
    const src = companionOf(plan.profile);
    const at = [...k.entries()].filter(([x]) => SSO_KEYS.has(x)).map(([, v]) => v.at - s.start).sort((a, b) => a - b);
    removed = at.map((i) => body[i]);
    removedAt = at;
    added = [
      withEol(`# vswarm gate aws: the SSO settings are in [profile ${src}] now; vswarm gate aws --off ${plan.profile} puts them back`),
      withEol(`credential_process = ${prefix(launcher, win)}aws configure export-credentials --profile ${awsWord(src, win)} --format process`),
    ];
    for (const i of [...at].reverse()) body.splice(i, 1);
    body.splice(at[0], 0, ...added);
    // The companion follows the profile's section, set apart by a blank line as aws configure writes them.
    if (!/\n$/.test(body[body.length - 1])) body[body.length - 1] += eol;
    if (bare(body[body.length - 1]).trim()) body.push(eol);
    const more = s.end < lines.length;
    companion = [`[profile ${src}]${eol}`, withEol(`# written by vswarm gate aws: the SSO sign-in of [profile ${plan.profile}]; sign in with aws sso login --profile ${src}`), ...removed.map(withEol), ...(more ? [eol] : [])].join("");
    body.push(companion);
  }
  const text = [...lines.slice(0, s.start), ...body, ...lines.slice(s.end)].join("");
  // What was written, read back the way --off will look for it.
  const after = linesOf(text);
  const ns = find(after, false, plan.profile)!;
  const cs = companion ? find(after, false, companionOf(plan.profile)) : undefined;
  return { text, hook: { kind: plan.kind, original, written: textOf(after, ns), removed, removedAt, added, companion: cs ? textOf(after, cs) : undefined } };
}

/** The config text with vswarm's change to `profile` undone, and what could not be undone. */
export function awsUngateText(config: string, profile: string, h: AwsHook): { text: string; notes: string[] } {
  const lines = linesOf(config);
  const notes: string[] = [];
  const edits: { start: number; end: number; put: string[] }[] = [];
  const s = find(lines, false, profile);
  if (!s) notes.push(`[profile ${profile}] is no longer in ${h.file}; nothing to put back (the backup is ${h.backup})`);
  else if (textOf(lines, s) === h.written) edits.push({ start: s.start, end: s.end, put: [h.original] });
  else {
    // Edited since (aws configure set …): only vswarm's own lines are swapped back, the rest stays as it is now.
    const body = lines.slice(s.start, s.end);
    const at = h.added.map((a) => body.findIndex((l) => bare(l) === bare(a)));
    if (at.every((i) => i >= 0)) {
      for (const i of [...at].sort((a, b) => b - a)) body.splice(i, 1);
      // Each line back where it stood (edits are usually added at the end of a section); without the places, together.
      if (h.removedAt?.length === h.removed.length) h.removed.forEach((l, j) => body.splice(Math.min(h.removedAt![j], body.length), 0, l));
      else body.splice(Math.min(...at), 0, ...h.removed);
      edits.push({ start: s.start, end: s.end, put: body });
      notes.push(`[profile ${profile}] was edited since vswarm wrote it: vswarm's lines were swapped back, your other changes kept`);
    } else notes.push(`[profile ${profile}] no longer has the lines vswarm wrote; left as it is (the backup is ${h.backup})`);
  }
  // The companion goes only once its settings are back in the profile; otherwise it is the only copy outside the backup.
  if (h.companion) {
    const c = find(lines, false, companionOf(profile));
    if (!edits.length) {
      if (c) notes.push(`[profile ${companionOf(profile)}] keeps the SSO settings; left as it is`);
    } else if (c && textOf(lines, c) === h.companion) edits.push({ start: c.start, end: c.end, put: [] });
    else if (c) notes.push(`[profile ${companionOf(profile)}] was changed since vswarm wrote it; left as it is`);
  }
  for (const e of edits.sort((a, b) => b.start - a.start)) lines.splice(e.start, e.end - e.start, ...e.put);
  return { text: lines.join(""), notes };
}

/** Each gated profile and whether its gate is still in place. */
export function awsStatus(e: CloudEnv): { name: string; ok: boolean; detail: string }[] {
  const { credentials } = awsFiles(e);
  const creds = linesOf(readText(credentials) ?? "");
  return Object.entries(loadCloudGates().aws).map(([name, h]) => {
    const lines = linesOf(readText(h.file) ?? "");
    const s = find(lines, false, name);
    const cp = h.added[h.added.length - 1];
    const roles = h.for.filter((f) => f !== name);
    const covers = roles.length ? ` · used by ${roles.join(", ")}` : "";
    if (!s || !lines.slice(s.start, s.end).some((l) => bare(l) === bare(cp))) return { name, ok: false, detail: `${h.file}: [profile ${name}] was changed by hand; its credential_process no longer runs vswarm preflight` };
    // Static keys added since, for the profile or for a role that goes through it, in either file: aws sends those
    // before it would run credential_process, so the gate is bypassed.
    for (const p of [name, ...roles]) {
      const k = find(creds, true, p);
      if (k && keys(creds, k).has("aws_access_key_id")) return { name, ok: false, detail: `${credentials} has static keys for ${p} now, which aws uses before credential_process: the gate is bypassed` };
      const cs = find(lines, false, p);
      if (cs && keys(lines, cs).has("aws_access_key_id")) return { name, ok: false, detail: `${h.file} has static keys in [profile ${p}] now, which aws uses before credential_process: the gate is bypassed` };
    }
    if (h.kind === "sso" && !find(lines, false, companionOf(name))) return { name, ok: false, detail: `[profile ${companionOf(name)}] is gone: ${name} has no SSO sign-in to hand out` };
    const edited = textOf(lines, s) !== h.written ? " · section edited since, still gated" : "";
    return { name, ok: true, detail: `${h.file} · credential_process runs preflight first${h.kind === "sso" ? ` (SSO in [profile ${companionOf(name)}])` : ""}${covers}${edited}` };
  });
}

// ── the command

/** Turns the gate on `profile` off. Returns what happened, for the caller to print. */
export function awsGateOff(profile: string): { done: boolean; notes: string[] } {
  const state = loadCloudGates();
  const h = state.aws[profile];
  if (!h) return { done: false, notes: [] };
  const text = readText(h.file);
  let notes: string[] = [];
  if (text === undefined) notes = [`${h.file} is gone; nothing to put back (the backup is ${h.backup})`];
  else {
    const r = awsUngateText(text, profile, h);
    notes = r.notes;
    if (r.text !== text) writeFileSync(h.file, r.text);
  }
  delete state.aws[profile];
  saveCloudGates(state);
  pruneBackup(h.backup, h.file, state);
  return { done: true, notes };
}

/** vswarm gate aws <profile…> | --off [profile…] | (status). Returns false when a profile was refused. */
export async function gateAws(args: string[], e?: CloudEnv): Promise<boolean> {
  e ??= await realEnv();
  const offAt = args.indexOf("--off");
  if (offAt >= 0) {
    args.splice(offAt, 1);
    const all = loadCloudGates().aws;
    const names = args.length ? args : Object.keys(all);
    if (!names.length) note("no aws profile is gated");
    for (const n of names) {
      const hit = Object.entries(all).filter(([k, h]) => k === n || h.for.includes(n)).map(([k]) => k);
      if (!hit.length) note(`${n}: not gated by vswarm`);
      for (const k of hit) {
        const r = awsGateOff(k);
        if (!r.done) continue; // named twice, or through two of its roles
        const others = all[k].for.filter((f) => f !== n && f !== k);
        ok(`aws profile ${k} restored`, all[k].file);
        if (others.length) note(`${others.join(", ")} assume${others.length === 1 ? "s" : ""} a role with ${k}'s credentials, and ${others.length === 1 ? "is" : "are"} no longer gated either`);
        for (const x of r.notes) warn(x);
      }
    }
    return true;
  }
  if (!args.length || (args.length === 1 && args[0] === "status")) {
    const st = awsStatus(e);
    for (const s of st) (s.ok ? ok : warn)(`aws profile ${s.name}: credential_process runs preflight`, s.detail);
    if (!st.length) note("no aws profile is gated · vswarm gate aws <profile…>");
    return true;
  }
  const { config, credentials } = awsFiles(e);
  if (readText(config) === undefined) throw new Error(`no ${config}; set up a profile first (aws configure sso)`);
  const win = process.platform === "win32";
  let refused = false;
  let backup: string | undefined;
  for (const name of args) {
    let plan: AwsPlan;
    const text = readText(config) ?? "";
    try {
      plan = awsPlan(name, text, readText(credentials) ?? "");
    } catch (err: any) {
      refused = true;
      warn(`aws profile ${name} not gated`, err.message);
      continue;
    }
    const state = loadCloudGates();
    const via = plan.chain.length ? ` (${plan.chain.join(" → ")} → ${plan.profile}: the role is assumed with ${plan.profile}'s credentials)` : "";
    if (plan.kind === "gated") {
      const h = state.aws[plan.profile];
      if (h) {
        if (!h.for.includes(name)) (h.for.push(name), saveCloudGates(state));
        ok(`aws profile ${name}: already gated${via}`, h.file);
      } else warn(`aws profile ${plan.profile}: its credential_process already runs vswarm preflight, but not as vswarm wrote it; left as it is${via}`);
      continue;
    }
    // In ~/.vswarm/backups, not beside the file; removed again with the last gate that needs it.
    if (!backup) backup = backupCopy(config, "aws");
    const r = awsGateText(text, plan, e.launcher, win);
    writeFileSync(config, r.text);
    state.aws[plan.profile] = { file: config, backup, for: [name], ...r.hook, at: Date.now() };
    saveCloudGates(state);
    ok(`aws profile ${name}: credentials come only after vswarm preflight passes${via}`, config);
    if (plan.kind === "sso") {
      const src = companionOf(plan.profile);
      const session = /^sso_session\s*=\s*(.+?)\s*$/m.exec(r.hook.companion ?? "")?.[1];
      note(`the SSO settings moved to [profile ${src}]; sign in with ${session ? `aws sso login --sso-session ${session}` : `aws sso login --profile ${src}`}`);
      note("needs AWS CLI v2.9 or later (aws configure export-credentials)");
    }
  }
  if (backup) note(`backup ${backup} · turn off: vswarm gate aws --off ${args.join(" ")}`);
  note("aws and the SDKs run credential_process each time they need credentials, so the check runs then; a BLOCK means none");
  return !refused;
}

/** For uninstall: every aws gate turned off. */
export function awsUninstall(): string[] {
  const out: string[] = [];
  for (const n of Object.keys(loadCloudGates().aws)) {
    const r = awsGateOff(n);
    if (r.done) out.push(`aws profile ${n} restored${r.notes.length ? ` (${r.notes.join("; ")})` : ""}`);
  }
  return out;
}
