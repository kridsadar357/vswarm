// kubectl: the credential a context's user hands out runs vswarm preflight first.
//
// `vswarm gate kube <context…>` changes the exec credential plugin of each context's user: its command becomes vswarm
// and its args `preflight --quiet --then <the plugin's command> <its args>`; env, apiVersion and everything else stay.
// kubectl (and client-go, so Helm, k9s, Lens …) runs the plugin whenever it needs a token, and reads the
// ExecCredential JSON the plugin prints; preflight prints nothing on stdout, so that JSON reaches kubectl untouched.
// A static token, client certificate or password is refused: kubectl sends it without running anything.
//
// With KUBECONFIG naming several files, kubectl takes each context and user from the first file that has it, so that is
// the file vswarm changes. There is no YAML library here: the exec block of that one user is found and rewritten line
// by line, and only kubeconfigs written in block style (as kubectl writes them) are changed; anything else is refused
// rather than reformatted. vswarm keeps a backup, the block before and after, and the original command and args, so
// --off puts the bytes back, or, after kubectl rewrote the file, the command and args.

import { readFileSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { readText } from "./ctx";
import { linesOf } from "./awsgate";
import { loadCloudGates, note, ok, realEnv, saveCloudGates, warn, type CloudEnv } from "./cloudgate";

export interface KubeHook {
  /** The kubeconfig vswarm changed: the first one that defines the user. */
  file: string;
  backup: string;
  /** The contexts named on the command line that use this user. */
  for: string[];
  /** The user's exec block before and as vswarm wrote it, exactly. */
  original: string;
  written: string;
  /** The plugin's command and args before vswarm. */
  command: string;
  args: string[];
  at: number;
}

// ── a careful reader for block-style YAML, the shape kubectl writes

interface Line {
  raw: string;
  body: string;
  indent: number;
  /** Blank or a comment: no structure. */
  skip: boolean;
}

export const yamlLines = (text: string): Line[] =>
  linesOf(text).map((raw) => {
    const body = raw.replace(/\r?\n$/, "");
    const t = body.trimStart();
    return { raw, body, indent: body.length - t.length, skip: !t || t.startsWith("#") };
  });

class Unsupported extends Error {}
const unsupported = (what: string) => new Unsupported(`${what}; vswarm changes only kubeconfigs in block style, as kubectl writes them. Change it by hand (see vswarm help)`);

/** A one-line scalar: plain, 'single' or "double" quoted, a trailing comment dropped. Anything else is refused. */
export function scalar(v: string): string | undefined {
  const s = v.trim();
  if (!s || s.startsWith("#")) return;
  if (s.startsWith('"')) {
    const m = /^"((?:[^"\\]|\\.)*)"\s*(#.*)?$/.exec(s);
    if (!m) throw unsupported(`the value ${s.slice(0, 40)} is not one quoted string`);
    try {
      return JSON.parse(`"${m[1]}"`);
    } catch {
      throw unsupported(`the value ${s.slice(0, 40)} uses an escape vswarm does not read`);
    }
  }
  if (s.startsWith("'")) {
    const m = /^'((?:[^']|'')*)'\s*(#.*)?$/.exec(s);
    if (!m) throw unsupported(`the value ${s.slice(0, 40)} is not one quoted string`);
    return m[1].replace(/''/g, "'");
  }
  if (/^[[{&*!|>%@`]/.test(s)) throw unsupported(`the value ${s.slice(0, 40)} is not a plain string`);
  return s.replace(/\s+#.*$/, "");
}

/** `[a, "b c"]` as a list of strings. */
function flowList(v: string): string[] {
  const s = v.trim().replace(/\s+#[^\]]*$/, "");
  if (!/^\[.*\]$/.test(s)) throw unsupported(`the list ${s.slice(0, 40)} runs over several lines`);
  const inner = s.slice(1, -1).trim();
  if (!inner) return [];
  const out: string[] = [];
  const re = /\s*("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^,"'[\]{}]+?)\s*(,|$)/y;
  let m: RegExpExecArray | null;
  while (re.lastIndex < inner.length && (m = re.exec(inner))) out.push(scalar(m[1]) ?? "");
  if (re.lastIndex < inner.length) throw unsupported(`the list ${s.slice(0, 40)} is not a list of plain strings`);
  return out;
}

interface Entry {
  key: string;
  /** What follows the colon on the key's own line. */
  value: string;
  line: number;
  /** One past the entry's last line with content. */
  end: number;
}

/**
 * The keys of a block mapping whose keys sit at column `col`, between lines `from` and `to`. The first line may be a
 * list item (`- name: x`), whose key also sits at `col`.
 */
function entries(ls: Line[], from: number, to: number, col: number): Entry[] {
  const out: Entry[] = [];
  for (let i = from; i < to; i++) {
    const l = ls[i];
    if (l.skip) continue;
    // A list item's first key sits after its "- ".
    const item = i === from && /^-(\s|$)/.test(l.body.slice(l.indent));
    const at = item ? col : l.indent;
    if (at < col) throw unsupported(`line ${i + 1} is indented less than the mapping it belongs to`);
    if (at > col) continue;
    const kv = /^([A-Za-z0-9_.-]+|"[^"]*"|'[^']*'):(?:\s+(.*)|\s*)$/.exec(l.body.slice(col));
    if (!kv) {
      if (!item && /^-(\s|$)/.test(l.body.slice(col))) continue; // a list under the previous key, at the same column
      throw unsupported(`line ${i + 1} is not a key: value line`);
    }
    if (out.length) out[out.length - 1].end = lastContent(ls, out[out.length - 1].line, i);
    out.push({ key: kv[1].replace(/^["']|["']$/g, ""), value: kv[2] ?? "", line: i, end: to });
  }
  if (out.length) out[out.length - 1].end = lastContent(ls, out[out.length - 1].line, to);
  return out;
}

const lastContent = (ls: Line[], from: number, to: number) => {
  let e = to;
  while (e - 1 > from && ls[e - 1].skip) e--;
  return e;
};

/** The column a nested block's keys sit at: that of its first line with content. */
const childCol = (ls: Line[], e: Entry, parent: number): number | undefined => {
  for (let i = e.line + 1; i < e.end; i++) if (!ls[i].skip) return ls[i].indent > parent ? ls[i].indent : undefined;
};

/** The items of a top-level list (users:, contexts:), each with its mapping's entries. */
function listOf(ls: Line[], key: string): { start: number; end: number; col: number; entries: Entry[] }[] {
  const at = ls.findIndex((l) => !l.skip && l.indent === 0 && new RegExp(`^${key}:(\\s|$)`).test(l.body));
  if (at < 0) return [];
  const rest = ls[at].body.slice(key.length + 1).trim();
  if (rest && !rest.startsWith("#")) {
    if (/^\[\s*\]$|^null$|^~$/.test(rest.replace(/\s+#.*$/, ""))) return [];
    throw unsupported(`${key}: is written in flow style`);
  }
  let end = ls.length;
  for (let i = at + 1; i < ls.length; i++) if (!ls[i].skip && ls[i].indent === 0 && !/^-(\s|$)/.test(ls[i].body)) {
    end = i;
    break;
  }
  const first = ls.findIndex((l, i) => i > at && i < end && !l.skip);
  if (first < 0) return [];
  const dash = ls[first].indent;
  const out: { start: number; end: number; col: number; entries: Entry[] }[] = [];
  for (let i = first; i < end; i++) {
    const l = ls[i];
    if (l.skip || l.indent !== dash) continue;
    const m = /^-(\s+)(\S.*)?$/.exec(l.body.slice(dash));
    if (!m) throw unsupported(`line ${i + 1} in ${key}: is not a list item`);
    if (out.length) out[out.length - 1].end = i;
    out.push({ start: i, end, col: m[2] === undefined ? -1 : dash + 1 + m[1].length, entries: [] });
  }
  for (const it of out) {
    if (it.col < 0) {
      // "-" alone on its line: the mapping starts on the next one.
      const n = ls.findIndex((l, i) => i > it.start && i < it.end && !l.skip);
      if (n < 0) continue;
      it.col = ls[n].indent;
      it.entries = entries(ls, n, it.end, it.col);
    } else it.entries = entries(ls, it.start, it.end, it.col);
  }
  return out;
}

const get = (es: Entry[], k: string) => es.find((e) => e.key === k);

export interface KubeUser {
  name: string;
  /** How it signs in: exec, or the static kind that makes it impossible to gate. */
  how: "exec" | "token" | "client certificate" | "password" | "auth-provider" | "none";
  /** Also has a static credential next to its exec plugin. */
  alsoStatic?: string;
  exec?: { start: number; end: number; col: number; command?: string; args: string[]; commandAt?: Entry; argsAt?: Entry; entries: Entry[] };
}

const STATIC: Record<string, KubeUser["how"]> = {
  token: "token", tokenFile: "token", "client-certificate": "client certificate", "client-certificate-data": "client certificate", "client-key": "client certificate", "client-key-data": "client certificate",
  username: "password", password: "password", "auth-provider": "auth-provider",
};

export function kubeUserOf(ls: Line[], name: string): KubeUser | undefined {
  for (const it of listOf(ls, "users")) {
    const n = get(it.entries, "name");
    if (!n || scalar(n.value) !== name) continue;
    const u = get(it.entries, "user");
    if (!u) return { name, how: "none" };
    if (scalar(u.value) !== undefined) throw unsupported(`user ${name} is written in flow style`);
    const ucol = childCol(ls, u, it.col);
    if (ucol === undefined) return { name, how: "none" };
    const ue = entries(ls, u.line + 1, u.end, ucol);
    const stat = ue.map((e) => STATIC[e.key]).find(Boolean);
    const ex = get(ue, "exec");
    if (!ex) return { name, how: stat ?? "none" };
    if (scalar(ex.value) !== undefined) throw unsupported(`the exec plugin of user ${name} is written in flow style`);
    const xcol = childCol(ls, ex, ucol);
    if (xcol === undefined) throw unsupported(`the exec plugin of user ${name} is empty`);
    const xe = entries(ls, ex.line + 1, ex.end, xcol);
    const c = get(xe, "command"), a = get(xe, "args");
    // A command folded over several lines would lose its rest when rewritten.
    if (c && ls.slice(c.line + 1, c.end).some((l) => !l.skip)) throw unsupported(`the exec command of user ${name} runs over several lines`);
    let args: string[] = [];
    if (a) {
      const inline = a.value.trim();
      if (inline && !inline.startsWith("#")) args = flowList(inline);
      else
        for (let i = a.line + 1; i < a.end; i++) {
          if (ls[i].skip) continue;
          const m = /^-\s+(.*)$|^-$/.exec(ls[i].body.slice(ls[i].indent));
          if (!m || ls[i].indent < xcol) throw unsupported(`the args of user ${name} are not a list of plain strings`);
          args.push(scalar(m[1] ?? "") ?? "");
        }
    }
    return { name, how: "exec", alsoStatic: stat, exec: { start: ex.line, end: ex.end, col: xcol, command: c ? scalar(c.value) : undefined, args, commandAt: c, argsAt: a, entries: xe } };
  }
}

/** The user of each context in one file. */
export function kubeContexts(ls: Line[]): Map<string, string | undefined> {
  const out = new Map<string, string | undefined>();
  for (const it of listOf(ls, "contexts")) {
    const n = get(it.entries, "name");
    const name = n ? scalar(n.value) : undefined;
    if (!name || out.has(name)) continue;
    const cx = get(it.entries, "context");
    const col = cx ? childCol(ls, cx, it.col) : undefined;
    const user = cx && col !== undefined ? get(entries(ls, cx.line + 1, cx.end, col), "user") : undefined;
    out.set(name, user ? scalar(user.value) : undefined);
  }
  return out;
}

// ── writing it

/**
 * A YAML scalar for a value vswarm writes: plain where that reads back the same, else single-quoted (backslashes in a
 * Windows path stay as they are), double-quoted only for control characters.
 */
export function yamlWord(s: string): string {
  const plain = /^(?:[A-Za-z_/~]|--?[A-Za-z])[\w./@%+=,~-]*$/.test(s) && !/^(true|false|yes|no|on|off|y|n|null|~)$/i.test(s);
  return plain ? s : /[\x00-\x1f\x7f]/.test(s) ? JSON.stringify(s) : `'${s.replace(/'/g, "''")}'`;
}

/** Whether a plugin already runs vswarm preflight first. */
export function gatedExec(command: string | undefined, args: string[]): boolean {
  const i = args.indexOf("preflight");
  return i >= 0 && args[i + 1] === "--quiet" && args[i + 2] === "--then" && [command ?? "", ...args.slice(0, i)].some((w) => /vswarm|cli\.ts$/.test(w));
}

/** Why a user cannot be gated, or undefined when it can. */
export function kubeRefusal(u: KubeUser): string | undefined {
  const cure = "Use an exec plugin that issues short-lived tokens (aws eks get-token, gke-gcloud-auth-plugin, kubelogin for OIDC), then gate it";
  if (u.how === "token") return `user ${u.name} sends a static token (in the kubeconfig or a token file). kubectl sends it without running anything, so no check can stand in front of it. ${cure}`;
  if (u.how === "client certificate") return `user ${u.name} signs in with a client certificate and key on disk, which kubectl uses without running anything. ${cure}`;
  if (u.how === "password") return `user ${u.name} signs in with a username and password, which kubectl sends without running anything. ${cure}`;
  if (u.how === "auth-provider") return `user ${u.name} uses an auth-provider, which kubectl 1.26 and later no longer run. Move it to an exec plugin (kubelogin for OIDC), then gate it`;
  if (u.how === "none") return `user ${u.name} has no credential of its own to gate`;
  if (u.alsoStatic) return `user ${u.name} has an exec plugin and also a stored ${u.alsoStatic}; remove the stored one first, so only the plugin signs in`;
  if (!u.exec?.command) return `the exec plugin of user ${u.name} has no command`;
}

/** The file text with the user's exec plugin running preflight first, and what to record. */
export function kubeGateText(text: string, user: string, launcher: string[]): { text: string; hook: Pick<KubeHook, "original" | "written" | "command" | "args"> } {
  const ls = yamlLines(text);
  const u = kubeUserOf(ls, user);
  if (!u) throw new Error(`no user ${user}`);
  const why = kubeRefusal(u);
  if (why) throw new Error(why);
  const x = u.exec!;
  if (gatedExec(x.command, x.args)) throw new Error(`the exec plugin of user ${user} already runs vswarm preflight`);
  const eol = (ls[x.start].raw.match(/\r?\n$/) ?? ["\n"])[0];
  const pad = " ".repeat(x.col);
  const [cmd, ...pre] = launcher;
  const put = [`${pad}command: ${yamlWord(cmd)}${eol}`, `${pad}args:${eol}`, ...[...pre, "preflight", "--quiet", "--then", x.command!, ...x.args].map((a) => `${pad}- ${yamlWord(a)}${eol}`)];
  // The block's lines: command and args go where command was, the rest stays as it is.
  const drop = new Set<number>();
  for (const e of [x.commandAt!, x.argsAt].filter(Boolean) as Entry[]) for (let i = e.line; i < e.end; i++) drop.add(i);
  const lines = ls.map((l) => l.raw);
  if (!/\n$/.test(lines[x.end - 1])) lines[x.end - 1] += eol;
  const block: string[] = [];
  for (let i = x.start; i < x.end; i++) {
    if (i === x.commandAt!.line) block.push(...put);
    if (!drop.has(i)) block.push(lines[i]);
  }
  const original = ls.slice(x.start, x.end).map((l) => l.raw).join("");
  lines.splice(x.start, x.end - x.start, ...block);
  return { text: lines.join(""), hook: { original, written: block.join(""), command: x.command!, args: x.args } };
}

/** The file text with vswarm's change to the user undone, and what could not be undone. */
export function kubeUngateText(text: string, user: string, h: KubeHook): { text: string; note?: string } {
  const ls = yamlLines(text);
  let u: KubeUser | undefined;
  try {
    u = kubeUserOf(ls, user);
  } catch (e: any) {
    return { text, note: `${h.file} cannot be read any more (${e.message}); left as it is (the backup is ${h.backup})` };
  }
  const x = u?.exec;
  if (!x) return { text, note: `user ${user} no longer has an exec plugin in ${h.file}; left as it is (the backup is ${h.backup})` };
  const lines = ls.map((l) => l.raw);
  const now = lines.slice(x.start, x.end).join("");
  const restoring = now === h.written || now === h.written.replace(/\r?\n$/, "");
  if (restoring) {
    lines.splice(x.start, x.end - x.start, h.original);
    return { text: lines.join("") };
  }
  if (!gatedExec(x.command, x.args)) return { text, note: `the exec plugin of user ${user} no longer runs vswarm preflight; left as it is` };
  // kubectl rewrote the file since (it does on config changes): the command and args go back, in its layout.
  const eol = (ls[x.start].raw.match(/\r?\n$/) ?? ["\n"])[0];
  const pad = " ".repeat(x.col);
  const put = [`${pad}command: ${yamlWord(h.command)}${eol}`, ...(h.args.length ? [`${pad}args:${eol}`, ...h.args.map((a) => `${pad}- ${yamlWord(a)}${eol}`)] : [])];
  const drop = new Set<number>();
  for (const e of [x.commandAt!, x.argsAt].filter(Boolean) as Entry[]) for (let i = e.line; i < e.end; i++) drop.add(i);
  const block: string[] = [];
  for (let i = x.start; i < x.end; i++) {
    if (i === x.commandAt!.line) block.push(...put);
    if (!drop.has(i)) block.push(lines[i]);
  }
  lines.splice(x.start, x.end - x.start, ...block);
  return { text: lines.join(""), note: `${h.file} was rewritten since vswarm changed it (kubectl does that): the plugin's command and args were put back, in the file's current layout` };
}

// ── which file

/** The kubeconfig files kubectl reads, in its order: KUBECONFIG's, else ~/.kube/config. */
export function kubeFiles(e: CloudEnv): string[] {
  const list = (e.env.KUBECONFIG ?? "").split(delimiter).filter(Boolean);
  return list.length ? [...new Set(list)] : [join(e.home, ".kube", "config")];
}

/** The context's user and the file that defines that user: the first of each, as kubectl merges them. */
export function kubeLocate(context: string, files: string[]): { user: string; file: string } {
  let user: string | undefined;
  let found = false;
  for (const f of files) {
    const t = readText(f);
    if (t === undefined) continue;
    const cx = kubeContexts(yamlLines(t));
    if (cx.has(context)) {
      user = cx.get(context);
      found = true;
      break;
    }
  }
  if (!found) throw new Error(`no context ${context} in ${files.join(", ")}`);
  if (!user) throw new Error(`context ${context} names no user`);
  for (const f of files) {
    const t = readText(f);
    if (t !== undefined && kubeUserOf(yamlLines(t), user)) return { user, file: f };
  }
  throw new Error(`context ${context} uses user ${user}, which no kubeconfig defines`);
}

/** Each gated user and whether its gate is still in place. */
export function kubeStatus(): { name: string; ok: boolean; detail: string }[] {
  return Object.entries(loadCloudGates().kube).map(([name, h]) => {
    const t = readText(h.file);
    let u: KubeUser | undefined;
    try {
      u = t === undefined ? undefined : kubeUserOf(yamlLines(t), name);
    } catch {}
    const x = u?.exec;
    const ctx = `context${h.for.length === 1 ? "" : "s"} ${h.for.join(", ")}`;
    if (!x || !gatedExec(x.command, x.args)) return { name, ok: false, detail: `${h.file}: user ${name} (${ctx}) was changed by hand; its exec plugin no longer runs vswarm preflight` };
    if (u!.alsoStatic) return { name, ok: false, detail: `user ${name} has a stored ${u!.alsoStatic} now, next to its exec plugin` };
    const now = yamlLines(t!).slice(x.start, x.end).map((l) => l.raw).join("");
    return { name, ok: true, detail: `${h.file} · ${ctx} · exec plugin runs preflight first${now === h.written ? "" : " · file rewritten since, still gated"}` };
  });
}

// ── the command

export function kubeGateOff(user: string): { done: boolean; note?: string } {
  const state = loadCloudGates();
  const h = state.kube[user];
  if (!h) return { done: false };
  const t = readText(h.file);
  let n: string | undefined;
  if (t === undefined) n = `${h.file} is gone; nothing to put back (the backup is ${h.backup})`;
  else {
    const r = kubeUngateText(t, user, h);
    n = r.note;
    if (r.text !== t) writeFileSync(h.file, r.text);
  }
  delete state.kube[user];
  saveCloudGates(state);
  return { done: true, note: n };
}

/** vswarm gate kube <context…> | --off [context…] | (status). Returns false when a context was refused. */
export async function gateKube(args: string[], e?: CloudEnv): Promise<boolean> {
  e ??= await realEnv();
  const offAt = args.indexOf("--off");
  if (offAt >= 0) {
    args.splice(offAt, 1);
    const all = loadCloudGates().kube;
    const names = args.length ? args : Object.keys(all);
    if (!names.length) note("no kubectl context is gated");
    for (const n of names) {
      const hit = Object.entries(all).filter(([u, h]) => h.for.includes(n) || (!args.length && u === n)).map(([u]) => u);
      if (!hit.length) note(`${n}: not gated by vswarm`);
      for (const u of hit) {
        const r = kubeGateOff(u);
        if (!r.done) continue;
        const others = all[u].for.filter((c) => c !== n);
        ok(`kubectl user ${u} restored${args.length ? ` (context ${n})` : ""}`, all[u].file);
        if (args.length && others.length) note(`context${others.length === 1 ? "" : "s"} ${others.join(", ")} use${others.length === 1 ? "s" : ""} the same user, and ${others.length === 1 ? "is" : "are"} no longer gated either`);
        if (r.note) warn(r.note);
      }
    }
    return true;
  }
  if (!args.length || (args.length === 1 && args[0] === "status")) {
    const st = kubeStatus();
    for (const s of st) (s.ok ? ok : warn)(`kubectl user ${s.name}: exec plugin runs preflight`, s.detail);
    if (!st.length) note("no kubectl context is gated · vswarm gate kube <context…>");
    return true;
  }
  const files = kubeFiles(e);
  let refused = false;
  const backups = new Map<string, string>();
  for (const context of args) {
    try {
      const { user, file } = kubeLocate(context, files);
      const state = loadCloudGates();
      const text = readFileSync(file, "utf8");
      const u = kubeUserOf(yamlLines(text), user)!;
      if (u.exec && gatedExec(u.exec.command, u.exec.args)) {
        const h = state.kube[user];
        if (h && h.file === file) {
          if (!h.for.includes(context)) (h.for.push(context), saveCloudGates(state));
          ok(`kubectl context ${context}: already gated (user ${user})`, file);
        } else warn(`kubectl context ${context}: the exec plugin of user ${user} already runs vswarm preflight, but not as vswarm wrote it; left as it is`, file);
        continue;
      }
      const r = kubeGateText(text, user, e.launcher);
      if (!backups.has(file)) {
        const b = `${file}.bak-vswarm-${Date.now()}`;
        writeFileSync(b, readFileSync(file), { mode: 0o600 });
        backups.set(file, b);
      }
      writeFileSync(file, r.text);
      state.kube[user] = { file, backup: backups.get(file)!, for: [context], ...r.hook, at: Date.now() };
      saveCloudGates(state);
      ok(`kubectl context ${context}: user ${user} gets a token only after vswarm preflight passes`, file);
      note(`its exec plugin runs: vswarm preflight --quiet --then ${[r.hook.command, ...r.hook.args].join(" ")}`);
    } catch (err: any) {
      refused = true;
      warn(`kubectl context ${context} not gated`, err.message);
    }
  }
  for (const [f, b] of backups) note(`backup of ${f}: ${b}`);
  if (backups.size) note(`kubectl runs the plugin whenever it needs a new token, so the check runs then; a BLOCK means none · turn off: vswarm gate kube --off ${args.join(" ")}`);
  return !refused;
}

/** For uninstall: every kubectl gate turned off. */
export function kubeUninstall(): string[] {
  const out: string[] = [];
  for (const u of Object.keys(loadCloudGates().kube)) {
    const r = kubeGateOff(u);
    if (r.done) out.push(`kubectl user ${u} restored${r.note ? ` (${r.note})` : ""}`);
  }
  return out;
}
