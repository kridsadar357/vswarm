// Terminal output for checks. A gate's output goes to stderr, so `--then` can pass stdout through untouched; a
// command whose output is the report (scan, diff, secrets, why …) sends it to stdout with toStdout(), so
// `vswarm scan > out.txt` keeps it. Questions always go to stderr.
//
// One vocabulary everywhere a verdict is shown, in plain words with a traffic-light dot (the words are in src/i18n):
//   ● Safe        PASS     nothing to do
//   ● Check this  WARN     something new or changed: worth a look
//   ● Stop        BLOCK    don't use production until it's sorted
// The PASS / WARN / BLOCK tag stays beside it, dimmed, so scripts and the docs still match; --json and exit codes
// keep them as they were. Findings go in three groups: needs action, worth a look, FYI.
//
// Colour marks the state and the action only. NO_COLOR turns it off and nothing is lost: the dot, the words and the
// tag carry the meaning. 24-bit colour where the terminal says it has it (COLORTERM), the 16 basic colours otherwise.
// Lines wrap at the terminal's width; output to a file or a pipe is not wrapped.

import type { Check } from "./engine";
import { lang, t, tMaybe, type Key, type Lang, type Vars } from "../i18n";
import { actionOf, groupOf, plainOf, type Group } from "../i18n/findings";
import type { Finding, Verdict } from "./types";

/** 0: no colour; 16: the basic ANSI colours; 24: 24-bit colour. */
export type Depth = 0 | 16 | 24;

export function colorDepth(s: { isTTY?: boolean }, env: Record<string, string | undefined> = process.env): Depth {
  if (env.NO_COLOR) return 0;
  const force = env.FORCE_COLOR;
  if (force === "0" || force === "false") return 0;
  if (!s.isTTY && !force) return 0;
  if (env.TERM === "dumb" && !force) return 0;
  if (force === "3" || /^(truecolor|24bit)$/i.test(env.COLORTERM ?? "") || !!env.WT_SESSION) return 24;
  return 16;
}

let out: NodeJS.WriteStream = process.stderr;
let depth: Depth = colorDepth(out);
/** Report output goes to stdout from here on (and is coloured only when stdout is a terminal). */
export function toStdout() {
  out = process.stdout;
  depth = colorDepth(out);
}

/** Colours for a stream: the same names everywhere, 16 or 24-bit as the terminal has them. */
export function palette(d: () => Depth) {
  const paint = (basic: string, rgb?: string) => (s: string) => {
    const k = d();
    return k === 0 ? s : `\x1b[${k === 24 && rgb ? `38;2;${rgb}` : basic}m${s}\x1b[0m`;
  };
  return {
    bold: paint("1"), dim: paint("2"),
    red: paint("31", "239;107;107"), amber: paint("33", "227;163;58"), green: paint("32", "69;192;122"),
    cyan: paint("36", "79;179;209"), violet: paint("35", "180;140;255"),
  };
}
export const c = palette(() => depth);

// Names, paths and descriptions found on the machine are printed as they are. A control character in one could move
// the cursor or erase the line that reports it, so only vswarm's own colour codes get through.
const OWN_SGR_OR_CONTROL = /\x1b\[(?:0|1|2|3[0-7]|38;2;\d{1,3};\d{1,3};\d{1,3})m|[\x00-\x08\x0b-\x1f\x7f-\x9f]/g;

export function clean(s: string): string {
  return s.replace(OWN_SGR_OR_CONTROL, (m) => (m.length > 1 ? m : ""));
}

export function line(s = "") {
  out.write(clean(s) + "\n");
}

// ── width

/** Columns to wrap at: the terminal's, within 40…120; 0 (no wrapping) when the output is not a terminal. */
export function width(s: { isTTY?: boolean; columns?: number } = out, env: Record<string, string | undefined> = process.env): number {
  const cols = s.isTTY ? s.columns : Number(env.COLUMNS) || undefined;
  return cols ? Math.max(40, Math.min(cols, 120)) : 0;
}

const ANSI = /\x1b\[[0-9;]*m/g;
/** Cells a text takes on the terminal: Thai vowel and tone marks take none, wide characters two. */
export const cells = (s: string) => Bun.stringWidth(s.replace(ANSI, ""));

let words: Intl.Segmenter | undefined;
/** A word too long for the line, in pieces: Thai at its word breaks (Thai puts no spaces between words), the rest anywhere. */
function pieces(w: string, room: number): string[] {
  words ??= new Intl.Segmenter("th", { granularity: "word" });
  const out: string[] = [];
  let cur = "";
  for (const { segment } of words.segment(w)) {
    for (const part of cells(segment) > room ? [...segment] : [segment]) {
      if (cur && cells(cur + part) > room) (out.push(cur), (cur = ""));
      cur += part;
    }
  }
  if (cur) out.push(cur);
  return out;
}

// A vswarm command in a sentence stays on one line: `vswarm agents --inspect` is never split after `agents`.
const CMD = /\bvswarm (?:scan|diff|check|baseline|watch|secrets|agents|preflight|ui|why|ok|fix|policy|accept|respond|report|unlock|gate|guard|pkg|try|ca|cert|agent|canary|selftest|doctor|install|update|trust|team|uninstall|help|setup|lang)(?: (?:--?[\w-]+|[a-z][\w-]*|\d+|<[^ >]+>|"[^" ]+"|~\/[^ ]+)){0,3}/g;
const NBSP = "\u00a0";

/** Plain text in lines of at most `room` cells; one line when room is 0. */
export function wrap(text: string, room: number): string[] {
  if (!(room > 0) || cells(text) <= room) return [text];
  const glued = text.replace(CMD, (m) => (cells(m) <= room ? m.replace(/ /g, NBSP) : m));
  return wrapWords(glued, room).map((l) => l.replaceAll(NBSP, " "));
}

function wrapWords(text: string, room: number): string[] {
  const parts: { s: string; space: boolean }[] = [];
  text.split(" ").forEach((w, i) => {
    if (cells(w) <= room) parts.push({ s: w, space: i > 0 });
    else pieces(w, room).forEach((p, j) => parts.push({ s: p, space: i > 0 && j === 0 }));
  });
  const lines: string[] = [];
  let cur: string | undefined;
  for (const p of parts) {
    const next = cur === undefined ? p.s : cur + (p.space ? " " : "") + p.s;
    if (cur !== undefined && cells(next) > room) (lines.push(cur), (cur = p.s));
    else cur = next;
  }
  if (cur !== undefined) lines.push(cur);
  return lines;
}

/** Writes plain text wrapped under an indent, each line coloured with `paint`; the first line can start differently. */
export function para(text: string, indent: number, paint: (s: string) => string = (s) => s, first?: string) {
  const w = width();
  const pad = " ".repeat(indent);
  const lines = wrap(text, w ? w - indent : 0);
  lines.forEach((l, i) => line(`${i === 0 && first !== undefined ? first : pad}${paint(l)}`));
}

// ── the one vocabulary

const DOT: Record<Verdict, (s: string) => string> = { get pass() { return c.green; }, get warn() { return c.amber; }, get block() { return c.red; } };
const WORD: Record<Verdict, Key> = { pass: "level.safe", warn: "level.check", block: "level.stop" };
const TAG: Record<Verdict, string> = { pass: "PASS", warn: "WARN", block: "BLOCK" };

/** "Safe", "Check this", "Stop" in the language in use. */
export const verdictWord = (v: Verdict) => t(WORD[v]);

/** ● Check this  WARN: the dot and the word in the state's colour, the stable tag dimmed (another tag for try's own). */
export function verdictMark(v: Verdict, tag = TAG[v]): string {
  return `${DOT[v]("●")} ${DOT[v](c.bold(verdictWord(v)))} ${c.dim(tag)}`;
}

export const VERDICT: Record<Verdict, string> = {
  get pass() {
    return verdictMark("pass");
  },
  get warn() {
    return verdictMark("warn");
  },
  get block() {
    return verdictMark("block");
  },
};

const GROUP_LABEL: Record<Group, Key> = { action: "cli.group.action", look: "cli.group.look", fyi: "cli.group.fyi" };
const GROUP_PAINT: Record<Group, (s: string) => string> = { get action() { return c.red; }, get look() { return c.amber; }, get fyi() { return c.dim; } };

/** Needs action / Worth a look / FYI, for a finding. */
export const severityLabel = (f: Pick<Finding, "rule" | "severity">) => t(GROUP_LABEL[groupOf(f)]);

/**
 * One finding, short: a coloured dot, its title and its plain severity label, the details under it. `n` is its
 * number in the last check (vswarm ok <n>, vswarm fix <n>); none for findings that are not saved.
 */
export function finding(f: Finding, verbose = true, n?: number) {
  const g = groupOf(f);
  const num = n === undefined ? "" : `${c.bold(String(n).padStart(2))}  `;
  const pad = n === undefined ? "" : "    ";
  line(`  ${num}${GROUP_PAINT[g]("●")} ${f.title}  ${c.dim(t(GROUP_LABEL[g]))}`);
  if (!verbose) return;
  for (const d of f.detail) if (d) line(`      ${pad}${c.dim(d)}`);
  if (f.fix) line(`      ${pad}${c.cyan("→")} ${f.fix}`);
  if (f.id) line(`      ${pad}${c.dim(n === undefined ? `id ${f.id}` : `${t("cli.act.ok")} vswarm ok ${n}  ·  id ${f.id}`)}`);
}

/** Each finding's number: its place in the check as saved (last.json), so the numbers mean the same to ok and fix. */
export const numbers = (fs: Finding[]) => new Map(fs.map((f, i) => [f.id, i + 1]));

/** A sentence from vswarm's notes, for people (src/i18n keys). */
export interface Say {
  key: string;
  vars?: Vars;
}
export const say = (s: Say) => tMaybe(s.key, s.vars) ?? s.key;

/**
 * A finding as a small card: the number, a plain title, why it matters in one sentence, one command to run, and
 * vswarm's technical title dimmed under it (or every detail, with `details`).
 */
export function card(f: Finding, n: number | undefined, opt: { details?: boolean; fixable?: boolean; todo?: boolean; action?: boolean } = {}) {
  const p = plainOf(f);
  const g = groupOf(f);
  const num = n === undefined ? "   ·" : String(n).padStart(4);
  const indent = 7;
  para(p.title, indent, (s) => s, `${c.bold(GROUP_PAINT[g](num))}   `);
  para(p.why, indent, c.dim);
  if (opt.todo) para(p.todo, indent);
  const a = opt.action === false ? undefined : actionOf(f, n, !!opt.fixable);
  // vswarm's own one-line fix is technical (and English): the way on when there is no command and no plain sentence.
  const fixShown = !a && opt.action !== false && !!f.fix && !(opt.todo && p.plain);
  if (a) line(`${" ".repeat(indent)}${c.cyan("→")} ${t(a.label)} ${c.cyan(c.bold(a.cmd))}`);
  else if (fixShown) para(f.fix!, indent + 2, (s) => s, `${" ".repeat(indent)}${c.cyan("→")} `);
  if (p.plain && f.title !== p.title) para(f.title, indent, c.dim);
  if (opt.details) {
    for (const d of f.detail) if (d) para(d, indent + 2, c.dim);
    if (f.fix && !fixShown) para(`→ ${f.fix}`, indent + 4, c.dim, `${" ".repeat(indent + 2)}`);
    if (f.id) para(`id ${f.id}`, indent + 2, c.dim);
  }
}

/** A group's heading (Needs action, Worth a look, FYI) in its colour. */
export const groupHeading = (g: Group) => `  ${GROUP_PAINT[g](c.bold(t(GROUP_LABEL[g])))}`;

/** A date and time as people here write it: 9 Nov 2026 14:02, or 9 พ.ย. 2569 14:02 in Thai. */
export function dateOf(at: number, l: Lang = lang()): string {
  const d = new Date(at);
  const loc = l === "th" ? "th-TH" : "en-GB";
  return `${d.toLocaleDateString(loc, { day: "numeric", month: "short", year: "numeric" })} ${d.toLocaleTimeString(loc, { hour: "2-digit", minute: "2-digit", hour12: false })}`;
}

/** "checked just now" / "checked 5 min ago". */
export function checkedAt(at: number, now = Date.now()): string {
  const min = Math.floor((now - at) / 60_000);
  if (min < 1) return t("cli.when.now");
  if (min < 120) return t("cli.when.min", { n: min });
  return t("cli.when.at", { at: dateOf(at) });
}

/** The headline: the state in plain words and what it comes to, then when it was checked. */
export function headline(v: Verdict, sentence: string, sub?: string) {
  const mark = verdictMark(v);
  const head = `${DOT[v]("●")} ${DOT[v](c.bold(verdictWord(v)))}`;
  const w = width();
  const room = w ? w - cells(mark) - 3 : 0;
  const lines = wrap(sentence, room);
  line(`${head}  ${lines[0]}  ${c.dim(TAG[v])}`);
  for (const l of lines.slice(1)) line(`${" ".repeat(cells(head) + 2)}${l}`);
  if (sub) para(sub, 2, c.dim, "  ");
}

/** How the check comes out, in one sentence. */
export function sentenceOf(r: Pick<Check, "verdict" | "findings" | "lock">): string {
  if (r.lock) return t("cli.head.locked", { incident: r.lock.incident });
  const n = (g: Group) => r.findings.filter((f) => groupOf(f) === g).length;
  if (r.verdict === "block") return t("cli.head.block", { n: n("action") });
  if (r.verdict === "warn") return t("cli.head.warn", { n: n("look") });
  return t("cli.head.pass");
}

/** Notes after a check: one short dim line each. */
export function notesOut(said: Say[]) {
  for (const s of said) para(say(s), 4, c.dim, `  ${c.dim("·")} `);
}

export function summary(r: Check, opt: { all?: boolean; title?: string; policy?: "allow" | "refuse"; numbered?: Map<string, number>; details?: boolean; fixable?: (f: Finding) => boolean } = {}) {
  const shown = opt.all ? r.findings : r.findings.filter((f) => f.severity !== "info" && f.severity !== "low");
  const hidden = r.findings.length - shown.length;
  const nums = opt.numbered ?? numbers(r.findings);
  const base = r.baseline ? t("cli.sum.baseline", { at: dateOf(r.baseline.at) }) : t("cli.sum.noBaseline");
  headline(r.verdict, sentenceOf(r), `${checkedAt(Date.now())} · ${base}`);
  if (r.lock) para(t("cli.sum.lock", { incident: r.lock.incident, why: r.lock.reason }), 2, c.red, "  ");
  for (const g of ["action", "look", "fyi"] as Group[]) {
    const xs = shown.filter((f) => groupOf(f) === g);
    if (!xs.length) continue;
    line(`\n${groupHeading(g)}`);
    for (const f of xs) card(f, nums.get(f.id), { details: opt.details, fixable: opt.fixable?.(f) });
  }
  line("");
  if (hidden) para(t("cli.sum.hidden", { n: hidden }), 4, c.dim, "  ");
  if (r.accepted) para(t("cli.sum.accepted", { n: r.accepted }), 4, c.dim, "  ");
  notesOut(r.said ?? r.notes.map((n) => ({ key: n })));
  // The way on, last, where the eye ends up.
  const next = r.verdict === "block" ? t("cli.sum.next.block") : r.verdict === "warn" ? t(opt.policy === "refuse" ? "cli.sum.next.warnRefused" : "cli.sum.next.warn") : "";
  if (next) para(next, 2, r.verdict === "block" ? c.red : c.amber, "  ");
  para(t("cli.sum.foot", { items: r.scan.items.length, ms: r.ms, details: opt.details ? "" : t("cli.sum.footDetails") }), 2, c.dim, "  ");
}
