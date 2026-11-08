// Words for people, in English and Thai: one catalog for the terminal and the dashboard (src/i18n/en.json, th.json).
//
//   t("key", { n: 2 })      the sentence in the language in use; a key Thai lacks comes out in English, never as a key
//   {name}                  a value put in as given
//   {n:thing|things}        the first form when n is 1 (English; Thai has no plural)
//
// Keys starting with "cli." are the terminal's own; the dashboard is sent the rest (uiCatalog).
//
// Which language: VSWARM_LANG (th, en or auto), then the choice saved by `vswarm lang` or the dashboard (ui.json beside
// vswarm's state), then auto: LC_ALL, LC_MESSAGES, LANG, and on macOS the AppleLanguages default; English otherwise.
// Only words for people go through here: --json, logs and sealed state stay English and stable.

import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { readJson } from "../sec/ctx";
import { SEC, writePrivate } from "../sec/store";
import en from "./en.json";
import th from "./th.json";

export type Lang = "en" | "th";
export type LangSetting = Lang | "auto";
export type Key = keyof typeof en;
export type Vars = Record<string, string | number | undefined>;

const CATALOG: Record<Lang, Record<string, string>> = { en, th };

export const asLang = (s?: string): Lang | undefined => (s && /^th/i.test(s) ? "th" : s && /^en/i.test(s) ? "en" : undefined);
const asSetting = (s?: string): LangSetting | undefined => (s === "auto" ? "auto" : asLang(s));

// Beside the rest of vswarm's state, so a scratch VSWARM_SEC_DIR keeps it too. Not sealed: it changes words only.
export const langFile = () => join(SEC(), "ui.json");

/** The saved choice (`vswarm lang`, or the dashboard's switch); none when it was never made. */
export const savedLang = (): LangSetting | undefined => asSetting(readJson<{ lang?: string }>(langFile())?.lang);

export function saveLang(lang: LangSetting) {
  writePrivate(langFile(), { ...(readJson<Record<string, unknown>>(langFile()) ?? {}), lang });
  cache = undefined;
}

/**
 * The system's language, for `auto`: the locale variables in POSIX order (LC_ALL wins, then LC_MESSAGES, then LANG;
 * C and POSIX say nothing), then on macOS the first of AppleLanguages. Windows: English (no PowerShell is started for it).
 */
export function systemLang(env: Record<string, string | undefined> = process.env, platform: NodeJS.Platform = process.platform, apple: () => string | undefined = appleLanguage): Lang {
  for (const v of [env.LC_ALL, env.LC_MESSAGES, env.LANG]) {
    if (!v || /^(C|POSIX)([.@]|$)/i.test(v)) continue;
    return asLang(v) ?? "en";
  }
  if (platform === "darwin") return asLang(apple()) ?? "en";
  return "en";
}

let apple: { v?: string } | undefined;
/** `defaults read -g AppleLanguages`, once per run: a read-only look at the user's preferred languages. */
function appleLanguage(): string | undefined {
  if (apple) return apple.v;
  apple = {};
  try {
    const r = spawnSync("/usr/bin/defaults", ["read", "-g", "AppleLanguages"], { encoding: "utf8", timeout: 1500, stdio: ["ignore", "pipe", "ignore"] });
    apple.v = /"?([A-Za-z]{2}[\w-]*)"?/.exec(r.stdout?.replace(/^\s*\(\s*/, "") ?? "")?.[1];
  } catch {}
  return apple.v;
}

/** Where the language in use comes from, for `vswarm lang`. */
export function langSource(env: Record<string, string | undefined> = process.env): { setting: LangSetting; from: "env" | "saved" | "default"; lang: Lang } {
  const fromEnv = asSetting(env.VSWARM_LANG);
  const saved = fromEnv ? undefined : savedLang();
  const setting = fromEnv ?? saved ?? "auto";
  return { setting, from: fromEnv ? "env" : saved ? "saved" : "default", lang: setting === "auto" ? systemLang(env) : setting };
}

let cache: { k: string; v: Lang } | undefined;
/** The language for words shown to people now. */
export function lang(env: Record<string, string | undefined> = process.env): Lang {
  const k = `${env.VSWARM_LANG ?? ""}\0${SEC()}\0${env.LC_ALL ?? ""}\0${env.LC_MESSAGES ?? ""}\0${env.LANG ?? ""}`;
  if (env === process.env && cache?.k === k) return cache.v;
  let v = langSource(env).lang;
  // Thai only where it can be read: see windowsCanShowThai.
  if (v === "th" && env === process.env && process.platform === "win32" && !windowsCanShowThai({ explicit: asLang(env.VSWARM_LANG) === "th", tty: !!process.stdout.isTTY || !!process.stderr.isTTY, cp: consoleCodePage() })) v = "en";
  if (env === process.env) cache = { k, v };
  return v;
}

/** For tests: forget the language worked out earlier in this process. */
export const forgetLang = () => void (cache = undefined);

// ── Windows consoles
//
// vswarm writes UTF-8. A console shows it once its output code page is 65001 (UTF-8), which useWindowsUtf8() sets for
// the run and puts back at exit; Windows Terminal and conhost on Windows 10 and later then draw Thai. Output that goes
// into a pipe or a file is read by whoever reads it: PowerShell 5.1 decodes a program's output in the console's code
// page, so Thai there would turn into question marks unless that code page is UTF-8 already. Then the words are English,
// unless VSWARM_LANG=th asks for Thai anyway.

/** Whether Thai text can be written now on Windows: to a console, or anywhere when the code page is UTF-8, or when asked for. */
export function windowsCanShowThai(o: { explicit: boolean; tty: boolean; cp: number | undefined }): boolean {
  return o.explicit || o.tty || o.cp === 65001;
}

/** What useWindowsUtf8 does: set 65001 for a console that is on another code page (and put the old one back at exit). */
export function utf8Plan(o: { platform: NodeJS.Platform; tty: boolean; cp: number | undefined }): { set: boolean; restore?: number } {
  if (o.platform !== "win32" || !o.tty || o.cp === undefined || o.cp === 0 || o.cp === 65001) return { set: false };
  return { set: true, restore: o.cp };
}

type Kernel = { GetConsoleOutputCP: () => number; SetConsoleOutputCP: (cp: number) => number };
let kernel: Kernel | null | undefined;
function kernel32(): Kernel | null {
  if (kernel !== undefined) return kernel;
  kernel = null;
  if (process.platform !== "win32") return kernel;
  try {
    // bun:ffi only here, only on Windows: two calls into kernel32, nothing else.
    const { dlopen, FFIType } = require("bun:ffi");
    const lib = dlopen("kernel32.dll", { GetConsoleOutputCP: { args: [], returns: FFIType.u32 }, SetConsoleOutputCP: { args: [FFIType.u32], returns: FFIType.i32 } });
    kernel = lib.symbols as Kernel;
  } catch {}
  return kernel;
}

/** The console's output code page on Windows (0 without a console); undefined elsewhere or when it cannot be read. */
export function consoleCodePage(): number | undefined {
  try {
    return kernel32()?.GetConsoleOutputCP() ?? undefined;
  } catch {
    return undefined;
  }
}

let utf8Set = false;
/** On a Windows console, UTF-8 output for this run; the code page it had comes back at exit. */
export function useWindowsUtf8() {
  if (utf8Set || process.platform !== "win32") return;
  utf8Set = true;
  const plan = utf8Plan({ platform: process.platform, tty: !!process.stdout.isTTY || !!process.stderr.isTTY, cp: consoleCodePage() });
  if (!plan.set) return;
  try {
    kernel32()?.SetConsoleOutputCP(65001);
    process.on("exit", () => {
      try {
        kernel32()?.SetConsoleOutputCP(plan.restore!);
      } catch {}
    });
  } catch {}
}

// ── sentences

export function fill(s: string, vars?: Vars): string {
  s = s.replace(/\{(\w+):([^|}]*)\|([^}]*)\}/g, (_m, k, one, many) => (vars && Number(vars[k]) === 1 ? one : many));
  return s.replace(/\{(\w+)\}/g, (m, k) => (vars && vars[k] !== undefined ? String(vars[k]) : m));
}

/** A sentence in the language in use (`l` to choose one); English where Thai has none. */
export function t(key: Key, vars?: Vars, l: Lang = lang()): string {
  return fill(CATALOG[l][key] ?? CATALOG.en[key] ?? key, vars);
}

/** The same for a key put together at run time (rule names); undefined when not even English has it. */
export function tMaybe(key: string, vars?: Vars, l: Lang = lang()): string | undefined {
  const s = CATALOG[l][key] ?? CATALOG.en[key];
  return s === undefined ? undefined : fill(s, vars);
}

/** The placeholders a sentence needs ({name}, and n of {n:a|b}). */
export const needs = (s: string) => [...new Set([...s.matchAll(/\{(\w+)(?::[^}]*)?\}/g)].map((m) => m[1]))];

/** What the dashboard is sent: everything but the terminal's own keys. */
export function uiCatalog(l: Lang): Record<string, string> {
  return Object.fromEntries(Object.entries(CATALOG[l]).filter(([k]) => !k.startsWith("cli.")));
}

export const catalogs = CATALOG;
