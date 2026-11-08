// Words in English and Thai: one catalog for the terminal and the dashboard, the language setting both share, and
// the terminal's look (colour depth, wrapping, the one verdict vocabulary). State goes to temp folders of its own.
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HELP, helpRow } from "../src/cli";
import { catalogs, fill, langSource, needs, saveLang, systemLang, t, tMaybe, uiCatalog, utf8Plan, windowsCanShowThai, lang } from "../src/i18n";
import { actionOf, groupOf, plainOf } from "../src/i18n/findings";
import { cells, colorDepth, palette, sentenceOf, verdictMark, width, wrap } from "../src/sec/print";
import type { Finding } from "../src/sec/types";
import { langNow } from "../src/ui/state";

const CLI = join(import.meta.dir, "../src/cli.ts");
const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-i18n-${tag}-`));

async function vswarm(env: Record<string, string>, ...a: string[]) {
  const home = tmp("home");
  const p = Bun.spawn([process.execPath, CLI, ...a], { env: { ...process.env, NO_COLOR: "1", HOME: home, USERPROFILE: home, VSWARM_HOME: join(home, ".vswarm"), ...env }, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { out, err, code };
}

async function withSec<T>(fn: (sec: string) => Promise<T> | T): Promise<T> {
  const prev = process.env.VSWARM_SEC_DIR;
  const sec = tmp("sec");
  process.env.VSWARM_SEC_DIR = sec;
  try {
    return await fn(sec);
  } finally {
    process.env.VSWARM_SEC_DIR = prev;
  }
}

describe("the catalogs", () => {
  const en = catalogs.en, th = catalogs.th;

  test("English and Thai have the same keys, and each sentence the same placeholders", () => {
    expect(Object.keys(th).sort()).toEqual(Object.keys(en).sort());
    for (const k of Object.keys(en)) expect(`${k}: ${needs(th[k]).sort().join(",")}`).toBe(`${k}: ${needs(en[k]).sort().join(",")}`);
  });

  test("every Thai sentence is written out (none left empty or in English where English has words)", () => {
    const same = Object.keys(en).filter((k) => th[k] === en[k] && /[a-z]{4,} [a-z]{4,} [a-z]{4,}/i.test(en[k].replace(/\{[^}]*\}|vswarm [^ ]+( --?[\w-]+)*|[\w.~/-]*[/.][\w.~/-]+/g, "")));
    expect(same).toEqual([]);
    for (const k of Object.keys(th)) expect(th[k].trim().length > 0 ? "ok" : k).toBe("ok");
  });

  test("a sentence Thai lacks comes out in English, never as its key; a missing key is undefined, not invented", () => {
    const k = "cli.head.pass" as const;
    const keep = th[k];
    delete th[k];
    try {
      expect(t(k, {}, "th")).toBe(en[k]);
    } finally {
      th[k] = keep;
    }
    expect(t(k, {}, "th")).toBe(keep);
    expect(tMaybe("rule.no-such-rule.what")).toBeUndefined();
  });

  test("placeholders and English plurals", () => {
    expect(fill("{n} {n:thing|things} in {where}", { n: 1, where: "~" })).toBe("1 thing in ~");
    expect(fill("{n} {n:thing|things}", { n: 2 })).toBe("2 things");
    expect(needs("{n} {n:a|b} {name}")).toEqual(["n", "name"]);
    expect(t("cli.head.warn", { n: 2 }, "th")).toContain("2");
  });

  test("the dashboard is sent the shared words only, never the terminal's", () => {
    const ui = uiCatalog("th");
    expect(Object.keys(ui).some((k) => k.startsWith("cli."))).toBe(false);
    expect(ui["level.check"]).toBe("ควรดูสักนิด");
    expect(ui["rule.secret.sshProd.what"]).toBeString();
  });

  test("the words the issue asked for: gate is ด่าน, vault is ตู้เซฟ, baseline is จุดอ้างอิง", () => {
    expect(th["cli.help.gateSsh"]).toContain("ด่าน");
    expect(th["cli.help.agent"]).toContain("ตู้เซฟ");
    expect(th["cli.help.diff"]).toContain("จุดอ้างอิง");
    // Command names, flags and paths stay as they are typed.
    expect(th["cli.help.policy"]).toContain("WARN");
    expect(th["cli.setup.noHosts"]).toContain('vswarm gate ssh "prod-*"');
  });
});

describe("which language", () => {
  test("VSWARM_LANG, then the saved choice (shared with the dashboard), then the system's; auto follows the system", () => withSec(async (sec) => {
    expect(lang({ LANG: "th_TH.UTF-8" })).toBe("th");
    expect(lang({ LANG: "en_NZ.UTF-8" })).toBe("en");
    saveLang("th");
    expect(JSON.parse(readFileSync(join(sec, "ui.json"), "utf8")).lang).toBe("th");
    expect(lang({ LANG: "en_US.UTF-8" })).toBe("th");
    expect(langNow({ LANG: "en_US.UTF-8" })).toBe("th");
    expect(lang({ LANG: "th_TH.UTF-8", VSWARM_LANG: "en" })).toBe("en");
    saveLang("auto");
    expect(lang({ LANG: "th_TH.UTF-8" })).toBe("th");
    expect(langSource({ LANG: "en_GB.UTF-8" })).toEqual({ setting: "auto", from: "saved", lang: "en" });
    expect(langSource({ VSWARM_LANG: "auto", LC_ALL: "th_TH.UTF-8" })).toEqual({ setting: "auto", from: "env", lang: "th" });
  }));

  test("auto: LC_ALL before LC_MESSAGES before LANG; C and POSIX say nothing; macOS asks AppleLanguages; Windows is English", () => {
    const apple = (v?: string) => () => v;
    expect(systemLang({ LC_ALL: "th_TH.UTF-8", LANG: "en_US.UTF-8" }, "linux")).toBe("th");
    expect(systemLang({ LC_MESSAGES: "en_US.UTF-8", LANG: "th_TH.UTF-8" }, "linux")).toBe("en");
    expect(systemLang({ LC_ALL: "C", LANG: "th_TH.UTF-8" }, "linux")).toBe("th");
    expect(systemLang({ LANG: "C.UTF-8" }, "darwin", apple("th-TH"))).toBe("th");
    expect(systemLang({}, "darwin", apple("en-GB"))).toBe("en");
    expect(systemLang({}, "darwin", apple(undefined))).toBe("en");
    expect(systemLang({ LANG: "de_DE.UTF-8" }, "linux")).toBe("en");
    expect(systemLang({}, "win32", apple("th"))).toBe("en");
  });

  test("Windows: Thai on a console (set to UTF-8 for the run), or in a pipe when the code page is UTF-8 already, or when asked for", () => {
    expect(windowsCanShowThai({ explicit: false, tty: true, cp: 874 })).toBe(true);
    expect(windowsCanShowThai({ explicit: false, tty: false, cp: 65001 })).toBe(true);
    // PowerShell 5.1 reads a pipe in the console's code page: Thai in UTF-8 would come out as question marks.
    expect(windowsCanShowThai({ explicit: false, tty: false, cp: 437 })).toBe(false);
    expect(windowsCanShowThai({ explicit: false, tty: false, cp: undefined })).toBe(false);
    expect(windowsCanShowThai({ explicit: true, tty: false, cp: 437 })).toBe(true);
    expect(utf8Plan({ platform: "win32", tty: true, cp: 874 })).toEqual({ set: true, restore: 874 });
    expect(utf8Plan({ platform: "win32", tty: true, cp: 65001 })).toEqual({ set: false });
    expect(utf8Plan({ platform: "win32", tty: false, cp: 437 })).toEqual({ set: false });
    expect(utf8Plan({ platform: "win32", tty: true, cp: 0 })).toEqual({ set: false });
    expect(utf8Plan({ platform: "darwin", tty: true, cp: 437 })).toEqual({ set: false });
  });

  test("vswarm lang th|en|auto: saved where the dashboard reads it; VSWARM_LANG still wins; a bad value is refused", async () => {
    const sec = tmp("sec");
    const set = await vswarm({ VSWARM_SEC_DIR: sec }, "lang", "th");
    expect(set.code).toBe(0);
    expect(set.err).toContain("ไทย");
    expect(JSON.parse(readFileSync(join(sec, "ui.json"), "utf8")).lang).toBe("th");
    // The isolation preload sets VSWARM_LANG=en for every test; without it the saved choice speaks.
    const now = await vswarm({ VSWARM_SEC_DIR: sec, VSWARM_LANG: "" }, "lang");
    expect(now.out).toContain("ภาษา: ไทย (th)");
    expect((await vswarm({ VSWARM_SEC_DIR: sec, VSWARM_LANG: "en" }, "lang")).out).toContain("Language: English (en)");
    const bad = await vswarm({ VSWARM_SEC_DIR: sec }, "lang", "fr");
    expect(bad.code).toBe(4);
    expect(bad.err).toContain("vswarm lang [th|en|auto]");
    expect((await vswarm({ VSWARM_SEC_DIR: sec }, "lang", "auto")).code).toBe(0);
    expect(JSON.parse(readFileSync(join(sec, "ui.json"), "utf8")).lang).toBe("auto");
  });

  test("Thai for people, English for scripts: errors and help are translated, --json is not", async () => {
    const sec = tmp("sec");
    const help = await vswarm({ VSWARM_SEC_DIR: sec, VSWARM_LANG: "th" }, "help");
    expect(help.out).toContain("ใช้ประจำ");
    expect(help.out).toContain("vswarm setup");
    const err = await vswarm({ VSWARM_SEC_DIR: sec, VSWARM_LANG: "th" }, "fix", "1");
    expect(err.err).toContain("สั่ง vswarm scan ก่อน");
    const unknown = await vswarm({ VSWARM_SEC_DIR: sec, VSWARM_LANG: "th" }, "scna");
    expect(unknown.err).toContain("vswarm scan");
    const json = await vswarm({ VSWARM_SEC_DIR: sec, VSWARM_LANG: "th" }, "preflight", "--json", "--offline");
    const v = JSON.parse(json.out);
    expect(["pass", "warn", "block"]).toContain(v.verdict);
    expect(JSON.stringify(v)).not.toMatch(/[฀-๿]/);
    expect(existsSync(join(sec, "ui.json"))).toBe(false);
  }, 120_000);
});

describe("the look", () => {
  const f = (over: Partial<Finding>): Finding => ({ id: "x", rule: "agent-mcp-new", severity: "medium", title: "New MCP server for cursor: docs", detail: [], item: { kind: "mcp", id: "cursor:docs", name: "docs", source: "cursor" }, ...over });

  test("one vocabulary: the state in plain words with a dot, the PASS / WARN / BLOCK tag beside it", () => {
    expect(verdictMark("warn")).toBe("● Check this WARN");
    expect(verdictMark("block")).toBe("● Stop BLOCK");
    expect(verdictMark("pass", "NOTHING SEEN")).toBe("● Safe NOTHING SEEN");
    expect(groupOf({ rule: "x", severity: "critical" })).toBe("action");
    expect(groupOf({ rule: "vswarm-state", severity: "medium" })).toBe("action");
    expect(groupOf({ rule: "x", severity: "medium" })).toBe("look");
    expect(groupOf({ rule: "x", severity: "low" })).toBe("fyi");
    expect(sentenceOf({ verdict: "warn", findings: [f({})] })).toBe("Nothing dangerous, 1 thing worth a look.");
    expect(sentenceOf({ verdict: "block", findings: [f({ severity: "high" }), f({ severity: "high" })] })).toBe("2 things need action before you use production.");
  });

  test("a finding in plain words, with one command; the technical title stays for whoever wants it", () => {
    const p = plainOf(f({}), "th");
    expect(p.title).toBe("มี tool server ของ AI ตัวใหม่โผล่มาใน Cursor");
    expect(p.plain).toBe(true);
    // A rule with no words of its own keeps vswarm's title.
    expect(plainOf(f({ rule: "pkg-integrity", title: "integrity mismatch" })).title).toBe("integrity mismatch");
    expect(actionOf(f({}), 3, false)).toEqual({ label: "cli.act.ok", cmd: "vswarm ok 3" });
    expect(actionOf(f({ severity: "high" }), 3, false)?.cmd).toBe("vswarm why 3");
    expect(actionOf(f({}), 3, true)?.cmd).toBe("vswarm fix 3");
    expect(actionOf(f({ rule: "malicious", severity: "critical" }), 3, false)?.cmd).toBe("vswarm respond");
  });

  test("colour: none with NO_COLOR or into a pipe, the 16 basic colours unless the terminal says it has 24-bit", () => {
    expect(colorDepth({ isTTY: true }, { NO_COLOR: "1" })).toBe(0);
    expect(colorDepth({ isTTY: false }, {})).toBe(0);
    expect(colorDepth({ isTTY: true }, { TERM: "xterm" })).toBe(16);
    expect(colorDepth({ isTTY: true }, { COLORTERM: "truecolor" })).toBe(24);
    expect(colorDepth({ isTTY: false }, { FORCE_COLOR: "1" })).toBe(16);
    expect(colorDepth({ isTTY: true }, { TERM: "dumb" })).toBe(0);
    expect(palette(() => 16).red("x")).toBe("\x1b[31mx\x1b[0m");
    expect(palette(() => 24).red("x")).toBe("\x1b[38;2;239;107;107mx\x1b[0m");
    expect(palette(() => 0).red("x")).toBe("x");
  });

  test("wrapping at the terminal's width: Thai by its width on screen and at its word breaks, commands kept whole", () => {
    expect(cells("ปลอดภัย")).toBe(6);
    expect(width({ isTTY: false }, {})).toBe(0);
    expect(width({ isTTY: true, columns: 200 }, {})).toBe(120);
    expect(width({ isTTY: true, columns: 20 }, {})).toBe(40);
    const th = t("cli.sum.next.block", {}, "th");
    for (const room of [30, 40, 60]) {
      const lines = wrap(th, room);
      expect(lines.every((l) => cells(l) <= room)).toBe(true);
      expect(lines.join("").replace(/ /g, "")).toBe(th.replace(/ /g, ""));
    }
    const en = "Look them over, then take a new starting point: vswarm agents --inspect and vswarm baseline";
    expect(wrap(en, 40).some((l) => l.includes("vswarm agents --inspect"))).toBe(true);
    expect(wrap("no limit", 0)).toEqual(["no limit"]);
  });

  test("help: four plain headings, every command as it is typed, rows that fit the width in Thai too", () => {
    expect(HELP.map(([h]) => t(h, {}, "en"))).toEqual(["Everyday", "When something is found", "Production", "Advanced"]);
    for (const [, rows] of HELP) for (const [cmd, key] of rows) {
      expect(cmd.startsWith("vswarm ")).toBe(true);
      const r = helpRow(cmd, t(key, {}, "th"), 100, 44);
      expect(r.desc.every((l) => cells(l) <= 100 - 48 || !l.includes(" "))).toBe(true);
    }
  });
});
