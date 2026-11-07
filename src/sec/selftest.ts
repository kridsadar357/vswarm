// `vswarm selftest`: builds a fake home folder, records a clean baseline, plants harmless stand-ins for real attack
// steps one at a time, and reports which ones vswarm caught, per ATT&CK technique. It also plants benign look-alikes
// (a jump host in ~/.ssh/config, the official npm registry, an editable pip install) and counts every alarm they raise.
// The rates it prints are measured, not estimated; anyone can run it and add cases (src/sec/selftest-cases.ts).
// Nothing outside the temporary folder is touched.

import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, type Ctx } from "./ctx";
import { check } from "./engine";
import { forBaseline, scan } from "./scan";
import { saveBaseline, writePrivate, files } from "./store";
import { BENIGN, CASES, plantClean, type Benign, type Case, type Fake } from "./selftest-cases";
import { RANK, type Finding, type Severity } from "./types";

export { BENIGN, CASES };

export interface SelftestResult {
  cases: { name: string; like: string; technique: string; caught: boolean; severity?: Severity; min: Severity; skipped?: boolean }[];
  /** Benign look-alikes and ordinary changes, and the worst each one raised. */
  benign: { name: string; technique: string; when: Benign["when"]; ok: boolean; severity?: Severity; max: Severity }[];
  caught: number;
  /** Cases that ran on this platform. */
  total: number;
  /** Alarms on the clean machine (medium and above), and on benign changes above what they may raise. */
  falseAlarms: Finding[];
  /** Per technique: caught / run, and benign look-alikes that raised an alarm / benign ones. */
  techniques: Record<string, { caught: number; total: number; alarms: number; benign: number }>;
  ms: number;
}

const worst = (fs: Finding[]): Severity | undefined => fs.reduce<Severity | undefined>((w, f) => (!w || RANK[f.severity] > RANK[w] ? f.severity : w), undefined);

export async function selftest(opt: { cases?: Case[]; benign?: Benign[] } = {}): Promise<SelftestResult> {
  const cases = opt.cases ?? CASES;
  const benign = opt.benign ?? BENIGN;
  const t0 = Date.now();
  const root = mkdtempSync(join(tmpdir(), "vswarm-selftest-"));
  const home = join(root, "home");
  const brew = join(root, "brew");
  const sec = join(root, "sec");
  const prevSec = process.env.VSWARM_SEC_DIR;
  process.env.VSWARM_SEC_DIR = sec;
  try {
    const fake: Fake = { home, brew, win: {} };
    const wrote = plantClean(fake);
    const ctx: Ctx = {
      home, brew, pathDirs: [join(home, ".local/bin")], system: false, host: "selftest", user: "selftest",
      // Only local file tools, and the fake crontab; nothing that would read the real machine.
      run: (cmd, t) => (cmd[0] === "crontab" ? Promise.resolve(fake.crontab) : ["plutil", "codesign"].includes(cmd[0]) ? run(cmd, t) : Promise.resolve(undefined)),
      // The Windows part reads the fake snapshot on every platform, never the real machine. A copy each time, so
      // what the baseline kept is not changed by the plants.
      win: async () => structuredClone(fake.win),
    };
    await saveBaseline(forBaseline(await scan(ctx, { live: false })));
    // The known-malicious database is stubbed so the test runs offline and never reports a real package.
    writePrivate(files.osv(), { "npm:event-stream-helper@3.3.6": { at: Date.now(), mal: ["MAL-0000-SELFTEST"] } });
    // Each case starts again from this clean machine and its baseline.
    const clean = { win: structuredClone(fake.win), crontab: fake.crontab };
    for (const d of [home, brew, sec]) cpSync(d, `${d}.clean`, { recursive: true });
    const reset = () => {
      for (const d of [home, brew, sec]) {
        rmSync(d, { recursive: true, force: true });
        cpSync(`${d}.clean`, d, { recursive: true });
      }
      fake.win = structuredClone(clean.win);
      fake.crontab = clean.crontab;
    };
    const falseAlarms: Finding[] = [];
    // The clean machine itself, with its look-alike configs: anything at medium or above is a false alarm.
    const calm = await check(ctx, { offline: true });
    const loud = calm.findings.filter((f) => RANK[f.severity] >= RANK.medium);
    falseAlarms.push(...loud);

    const out: SelftestResult["cases"] = [];
    for (const c of cases) {
      if (c.only && !c.only.includes(process.platform)) {
        out.push({ name: c.name, like: c.like, technique: c.technique, caught: false, min: c.min, skipped: true });
        continue;
      }
      reset();
      c.plant(home, brew, fake.win, fake);
      const r = await check(ctx, { offline: true });
      const hits = r.findings.filter((x) => c.expect(x));
      const top = worst(hits);
      out.push({ name: c.name, like: c.like, technique: c.technique, caught: top !== undefined && RANK[top] >= RANK[c.min], severity: top, min: c.min });
    }

    const quiet: SelftestResult["benign"] = [];
    for (const b of benign) {
      if (b.when === "clean") {
        // Part of the clean machine: judged by what the clean check raised about the files it wrote.
        const mine = [...(wrote.get(b.name) ?? [])];
        const about = loud.filter((f) => [f.item?.path, f.item?.id, ...f.detail].some((x) => x && mine.some((p) => p === x || p.endsWith(`/${x}`) || x.includes(p))));
        quiet.push({ name: b.name, technique: b.technique, when: b.when, ok: !about.length, severity: worst(about), max: b.max });
        continue;
      }
      reset();
      b.plant(home, brew, fake.win, fake);
      const r = await check(ctx, { offline: true });
      // What the clean machine raised already is counted once, above.
      const over = r.findings.filter((f) => RANK[f.severity] > RANK[b.max] && !loud.some((x) => x.id === f.id));
      falseAlarms.push(...over);
      quiet.push({ name: b.name, technique: b.technique, when: b.when, ok: !over.length, severity: worst(r.findings), max: b.max });
    }

    const techniques: SelftestResult["techniques"] = {};
    const t = (k: string) => (techniques[k] ??= { caught: 0, total: 0, alarms: 0, benign: 0 });
    for (const c of out.filter((x) => !x.skipped)) (t(c.technique).total++, c.caught && t(c.technique).caught++);
    for (const b of quiet) (t(b.technique).benign++, !b.ok && t(b.technique).alarms++);
    const ran = out.filter((x) => !x.skipped);
    return { cases: out, benign: quiet, caught: ran.filter((c) => c.caught).length, total: ran.length, falseAlarms, techniques, ms: Date.now() - t0 };
  } finally {
    if (prevSec === undefined) delete process.env.VSWARM_SEC_DIR;
    else process.env.VSWARM_SEC_DIR = prevSec;
    rmSync(root, { recursive: true, force: true });
  }
}
