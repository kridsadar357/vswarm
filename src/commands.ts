// Commands with a report or a decision of their own, shared by the command line and `vswarm setup`: the baseline
// (refused over HIGH and CRIT findings), ok / accept, why, and the secrets report.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { t } from "./i18n";
import { groupOf, plainOf } from "./i18n/findings";
import { realCtx, type Ctx } from "./sec/ctx";
import { check, STATE_RULE, type Check } from "./sec/engine";
import { c, card, checkedAt, groupHeading, headline, line, notesOut, numbers, para, sentenceOf, summary, verdictMark } from "./sec/print";
import { forBaseline } from "./sec/scan";
import { files, loadAccepted, loadLast, saveAccepted, saveBaseline } from "./sec/store";
import { RANK, type Finding } from "./sec/types";

/** How to start this vswarm again: the launcher once installed, this checkout otherwise. */
export async function selfCommand(): Promise<string[]> {
  const { launcherPath } = await import("./setup");
  return existsSync(launcherPath()) ? [launcherPath()] : [process.execPath, join(import.meta.dir, "cli.ts")];
}

/** Whether vswarm fix has an automatic fix for a finding. */
export async function fixable(): Promise<(f: Finding, n: number) => boolean> {
  const { fixFor } = await import("./sec/fix");
  const self = await selfCommand();
  return (f, n) => !!fixFor(f, { n, self }).run;
}

/** The HIGH and CRIT findings a baseline would make normal, as `vswarm baseline` lists them when it refuses. */
export function seriousList(serious: Finding[]) {
  for (const f of serious) {
    const p = plainOf(f);
    line(`    ${c.red("●")} ${p.title}  ${c.dim(f.severity === "critical" ? "CRIT" : "HIGH")}`);
    if (p.plain && p.title !== f.title) line(`      ${c.dim(f.title)}`);
  }
}

export type BaselineResult = "recorded" | "refused" | "declined";

/**
 * `vswarm baseline`: a check, then this machine as the starting point. Never over HIGH or CRIT findings without
 * --accept-high: a baseline taken then would make them normal from now on.
 */
export async function baselineCommand(opt: { auto?: boolean; acceptHigh?: boolean; offline?: boolean; ctx?: Ctx; yes: (q: string, def?: boolean) => Promise<boolean>; quiet?: boolean; r?: Check }): Promise<BaselineResult> {
  const r = opt.r ?? (await check(opt.ctx ?? realCtx(), { offline: opt.offline }));
  if (!opt.quiet) summary(r, { title: "baseline check" });
  // During an incident this is the step that records the cleaned machine; vswarm unlock needs it.
  if (r.lock) para(t("cli.baseline.incident", { incident: r.lock.incident }), 2, c.amber, "\n  ");
  const serious = r.findings.filter((f) => RANK[f.severity] >= RANK.high);
  if (serious.length && !opt.acceptHigh) {
    para(t("cli.baseline.refused", { n: serious.length }), 2, c.red, "\n  ");
    seriousList(serious);
    para(t("cli.baseline.refusedHow"), 2, c.dim, "  ");
    return "refused";
  }
  if (serious.length) para(t("cli.baseline.acceptHigh", { n: serious.length }), 2, c.amber, "\n  ");
  const count = r.scan.items.filter((i) => i.kind !== "proc" && i.kind !== "conn").length;
  if (!opt.auto) line("");
  const ok = opt.auto || (await opt.yes(t("cli.baseline.ask", { n: count }), !serious.length));
  if (!ok) {
    line(c.dim(`  ${t("cli.baseline.notRecorded")}`));
    return "declined";
  }
  await saveBaseline(forBaseline(r.scan));
  line(`  ${c.green("✔")} ${t("cli.baseline.done")} ${c.dim(files.baseline())}`);
  para(t("cli.baseline.after"), 2, c.dim, "  ");
  return "recorded";
}

/** What `vswarm ok` refuses to accept, and why (undefined: it can be accepted). */
export function cannotAccept(f: Finding): string | undefined {
  if (f.rule === "malicious") return t("cli.ok.malicious", { title: f.title });
  if (f.rule === STATE_RULE) return t("cli.ok.state", { title: f.title, fix: f.fix ?? "" });
}

/** Marks findings of the last check as yours. Returns how many were. */
export async function acceptFindings(pick: Finding[]): Promise<number> {
  const acc = await loadAccepted();
  let n = 0;
  for (const f of pick) {
    const no = cannotAccept(f);
    if (no) {
      line(`  ${c.red("✖")} ${no}`);
      continue;
    }
    acc[f.id] = { at: Date.now(), title: f.title };
    line(`  ${c.green("✔")} ${t("cli.ok.done", { title: f.title })}`);
    n++;
  }
  await saveAccepted(acc);
  return n;
}

/** `vswarm ok <n…> | <id…> | --all`: findings of the last check vswarm itself wrote, by number or id. */
export async function okCommand(args: string[], all: boolean) {
  // Only ids from a check vswarm itself wrote: a forged last.json must not name what gets accepted.
  const last = await loadLast();
  if (!last) throw new Error(t("cli.err.scanFirst"));
  // A number is the finding shown with it in the last check; an id is taken as it is.
  const bad = args.filter((a) => /^\d+$/.test(a) && !last.findings[Number(a) - 1]);
  if (bad.length) throw new Error(t("cli.err.noFinding", { list: bad.join(", "), n: last.findings.length }));
  const pick = all ? last.findings : last.findings.filter((f, i) => args.includes(f.id) || args.includes(String(i + 1)));
  if (!pick.length) throw new Error(t("cli.err.okWhich"));
  await acceptFindings(pick);
}

/**
 * `vswarm why [n]`: a fresh check, each finding that counts with why it matters, what to do and both ways out (fix,
 * or mark as yours), its technical details, and the policy at the end. With n, only that finding.
 */
export async function whyCommand(opt: { offline?: boolean; n?: number }): Promise<number> {
  const { readPolicy, policyLine } = await import("./sec/policy");
  const { fixFor } = await import("./sec/fix");
  const pol = await readPolicy();
  const r = await check(realCtx(), { offline: opt.offline });
  const nums = numbers(r.findings);
  const self = await selfCommand();
  line(`${c.violet("▼ vswarm why")} ${c.dim(`· ${t("cli.why.sub")}`)}`);
  headline(r.verdict, sentenceOf(r), checkedAt(Date.now()));
  if (r.lock) para(t("cli.why.locked", { incident: r.lock.incident, why: r.lock.reason }), 2, c.red, "  ");
  let shown = r.findings.filter((f) => RANK[f.severity] >= RANK.medium);
  if (opt.n !== undefined) {
    const f = r.findings[opt.n - 1];
    if (!f) throw new Error(t("cli.err.noNumber", { n: opt.n, count: r.findings.length }));
    shown = [f];
  }
  if (!shown.length) line(`\n  ${c.green("✔")} ${t("cli.why.none")}`);
  for (const f of shown) {
    const n = nums.get(f.id)!;
    line("");
    const plan = fixFor(f, { n, self: [self.length === 1 ? "vswarm" : self.join(" ")] });
    card(f, n, { details: true, todo: true, fixable: !!plan.run });
    const pad = " ".repeat(7);
    if (plan.run) para(plan.what, 9, c.dim, `${pad}  `);
    // The other way out, when the card's command was the fix or a closer look.
    if (f.rule === "malicious" || f.rule === STATE_RULE) para(t("cli.why.cannotAccept"), 9, c.dim, pad);
    else if (f.rule === "team-require") para(t("cli.why.teamOnly"), 9, c.dim, pad);
    else if (plan.run || groupOf(f) === "action") line(`${pad}${c.cyan("→")} ${t("cli.act.ok")} ${c.cyan(c.bold(`vswarm ok ${n}`))}`);
  }
  const low = opt.n === undefined ? r.findings.length - shown.length : 0;
  if (low) para(t("cli.why.low", { n: low }), 4, c.dim, "\n  ");
  notesOut(r.said ?? []);
  line(`\n${verdictMark(r.verdict)}  ${c.dim(r.verdict === "warn" ? (pol.warn === "allow" ? t("cli.why.letThrough") : t("cli.why.refused")) : r.verdict === "block" ? t("cli.why.refused") : t("cli.why.letThrough"))}`);
  para(policyLine(pol), 2, c.dim, "  ");
  const { listVaults, keyOverrides } = await import("./sec/agent");
  if (process.platform !== "win32" && listVaults().length) for (const k of await keyOverrides()) para(k, 2, c.dim, "  ");
  return r.verdict === "block" ? 3 : r.verdict === "warn" && pol.warn === "refuse" ? 2 : 0;
}

/** `vswarm secrets`: where long-lived credentials live, grouped like a check, values never read out. */
export async function secretsCommand() {
  const { secrets } = await import("./sec/secrets");
  const f = await secrets(realCtx());
  line(`${c.violet("▼ vswarm secrets")} ${c.dim(`· ${t("cli.secrets.sub")}`)}`);
  if (!f.length) return line(`  ${c.green("✔")} ${t("cli.secrets.none")}`);
  para(t("cli.secrets.found", { n: f.length }), 2, (s) => s, "  ");
  for (const g of ["action", "look", "fyi"] as const) {
    const xs = f.filter((x) => groupOf(x) === g);
    if (!xs.length) continue;
    line(`\n${groupHeading(g)}`);
    for (const x of xs) card(x, undefined, { details: true, todo: true });
  }
  para(t("cli.secrets.after"), 2, c.dim, "\n  ");
}
