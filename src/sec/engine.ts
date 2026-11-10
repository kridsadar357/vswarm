// One check of the machine: scan, credentials, known-malicious packages, rules, then the verdict.

import type { Ctx } from "./ctx";
import { t } from "../i18n";
import type { Say } from "./print";
import { osvMalicious } from "./intel";
import { evaluate, uncovered } from "./rules";
import { forBaseline, scan as runScan } from "./scan";
import { secrets as findSecrets } from "./secrets";
import { ensureSec, files, lockState, readAccepted, readBaseline, saveLast, stateKey, type Lock } from "./store";
import { applyAllow, loadPolicy, matches, requirements } from "./team";
import { RANK, verdictOf, type Finding, type Scan, type Verdict } from "./types";

export interface Check {
  scan: Scan;
  baseline?: Scan;
  findings: Finding[];
  /** Findings you accepted earlier; kept out of the verdict but still counted. */
  accepted: number;
  verdict: Verdict;
  lock?: Lock;
  /** What vswarm noticed besides findings, in English (as --json gives them). */
  notes: string[];
  /** The same notes for people: catalog keys (src/i18n), shown in the language in use. */
  said?: Say[];
  ms: number;
  /** Packages the known-malicious check could not ask about (offline, or OSV did not answer in time). */
  osvUnchecked?: number;
}

/** Findings about vswarm's own files. They can never be accepted away: accepting them would need the files they doubt. */
export const STATE_RULE = "vswarm-state";

/**
 * Accepted under an id vswarm no longer gives: until 2.7 every SSH key without a passphrase was one finding,
 * `secret:ssh:<a>,<b>`; a key accepted that way stays accepted now that each key is a finding of its own.
 */
export function acceptedBefore(accepted: Record<string, unknown>, id: string): boolean {
  const key = /^secret:ssh:([^,]+)$/.exec(id)?.[1];
  if (!key) return false;
  return Object.keys(accepted).some((a) => a.startsWith("secret:ssh:") && a.includes(",") && a.slice("secret:ssh:".length).split(",").includes(key));
}

/**
 * `only` checks just those parts of the scan (see scan.ts), without credentials or the team's requirements, and does
 * not save the result: a gate must never reuse a verdict that looked at part of the machine.
 */
export async function check(ctx: Ctx, opt: { offline?: boolean; osvNewOnly?: boolean; sign?: Parameters<typeof evaluate>[0]["sign"]; only?: string[] } = {}): Promise<Check> {
  const t0 = Date.now();
  ensureSec();
  const own: Finding[] = [];
  const state = (id: string, severity: Finding["severity"], title: string, detail: string[], fix: string) =>
    own.push({ id: `${STATE_RULE}:${id}`, rule: STATE_RULE, severity, title, detail, fix });
  const b = await readBaseline();
  // A baseline that does not verify could hide anything that was added to it; it is set aside, and that blocks.
  let baseline = b.untrusted && !b.nokey ? undefined : b.value;
  if (b.untrusted && !b.nokey)
    state("baseline", "high", "vswarm's baseline was changed outside vswarm", [`${files.baseline()} ${b.untrusted}`, "Code that adds itself to the baseline would never be reported as new."],
      "If you did not edit it, treat the machine as suspect (vswarm respond). Otherwise review vswarm diff, then record a new one: vswarm baseline");
  const partial = opt.only !== undefined;
  const [scanned, secretFindings] = await Promise.all([runScan(ctx, partial ? { only: opt.only, live: false } : {}), partial ? [] : findSecrets(ctx)]);
  // A quiet gate asks OSV only about packages it has never asked about, with a short wait, so a package installed a
  // minute ago is checked before production access while a slow network still cannot hold up a login.
  const osv = await osvMalicious(scanned.items, files.osv(), { offline: opt.offline, onlyNew: opt.osvNewOnly, timeoutMs: opt.osvNewOnly ? 3000 : undefined });
  // The team policy, if this machine follows one: its own package names are not look-alikes, its accepted findings
  // count as accepted, and what it requires is checked.
  const team = await loadPolicy();
  applyAllow(team.policy);
  if (team.untrusted)
    state("team-policy", "medium", "the team policy on this machine was changed outside vswarm; it is not used", [`policy.json ${team.untrusted}`], "Fetch the signed one again: vswarm team sync");
  const all = await evaluate({ scan: scanned, baseline, malicious: osv.hits, secrets: secretFindings, sign: opt.sign });
  if (team.policy && !partial) own.push(...(await requirements(team.policy, ctx, baseline?.at)));
  // MCP servers against what `agents --inspect` saw last, without starting any of them.
  const { loadPins, mcpDrift } = await import("./mcp");
  const pinned = await loadPins();
  const drift = mcpDrift(scanned.items, pinned.pins);
  all.push(...drift.findings);
  // Lists of dangerous things this machine follows (vswarm feed), compared here; nothing is fetched during a check.
  const { expired, feedFindings, keptLists } = await import("./feed");
  const feeds = await keptLists();
  all.push(...feedFindings(scanned.items, feeds.lists));
  feeds.problems.forEach((p, i) => state(`feed-${i}`, "medium", `a vswarm feed is not used: ${p}`, [p], "Fetch it again: vswarm feed update (or vswarm feed remove <name>)"));
  if (pinned.untrusted && !pinned.nokey)
    state("mcp-pins", "medium", "vswarm's record of MCP tool definitions was changed outside vswarm; it is ignored", [`mcp-tools.json ${pinned.untrusted}`],
      "A changed record could hide a server that changed its tools. Inspect them again: vswarm agents --inspect");
  const { readPolicy } = await import("./policy");
  const pol = await readPolicy();
  if (pol.untrusted)
    state("policy", "medium", "vswarm's WARN policy was changed outside vswarm; WARN is refused until it is set again", [`policy.json ${pol.untrusted}`],
      "If you did not edit it, treat the machine as suspect (vswarm respond). Otherwise set it again: vswarm policy warn allow (or refuse)");
  const a = await readAccepted();
  // An accepted list that does not verify accepts nothing.
  const acceptedIds = a.untrusted ? {} : a.value ?? {};
  if (a.untrusted && !a.nokey)
    state("accepted", "medium", "vswarm's list of accepted findings was changed outside vswarm; nothing in it counts", [`${files.accepted()} ${a.untrusted}`],
      "Review what is shown, then accept again what you expect: vswarm accept <id>");
  if (b.nokey || a.nokey)
    state("nokey", "medium", "vswarm could not check its own files: its sealing key is not readable right now", [String((b.nokey ? b : a).untrusted)],
      "Unlock the login keychain (macOS) or keyring (Linux) and check again; vswarm doctor shows where the key is");
  const k = await stateKey();
  if (k.tampered)
    state("keystore", "high", "vswarm's sealing key was moved to a plain file, and vswarm did not move it", [`${files.keystore()}: ${k.tampered}`, `vswarm uses ${k.store.where} instead.`, "A key in a file someone chose lets them seal forged state (a passing verdict, a closed incident)."],
      `If you did not edit it, treat the machine as suspect (vswarm respond). Then remove ${files.keystore()}; vswarm goes back to ${k.store.where}`);
  // A known-malicious package can never be accepted away.
  const findings = [...own, ...all]
    .filter((f) => f.rule === "malicious" || f.rule === STATE_RULE || f.rule === "team-require" || (!acceptedIds[f.id] && !acceptedBefore(acceptedIds, f.id) && !matches(team.policy?.accept, f.id)))
    .sort((x, y) => RANK[y.severity] - RANK[x.severity]);
  // Each note twice: in English for --json and the dashboard's details, and as words for the terminal.
  const notes: string[] = [];
  const said: Say[] = [];
  const note = (text: string, s: Say) => (notes.push(text), said.push(s));
  if (!baseline) note(t("cli.note.noBaseline", {}, "en"), { key: "cli.note.noBaseline.human" });
  const fresh = uncovered(scanned, baseline);
  if (fresh.length) note(t("cli.note.olderBaseline", { list: fresh.join(", ") }, "en"), { key: "cli.note.olderBaseline.human", vars: { list: fresh.join(", ") } });
  if (drift.never.length) {
    const names = [...new Set(drift.never.map((i) => i.name))];
    const list = `${names.slice(0, 4).join(", ")}${names.length > 4 ? " …" : ""}`;
    note(t("cli.note.neverInspected", { n: names.length, list }, "en"), { key: "cli.note.neverInspected.human", vars: { n: names.length, list } });
  }
  if (osv.error) note(osv.error, { key: "cli.note.osv", vars: { why: osv.error } });
  const oldFeeds = expired(feeds.lists);
  if (oldFeeds.length) note(t("cli.note.feedOld", { list: oldFeeds.join(", ") }, "en"), { key: "cli.note.feedOld", vars: { list: oldFeeds.join(", ") } });
  if (opt.offline) note(t("cli.note.offline", {}, "en"), { key: "cli.note.offline" });
  // Places skipped for the same reason are listed together; for people, with the way to include them where there is one.
  const byWhy = new Map<string, string[]>();
  for (const [k, v] of Object.entries(scanned.gaps)) byWhy.set(v, [...(byWhy.get(v) ?? []), k]);
  for (const [why, what] of byWhy)
    note(t("cli.note.gap", { what: what.join(", "), why }, "en"), /Full Disk Access/.test(why) ? { key: "cli.note.gap.fda", vars: { what: what.join(", ") } } : { key: "cli.note.gap.human", vars: { what: what.join(", "), why } });
  const ls = await lockState();
  const lock = ls.lock && ls.why ? { ...ls.lock, reason: ls.why } : ls.lock;
  let verdict = verdictOf(findings);
  if (lock) verdict = "block";
  const result: Check = { scan: scanned, baseline, findings, accepted: all.length - findings.length + own.length, verdict, lock, notes, said, ms: Date.now() - t0, osvUnchecked: osv.unchecked };
  if (!partial) await saveLast({ scan: forBaseline(scanned), findings, verdict, at: Date.now() });
  return result;
}
