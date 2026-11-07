// One check of the machine: scan, credentials, known-malicious packages, rules, then the verdict.

import type { Ctx } from "./ctx";
import { osvMalicious } from "./intel";
import { evaluate, uncovered } from "./rules";
import { forBaseline, scan as runScan } from "./scan";
import { secrets as findSecrets } from "./secrets";
import { ensureSec, files, lockState, readAccepted, readBaseline, saveLast, type Lock } from "./store";
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
  notes: string[];
  ms: number;
  /** Packages the known-malicious check could not ask about (offline, or OSV did not answer in time). */
  osvUnchecked?: number;
}

/** Findings about vswarm's own files. They can never be accepted away: accepting them would need the files they doubt. */
export const STATE_RULE = "vswarm-state";

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
  if (pinned.untrusted)
    state("mcp-pins", "medium", "vswarm's record of MCP tool definitions was changed outside vswarm; it is ignored", [`mcp-tools.json ${pinned.untrusted}`],
      "A changed record could hide a server that changed its tools. Inspect them again: vswarm agents --inspect");
  const a = await readAccepted();
  // An accepted list that does not verify accepts nothing.
  const acceptedIds = a.untrusted ? {} : a.value ?? {};
  if (a.untrusted && !a.nokey)
    state("accepted", "medium", "vswarm's list of accepted findings was changed outside vswarm; nothing in it counts", [`${files.accepted()} ${a.untrusted}`],
      "Review what is shown, then accept again what you expect: vswarm accept <id>");
  if (b.nokey || a.nokey)
    state("nokey", "medium", "vswarm could not check its own files: its sealing key is not readable right now", [String((b.nokey ? b : a).untrusted)],
      "Unlock the login keychain (macOS) or keyring (Linux) and check again; vswarm doctor shows where the key is");
  // A known-malicious package can never be accepted away.
  const findings = [...own, ...all]
    .filter((f) => f.rule === "malicious" || f.rule === STATE_RULE || f.rule === "team-require" || (!acceptedIds[f.id] && !matches(team.policy?.accept, f.id)))
    .sort((x, y) => RANK[y.severity] - RANK[x.severity]);
  const notes: string[] = [];
  if (!baseline) notes.push("No baseline yet: only always-wrong things are checked. Run `vswarm baseline` on a machine you trust.");
  const fresh = uncovered(scanned, baseline);
  if (fresh.length) notes.push(`Your baseline is older than these checks: ${fresh.join(", ")}. Review them (vswarm agents), then vswarm baseline.`);
  if (drift.never.length) {
    const names = [...new Set(drift.never.map((i) => i.name))];
    notes.push(`${names.length} MCP server${names.length > 1 ? "s were" : " was"} never inspected (${names.slice(0, 4).join(", ")}${names.length > 4 ? " …" : ""}): vswarm agents --inspect starts each in the sandbox and reads what the model will read.`);
  }
  if (osv.error) notes.push(osv.error);
  if (opt.offline) notes.push("Offline: known-malicious check used the cache only.");
  // Places skipped for the same reason are listed together.
  const byWhy = new Map<string, string[]>();
  for (const [k, v] of Object.entries(scanned.gaps)) byWhy.set(v, [...(byWhy.get(v) ?? []), k]);
  for (const [why, what] of byWhy) notes.push(`Could not check ${what.join(", ")}: ${why}`);
  const ls = await lockState();
  const lock = ls.lock && ls.why ? { ...ls.lock, reason: ls.why } : ls.lock;
  let verdict = verdictOf(findings);
  if (lock) verdict = "block";
  const result: Check = { scan: scanned, baseline, findings, accepted: all.length - findings.length + own.length, verdict, lock, notes, ms: Date.now() - t0, osvUnchecked: osv.unchecked };
  if (!partial) await saveLast({ scan: forBaseline(scanned), findings, verdict, at: Date.now() });
  return result;
}
