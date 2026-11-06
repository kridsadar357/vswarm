// One check of the machine: scan, credentials, known-malicious packages, rules, then the verdict.

import type { Ctx } from "./ctx";
import { osvMalicious } from "./intel";
import { evaluate, uncovered } from "./rules";
import { forBaseline, scan as runScan } from "./scan";
import { secrets as findSecrets } from "./secrets";
import { ensureSec, files, loadAccepted, loadBaseline, loadLock, saveLast, type Lock } from "./store";
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
}

export async function check(ctx: Ctx, opt: { offline?: boolean; sign?: Parameters<typeof evaluate>[0]["sign"] } = {}): Promise<Check> {
  const t0 = Date.now();
  ensureSec();
  const baseline = loadBaseline();
  const [scanned, secretFindings] = await Promise.all([runScan(ctx), findSecrets(ctx)]);
  const osv = await osvMalicious(scanned.items, files.osv(), { offline: opt.offline });
  const all = await evaluate({ scan: scanned, baseline, malicious: osv.hits, secrets: secretFindings, sign: opt.sign });
  const acceptedIds = loadAccepted();
  // A known-malicious package can never be accepted away.
  const findings = all
    .filter((f) => f.rule === "malicious" || !acceptedIds[f.id])
    .sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  const notes: string[] = [];
  if (!baseline) notes.push("No baseline yet: only always-wrong things are checked. Run `vswarm baseline` on a machine you trust.");
  const fresh = uncovered(scanned, baseline);
  if (fresh.length) notes.push(`Your baseline is older than these checks: ${fresh.join(", ")}. Review them (vswarm agents), then vswarm baseline.`);
  if (osv.error) notes.push(osv.error);
  if (opt.offline) notes.push("Offline: known-malicious check used the cache only.");
  // Places skipped for the same reason are listed together.
  const byWhy = new Map<string, string[]>();
  for (const [k, v] of Object.entries(scanned.gaps)) byWhy.set(v, [...(byWhy.get(v) ?? []), k]);
  for (const [why, what] of byWhy) notes.push(`Could not check ${what.join(", ")}: ${why}`);
  const lock = loadLock();
  let verdict = verdictOf(findings);
  if (lock) verdict = "block";
  const result: Check = { scan: scanned, baseline, findings, accepted: all.length - findings.length, verdict, lock, notes, ms: Date.now() - t0 };
  saveLast({ scan: forBaseline(scanned), findings, verdict, at: Date.now() });
  return result;
}
