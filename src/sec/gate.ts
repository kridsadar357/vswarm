// The verdict a gate acts on: the last check if it is recent, otherwise a fresh one. Shared by preflight and cert.

import { realCtx } from "./ctx";
import { check } from "./engine";
import { c, line, summary, VERDICT } from "./print";
import { decisionsSince, loadLast, loadLock } from "./store";
import { RANK, type Verdict } from "./types";

export async function verdictNow(opt: { fresh?: boolean; quiet?: boolean; offline?: boolean; maxAge?: number } = {}): Promise<Verdict> {
  const maxAge = opt.maxAge ?? 120_000;
  const last = loadLast();
  const lock = loadLock();
  let verdict: Verdict;
  // ssh and kubectl call gates on every connection, so a verdict from the last couple of minutes is reused.
  // A verdict from before you accepted findings or took a baseline would answer for decisions it never saw.
  if (!opt.fresh && !lock && last && Date.now() - last.at < maxAge && !decisionsSince(last.at)) {
    verdict = last.verdict;
    if (verdict !== "pass") {
      const n = last.findings.filter((f) => RANK[f.severity] >= RANK.medium).length;
      line(`${VERDICT[verdict]} ${c.dim(`vswarm preflight · ${n} finding${n === 1 ? "" : "s"} · details: vswarm preflight --fresh`)}`);
    }
  } else {
    // In a quiet gate the known-malicious lookup uses its cache, so a slow network never delays a login.
    const r = await check(realCtx(), { offline: opt.offline || opt.quiet });
    verdict = r.verdict;
    if (!opt.quiet || verdict === "block") summary(r, { title: "preflight" });
    else if (verdict === "warn") {
      const n = r.findings.filter((f) => RANK[f.severity] >= RANK.medium).length;
      line(`${VERDICT.warn} ${c.dim(`vswarm preflight · ${n} finding${n === 1 ? "" : "s"} · details: vswarm preflight --fresh`)}`);
    }
  }
  return lock ? "block" : verdict;
}
