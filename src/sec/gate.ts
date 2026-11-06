// The verdict a gate acts on: the last check if it is recent and its seal matches, otherwise a fresh one. Shared by
// preflight and cert.

import { realCtx, type Ctx } from "./ctx";
import { check } from "./engine";
import { c, line, summary, VERDICT } from "./print";
import { decisionsSince, lockState, readLast } from "./store";
import { RANK, type Verdict } from "./types";

export async function verdictNow(opt: { fresh?: boolean; quiet?: boolean; offline?: boolean; maxAge?: number; ctx?: Ctx } = {}): Promise<Verdict> {
  const maxAge = opt.maxAge ?? 120_000;
  const last = await readLast();
  const { lock } = await lockState();
  let verdict: Verdict;
  // ssh and kubectl call gates on every connection, so a verdict from the last couple of minutes is reused.
  // A verdict from before you accepted findings or took a baseline would answer for decisions it never saw, and one
  // whose seal does not match was not written by vswarm: both mean a fresh check, never a reused "pass".
  const reuse = !opt.fresh && !lock && last.value && !last.untrusted && Date.now() - last.value.at < maxAge && !decisionsSince(last.value.at);
  if (reuse) {
    verdict = last.value!.verdict;
    if (verdict !== "pass") {
      const n = last.value!.findings.filter((f) => RANK[f.severity] >= RANK.medium).length;
      line(`${VERDICT[verdict]} ${c.dim(`vswarm preflight · ${n} finding${n === 1 ? "" : "s"} · details: vswarm preflight --fresh`)}`);
    }
  } else {
    if (last.untrusted && !last.nokey) line(c.amber(`vswarm: the last check ${last.untrusted}; checking again`));
    // In a quiet gate the known-malicious lookup asks only about packages it never saw, with a short wait.
    const r = await check(opt.ctx ?? realCtx(), { offline: opt.offline, osvNewOnly: opt.quiet && !opt.offline });
    verdict = r.verdict;
    if (!opt.quiet || verdict === "block") summary(r, { title: "preflight" });
    else if (verdict === "warn") {
      const n = r.findings.filter((f) => RANK[f.severity] >= RANK.medium).length;
      line(`${VERDICT.warn} ${c.dim(`vswarm preflight · ${n} finding${n === 1 ? "" : "s"} · details: vswarm preflight --fresh`)}`);
    }
    // Said even when quiet: a package installed since the last full check went unchecked.
    if (opt.quiet && verdict !== "block" && r.osvUnchecked && !opt.offline)
      line(c.dim(`vswarm preflight · ${r.osvUnchecked} new package version${r.osvUnchecked === 1 ? "" : "s"} not checked against known-malicious records (OSV did not answer) · vswarm scan when online`));
  }
  return lock ? "block" : verdict;
}
