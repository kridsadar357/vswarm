// The verdict a gate acts on: the last check if it is recent and its seal matches, otherwise a fresh one. Shared by
// preflight and cert. What a gate then does with WARN is the policy's (policy.ts): one answer for every gate.

import { realCtx, type Ctx } from "./ctx";
import { check } from "./engine";
import { agentSaysSo } from "./human";
import { readPolicy, type PolicyState } from "./policy";
import { t } from "../i18n";
import { c, line, summary, VERDICT } from "./print";
import { decisionsSince, lockState, readLast } from "./store";
import { RANK, type Verdict } from "./types";

/**
 * `silent`: print nothing (the caller says why in its own words: the agent's check before an ssh login, which would
 * otherwise repeat the WARN line the ssh gate's own preflight just printed).
 */
export async function verdictNow(opt: { fresh?: boolean; quiet?: boolean; offline?: boolean; maxAge?: number; ctx?: Ctx; policy?: PolicyState; silent?: boolean } = {}): Promise<Verdict> {
  const maxAge = opt.maxAge ?? 120_000;
  const last = await readLast();
  const { lock } = await lockState();
  const policy = opt.policy ?? (await readPolicy());
  let verdict: Verdict;
  // ssh and kubectl call gates on every connection, so a verdict from the last couple of minutes is reused.
  // A verdict from before you accepted findings or took a baseline would answer for decisions it never saw, and one
  // whose seal does not match was not written by vswarm: both mean a fresh check, never a reused "pass".
  const reuse = !opt.fresh && !lock && last.value && !last.untrusted && Date.now() - last.value.at < maxAge && !decisionsSince(last.value.at);
  const warned = (n: number) => opt.silent || line(`${VERDICT.warn}  ${c.dim(t("cli.pre.warn", { n, refused: policy.warn === "refuse" ? t("cli.pre.refusedTag") : "" }))}`);
  if (reuse) {
    verdict = last.value!.verdict;
    if (verdict === "warn") warned(last.value!.findings.filter((f) => RANK[f.severity] >= RANK.medium).length);
    else if (verdict === "block" && !opt.silent) {
      const n = last.value!.findings.filter((f) => RANK[f.severity] >= RANK.medium).length;
      line(`${VERDICT.block}  ${c.dim(t("cli.pre.block", { n }))}`);
    }
  } else {
    if (last.untrusted && !last.nokey && !opt.silent) line(c.amber(t("cli.pre.untrusted", { why: last.untrusted })));
    // In a quiet gate the known-malicious lookup asks only about packages it never saw, with a short wait.
    const r = await check(opt.ctx ?? realCtx(), { offline: opt.offline, osvNewOnly: opt.quiet && !opt.offline });
    verdict = r.verdict;
    if (opt.silent) {
      // said by the caller
    } else if (!opt.quiet || verdict === "block") {
      // The same card as vswarm scan: `vswarm fix n` where vswarm has a fix.
      const { fixable, heldLines } = await import("../commands");
      const canFix = await fixable();
      summary(r, { title: "preflight", policy: policy.warn, fixable: (f) => canFix(f, r.findings.indexOf(f) + 1), held: await heldLines(r.verdict) });
    }
    else if (verdict === "warn") warned(r.findings.filter((f) => RANK[f.severity] >= RANK.medium).length);
    // Said even when quiet: a package installed since the last full check went unchecked.
    if (opt.quiet && !opt.silent && verdict !== "block" && r.osvUnchecked && !opt.offline)
      line(c.dim(t("cli.pre.osv", { n: r.osvUnchecked })));
  }
  return lock ? "block" : verdict;
}

export interface GateAnswer {
  verdict: Verdict;
  /** Whether the gate lets this through: never on BLOCK, on WARN as the policy (or --strict) says. */
  allowed: boolean;
  /** The exit code for the gate: 0, 2 (WARN refused) or 3 (BLOCK). */
  code: number;
  policy: PolicyState;
}

/**
 * After a refusal, when an AI agent says it ran the command (human.ts agentSaysSo): a line for the agent, which reads
 * this output, so it hands the refusal to the user instead of trying another way in.
 */
export function toAgent(env: Record<string, string | undefined> = process.env) {
  if (agentSaysSo(env)) line(c.amber(t("cli.pre.agent")));
}

/**
 * The verdict and what the policy makes of it. A WARN the policy refuses is said on stderr with the way out, so the
 * person at the terminal sees why ssh, aws or kubectl stopped.
 */
export async function gateVerdict(opt: Parameters<typeof verdictNow>[0] & { strict?: boolean } = {}): Promise<GateAnswer> {
  const policy = await readPolicy();
  const verdict = await verdictNow({ ...opt, policy });
  if (verdict === "block") {
    toAgent();
    return { verdict, allowed: false, code: 3, policy };
  }
  if (verdict === "warn" && (opt.strict || policy.warn === "refuse")) {
    line(c.amber(t("cli.pre.refused", { by: opt.strict ? "--strict" : t("cli.pre.policyWord") })) + c.dim(`${t("cli.pre.refusedHow")}${opt.strict ? "" : t("cli.pre.allowAgain")}`));
    toAgent();
    return { verdict, allowed: false, code: 2, policy };
  }
  return { verdict, allowed: true, code: 0, policy };
}
