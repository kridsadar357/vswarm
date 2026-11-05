// Asks Jev (typesafe.ai systemone) one choice question and returns it as a fork decision.
// Same request shape as ~/develop/jev-compute/jev-drive.ts.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Stamped } from "./state";

export interface JevAsk {
  q: string;
  state: string;
  /** Option names, or option name → what that option means. */
  options: string[] | Record<string, string>;
  instructions?: string;
}

export type JevDecision = Extract<Stamped, { type: "decision" }>;

/** JEV_API_KEY, else ~/.v-swarm/jev.key. */
export function jevKey(): string {
  if (process.env.JEV_API_KEY) return process.env.JEV_API_KEY;
  try {
    return readFileSync(join(homedir(), ".v-swarm", "jev.key"), "utf8").trim();
  } catch {
    return "";
  }
}

export async function askJev(ask: JevAsk, key = jevKey()): Promise<JevDecision> {
  if (!key) throw new Error("no Jev key: set JEV_API_KEY or write ~/.v-swarm/jev.key");
  const criteria = Array.isArray(ask.options) ? Object.fromEntries(ask.options.map((o) => [o, o])) : ask.options;
  if (Object.keys(criteria).length < 2) throw new Error("need at least two options");
  const res = await fetch(process.env.JEV_URL ?? "https://api.typesafe.ai/v1/systemone", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: process.env.JEV_MODEL ?? "jev-latest",
      state: ask.state,
      questions: { pick: { type: "choice", instructions: ask.instructions ?? ask.q, criteria } },
    }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) throw new Error(`Jev ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const body: any = await res.json();
  const pick = body?.answers?.pick;
  if (!pick?.choice) throw new Error("Jev returned no choice");
  return { t: Date.now(), type: "decision", q: ask.q, answer: String(pick.choice), p: Number(pick.confidence ?? 0) };
}
