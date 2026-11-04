// Asks Jev (typesafe.ai systemone) one choice question and returns it as a fork decision.
// Same request shape as ~/develop/jev-compute/jev-drive.ts.

import type { Stamped } from "./state";

export interface JevAsk {
  q: string;
  state: string;
  options: string[];
  instructions?: string;
}

export async function askJev(ask: JevAsk, key = process.env.JEV_API_KEY ?? ""): Promise<Stamped> {
  if (!key) throw new Error("JEV_API_KEY is not set");
  if (ask.options.length < 2) throw new Error("need at least two options");
  const criteria = Object.fromEntries(ask.options.map((o) => [o, o]));
  const res = await fetch(process.env.JEV_URL ?? "https://api.typesafe.ai/v1/systemone", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: process.env.JEV_MODEL ?? "jev-latest",
      state: ask.state,
      questions: { pick: { type: "choice", instructions: ask.instructions ?? ask.q, criteria } },
    }),
  });
  if (!res.ok) throw new Error(`Jev ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const body: any = await res.json();
  const pick = body?.answers?.pick;
  if (!pick?.choice) throw new Error("Jev returned no choice");
  return { t: Date.now(), type: "decision", q: ask.q, answer: String(pick.choice), p: Number(pick.confidence ?? 0) };
}
