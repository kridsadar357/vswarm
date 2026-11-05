// The advisor: a stronger model that reads the session and gives short advice. It never writes code.
// It runs as a nested `claude -p`, so it uses the same Claude Code login as the session it watches.

import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";

export type Moment = "plan" | "error" | "done";

export interface Advice {
  ok: boolean;
  headline: string;
  advice: string[];
  model?: string;
  tokens: number;
}

/** Marks the nested advisor process so its own hooks do nothing. */
export const ADVISOR_ENV = "VSWARM_ADVISOR";

function textOf(content: any): string[] {
  if (typeof content === "string") return [content];
  if (!Array.isArray(content)) return [];
  const out: string[] = [];
  for (const c of content) {
    if (c.type === "text") out.push(c.text);
    else if (c.type === "tool_use") out.push(`[tool ${c.name}] ${JSON.stringify(c.input).slice(0, 400)}`);
    else if (c.type === "tool_result") {
      const body = typeof c.content === "string" ? c.content : textOf(c.content).join(" ");
      out.push(`[result${c.is_error ? " ERROR" : ""}] ${body.slice(0, 600)}`);
    }
  }
  return out;
}

/** The whole session as plain lines, keeping the first request and the most recent activity. */
export function digest(transcriptPath: string | undefined, budget = 90_000): string {
  if (!transcriptPath) return "(no transcript)";
  let raw: string;
  try {
    raw = readFileSync(transcriptPath, "utf8");
  } catch {
    return "(transcript unreadable)";
  }
  const lines: string[] = [];
  for (const l of raw.split("\n")) {
    if (!l.trim()) continue;
    let d: any;
    try {
      d = JSON.parse(l);
    } catch {
      continue;
    }
    if (d.type !== "user" && d.type !== "assistant") continue;
    const who = d.type === "user" ? "USER" : "ASSISTANT";
    for (const t of textOf(d.message?.content)) lines.push(`${who}: ${t.replace(/\s+/g, " ").trim()}`);
  }
  const all = lines.join("\n");
  if (all.length <= budget) return all;
  const head = lines.find((l) => l.startsWith("USER:"))?.slice(0, 4000) ?? "";
  return `${head}\n… (${all.length - budget} chars of earlier activity omitted) …\n${all.slice(-budget)}`;
}

const ASK: Record<Moment, string> = {
  plan:
    "The lead model is about to plan this request. Point out what the plan is likely to miss, " +
    "wrong assumptions, and how to split the work. Set ok=true.",
  error:
    "The same tool error has now happened twice. Explain the likely root cause and the one change " +
    "that should fix it, or say to switch approach. Set ok=true.",
  done:
    "The lead model believes it is finished. Check the result against the original request. " +
    "Set ok=false only if something required is missing or wrong, and say exactly what to fix.",
};

export function advisorPrompt(moment: Moment, session: string, extra = "", cwd?: string): string {
  return [
    "You are the advisor for a Claude Code session. You read the session and give advice;",
    "you never write code or files yourself, and you must not use any tools.",
    cwd && `The session's working directory is ${cwd}. You run elsewhere, so judge paths against that directory, not your own.`,
    ASK[moment],
    "Reply with only a JSON object, no prose around it:",
    '{"ok": true|false, "headline": "<at most 22 characters>", "advice": ["<short, concrete point>", "... at most 3"]}',
    extra && `\nContext for this moment:\n${extra}`,
    "\n--- SESSION ---\n" + session,
  ]
    .filter(Boolean)
    .join("\n");
}

/** Pulls the advice object out of the model's reply, tolerating code fences or stray text. */
export function parseAdvice(text: string): Omit<Advice, "tokens" | "model"> {
  const m = /\{[\s\S]*\}/.exec(text);
  try {
    const j = JSON.parse(m?.[0] ?? "");
    const advice = (Array.isArray(j.advice) ? j.advice : [String(j.advice ?? "")]).map(String).filter(Boolean).slice(0, 3);
    return { ok: j.ok !== false, headline: String(j.headline ?? advice[0] ?? "").slice(0, 40), advice };
  } catch {
    const t = text.trim();
    return { ok: true, headline: t.slice(0, 22), advice: t ? [t.slice(0, 400)] : [] };
  }
}

export async function askAdvisor(moment: Moment, transcriptPath: string | undefined, extra = "", cwd?: string): Promise<Advice> {
  const model = process.env.VSWARM_ADVISOR_MODEL ?? "opus";
  const prompt = advisorPrompt(moment, digest(transcriptPath), extra, cwd);
  const child = Bun.spawn(["claude", "-p", "--model", model, "--output-format", "json"], {
    cwd: tmpdir(),
    stdin: new Blob([prompt]),
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, [ADVISOR_ENV]: "1" },
  });
  const timer = setTimeout(() => child.kill(), Number(process.env.VSWARM_ADVISOR_TIMEOUT ?? 240) * 1000);
  const out = await new Response(child.stdout).text();
  clearTimeout(timer);
  await child.exited;
  let body: any = {};
  try {
    body = JSON.parse(out);
  } catch {}
  if (body.is_error || typeof body.result !== "string") {
    throw new Error(`advisor failed: ${String(body.result ?? out).slice(0, 200) || "no output"}`);
  }
  const u = body.usage ?? {};
  const tokens = (u.input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0);
  const used = Object.keys(body.modelUsage ?? {}).find((k) => k.includes(model)) ?? Object.keys(body.modelUsage ?? {})[0];
  return { ...parseAdvice(body.result), model: used ?? model, tokens };
}
