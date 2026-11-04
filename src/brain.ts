// What swarmdeck does back to the session, on top of recording events:
//   before a plan   → the advisor reads the request and the session, its advice goes to the lead
//   a tool fails    → Jev decides retry or stop; sharp answers are acted on, split ones left to the lead
//   same error x2   → the advisor explains the root cause
//   before done     → the advisor reviews the result and can send the lead back to fix it (once)

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { askAdvisor, type Advice, type Moment } from "./advisor";
import { append } from "./hook";
import { askJev, jevKey } from "./jev";
import { SHARP, type Stamped } from "./state";

type Payload = Record<string, any>;
export type HookOutput = Record<string, unknown> | undefined;

interface Memory {
  failures: Record<string, number>;
  reviewed?: boolean;
}

const DIR = join(homedir(), ".swarmdeck", "sessions");

function moments(): Set<Moment> {
  const v = process.env.SWARMDECK_ADVISOR_AT ?? "plan,error,done";
  return new Set(v.split(",").map((s) => s.trim()).filter(Boolean) as Moment[]);
}

function load(sid: string): Memory {
  try {
    return JSON.parse(readFileSync(join(DIR, `${sid}.json`), "utf8"));
  } catch {
    return { failures: {} };
  }
}

function save(sid: string, m: Memory) {
  mkdirSync(DIR, { recursive: true });
  writeFileSync(join(DIR, `${sid}.json`), JSON.stringify(m));
}

/** Same error, ignoring numbers and paths that change between attempts. */
export function signature(tool: string, error: string): string {
  const first = error.split("\n").find((l) => l.trim() && !/^exit code/i.test(l.trim())) ?? error;
  return `${tool}:${first.replace(/\d+/g, "#").replace(/\/[^\s:]+/g, "<path>").trim().slice(0, 160)}`;
}

function context(event: string, text: string): HookOutput {
  return { hookSpecificOutput: { hookEventName: event, additionalContext: text } };
}

async function advise(file: string, sid: string, moment: Moment, mark: string, p: Payload, extra = ""): Promise<Advice | undefined> {
  const post = (e: Stamped) => append(file, [{ t: Date.now(), sid, ...e } as Stamped]);
  post({ type: "advisor", model: process.env.SWARMDECK_ADVISOR_MODEL ?? "opus", status: "reading", mark });
  try {
    const a = await askAdvisor(moment, p.transcript_path, extra);
    post({ type: "advisor", model: a.model, status: "on call", note: a.headline || (a.ok ? "looks right" : "needs fixes"), tokens: a.tokens });
    for (const line of a.advice) post({ type: "log", who: a.model ?? "advisor", text: line });
    return a;
  } catch (err: any) {
    post({ type: "advisor", status: "on call" });
    post({ type: "error", text: `advisor: ${err.message ?? err}` });
  }
}

const bullets = (a: Advice) => a.advice.map((x) => `- ${x}`).join("\n");

export async function react(p: Payload, file: string): Promise<HookOutput> {
  const sid: string | undefined = p.session_id;
  if (!sid) return;
  const at = moments();
  const event = p.hook_event_name;

  if (event === "UserPromptSubmit") {
    const prompt = String(p.prompt ?? "");
    if (!at.has("plan") || prompt.startsWith("<task-notification>")) return;
    const a = await advise(file, sid, "plan", "before a plan", p, `New request:\n${prompt.slice(0, 8000)}`);
    if (!a?.advice.length) return;
    return context(event, `swarmdeck advisor (${a.model}) — notes before you plan:\n${bullets(a)}`);
  }

  if (event === "PostToolUseFailure" || event === "PostToolUse") {
    const r = p.tool_response;
    const failedInPost = r && typeof r === "object" && (r.is_error || r.isError);
    if (event === "PostToolUse" && !failedInPost) return;
    if (p.is_interrupt) return;
    const tool = String(p.tool_name ?? "?");
    const error = String(p.error ?? (typeof r === "string" ? r : JSON.stringify(r ?? "")));
    const mem = load(sid);
    const sig = signature(tool, error);
    const n = (mem.failures[sig] = (mem.failures[sig] ?? 0) + 1);
    save(sid, mem);

    const notes: string[] = [];
    if (jevKey()) {
      try {
        const d = await askJev({
          q: "retry or stop",
          state:
            `A coding agent's ${tool} call failed${p.agent_type ? ` inside the ${p.agent_type} subagent` : ""}.\n` +
            `Input: ${JSON.stringify(p.tool_input ?? {}).slice(0, 1500)}\n` +
            `Error: ${error.slice(0, 1500)}\n` +
            `This exact error has now happened ${n} time${n > 1 ? "s" : ""} in this session.`,
          instructions: "Should the agent retry this step (after a small fix) or stop and change approach?",
          options: {
            retry: "the error looks transient or fixable with a small change to the same call",
            stop: "repeating this call will keep failing; the agent should change approach",
          },
        });
        append(file, [{ ...d, sid }]);
        notes.push(
          d.p >= SHARP
            ? `swarmdeck jev: ${d.answer === "stop" ? "stop repeating this call and change approach" : "retrying this step is fine"} (confidence ${d.p.toFixed(2)}).`
            : `swarmdeck jev was unsure whether to retry or stop (confidence ${d.p.toFixed(2)}); use your own judgement.`,
        );
      } catch (err: any) {
        append(file, [{ t: Date.now(), sid, type: "error", text: `jev: ${err.message ?? err}` }]);
      }
    }
    if (n === 2 && at.has("error")) {
      const a = await advise(file, sid, "error", "same error x2", p, `Failing call: ${tool}\nError:\n${error.slice(0, 3000)}`);
      if (a?.advice.length) notes.push(`swarmdeck advisor (${a.model}) on this repeated error:\n${bullets(a)}`);
    }
    return notes.length ? context(event, notes.join("\n\n")) : undefined;
  }

  if (event === "Stop") {
    if (!at.has("done") || p.stop_hook_active) return;
    const mem = load(sid);
    if (mem.reviewed) return;
    mem.reviewed = true;
    save(sid, mem);
    const a = await advise(file, sid, "done", "before done", p, `Lead's final message:\n${String(p.last_assistant_message ?? "").slice(0, 6000)}`);
    if (!a || a.ok) return;
    return {
      decision: "block",
      reason: `swarmdeck advisor (${a.model}) reviewed the result before you finish. Fix these, then finish:\n${bullets(a)}`,
    };
  }
}
