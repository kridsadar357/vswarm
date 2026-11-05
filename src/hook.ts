// Turns one Claude Code hook payload into dashboard events.
// Runs inside every hook call, so it must be fast and must never break the session.

import { appendFileSync, closeSync, fstatSync, mkdirSync, openSync, readSync } from "node:fs";
import { dirname } from "node:path";
import type { Stamped } from "./state";

type Payload = Record<string, any>;

/** Last model id written to a transcript, read from its tail only. */
export function modelFromTranscript(path?: string, tailBytes = 64 * 1024): string | undefined {
  if (!path) return;
  try {
    const fd = openSync(path, "r");
    try {
      const size = fstatSync(fd).size;
      const len = Math.min(size, tailBytes);
      const buf = Buffer.alloc(len);
      readSync(fd, buf, 0, len, size - len);
      const all = [...buf.toString("utf8").matchAll(/"model"\s*:\s*"(claude-[^"]+)"/g)];
      return all.at(-1)?.[1];
    } finally {
      closeSync(fd);
    }
  } catch {
    return;
  }
}

/** One short human-readable hint about what a tool call touches. */
export function toolDetail(tool: string, input: any): string | undefined {
  if (!input || typeof input !== "object") return;
  const v =
    input.file_path ?? input.path ?? input.pattern ?? input.command ?? input.url ?? input.query ?? input.description;
  if (typeof v !== "string") return;
  const s = v.replace(/\s+/g, " ").trim();
  return tool === "Bash" ? s.slice(0, 80) : s.split("/").slice(-2).join("/").slice(0, 80);
}

function failed(p: Payload): boolean {
  const r = p.tool_response;
  return Boolean(r && typeof r === "object" && (r.is_error || r.isError || r.interrupted));
}

const SUBAGENT_TOOLS = new Set(["Agent", "Task"]);

export function map(p: Payload, now = Date.now()): Stamped[] {
  const sid: string | undefined = p.session_id;
  const t = now;
  const out: Stamped[] = [];
  const effort = typeof p.effort === "object" ? p.effort?.level : p.effort;
  const agentId: string | undefined = p.agent_id;

  switch (p.hook_event_name) {
    case "SessionStart":
      out.push({ t, type: "session", sid, lead: p.model ?? modelFromTranscript(p.transcript_path), effort, start: true });
      break;
    case "UserPromptSubmit": {
      out.push({ t, type: "session", sid, effort, lead: modelFromTranscript(p.transcript_path) });
      const text = String(p.prompt ?? "").trim();
      // Background subagents report back through a synthetic prompt; that is not the user's request.
      const note = /^<task-notification>[\s\S]*?<status>([^<]*)<\/status>/.exec(text);
      if (text.startsWith("<task-notification>")) {
        out.push({ t, type: "log", who: "lead", text: `subagent result back${note ? ` · ${note[1]}` : ""}` });
      } else {
        out.push({ t, type: "prompt", text });
      }
      break;
    }
    case "PreToolUse": {
      const tool = String(p.tool_name ?? "?");
      const detail = toolDetail(tool, p.tool_input);
      if (agentId) {
        out.push({ t, type: "agent.tool", id: agentId, tool, detail });
        break;
      }
      // The lead's model is already in the transcript by the time it calls a tool.
      out.push({ t, type: "session", sid, effort, lead: modelFromTranscript(p.transcript_path) });
      out.push({ t, type: "tool", tool, detail: SUBAGENT_TOOLS.has(tool) ? p.tool_input?.description : detail });
      if (SUBAGENT_TOOLS.has(tool)) {
        // SubagentStart carries no description or model; the watcher pairs this request with it.
        out.push({
          t,
          type: "log",
          who: "lead",
          text: `delegate → ${p.tool_input?.subagent_type ?? "agent"}${p.tool_input?.model ? ` (${p.tool_input.model})` : ""}`,
        });
        out.push({
          t,
          type: "agent.request",
          name: p.tool_input?.subagent_type ?? "general-purpose",
          desc: p.tool_input?.description,
          model: p.tool_input?.model,
        });
      }
      break;
    }
    case "PostToolUse":
    case "PostToolUseFailure":
      if (p.hook_event_name === "PostToolUseFailure" || failed(p)) {
        const why = String(p.error ?? "").split("\n").find((l) => l.trim() && !/^exit code/i.test(l.trim()));
        out.push({ t, type: "error", text: `${p.tool_name}${agentId ? ` (${p.agent_type})` : ""} failed${why ? ` · ${why.trim()}` : ""}` });
      }
      break;
    case "SubagentStart": {
      const name = String(p.agent_type ?? "agent");
      out.push({ t, type: "agent.start", id: String(agentId), name });
      break;
    }
    case "SubagentStop":
      out.push({ t, type: "agent.stop", id: String(agentId), model: modelFromTranscript(p.agent_transcript_path) });
      break;
    case "Stop":
      out.push({ t, type: "phase", phase: "done" });
      if (p.last_assistant_message) out.push({ t, type: "say", who: "claude", text: String(p.last_assistant_message) });
      break;
    case "SessionEnd":
      out.push({ t, type: "log", who: "lead", text: `session ended (${p.reason ?? "?"})` });
      break;
  }
  for (const e of out) if (e.type === "session" && !e.lead) delete e.lead;
  return out.map((e) => ({ ...e, sid }) as Stamped);
}

export function append(file: string, events: Stamped[]) {
  if (!events.length) return;
  mkdirSync(dirname(file), { recursive: true });
  appendFileSync(file, events.map((e) => JSON.stringify(e)).join("\n") + "\n");
}
