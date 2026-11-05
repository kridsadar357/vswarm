import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { demoUntil } from "../src/demo";
import { map, modelFromTranscript } from "../src/hook";
import { clip, Screen, width } from "../src/screen";
import { apply, initial, type Stamped } from "../src/state";
import { draw, H, modelName, W } from "../src/view";

const fold = (events: Stamped[]) => events.reduce(apply, initial());

// Shapes copied from a real Claude Code 2.1.318 session with three Explore subagents.
const base = { session_id: "s1", transcript_path: "/nonexistent", prompt_id: "p1" };
const payloads = [
  { ...base, hook_event_name: "SessionStart", source: "startup" },
  { ...base, hook_event_name: "UserPromptSubmit", prompt: "read the files" },
  { ...base, hook_event_name: "PreToolUse", effort: { level: "medium" }, tool_name: "Agent",
    tool_input: { description: "Read a.txt", subagent_type: "Explore", model: "haiku", prompt: "…" } },
  { ...base, hook_event_name: "SubagentStart", agent_id: "a1", agent_type: "Explore" },
  { ...base, hook_event_name: "PreToolUse", agent_id: "a1", agent_type: "Explore", tool_name: "Read",
    tool_input: { file_path: "/tmp/x/a.txt" } },
  { ...base, hook_event_name: "SubagentStop", agent_id: "a1", agent_type: "Explore", agent_transcript_path: "/nonexistent" },
  { ...base, hook_event_name: "UserPromptSubmit",
    prompt: "<task-notification>\n<task-id>a1</task-id>\n<status>completed</status>\n</task-notification>" },
  { ...base, hook_event_name: "Stop" },
];

describe("hook mapping", () => {
  const s = fold(payloads.flatMap((p, i) => map(p, 1000 + i * 100)));

  test("pairs the Agent request with SubagentStart", () => {
    expect(s.agents).toHaveLength(1);
    expect(s.agents[0]).toMatchObject({ id: "a1", name: "Explore", model: "haiku", desc: "Read a.txt", tools: 1, status: "done" });
  });

  test("counts lead tools, effort and phase", () => {
    expect(s.lead.tools).toBe(1);
    expect(s.lead.effort).toBe("medium");
    expect(s.phase).toBe("done");
  });

  test("a background result does not replace the user's prompt", () => {
    expect(s.prompt).toBe("read the files");
    expect(s.log.some((l) => l.text === "subagent result back · completed")).toBe(true);
  });

  test("failed tool results count as errors", () => {
    const e = map({ ...base, hook_event_name: "PostToolUse", tool_name: "Bash", tool_response: { is_error: true } });
    expect(fold(e).errors).toBe(1);
  });

  test("reads the latest model from a transcript tail", () => {
    const dir = mkdtempSync(join(tmpdir(), "deck-"));
    const f = join(dir, "t.jsonl");
    writeFileSync(f, '{"message":{"model":"claude-sonnet-5-5"}}\n{"message":{"model":"claude-haiku-5-5"}}\n');
    expect(modelFromTranscript(f)).toBe("claude-haiku-5-5");
    expect(modelFromTranscript("/nonexistent")).toBeUndefined();
  });
});

describe("state", () => {
  test("a new session id clears the board", () => {
    const s = fold([
      { type: "session", sid: "a" },
      { type: "agent.start", id: "x", name: "search" },
      { type: "session", sid: "b" },
    ]);
    expect(s.agents).toHaveLength(0);
    expect(s.sid).toBe("b");
  });

  test("decisions keep the latest answer per question, five at most", () => {
    const s = fold(["a", "b", "a", "c", "d", "e", "f"].map((q, i) => ({ type: "decision", q, p: i / 10, answer: "x" }) as Stamped));
    expect(s.forks).toBe(7);
    expect(s.decisions.map((d) => d.q)).toEqual(["a", "c", "d", "e", "f"]);
  });
});

describe("rendering", () => {
  test("Thai combining marks take no columns", () => {
    expect(width("ที่จอด")).toBe(4);
    const scr = new Screen(10, 1);
    scr.put(0, 0, "ล้างรถ|");
    expect(scr.plain()).toBe("ล้างรถ|");
    expect(width(clip("รายการล่าสุดของวันนี้", 6))).toBe(6);
  });

  test("model ids read as names", () => {
    expect(modelName("claude-sonnet-5-5")).toBe("Sonnet 5.5");
    expect(modelName("claude-haiku-4-5-20251001")).toBe("Haiku 4.5");
    expect(modelName("opus")).toBe("Opus");
  });

  test("every demo moment renders inside the frame", () => {
    for (let ms = 0; ms <= 30000; ms += 250) {
      const s = fold(demoUntil(ms));
      const rows = draw(s, ms / 120, s.updatedAt).plain().split("\n");
      expect(rows).toHaveLength(H);
      for (const r of rows) expect(width(r)).toBeLessThanOrEqual(W);
    }
  });

  test("an empty board renders", () => {
    expect(draw(initial(), 0).plain()).toContain("V-SWARM");
  });
});

import { digest, parseAdvice } from "../src/advisor";
import { signature } from "../src/brain";

describe("advisor and jev glue", () => {
  test("the same error matches across changing numbers and paths", () => {
    const a = signature("Bash", "Exit code 1\nls: /tmp/run-123/x: No such file or directory");
    const b = signature("Bash", "Exit code 2\nls: /tmp/run-456/y: No such file or directory");
    expect(a).toBe(b);
    expect(signature("Read", "ls: /a: No such file")).not.toBe(a);
  });

  test("advice JSON is read even inside fences or prose", () => {
    const r = parseAdvice('Sure:\n```json\n{"ok": false, "headline": "missing B- label", "advice": ["label B-", "add hub IN"]}\n```');
    expect(r).toEqual({ ok: false, headline: "missing B- label", advice: ["label B-", "add hub IN"] });
    expect(parseAdvice("not json at all").ok).toBe(true);
  });

  test("digest keeps text, tool calls and results", () => {
    const dir = mkdtempSync(join(tmpdir(), "deck-"));
    const f = join(dir, "t.jsonl");
    writeFileSync(f, [
      JSON.stringify({ type: "user", message: { content: "build the diagram" } }),
      JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", name: "Write", input: { file_path: "index.html" } }] } }),
      JSON.stringify({ type: "user", message: { content: [{ type: "tool_result", is_error: true, content: "denied" }] } }),
      "not json",
    ].join("\n"));
    const d = digest(f);
    expect(d).toContain("USER: build the diagram");
    expect(d).toContain("[tool Write]");
    expect(d).toContain("[result ERROR] denied");
  });
});
