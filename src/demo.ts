// Scripted session that shows every panel at work. No API calls; purely for display.

import type { Stamped } from "./state";

type Step = [delayMs: number, event: Stamped];

const AGENTS = [
  { id: "a-search", name: "search", desc: "maps the repo" },
  { id: "a-grep", name: "grep", desc: "finds call sites" },
  { id: "a-audit", name: "audit", desc: "runs in a worktree" },
];
const HAIKU = "claude-haiku-5-5";

function script(run: number): Step[] {
  const sid = `demo-${run}`;
  const steps: Step[] = [
    [0, { type: "session", sid, lead: "claude-sonnet-5-5", effort: "high", command: "claude --model sonnet --advisor opus" }],
    [0, { type: "advisor", model: "claude-opus-5-5", status: "on call" }],
    [0, { type: "decision", q: "which tool", p: 0.62, answer: "Grep", count: 1787 }],
    [500, { type: "prompt", text: "add rate limiting to /api/login and cover it with tests" }],
    [400, { type: "say", who: "claude", text: "I'll read the login handler first, then split the work: one subagent maps the repo, one finds every call site, one runs the tests in a worktree." }],
    [700, { type: "tool", tool: "Read", detail: "src/api/login.ts" }],
    [600, { type: "advisor", mark: "before a plan", note: "plan skips auth", tokens: 412_000 }],
    [700, { type: "advisor", note: "split in 3 PRs", tokens: 354_000 }],
    [600, { type: "decision", q: "which file", p: 0.91, answer: "test/api.spec.ts" }],
    [500, { type: "decision", q: "which tool", p: 0.58, answer: "Grep" }],
    [500, { type: "decision", q: "retry or stop", p: 0.88, answer: "retry" }],
    [600, { type: "tool", tool: "Agent", detail: "fan out 3 subagents" }],
  ];
  for (const a of AGENTS) {
    steps.push([150, { type: "agent.request", name: a.name, model: HAIKU, desc: a.desc }]);
    steps.push([100, { type: "agent.start", id: a.id, name: a.name }]);
  }
  // Each agent advances at its own pace; audit is the slow one.
  const speed = [0.11, 0.08, 0.05];
  const pct = [0.09, 0.13, 0.32].map((p) => p - 0.05);
  const notes = ["mapped 4 modules", "12 call sites", "tests green on branch"];
  let tick = 0;
  while (pct.some((p) => p < 1)) {
    tick++;
    AGENTS.forEach((a, i) => {
      if (pct[i] >= 1) return;
      pct[i] = Math.min(1, pct[i] + speed[i] * (0.6 + ((tick * (i + 3)) % 5) / 6));
      steps.push([120, { type: "agent.progress", id: a.id, pct: pct[i] }]);
      if (pct[i] >= 1) {
        steps.push([80, { type: "log", who: a.name, text: notes[i] }]);
        steps.push([80, { type: "agent.stop", id: a.id }]);
      }
    });
    if (tick === 3) steps.push([100, { type: "agent.tool", id: "a-grep", tool: "Grep", detail: "rateLimit(" }]);
    if (tick === 5) {
      steps.push([100, { type: "error", text: "audit · npm test failed (missing fixture)" }]);
      steps.push([200, { type: "error", text: "audit · npm test failed (missing fixture)" }]);
      steps.push([300, { type: "advisor", mark: "same error x2", note: "add login fixture", tokens: 96_000 }]);
    }
  }
  steps.push(
    [600, { type: "decision", q: "which file", p: 0.96, answer: "test/api.spec.ts" }],
    [700, { type: "tool", tool: "Bash", detail: "npm test -- api.spec" }],
    [900, { type: "advisor", mark: "before done", note: "verify 429 headers", tokens: 128_000 }],
    [900, { type: "tool", tool: "Edit", detail: "src/api/login.ts" }],
    [900, { type: "phase", phase: "done" }],
    [200, { type: "say", who: "claude", text: "Rate limiting is on /api/login (5 tries per minute per IP) and the new tests pass.\n\nWhere should the limit counters live?\n1) In memory (simple, resets on restart)\n2) Redis (shared across servers)\n3) The existing Postgres table" }],
    [5000, { type: "log", who: "lead", text: "restarting demo" }],
  );
  return steps;
}

export async function* demo(loop = true): AsyncGenerator<Stamped> {
  for (let run = 1; ; run++) {
    for (const [delay, e] of script(run)) {
      if (delay) await Bun.sleep(delay);
      yield { ...e, t: Date.now() };
    }
    if (!loop) return;
  }
}

/** Events of one demo run with synthetic timestamps, for snapshots and tests. */
export function demoUntil(ms: number, start = Date.UTC(2026, 10, 4, 16, 49, 30)): Stamped[] {
  let t = start;
  const out: Stamped[] = [];
  for (const [delay, e] of script(1)) {
    t += delay;
    if (t - start > ms) break;
    out.push({ ...e, t });
  }
  return out;
}
