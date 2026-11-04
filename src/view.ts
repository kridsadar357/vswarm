// Draws the whole dashboard onto a 92×47 grid.

import { Screen, clip, width, type Style } from "./screen";
import { SHARP, type Agent, type State } from "./state";

export const W = 92;
export const H = 47;

const C = {
  orange: "#f0915a",
  blue: "#7aa2f7",
  green: "#6fd49a",
  purple: "#a99cf2",
  text: "#e6e8ee",
  muted: "#8b93a7",
  dim: "#4a5163",
  red: "#f38ba8",
};

const S = {
  orange: { fg: C.orange },
  orangeB: { fg: C.orange, bold: true },
  blue: { fg: C.blue },
  blueB: { fg: C.blue, bold: true },
  green: { fg: C.green },
  greenB: { fg: C.green, bold: true },
  purple: { fg: C.purple },
  purpleB: { fg: C.purple, bold: true },
  text: { fg: C.text },
  textB: { fg: C.text, bold: true },
  muted: { fg: C.muted },
  dim: { fg: C.dim },
  red: { fg: C.red },
} satisfies Record<string, Style>;

const SPIN = ["◐", "◓", "◑", "◒"];
const EFFORT: Record<string, number> = { low: 1, medium: 2, high: 3, xhigh: 4, max: 5 };

/** "claude-sonnet-5-5" → "Sonnet 5.5", "haiku" → "Haiku". */
export function modelName(id?: string): string {
  if (!id) return "";
  const m = /(opus|sonnet|haiku|fable)[-_ ]?(\d+)?(?:[-.](\d+))?/i.exec(id);
  if (!m) return id;
  const fam = m[1][0].toUpperCase() + m[1].slice(1).toLowerCase();
  return m[2] ? `${fam} ${m[2]}${m[3] && m[3].length < 3 ? "." + m[3] : ""}` : fam;
}

function swarmModel(s: State): string {
  const counts = new Map<string, number>();
  for (const a of s.agents) if (a.model) counts.set(a.model, (counts.get(a.model) ?? 0) + 1);
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
  return top ? modelName(top[0]) : "";
}

function hhmmss(t: number): string {
  const d = new Date(t);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
}

function whoStyle(who: string, s: State): Style {
  const w = who.toLowerCase();
  if (w === "jev") return S.greenB;
  if (w === "error") return S.red;
  if (w === "lead" || w === "prompt") return S.orangeB;
  if (w.includes("opus") || w === "advisor" || w === (s.advisor.model ?? "").toLowerCase()) return S.purpleB;
  return S.blueB;
}

function bar(scr: Screen, x: number, y: number, w: number, frac: number, on: Style, off: Style = S.dim) {
  const n = Math.round(Math.max(0, Math.min(1, frac)) * w);
  scr.put(x, y, "█".repeat(n), on);
  scr.put(x + n, y, "░".repeat(w - n), off);
}

/** Up to three agents: running ones first, then the most recently finished. */
function visibleAgents(s: State): Agent[] {
  const running = s.agents.filter((a) => a.status === "running");
  const finished = s.agents.filter((a) => a.status !== "running").sort((a, b) => (b.endedAt ?? 0) - (a.endedAt ?? 0));
  // Keep start order so boxes do not swap places when one finishes.
  return [...running, ...finished].slice(0, 3).sort((a, b) => a.startedAt - b.startedAt);
}

function fmtTokens(n: number): string {
  return n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : String(n);
}

function elapsed(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}`;
}

export function draw(s: State, frame: number, now = Date.now()): Screen {
  const scr = new Screen(W, H);
  const lead = modelName(s.lead.model) || "Lead";
  const swarm = swarmModel(s) || "subagents";
  const hasAdvisor = Boolean(s.advisor.model);
  const running = s.agents.filter((a) => a.status === "running").length;
  const spin = SPIN[frame % SPIN.length];

  // Header and legend
  scr.centerRuns(0, W, 0, [
    ["SWARMDECK", S.textB],
    ["  ·  ", S.dim],
    [lead.toUpperCase(), S.orangeB],
    [" LEADS", S.text],
    ["  ·  ", S.dim],
    [swarm.toUpperCase(), S.blueB],
    [" SWARMS", S.text],
  ]);
  scr.hline(1, W - 2, 1, "━", S.dim);
  scr.centerRuns(0, W, 2, [
    ["■ ", S.orange], [`${lead.toLowerCase()} · lead`, S.muted], ["    ", S.dim],
    ["■ ", S.blue], [`${swarm.toLowerCase()} · swarm`, S.muted], ["    ", S.dim],
    ["■ ", S.green], ["jev · forks", S.muted], ["    ", S.dim],
    ["■ ", S.purple], [hasAdvisor ? `${modelName(s.advisor.model).toLowerCase()} · advisor` : "hooks · watch", S.muted],
  ]);

  // Left column: advisor, or session stats when no advisor is attached
  const LX = 1, LY = 4, LW = 23, LH = 34;
  scr.box(LX, LY, LW, LH, S.purple);
  const ix = LX + 2, iw = LW - 4;
  scr.center(LX + 1, LW - 2, LY + 1, hasAdvisor ? modelName(s.advisor.model).toUpperCase() : "SESSION", S.purpleB);
  scr.center(LX + 1, LW - 2, LY + 2, hasAdvisor ? `advisor · ${s.advisor.status}` : "hooks · live", S.purple);
  const marks = hasAdvisor
    ? [s.advisor.marks[0] ?? "before a plan", s.advisor.marks[1] ?? "same error x2", s.advisor.marks[2] ?? "before done"]
    : ["session start", s.errors ? `errors x${s.errors}` : "on error", "on stop"];
  const anchors = [LY + 3, LY + 22, LY + 30];
  scr.vline(ix, LY + 4, LY + 29, "┆", S.dim);
  anchors.forEach((y, i) => scr.put(ix, y, "◇ " + clip(marks[i], iw - 2), S.text));

  const body = (y: number, text: string, st: Style = S.text) => scr.put(ix + 2, y, clip(text, iw - 2), st);
  if (hasAdvisor) {
    ["reads the whole", "session, every", "tool call and", "every result"].forEach((l, i) => body(LY + 5 + i, l));
    body(LY + 10, "last advice:");
    const notes = s.advisor.notes.length ? s.advisor.notes : ["—"];
    notes.slice(-2).forEach((n, i) => body(LY + 11 + i, "» " + n, S.purpleB));
    scr.put(ix + 2, LY + 14, "calls", S.text);
    scr.put(ix + iw - String(s.advisor.calls).length, LY + 14, String(s.advisor.calls), S.purpleB);
    body(LY + 15, "tokens read");
    body(LY + 16, "  " + fmtTokens(s.advisor.tokens), S.purpleB);
    ["silent on every", "routine turn"].forEach((l, i) => body(LY + 18 + i, l));
    ["never writes", "code itself.", lead, "applies advice."].forEach((l, i) => body(LY + 24 + i, l));
  } else {
    ["every tool call", "and subagent", "from Claude Code", "hooks"].forEach((l, i) => body(LY + 5 + i, l));
    const stat = (y: number, label: string, value: string, st: Style) => {
      scr.put(ix + 2, y, label, S.text);
      scr.put(ix + iw - width(value), y, value, st);
    };
    stat(LY + 10, "lead tools", String(s.lead.tools), S.orangeB);
    stat(LY + 11, "subagents", String(s.spawned), S.blueB);
    stat(LY + 12, "agent tools", String(s.agents.reduce((n, a) => n + a.tools, 0)), S.blueB);
    stat(LY + 13, "jev forks", String(s.forks), S.greenB);
    stat(LY + 14, "errors", String(s.errors), s.errors ? S.red : S.muted);
    if (s.startedAt) stat(LY + 16, "elapsed", elapsed((s.updatedAt ?? now) - s.startedAt), S.muted);
    if (s.prompt) {
      body(LY + 18, "prompt:", S.muted);
      body(LY + 19, s.prompt, S.text);
    }
  }

  // Advisor connectors
  const CX = 58;
  const arrowsHot = [s.phase === "lead", s.phase === "delegating" && s.errors > 0, s.phase === "review"];
  const conn = (y: number, toX: number, hot: boolean) => {
    scr.hline(LX + LW, toX - 2, y, "┈", hot ? S.purple : S.dim);
    scr.put(toX - 1, y, "▸", hot ? S.purple : S.dim);
  };

  // Lead box
  const BX = 44, BW = 30;
  scr.box(BX, 4, BW, 5, S.orange);
  scr.centerRuns(BX, BW, 5, [[`${lead} · main session`, S.orangeB]]);
  scr.center(BX, BW, 6, s.lead.lastTool ? `last: ${s.lead.lastTool} · ${s.lead.tools} tools` : "edits + runs tests", S.text);
  const eff = s.lead.effort ?? "";
  scr.centerRuns(BX, BW, 7, eff
    ? [["effort ", S.muted], ["▮".repeat(EFFORT[eff] ?? 2), S.orange], [" " + eff, S.orange]]
    : [[s.command ? clip(s.command, BW - 4) : "--model " + (s.lead.model ?? "?"), S.muted]]);
  conn(anchors[0], BX, arrowsHot[0]);
  scr.put(CX, 9, "●", S.orange);
  scr.put(CX, 10, "│", S.dim);

  // Jev fork layer
  const FX = 34, FW = 49, FY = 11;
  scr.box(FX, FY, FW, 7, S.green);
  scr.put(FX + 2, FY + 1, "JEV · fork layer", S.greenB);
  const forks = s.forks.toLocaleString("en-US");
  scr.put(FX + FW - 3 - forks.length, FY + 1, forks, S.greenB);
  scr.put(FX + FW - 3 - forks.length - 7, FY + 1, "forks", S.muted);
  if (!s.decisions.length) {
    scr.center(FX + 1, FW - 2, FY + 3, "no decisions yet · swarmdeck jev …", S.muted);
  }
  s.decisions.forEach((d, i) => {
    const y = FY + 2 + i;
    const sharp = d.p >= SHARP;
    scr.put(FX + 2, y, clip(d.q, 17), S.text);
    bar(scr, FX + 20, y, 14, d.p, sharp ? S.green : S.orange);
    scr.put(FX + 36, y, d.p.toFixed(2), sharp ? S.text : S.orangeB);
    scr.put(FX + 41, y, sharp ? "sharp" : "split", sharp ? S.green : S.orangeB);
  });
  scr.put(FX + 2, FY + 5, "sharp → runs in code", S.green);
  scr.put(FX + 26, FY + 5, `split → ${lead}`, S.muted);
  scr.put(CX, FY + 7, "│", S.dim);

  // Delegation fan-out
  scr.centerRuns(0, W + 24, 19, [["delegate to subagents · ", S.text], [swarm.toLowerCase(), S.blueB]]);
  scr.put(CX, 20, "●", S.blue);
  const slots = [36, 58, 80];
  const shown = visibleAgents(s);
  scr.hline(slots[0], slots[2], 21, "─", S.dim);
  scr.put(slots[0], 21, "┌", S.dim);
  scr.put(slots[2], 21, "┐", S.dim);
  scr.put(CX, 21, "┼", S.dim);
  if (running) {
    const k = frame % 22;
    scr.put(CX - k, 21, "●", S.blue);
    scr.put(CX + k, 21, "●", S.blue);
  }
  slots.forEach((cx, i) => scr.put(cx, 22, "▼", shown[i] ? S.blue : S.dim));

  const AY = 23, AW = 21, AH = 6;
  slots.forEach((cx, i) => {
    const a = shown[i];
    const x = cx - 10;
    if (!a) {
      scr.box(x, AY, AW, AH, S.dim);
      scr.center(x, AW, AY + 2, "idle", S.dim);
      return;
    }
    const st = a.status === "failed" ? S.red : a.status === "done" ? S.green : S.blue;
    scr.box(x, AY, AW, AH, a.status === "running" ? S.blue : st);
    scr.center(x + 1, AW - 2, AY + 1, a.name, S.textB);
    scr.center(x + 1, AW - 2, AY + 2, modelName(a.model) || "subagent", S.blue);
    if (a.pct !== undefined) {
      bar(scr, x + 2, AY + 3, 12, a.pct, S.blue);
      const pct = `${Math.round(a.pct * 100)}%`;
      scr.put(x + AW - 2 - pct.length, AY + 3, pct, S.muted);
    } else {
      bar(scr, x + 2, AY + 3, 8, Math.min(a.tools, 20) / 20, S.blue);
      const n = `${a.tools} ${a.tools === 1 ? "tool" : "tools"}`;
      scr.put(x + AW - 2 - n.length, AY + 3, n, S.muted);
    }
    scr.center(x + 1, AW - 2, AY + 4, a.note ?? a.desc ?? a.lastTool ?? "", S.text);
    const status =
      a.status === "running"
        ? `${spin} running ${elapsed(now - a.startedAt)}`
        : a.status === "done"
          ? `✓ done ${elapsed((a.endedAt ?? now) - a.startedAt)}`
          : "✗ failed";
    scr.put(x, AY + AH - 1, "└" + "─".repeat(AW - 2) + "┘", a.status === "running" ? S.blue : st);
    scr.center(x + 1, AW - 2, AY + AH - 1, ` ${status} `, st);
  });
  const extra = s.agents.filter((a) => a.status === "running").length - shown.filter((a) => a.status === "running").length;
  if (extra > 0) scr.put(slots[2] + 4, 22, `+${extra} more`, S.blue);
  conn(AY + 3, slots[0] - 10, arrowsHot[1]);

  // Merge back to the lead
  slots.forEach((cx) => scr.put(cx, AY + AH, "│", S.dim));
  scr.hline(slots[0], slots[2], 30, "─", S.dim);
  scr.put(slots[0], 30, "└", S.dim);
  scr.put(slots[2], 30, "┘", S.dim);
  scr.put(CX, 30, "┴", S.dim);
  if (s.phase === "review" || s.agents.some((a) => a.status !== "running")) {
    const k = 21 - (frame % 22);
    if (s.phase === "review") {
      scr.put(CX - k, 30, "●", S.orange);
      scr.put(CX + k, 30, "●", S.orange);
    }
  }
  scr.put(CX, 31, "▼", s.phase === "review" || s.phase === "done" ? S.orange : S.dim);
  const RX = 42, RW = 33;
  const reviewing = s.phase === "review" || s.phase === "done";
  scr.box(RX, 32, RW, 4, reviewing ? S.orange : S.dim);
  scr.center(RX, RW, 33, `back to ${lead} · lead`, reviewing ? S.orangeB : S.muted);
  scr.center(RX, RW, 34, s.phase === "done" ? "✓ finished" : "review + verify", reviewing ? S.text : S.dim);
  conn(anchors[2], RX, arrowsHot[2]);

  // Session log
  const GY = 38, GH = 7;
  scr.box(1, GY, W - 2, GH, S.dim);
  scr.put(3, GY, " session log ", S.muted);
  s.log.slice(-(GH - 2)).forEach((l, i) => {
    const y = GY + 1 + i;
    scr.put(3, y, hhmmss(l.t), S.dim);
    scr.put(13, y, clip(l.who.startsWith("claude-") ? modelName(l.who) : l.who, 11), whoStyle(l.who, s));
    scr.put(26, y, clip(l.text.replace(/\s+/g, " "), W - 30), S.text);
  });

  // Prompt and status line
  const cursor = frame % 6 < 3 ? "█" : " ";
  const cmd = s.command ?? (s.lead.model ? `claude --model ${s.lead.model}` : "claude");
  const px = scr.put(1, 45, "~/app $ ", S.green);
  scr.put(scr.put(px, 45, clip(cmd, W - 12), S.text) + 1, 45, cursor, S.green);
  let sx = 1;
  const seg = (label: string, value: string, st: Style) => {
    sx = scr.put(sx, 46, label + " ", S.muted);
    sx = scr.put(sx, 46, `[${value}]`, st) + 4;
  };
  seg(swarm.toLowerCase(), running ? "swarming" : s.spawned ? "idle" : "standby", S.blueB);
  seg("subagents", `${running}/${s.spawned}`, S.blueB);
  seg(hasAdvisor ? modelName(s.advisor.model).toLowerCase() : "phase", hasAdvisor ? s.advisor.status : s.phase, S.purpleB);
  seg("jev", `${forks} forks`, S.greenB);
  return scr;
}
