// Draws the v-swarm board onto a 120×36 grid: phase rail on top, lead and advisor on the left,
// the swarm as lanes and the Jev forks on the right, a badge feed and a status rail at the bottom.

import { Screen, clip, width, type Style } from "./screen";
import { SHARP, type Agent, type State } from "./state";

export const W = 120;
export const H = 36;

const C = {
  bg: "#0b0f19",
  bar: "#131a2a",
  track: "#1c2436",
  line: "#2b3550",
  amber: "#f5b453",
  cyan: "#4fd8e8",
  lime: "#9be36a",
  violet: "#b48cff",
  rose: "#ff6b8b",
  text: "#e4e9f5",
  muted: "#7d88a6",
  dim: "#454f6b",
  ink: "#0b0f19",
};

const S = {
  amber: { fg: C.amber },
  amberB: { fg: C.amber, bold: true },
  cyan: { fg: C.cyan },
  cyanB: { fg: C.cyan, bold: true },
  lime: { fg: C.lime },
  limeB: { fg: C.lime, bold: true },
  violet: { fg: C.violet },
  violetB: { fg: C.violet, bold: true },
  rose: { fg: C.rose },
  roseB: { fg: C.rose, bold: true },
  text: { fg: C.text },
  textB: { fg: C.text, bold: true },
  muted: { fg: C.muted },
  dim: { fg: C.dim },
  line: { fg: C.line },
} satisfies Record<string, Style>;

/** Dark text on a coloured chip. */
const chip = (bg: string): Style => ({ fg: C.ink, bg, bold: true });

const SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const EIGHTHS = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
const SPARK = "▁▂▃▄▅▆▇█";
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

function fmtTokens(n: number): string {
  return n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : String(n);
}

function elapsed(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}`;
}

function mix(a: string, b: string, t: number): string {
  const p = (c: string) => [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16));
  const [x, y] = [p(a), p(b)];
  return "#" + x.map((v, i) => Math.round(v + (y[i] - v) * t).toString(16).padStart(2, "0")).join("");
}

/** Smooth bar in eighth-cells on a dark track, its colour shading from `from` to `to`. */
function meter(scr: Screen, x: number, y: number, w: number, frac: number, from: string, to = from) {
  const f = Math.max(0, Math.min(1, frac)) * w;
  for (let i = 0; i < w; i++) {
    const fg = mix(from, to, w > 1 ? i / (w - 1) : 0);
    const part = Math.max(0, Math.min(1, f - i));
    const ch = part >= 1 ? "█" : EIGHTHS[Math.floor(part * 8)] || " ";
    scr.put(x + i, y, ch, { fg, bg: C.track });
  }
}

/** Running agents first, then the most recently finished; kept in start order so lanes do not jump. */
function visibleAgents(s: State, n: number): Agent[] {
  const running = s.agents.filter((a) => a.status === "running");
  const finished = s.agents.filter((a) => a.status !== "running").sort((a, b) => (b.endedAt ?? 0) - (a.endedAt ?? 0));
  return [...running, ...finished].slice(0, n).sort((a, b) => a.startedAt - b.startedAt);
}

function badge(who: string, s: State): [string, Style] {
  const w = who.toLowerCase();
  if (w === "jev") return ["JEV", chip(C.lime)];
  if (w === "error") return ["ERROR", chip(C.rose)];
  if (w === "prompt") return ["PROMPT", chip(C.text)];
  if (w === "lead") return ["LEAD", chip(C.amber)];
  if (w.includes("opus") || w === "advisor" || w === (s.advisor.model ?? "").toLowerCase()) return ["ADVISE", chip(C.violet)];
  return [(w.startsWith("claude-") ? modelName(who) : who).toUpperCase(), chip(C.cyan)];
}

const PHASES = [
  { key: "lead", label: "PLAN", color: C.amber },
  { key: "delegating", label: "SWARM", color: C.cyan },
  { key: "review", label: "REVIEW", color: C.violet },
  { key: "done", label: "DONE", color: C.lime },
] as const;

export function draw(s: State, frame: number, now = Date.now()): Screen {
  const scr = new Screen(W, H);
  scr.fill(0, 0, W, H, C.bg);
  const lead = modelName(s.lead.model) || "Lead";
  const swarm = swarmModel(s) || "subagents";
  const adv = modelName(s.advisor.model);
  const running = s.agents.filter((a) => a.status === "running").length;
  const spin = SPIN[Math.floor(frame) % SPIN.length];
  const forks = s.forks.toLocaleString("en-US");

  // ── Title rail
  scr.fill(0, 0, W, 1, C.bar);
  let x = scr.put(1, 0, " ▼ ", chip(C.violet));
  const logo = "V-SWARM";
  [...logo].forEach((ch, i) => scr.put(x + 1 + i, 0, ch, { fg: mix(C.cyan, C.violet, i / (logo.length - 1)), bold: true }));
  x += logo.length + 3;
  for (const [t, st] of [
    [lead.toLowerCase(), S.amberB], [" leads  ", S.muted],
    [swarm.toLowerCase(), S.cyanB], [s.spawned ? ` ×${s.spawned}` : "", S.cyan], [" swarm  ", S.muted],
    ...(adv ? [[adv.toLowerCase(), S.violetB], [" advises", S.muted]] : []),
  ] as [string, Style][]) x = scr.put(x, 0, t, st);
  const clock = `${s.startedAt ? "⏱ " + elapsed((s.updatedAt ?? now) - s.startedAt) + "   " : ""}${hhmmss(s.updatedAt ?? now)} `;
  scr.put(W - width(clock), 0, clock, S.muted);

  // ── Phase rail
  const at = PHASES.findIndex((p) => p.key === s.phase);
  x = 1;
  PHASES.forEach((p, i) => {
    const state = s.phase === "done" || i < at ? "past" : i === at ? "now" : "next";
    const label = ` ${state === "past" ? "✓" : state === "now" ? spin : "○"} ${i + 1} ${p.label} `;
    x = scr.put(x, 2, label, state === "now" ? chip(p.color) : state === "past" ? { fg: p.color } : S.dim);
    if (i < PHASES.length - 1) x = scr.put(x, 2, " ━━━ ", i < at || s.phase === "done" ? { fg: p.color } : S.line);
  });
  if (s.prompt) scr.put(x + 3, 2, clip("❯ " + s.prompt.replace(/\s+/g, " "), W - x - 4), S.text);

  // ── Lead
  const LX = 0, LW = 38;
  scr.panel(LX, 4, LW, 11, S.line, [[" LEAD ", chip(C.amber)], [" main session ", S.muted]]);
  const lx = LX + 2, lw = LW - 4;
  scr.put(lx, 5, lead, S.amberB);
  const eff = s.lead.effort;
  if (eff) {
    const n = EFFORT[eff] ?? 2;
    const t = `${"●".repeat(n)}${"○".repeat(5 - n)} ${eff}`;
    scr.put(lx + lw - width(t), 5, t, S.amber);
  }
  scr.put(lx, 7, "tools", S.muted);
  scr.put(lx + 7, 7, String(s.lead.tools), S.textB);
  if (s.lead.lastTool) {
    scr.put(lx + 12, 7, "last", S.muted);
    scr.put(lx + 17, 7, clip(s.lead.lastTool, lw - 17), S.text);
  }
  // Activity: every logged event in the last minute, 3 s per column.
  const cols = lw - 9, span = 3000;
  const end = s.updatedAt ?? now;
  const buckets = Array(cols).fill(0);
  for (const l of s.log) {
    const k = cols - 1 - Math.floor((end - l.t) / span);
    if (k >= 0 && k < cols) buckets[k]++;
  }
  const peak = Math.max(1, ...buckets);
  scr.put(lx, 9, "activity", S.muted);
  buckets.forEach((b, i) =>
    scr.put(lx + 9 + i, 9, b ? SPARK[Math.min(7, Math.round((b / peak) * 7))] : "▁", { fg: b ? mix(C.amber, C.cyan, i / cols) : C.track }),
  );
  const cmd = s.command ?? (s.lead.model ? `claude --model ${s.lead.model}` : "claude");
  scr.put(lx, 12, clip("$ " + cmd, lw), S.dim);

  // ── Advisor, or plain session stats without one
  const AY = 15, AH = 10;
  if (adv) {
    scr.panel(LX, AY, LW, AH, S.line, [[" ADVISOR ", chip(C.violet)], [` ${adv} `, S.violet]]);
    const status = ` ${s.advisor.status.toUpperCase()} `;
    scr.put(LX + LW - 2 - width(status), AY, status, s.advisor.status === "reading" ? chip(C.violet) : S.violetB);
    // Checkpoint track: one node per moment the advisor can be called.
    const marks = ["before a plan", "same error x2", "before done"];
    const short = ["plan", "error ×2", "done"];
    const nodes = [lx + 1, lx + Math.floor(lw / 2), lx + lw - 2];
    scr.hline(nodes[0], nodes[2], AY + 1, "─", S.line);
    nodes.forEach((nx, i) => {
      const hit = s.advisor.marks.includes(marks[i]);
      scr.put(nx, AY + 1, hit ? "◆" : "◇", hit ? S.violetB : S.muted);
      const lbl = short[i];
      const lx0 = i === 0 ? nx - 1 : i === 2 ? nx + 2 - width(lbl) : nx - Math.floor(width(lbl) / 2);
      scr.put(lx0, AY + 2, lbl, hit ? S.violet : S.dim);
    });
    scr.put(lx, AY + 4, "latest advice", S.muted);
    const notes = s.advisor.notes.length ? s.advisor.notes.slice(-3) : ["silent — nothing to flag"];
    notes.forEach((n, i) => scr.put(lx, AY + 5 + i, clip((s.advisor.notes.length ? "› " : "  ") + n, lw), s.advisor.notes.length ? S.text : S.dim));
    scr.put(lx, AY + 8, "calls", S.muted);
    scr.put(lx + 6, AY + 8, String(s.advisor.calls), S.violetB);
    scr.put(lx + 11, AY + 8, "read", S.muted);
    scr.put(lx + 16, AY + 8, fmtTokens(s.advisor.tokens), S.violetB);
    scr.put(lx + lw - 13, AY + 8, "advises only", S.dim);
  } else {
    scr.panel(LX, AY, LW, AH, S.line, [[" SESSION ", chip(C.violet)], [" hooks · live ", S.muted]]);
    const stat = (r: number, label: string, value: string, st: Style) => {
      scr.put(lx, AY + r, label, S.muted);
      scr.put(lx + lw - width(value), AY + r, value, st);
      scr.hline(lx + width(label) + 1, lx + lw - width(value) - 2, AY + r, "·", S.line);
    };
    stat(2, "lead tools", String(s.lead.tools), S.amberB);
    stat(3, "subagents", String(s.spawned), S.cyanB);
    stat(4, "agent tools", String(s.agents.reduce((n, a) => n + a.tools, 0)), S.cyanB);
    stat(5, "jev forks", forks, S.limeB);
    stat(6, "errors", String(s.errors), s.errors ? S.roseB : S.muted);
    if (s.startedAt) stat(8, "elapsed", elapsed((s.updatedAt ?? now) - s.startedAt), S.text);
  }

  // ── Swarm lanes
  const RX = LW + 1, RW = W - RX;
  const SY = 4, LANES = 5;
  scr.panel(RX, SY, RW, LANES + 6, S.line, [[" SWARM ", chip(C.cyan)], [` ${swarm.toLowerCase()} `, S.cyan]]);
  const counts = `${running} running · ${s.agents.filter((a) => a.status === "done").length} done${s.agents.some((a) => a.status === "failed") ? ` · ${s.agents.filter((a) => a.status === "failed").length} failed` : ""}`;
  scr.put(RX + RW - 3 - width(counts), SY, ` ${counts} `, S.muted);
  const col = { st: RX + 2, name: RX + 5, bar: RX + 21, pct: RX + 40, tools: RX + 46, time: RX + 52, note: RX + 59 };
  const noteW = RX + RW - 2 - col.note;
  const hy = SY + 1;
  for (const [k, t] of [["name", "AGENT"], ["bar", "PROGRESS"], ["tools", "TOOLS"], ["time", "TIME"], ["note", "NOW"]] as const)
    scr.put(col[k], hy, t, S.dim);
  const shown = visibleAgents(s, LANES);
  for (let i = 0; i < LANES; i++) {
    const y = hy + 1 + i;
    const a = shown[i];
    if (!a) {
      scr.put(col.st, y, "·", S.line);
      if (i === 0) scr.put(col.name, y, s.requests.length ? `${s.requests.length} requested, waiting to start…` : "no subagents yet", S.dim);
      continue;
    }
    if (i % 2 === 0) scr.fill(RX + 1, y, RW - 2, 1, "#0f1422");
    const live = a.status === "running";
    const tint = a.status === "failed" ? C.rose : a.status === "done" ? C.lime : C.cyan;
    scr.put(col.st, y, live ? spin : a.status === "done" ? "✔" : "✖", { fg: tint, bold: true });
    const nx = scr.put(col.name, y, clip(a.name, 14), live ? S.textB : S.text);
    // The panel title names the swarm model; only an agent on a different one says so.
    const own = modelName(a.model);
    if (own && own !== swarm && nx < col.bar - 3) scr.put(nx + 1, y, clip(own.split(" ")[0].toLowerCase(), col.bar - nx - 2), S.muted);
    const frac = a.pct ?? (a.status === "done" ? 1 : Math.min(a.tools, 20) / 20);
    meter(scr, col.bar, y, 17, frac, a.status === "failed" ? C.rose : C.cyan, a.status === "failed" ? C.rose : C.lime);
    if (a.pct !== undefined || a.status === "done") scr.put(col.pct, y, `${Math.round(frac * 100)}%`.padStart(4), S.text);
    scr.put(col.tools, y, String(a.tools).padStart(3), S.text);
    scr.put(col.time, y, elapsed((live ? now : a.endedAt ?? now) - a.startedAt).padStart(5), live ? S.cyan : S.muted);
    scr.put(col.note, y, clip(a.note ?? a.lastTool ?? a.desc ?? "", noteW), live ? S.text : S.muted);
  }
  const more = s.agents.filter((a) => a.status === "running").length - shown.filter((a) => a.status === "running").length;
  if (more > 0) scr.put(RX + 2, SY + LANES + 4, `+${more} more running`, S.cyan);

  // Flow strip: lead → fan-out → lanes → merge → review, with a pulse on the active leg.
  const fy = SY + LANES + 3;
  const legs: [string, number, string][] = [
    ["lead", 0, C.amber], ["fan-out", 1, C.cyan], [`${running}/${s.spawned} lanes`, 1, C.cyan], ["merge", 2, C.violet], ["review", 2, C.violet],
  ];
  let fx = RX + 4;
  const starts: number[] = [];
  legs.forEach(([t, ph, color], i) => {
    const on = at >= ph || s.phase === "done";
    starts.push(fx);
    fx = scr.put(fx, fy, t, on ? { fg: color, bold: at === ph } : S.dim);
    if (i < legs.length - 1) {
      const len = 9;
      const hot = at === legs[i + 1][1] && s.phase !== "done";
      for (let k = 0; k < len; k++) {
        const pulse = hot && (frame + len - k) % len === 0;
        scr.put(fx + 1 + k, fy, k === len - 1 ? "▸" : pulse ? "●" : "─", pulse ? { fg: legs[i + 1][2], bold: true } : on ? { fg: color } : S.line);
      }
      fx += len + 2;
    }
  });

  // ── Jev forks
  const JY = SY + LANES + 6, JH = AY + AH - JY;
  scr.panel(RX, JY, RW, JH, S.line, [[" JEV ", chip(C.lime)], [" decision forks ", S.lime]]);
  const ft = ` ${forks} forks `;
  scr.put(RX + RW - 3 - width(ft), JY, ft, S.limeB);
  const jx = RX + 2;
  if (!s.decisions.length) scr.put(jx, JY + 2, "no decisions yet · v-swarm jev --q … <option> <option>", S.dim);
  s.decisions.forEach((d, i) => {
    const y = JY + 1 + i;
    const sharp = d.p >= SHARP;
    scr.put(jx, y, clip(d.q, 16), S.text);
    meter(scr, jx + 17, y, 24, d.p, sharp ? C.lime : C.amber, sharp ? C.lime : C.rose);
    // Threshold tick on the track.
    const tick = jx + 17 + Math.round(SHARP * 24) - 1;
    if (d.p * 24 < SHARP * 24 - 1) scr.put(tick, y, "┊", { fg: C.muted, bg: C.track });
    scr.put(jx + 43, y, d.p.toFixed(2), sharp ? S.textB : S.amberB);
    scr.put(jx + 49, y, sharp ? " SHARP " : " SPLIT ", chip(sharp ? C.lime : C.amber));
    scr.put(jx + 57, y, clip(`${sharp ? "→ code" : "→ " + lead} · ${d.answer}`, RW - 61), S.muted);
  });
  scr.put(jx, JY + JH - 2, `┊ ${SHARP.toFixed(2)} line — sharp runs in code, split goes back to ${lead}`, S.dim);

  // ── Feed
  const GY = AY + AH, GH = H - 1 - GY;
  scr.panel(0, GY, W, GH, S.line, [[" FEED ", chip(C.text)]]);
  s.log.slice(-(GH - 2)).forEach((l, i) => {
    const y = GY + 1 + i;
    scr.put(2, y, hhmmss(l.t), S.dim);
    const [label, st] = badge(l.who, s);
    scr.put(11, y, " " + clip(label, 8).padEnd(8) + " ", st);
    scr.put(23, y, clip(l.text.replace(/\s+/g, " "), W - 26), l.who === "error" ? S.rose : S.text);
  });

  // ── Status rail
  const y = H - 1;
  scr.fill(0, y, W, 1, C.bar);
  let sx = 0;
  const seg = (t: string, st: Style) => (sx = scr.put(sx, y, ` ${t} `, st) + 1);
  seg("v-swarm", chip(C.violet));
  seg(`${running ? spin + " swarming" : s.spawned ? "◼ idle" : "◻ standby"} ${running}/${s.spawned}`, { fg: C.cyan, bg: C.bar, bold: true });
  if (adv) seg(`◆ ${adv.toLowerCase()} ${s.advisor.status}`, { fg: C.violet, bg: C.bar, bold: true });
  seg(`⑂ ${forks} forks`, { fg: C.lime, bg: C.bar, bold: true });
  seg(`✖ ${s.errors} error${s.errors === 1 ? "" : "s"}`, s.errors ? chip(C.rose) : { fg: C.dim, bg: C.bar });
  const keys = "q quit ";
  scr.put(W - width(keys), y, keys, { fg: C.muted, bg: C.bar });
  return scr;
}
