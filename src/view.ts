// Draws the vswarm board. The grid follows the terminal: at least 120×36, wider and taller as it grows.
//
//   title rail · phase rail
//   FLOW   JEV rail ┊ PROMPT ──▸ LEAD ──┬▸ lane ──┬──▸ REVIEW ┊ ADVISOR rail
//   CHAT (conversation + reply box)      FEED (every event)
//   status rail

import { Screen, clip, width, wrap, type Style } from "./screen";
import { SHARP, type Agent, type State } from "./state";

export const W = 120;
export const H = 36;
export const MAX_W = 180;
export const MAX_H = 60;

/** What the board shows that is not session state: the reply box and what mode it runs in. */
export interface Ui {
  mode: "run" | "watch" | "demo" | "replay";
  /** Claude is working on a turn. */
  busy?: boolean;
  input?: string;
  /** Numbered choices found in Claude's last question. */
  options?: string[];
  /** Highlighted choice, -1 for none. */
  pick?: number;
  /** Text Claude is streaming right now. */
  partial?: string;
  /** One line of help or status above the reply box. */
  hint?: string;
}

const C = {
  bg: "#0a0e18",
  bar: "#121a2b",
  panel: "#0d1220",
  track: "#1b2335",
  line: "#2a3550",
  amber: "#f5b453",
  cyan: "#4fd8e8",
  lime: "#9be36a",
  violet: "#b48cff",
  rose: "#ff6b8b",
  text: "#e4e9f5",
  muted: "#7d88a6",
  dim: "#454f6b",
  ink: "#0a0e18",
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

const chip = (bg: string): Style => ({ fg: C.ink, bg, bold: true });

const SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const EIGHTHS = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];

/** "claude-sonnet-5-5" → "Sonnet 5.5", "haiku" → "Haiku". */
export function modelName(id?: string): string {
  if (!id) return "";
  const m = /(opus|sonnet|haiku|fable)[-_ ]?(\d+)?(?:[-.](\d+))?/i.exec(id);
  if (!m) return id;
  const fam = m[1][0].toUpperCase() + m[1].slice(1).toLowerCase();
  return m[2] ? `${fam} ${m[2]}${m[3] && m[3].length < 3 ? "." + m[3] : ""}` : fam;
}

/** Numbered choices at the end of a question, e.g. "1) Red" / "2. Blue". */
export function questionOptions(text?: string): string[] {
  if (!text) return [];
  const lines = text.trim().split("\n").slice(-14);
  const opts = lines
    .map((l) => /^\s*(?:\*\*)?(\d{1,2})[.)](?:\*\*)?\s+(.+)$/.exec(l))
    .filter((m): m is RegExpExecArray => Boolean(m))
    .map((m) => plain(m[2]).replace(/\s+[—–-]\s+.*$/, "").replace(/\s*\([^)]*\)\s*$/, "").trim());
  return opts.length >= 2 ? opts.slice(0, 9) : [];
}

/** Markdown down to what reads well in a terminal. */
export function plain(t: string): string {
  return t
    // Code fences: drop the ``` lines and indent what is inside, so commands stand out.
    .replace(/^```[^\n]*\n([\s\S]*?)^```[ \t]*$/gm, (_, body: string) => body.replace(/\n$/, "").split("\n").map((l) => "    " + l).join("\n"))
    .replace(/^```[^\n]*$/gm, "")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/`([^`\n]+)`/g, "$1");
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

/** Smooth bar in eighth-cells on a dark track, shading from `from` to `to`. */
function meter(scr: Screen, x: number, y: number, w: number, frac: number, from: string, to = from) {
  const f = Math.max(0, Math.min(1, frac)) * w;
  for (let i = 0; i < w; i++) {
    const part = Math.max(0, Math.min(1, f - i));
    const ch = part >= 1 ? "█" : EIGHTHS[Math.floor(part * 8)] || " ";
    scr.put(x + i, y, ch, { fg: mix(from, to, w > 1 ? i / (w - 1) : 0), bg: C.track });
  }
}

/** Running agents first, then the most recent finished ones, in start order so lanes do not jump. */
function visibleAgents(s: State, n: number): Agent[] {
  const running = s.agents.filter((a) => a.status === "running");
  const finished = s.agents.filter((a) => a.status !== "running").sort((a, b) => (b.endedAt ?? 0) - (a.endedAt ?? 0));
  return [...running, ...finished].slice(0, n).sort((a, b) => a.startedAt - b.startedAt);
}

function badge(who: string, s: State): [string, Style] {
  const w = who.toLowerCase();
  if (w === "jev") return ["JEV", chip(C.lime)];
  if (w === "error") return ["ERROR", chip(C.rose)];
  if (w === "prompt") return ["YOU", chip(C.text)];
  if (w === "lead") return ["LEAD", chip(C.amber)];
  if (w === "vswarm") return ["VSWARM", chip(C.violet)];
  if (w === "guard") return ["GUARD", chip(C.rose)];
  if (w === "claude") return ["CLAUDE", { fg: C.amber, bg: C.track, bold: true }];
  if (w.includes("opus") || w === "advisor" || w === (s.advisor.model ?? "").toLowerCase()) return ["ADVISE", chip(C.violet)];
  return [(w.startsWith("claude-") ? modelName(who) : who).toUpperCase(), chip(C.cyan)];
}

const PHASES = [
  { key: "lead", label: "PLAN", color: C.amber },
  { key: "delegating", label: "SWARM", color: C.cyan },
  { key: "review", label: "REVIEW", color: C.violet },
  { key: "done", label: "DONE", color: C.lime },
] as const;

/** An edge along a row: dim when not reached, lit once traversed, with a travelling pulse while active. */
function edge(scr: Screen, x1: number, x2: number, y: number, state: "off" | "on" | "live", color: string, frame: number, head = true) {
  const len = x2 - x1 + 1;
  for (let i = 0; i < len; i++) {
    const last = head && i === len - 1;
    const pulse = state === "live" && !last && (Math.floor(frame) % Math.max(1, len - 1)) === i;
    const ch = last ? "▸" : pulse ? "●" : state === "off" ? "╌" : "─";
    scr.put(x1 + i, y, ch, state === "off" ? S.line : { fg: color, bold: pulse || last });
  }
}

/** A node on the flow graph: rounded box, title chip and two lines. */
function node(scr: Screen, x: number, y: number, w: number, color: string, lit: boolean, title: string, l1: [string, Style], l2: [string, Style]) {
  const line = lit ? { fg: color } : S.line;
  scr.fill(x + 1, y + 1, w - 2, 3, C.panel);
  scr.panel(x, y, w, 5, line);
  scr.put(x + 2, y + 1, ` ${title} `, lit ? chip(color) : { fg: C.muted, bg: C.track, bold: true });
  scr.put(x + 2, y + 2, clip(l1[0], w - 4), l1[1]);
  scr.put(x + 2, y + 3, clip(l2[0], w - 4), l2[1]);
}

export function draw(s: State, frame: number, now = Date.now(), opt: { w?: number; h?: number; ui?: Ui } = {}): Screen {
  const Wd = Math.max(W, Math.min(MAX_W, opt.w ?? W));
  const Ht = Math.max(H, Math.min(MAX_H, opt.h ?? H));
  const ui: Ui = opt.ui ?? { mode: "watch" };
  const scr = new Screen(Wd, Ht);
  scr.fill(0, 0, Wd, Ht, C.bg);
  const lead = modelName(s.lead.model) || "Lead";
  const swarm = swarmModel(s) || "subagents";
  const adv = modelName(s.advisor.model);
  const running = s.agents.filter((a) => a.status === "running").length;
  const doneN = s.agents.filter((a) => a.status !== "running").length;
  const spin = SPIN[Math.floor(frame) % SPIN.length];
  const forks = s.forks.toLocaleString("en-US");
  const at = PHASES.findIndex((p) => p.key === s.phase);
  const finished = s.phase === "done";

  // ── Title rail
  scr.fill(0, 0, Wd, 1, C.bar);
  let x = scr.put(1, 0, " ▼ ", chip(C.violet));
  const logo = "V-SWARM";
  [...logo].forEach((ch, i) => scr.put(x + 1 + i, 0, ch, { fg: mix(C.cyan, C.violet, i / (logo.length - 1)), bold: true }));
  x += logo.length + 3;
  for (const [t, st] of [
    [lead.toLowerCase(), S.amberB], [" leads  ", S.muted],
    [swarm.toLowerCase(), S.cyanB], [" swarm  ", S.muted],
    ...(adv ? [[adv.toLowerCase(), S.violetB], [" advises  ", S.muted]] : []),
  ] as [string, Style][]) x = scr.put(x, 0, t, st);
  const clock = `${s.startedAt ? "⏱ " + elapsed((ui.mode === "run" ? now : s.updatedAt ?? now) - s.startedAt) + "   " : ""}${hhmmss(ui.mode === "replay" ? s.updatedAt ?? now : now)} `;
  scr.put(Wd - width(clock), 0, clock, S.muted);

  // ── Phase rail
  x = 1;
  PHASES.forEach((p, i) => {
    const past = finished || i < at;
    // A turn the lead handled alone never swarmed: that step is skipped, not done.
    const st = past && p.key === "delegating" && !s.spawned ? "skip" : past ? "past" : i === at ? "now" : "next";
    const label = ` ${st === "past" ? "✓" : st === "skip" ? "–" : st === "now" ? spin : "○"} ${p.label} `;
    x = scr.put(x, 1, label, st === "now" ? chip(p.color) : st === "past" ? { fg: p.color, bold: true } : S.dim);
    if (i < PHASES.length - 1) x = scr.put(x, 1, " ━━ ", i < at || finished ? { fg: p.color } : S.line);
  });
  const stats = `${s.lead.tools} lead tools · ${s.spawned} subagents · ${s.agents.reduce((n, a) => n + a.tools, 0)} agent tools · ${s.errors} errors`;
  scr.put(Wd - 1 - width(stats), 1, stats, S.dim);

  // ── FLOW
  const FY = 2, FH = 14;
  scr.panel(0, FY, Wd, FH, S.line, [[" FLOW ", chip(C.text)]]);
  const CY = FY + 6; // centre row of the pipeline
  const NY = CY - 2; // top of the node boxes
  const PX = 2, PW = 18;
  const LX = PX + PW + 4, LW = 22;
  const BUS = LX + LW + 4;
  const RVW = 20, RVX = Wd - 2 - RVW;
  const MBUS = RVX - 4;
  const laneX = BUS + 1, laneEnd = MBUS - 1;

  // Prompt node
  const ptxt = s.prompt ? wrap(plain(s.prompt.replace(/\s+/g, " ")), PW - 4) : [];
  const turns = s.chat.filter((m) => m.who === "you").length;
  node(scr, PX, NY, PW, C.text, Boolean(s.prompt), turns > 1 ? `❯ TURN ${turns}` : "❯ PROMPT",
    [ptxt[0] ?? (ui.mode === "run" ? "type below…" : "waiting"), s.prompt ? S.text : S.dim],
    [ptxt.length > 2 ? clip(ptxt[1], PW - 5) + "…" : ptxt[1] ?? "", S.text]);
  edge(scr, PX + PW, LX - 1, CY, !s.prompt ? "off" : at === 0 && !running ? "live" : "on", C.amber, frame);

  // Lead node
  const leadLit = at >= 0 || finished;
  node(scr, LX, NY, LW, C.amber, leadLit, "◉ LEAD",
    [lead, S.amberB],
    [s.lead.lastTool ? `${s.lead.tools} tools · ${s.lead.lastTool}` : finished ? "answered" : at >= 0 ? "thinking" : "idle", s.lead.lastTool ? S.text : S.dim]);

  const eff = s.lead.effort;
  if (eff) {
    const k = ({ low: 1, medium: 2, high: 3, xhigh: 4, max: 5 } as Record<string, number>)[eff] ?? 2;
    scr.put(LX + LW - 8, NY + 2, "●".repeat(k) + "○".repeat(5 - k), leadLit ? S.amber : S.dim);
  }

  // Lanes and the two buses
  const shown = visibleAgents(s, 5);
  const n = Math.max(1, shown.length);
  const first = CY - Math.floor((n - 1) / 2), last = first + n - 1;
  const fanState = !shown.length ? "off" : running ? "live" : "on";
  edge(scr, LX + LW, BUS - 1, CY, fanState, C.cyan, frame, false);
  for (let y = first; y <= last; y++) {
    const up = y > first, down = y < last;
    const mid = y === CY;
    const j = mid ? (up && down ? "┼" : up ? "┴" : down ? "┬" : "─") : up && down ? "├" : down ? "╭" : "╰";
    const mj = mid ? (up && down ? "┼" : up ? "┴" : down ? "┬" : "─") : up && down ? "┤" : down ? "╮" : "╯";
    const a = shown[y - first];
    const on = Boolean(a);
    scr.put(BUS, y, j, on ? { fg: C.cyan } : S.line);
    scr.put(MBUS, y, mj, on && a.status !== "running" ? { fg: a.status === "failed" ? C.rose : C.lime } : S.line);
    if (!a) {
      scr.put(laneX, y, "╌▸ ", S.line);
      scr.put(laneX + 3, y, s.requests.length ? `${s.requests.length} requested · starting…` : "no subagents yet", S.dim);
      scr.hline(laneX + 30, laneEnd, y, "╌", S.line);
      continue;
    }
    const live = a.status === "running";
    const tint = a.status === "failed" ? C.rose : a.status === "done" ? C.lime : C.cyan;
    scr.put(laneX, y, "─▸", { fg: C.cyan });
    scr.put(laneX + 3, y, live ? spin : a.status === "done" ? "✔" : "✖", { fg: tint, bold: true });
    scr.put(laneX + 5, y, clip(a.name, 12), live ? S.textB : S.text);
    const barX = laneX + 18;
    const room = laneEnd - barX;
    const noteW = room > 52 ? room - 40 : 0;
    const barW = Math.max(8, room - 13 - noteW);
    const frac = a.pct ?? (a.status === "done" ? 1 : Math.min(a.tools, 20) / 20);
    meter(scr, barX, y, barW, frac, a.status === "failed" ? C.rose : C.cyan, a.status === "failed" ? C.rose : C.lime);
    let tx = barX + barW + 1;
    const pct = a.pct !== undefined || a.status === "done" ? `${Math.round(frac * 100)}%` : `${a.tools}t`;
    tx = scr.put(tx, y, pct.padStart(4), S.text);
    tx = scr.put(tx + 1, y, elapsed((live ? now : a.endedAt ?? now) - a.startedAt).padStart(5), live ? S.cyan : S.muted);
    if (noteW) tx = scr.put(tx + 2, y, clip(a.note ?? a.lastTool ?? a.desc ?? "", noteW), S.muted);
    // The tail into the merge bus lights up once the lane has delivered.
    if (tx + 1 < MBUS) edge(scr, tx + 1, MBUS - 1, y, live ? "off" : "on", tint, frame, false);
  }
  if (s.agents.length > shown.length) scr.put(laneX + 3, last + 1, `+${s.agents.length - shown.length} more`, S.cyan);
  const mergeState = !shown.length ? (finished ? "on" : "off") : s.phase === "review" ? "live" : running ? "off" : "on";
  edge(scr, MBUS + 1, RVX - 1, CY, mergeState, C.violet, frame);
  if (!shown.length && leadLit) {
    // Nothing delegated: the lead's own path runs straight to review, under the empty lane.
    scr.put(BUS, CY, "─", S.line);
  }

  // Review node
  node(scr, RVX, NY, RVW, finished ? C.lime : C.violet, s.phase === "review" || finished,
    finished ? "✓ DONE" : "◎ REVIEW",
    [finished ? "answer ready" : s.phase === "review" ? `${spin} verifying` : "waiting", finished ? S.limeB : s.phase === "review" ? S.violetB : S.dim],
    [s.spawned ? `${doneN}/${s.spawned} lanes merged` : "lead only", S.muted]);

  // JEV rail above, tapping the lead
  const jy = FY + 1;
  const leadMid = LX + Math.floor(LW / 2);
  const hotJev = s.lastDecisionAt !== undefined && (s.updatedAt ?? now) - s.lastDecisionAt < 4000 && !finished;
  let jx = scr.put(2, jy, " JEV ", chip(C.lime));
  jx = scr.put(jx + 1, jy, `⑂ ${forks}`, S.limeB);
  jx += 2;
  for (const d of [...s.decisions].reverse()) {
    const sharp = d.p >= SHARP;
    const need = width(d.q) + 18;
    if (jx + need > Wd - 3) break;
    jx = scr.put(jx, jy, d.q + " ", S.text);
    meter(scr, jx, jy, 6, d.p, sharp ? C.lime : C.amber);
    jx = scr.put(jx + 7, jy, d.p.toFixed(2), sharp ? S.textB : S.amberB);
    jx = scr.put(jx + 1, jy, sharp ? "SHARP" : "SPLIT", sharp ? S.limeB : S.amberB) + 3;
  }
  if (!s.decisions.length) scr.put(jx, jy, "retry-or-stop on tool failures · vswarm jev to ask your own", S.dim);
  scr.put(leadMid, jy + 1, "┊", hotJev ? S.limeB : S.line);
  scr.put(leadMid, jy + 2, hotJev && Math.floor(frame) % 2 ? "▼" : "▽", hotJev ? S.limeB : S.line);

  // ADVISOR rail below, tapping lead (plan), lanes (error) and review (done)
  const ay = NY + 7;
  const taps = [
    { mark: "before a plan", label: "plan", x: leadMid },
    { mark: "same error x2", label: "error ×2", x: Math.floor((laneX + laneEnd) / 2) },
    { mark: "before done", label: "done", x: RVX + Math.floor(RVW / 2) },
  ];
  let ax = scr.put(2, ay, " ADVISOR ", adv ? chip(C.violet) : { fg: C.muted, bg: C.track, bold: true });
  ax = scr.put(ax + 1, ay, adv ? `${adv.toLowerCase()} · ${s.advisor.status}` : "off", adv ? S.violet : S.dim);
  scr.hline(ax + 1, Wd - 3, ay, "·", S.line);
  for (const tp of taps) {
    const hit = s.advisor.marks.includes(tp.mark);
    const reading = s.advisor.current === tp.mark;
    const st = reading ? S.violetB : hit ? S.violet : S.line;
    scr.put(tp.x, ay - 2, reading && Math.floor(frame) % 2 ? "▲" : "△", st);
    scr.put(tp.x, ay - 1, "┊", st);
    scr.put(tp.x, ay, reading ? spin : hit ? "◆" : "◇", reading || hit ? S.violetB : S.dim);
    scr.put(tp.x + 1, ay, " " + tp.label + " ", reading || hit ? S.violet : S.dim);
  }
  if (adv) {
    const note = s.advisor.notes.at(-1);
    const right = `${s.advisor.calls} calls · ${fmtTokens(s.advisor.tokens)} read`;
    scr.put(2, ay + 1, clip(note ? "› " + note : "silent until a checkpoint", Wd - 8 - width(right)), note ? S.text : S.dim);
    scr.put(Wd - 3 - width(right), ay + 1, right, S.muted);
  }

  // ── CHAT and FEED
  const BY = FY + FH, BH = Ht - 1 - BY;
  // FEED sits left of CHAT: some terminals misplace backgrounds to the right of Thai text in a row,
  // and FEED's coloured badges would be the ones to suffer.
  const FW = Wd - Math.floor(Wd * 0.58) - 1;
  const FX = 0;
  const CX0 = FW + 1, CW = Wd - CX0;
  scr.panel(CX0, BY, CW, BH, S.line, [[" CHAT ", chip(C.amber)], [ui.mode === "run" ? " you ⇄ claude " : ` ${ui.mode} `, S.muted]]);
  scr.panel(FX, BY, FW, BH, S.line, [[" FEED ", chip(C.cyan)], [` ${s.log.length} events `, S.muted]]);

  // Reply box at the bottom of CHAT.
  const inner = CW - 4;
  const boxRows = ui.mode === "run" ? 3 : 1;
  const chatBottom = BY + BH - 2 - boxRows;
  if (ui.mode === "run") {
    const iy = BY + BH - 2;
    const opts = ui.options ?? [];
    let ox = CX0 + 2;
    if (opts.length && !ui.busy) {
      ox = scr.put(ox, iy - 1, "choose ", S.muted);
      // Plain coloured text, no background: a background behind Thai text is what terminals misdraw.
      opts.forEach((o, i) => {
        const label = `${i === ui.pick ? "▸" : " "}${i + 1} ${clip(o, o.startsWith("/open") ? 40 : 24)}`;
        if (ox + width(label) > CX0 + CW - 2) return;
        ox = scr.put(ox, iy - 1, label, i === ui.pick ? S.amberB : o.startsWith("/open") ? S.cyan : S.text) + 2;
      });
    } else {
      scr.put(CX0 + 2, iy - 1, clip(ui.hint ?? "", inner), S.dim);
    }
    scr.hline(CX0 + 1, CX0 + CW - 2, iy - 2, "┄", S.line);
    if (ui.busy) {
      scr.put(CX0 + 2, iy, `${spin} claude is working`, S.cyanB);
      scr.put(CX0 + CW - 2 - width("esc interrupt"), iy, "esc interrupt", S.dim);
    } else {
      const text = ui.input ?? "";
      const cursor = Math.floor(frame) % 6 < 3 ? "▌" : " ";
      const tail = width(text) > inner - 4 ? "…" + [...text].slice(-(inner - 6)).join("") : text;
      const ex = scr.put(CX0 + 2, iy, "❯ ", S.amberB);
      const cx = scr.put(ex, iy, tail || "", S.textB);
      if (!text) scr.put(cx + 1, iy, "reply, or pick a number · ⏎ send · esc end", S.dim);
      scr.put(cx, iy, cursor, S.amberB);
    }
  } else {
    scr.put(CX0 + 2, BY + BH - 2, ui.mode === "watch" ? "watching hooked sessions · q quit" : ui.mode === "replay" ? "replay · space pause · q quit" : "demo · q quit", S.dim);
  }

  // Conversation, newest at the bottom.
  const rows: [string, Style][] = [];
  const msgs = [...s.chat];
  if (ui.partial) msgs.push({ t: now, who: "claude", text: ui.partial + " ▍" });
  for (const m of msgs) {
    const [tag, tagSt, body] =
      m.who === "you" ? ["you", S.amberB, S.text] : m.who === "claude" ? ["claude", S.cyanB, S.text] : ["vswarm", S.violetB, S.muted];
    rows.push([`\u0000${tag}`, tagSt]);
    for (const l of wrap(plain(m.text), inner - 2)) rows.push(["  " + l, body]);
  }
  const chatRows = chatBottom - BY;
  const visible = rows.slice(-chatRows);
  if (!visible.length) scr.put(CX0 + 2, BY + 2, ui.mode === "run" ? "the conversation shows here" : "no conversation yet", S.dim);
  visible.forEach(([t, st], i) => {
    const y = BY + 1 + i;
    if (t.startsWith("\u0000")) {
      const tag = t.slice(1);
      const tx = scr.put(CX0 + 2, y, "▍", st);
      scr.put(tx + 1, y, tag, st);
    } else scr.put(CX0 + 2, y, clip(t, inner), st);
  });

  // Feed
  const feedRows = BH - 2;
  s.log.slice(-feedRows).forEach((l, i) => {
    const y = BY + 1 + i;
    scr.put(FX + 2, y, hhmmss(l.t).slice(0, 8), S.dim);
    const [label, st] = badge(l.who, s);
    scr.put(FX + 11, y, " " + clip(label, 7).padEnd(7) + " ", st);
    scr.put(FX + 21, y, clip(l.text.replace(/\s+/g, " "), FW - 23), l.who === "error" || l.who === "guard" ? S.rose : S.text);
  });

  // ── Status rail
  const y = Ht - 1;
  scr.fill(0, y, Wd, 1, C.bar);
  let sx = 0;
  const seg = (t: string, st: Style) => (sx = scr.put(sx, y, ` ${t} `, st) + 1);
  seg("vswarm", chip(C.violet));
  seg(`${running ? spin + " swarming" : s.spawned ? "◼ idle" : "◻ standby"} ${running}/${s.spawned}`, { fg: C.cyan, bg: C.bar, bold: true });
  if (adv) seg(`◆ ${adv.toLowerCase()} ${s.advisor.status}`, { fg: C.violet, bg: C.bar, bold: true });
  seg(`⑂ ${forks} forks`, { fg: C.lime, bg: C.bar, bold: true });
  seg(`✖ ${s.errors} error${s.errors === 1 ? "" : "s"}`, s.errors ? chip(C.rose) : { fg: C.dim, bg: C.bar });
  const keys = ui.mode === "run" ? (ui.busy ? "esc interrupt · ^C quit " : "⏎ send · 1-9 pick · esc end ") : ui.mode === "replay" ? "space pause · q quit " : "q quit ";
  if (sx + width(keys) < Wd) scr.put(Wd - width(keys), y, keys, { fg: C.muted, bg: C.bar });
  return scr;
}
