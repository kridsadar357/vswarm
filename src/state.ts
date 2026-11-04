// Normalised event stream and the dashboard state it folds into.
// Every source (Claude Code hooks, Jev, the demo) speaks these events.

export type DeckEvent =
  | { type: "session"; sid?: string; lead?: string; effort?: string; command?: string }
  | { type: "prompt"; text: string }
  | { type: "phase"; phase: Phase }
  | { type: "tool"; tool: string; detail?: string }
  | { type: "agent.request"; name: string; model?: string; desc?: string }
  | { type: "agent.start"; id: string; name: string; model?: string; desc?: string }
  | { type: "agent.tool"; id: string; tool: string; detail?: string }
  | { type: "agent.progress"; id: string; pct: number; note?: string }
  | { type: "agent.stop"; id: string; ok?: boolean; model?: string }
  | { type: "decision"; q: string; p: number; answer: string; count?: number }
  | { type: "advisor"; model?: string; status?: string; note?: string; mark?: string; tokens?: number }
  | { type: "error"; text: string }
  | { type: "log"; who: string; text: string };

export type Stamped = DeckEvent & { t?: number; sid?: string };

export type Phase = "idle" | "lead" | "delegating" | "review" | "done";

export interface Agent {
  id: string;
  name: string;
  model?: string;
  desc?: string;
  status: "running" | "done" | "failed";
  tools: number;
  lastTool?: string;
  pct?: number;
  note?: string;
  startedAt: number;
  endedAt?: number;
}

export interface Decision {
  q: string;
  p: number;
  answer: string;
}

export interface LogLine {
  t: number;
  who: string;
  text: string;
}

export interface State {
  sid?: string;
  lead: { model?: string; effort?: string; tools: number; lastTool?: string };
  command?: string;
  prompt?: string;
  phase: Phase;
  agents: Agent[];
  spawned: number;
  /** Delegations the lead asked for whose SubagentStart has not arrived yet. */
  requests: { name: string; model?: string; desc?: string }[];
  forks: number;
  decisions: Decision[];
  advisor: { model?: string; status: string; notes: string[]; calls: number; tokens: number; marks: string[] };
  errors: number;
  log: LogLine[];
  startedAt?: number;
  updatedAt?: number;
}

/** Confidence at or above this is acted on in code; below it goes back to the lead model. */
export const SHARP = 0.8;

export function initial(): State {
  return {
    lead: { tools: 0 },
    phase: "idle",
    agents: [],
    spawned: 0,
    requests: [],
    forks: 0,
    decisions: [],
    advisor: { status: "idle", notes: [], calls: 0, tokens: 0, marks: [] },
    errors: 0,
    log: [],
  };
}

const LOG_KEEP = 50;

function log(s: State, t: number, who: string, text: string) {
  s.log.push({ t, who, text });
  if (s.log.length > LOG_KEEP) s.log.splice(0, s.log.length - LOG_KEEP);
}

export function apply(s: State, e: Stamped): State {
  const t = e.t ?? Date.now();
  s.startedAt ??= t;
  s.updatedAt = t;
  switch (e.type) {
    case "session":
      if (e.sid && e.sid !== s.sid) {
        // A new session starts a clean board, keeping only the log for context.
        const keepLog = s.log;
        Object.assign(s, initial(), { log: keepLog, startedAt: t, updatedAt: t });
        s.sid = e.sid;
      }
      if (e.lead) s.lead.model = e.lead;
      if (e.effort) s.lead.effort = e.effort;
      if (e.command) s.command = e.command;
      break;
    case "prompt":
      s.prompt = e.text;
      s.phase = "lead";
      log(s, t, "prompt", e.text);
      break;
    case "phase":
      s.phase = e.phase;
      break;
    case "tool":
      s.lead.tools++;
      s.lead.lastTool = e.tool;
      if (s.phase === "idle") s.phase = "lead";
      log(s, t, "lead", e.detail ? `${e.tool} · ${e.detail}` : e.tool);
      break;
    case "agent.request":
      s.requests.push({ name: e.name, model: e.model, desc: e.desc });
      if (s.requests.length > 20) s.requests.shift();
      break;
    case "agent.start": {
      const r = s.requests.findIndex((x) => x.name === e.name);
      const req = r >= 0 ? s.requests.splice(r, 1)[0] : undefined;
      const model = e.model ?? req?.model;
      const desc = e.desc ?? req?.desc;
      const existing = s.agents.find((a) => a.id === e.id);
      if (existing) {
        Object.assign(existing, { name: e.name, model: model ?? existing.model, desc: desc ?? existing.desc });
        break;
      }
      s.agents.push({ id: e.id, name: e.name, model, desc, status: "running", tools: 0, startedAt: t });
      s.spawned++;
      s.phase = "delegating";
      log(s, t, e.name, desc ? `started · ${desc}` : "started");
      break;
    }
    case "agent.tool": {
      const a = s.agents.find((x) => x.id === e.id);
      if (!a) break;
      a.tools++;
      a.lastTool = e.tool;
      log(s, t, a.name, e.detail ? `${e.tool} · ${e.detail}` : e.tool);
      break;
    }
    case "agent.progress": {
      const a = s.agents.find((x) => x.id === e.id);
      if (!a) break;
      a.pct = Math.max(0, Math.min(1, e.pct));
      if (e.note) a.note = e.note;
      break;
    }
    case "agent.stop": {
      const a = s.agents.find((x) => x.id === e.id);
      if (!a) break;
      a.status = e.ok === false ? "failed" : "done";
      a.endedAt = t;
      if (e.model) a.model = e.model;
      if (a.pct !== undefined) a.pct = 1;
      log(s, t, a.name, a.status === "done" ? `done · ${a.tools} tools` : "failed");
      if (!s.agents.some((x) => x.status === "running")) s.phase = "review";
      break;
    }
    case "decision": {
      s.forks += e.count ?? 1;
      const i = s.decisions.findIndex((d) => d.q === e.q);
      const d = { q: e.q, p: e.p, answer: e.answer };
      if (i >= 0) s.decisions.splice(i, 1);
      s.decisions.push(d);
      if (s.decisions.length > 3) s.decisions.shift();
      const verdict = e.p >= SHARP ? "sharp → code" : "split → lead";
      log(s, t, "jev", `${e.q} → ${e.answer}  p=${e.p.toFixed(2)}  ${verdict}`);
      break;
    }
    case "advisor":
      if (e.model) s.advisor.model = e.model;
      if (e.status) s.advisor.status = e.status;
      if (e.tokens) s.advisor.tokens += e.tokens;
      if (e.mark && !s.advisor.marks.includes(e.mark)) s.advisor.marks.push(e.mark);
      if (e.note) {
        s.advisor.calls++;
        s.advisor.notes.push(e.note);
        if (s.advisor.notes.length > 2) s.advisor.notes.shift();
        log(s, t, s.advisor.model ?? "advisor", e.note);
      }
      break;
    case "error":
      s.errors++;
      log(s, t, "error", e.text);
      break;
    case "log":
      log(s, t, e.who, e.text);
      break;
  }
  return s;
}
