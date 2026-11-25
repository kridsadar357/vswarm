// `vswarm notify`: a copy of vswarm's own alerts in a chat app on your phone (Thak today). Off until you give it a
// token with `vswarm notify thak`; nothing is sent before that.
//
// What goes out is a summary: the verdict, how many findings and how serious, what happened (a refusal, a lock, a
// question waiting for you) and the command to run. Never a path, a host name, a package name or the text of a
// finding, so a chat history is not a map of this machine. The machine's name is in the footer, to tell machines
// apart.
//
//   SEC/notify.json    { service, since, sent: { <kind>: last time } }
//   SEC/notify-token   the token, 0600 (THAK_NOTIFY_TOKEN overrides it, for scripts)
//
// Sending never stops what vswarm is doing: a few seconds at most, errors are kept for `notify status`, and the token
// is never printed or logged. Taking it away (`notify off`) weakens protection, so a person confirms it.

import { existsSync, readFileSync, rmSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { VERSION } from "../home";
import { SEC, writePrivate } from "./store";

export const ENDPOINT = "https://thak.app/v1/notify/send";
const configFile = () => join(SEC(), "notify.json");
const tokenFile = () => join(SEC(), "notify-token");

export type Level = "info" | "success" | "warning" | "critical";
export type Kind = "verdict" | "refused" | "locked" | "ask" | "digest" | "test";

export interface Event {
  kind: Kind;
  level: Level;
  title: string;
  /** Label and value rows: counts, the verdict, never names or paths. */
  rows?: [string, string][];
  /** The command to run, or what to do. */
  hint?: string;
}

interface Config {
  service: "thak";
  since: number;
  sent?: Partial<Record<Kind, number>>;
  error?: { at: number; what: string };
}

/** At most one of each per this many ms; findings are already told once each by the watch. */
const QUIET: Partial<Record<Kind, number>> = { refused: 5 * 60_000, ask: 60_000, digest: 20 * 3600_000 };
/** Thak's tone names: the level colours the card itself (and critical is a high-priority push). */
const TONE: Record<Level, string> = { info: "accent", success: "positive", warning: "warning", critical: "danger" };

function readConfig(): Config | undefined {
  try {
    const c = JSON.parse(readFileSync(configFile(), "utf8"));
    return c?.service === "thak" ? c : undefined;
  } catch {}
}

function token(env = process.env): { value: string; from: "env" | "file" } | undefined {
  if (env.THAK_NOTIFY_TOKEN?.trim()) return { value: env.THAK_NOTIFY_TOKEN.trim(), from: "env" };
  try {
    const v = readFileSync(tokenFile(), "utf8").trim();
    if (v) return { value: v, from: "file" };
  } catch {}
}

/** A token as the Thak app shows it: one word of printable characters. */
export function validToken(t: string): boolean {
  return /^[\x21-\x7e]{8,512}$/.test(t);
}

const VERDICT_TONE: Record<string, string> = { SAFE: "positive", CHECK: "warning", STOP: "danger" };

/**
 * The message Thak shows (thak.app/v1/notify/send): `level` colours it, the verdict is a badge, counts are metrics,
 * other rows key and value; `alt` is what a notification or an older app shows instead. Sizes are xs|s|m|l|xl and
 * tones default|muted|accent|positive|warning|danger: the server refuses anything else.
 */
export function card(e: Event, host = hostname().split(".")[0]) {
  const alt = [e.title, ...(e.rows ?? []).map(([k, v]) => `${k}: ${v}`), e.hint].filter(Boolean).join(" · ").slice(0, 4000);
  const rows = e.rows ?? [];
  const verdict = rows.find(([k]) => k === "Verdict")?.[1];
  const counts = rows.filter(([k, v]) => k !== "Verdict" && /^\d+$/.test(v));
  const rest = rows.filter((r) => r[0] !== "Verdict" && !counts.includes(r));
  return {
    level: e.level,
    card: {
      alt,
      size: "m",
      body: [
        { type: "text", text: e.title, size: "l", weight: "bold" },
        ...(verdict ? [{ type: "badges", items: [{ type: "badge", text: verdict, tone: VERDICT_TONE[verdict] ?? TONE[e.level] }] }] : []),
        ...(counts.length ? [{ type: "row", items: counts.map(([label, value]) => ({ type: "metric", label, value: Number(value) })) }] : []),
        ...rest.map(([label, value]) => ({ type: "kv", label, value })),
        ...(e.hint ? [{ type: "text", text: e.hint, size: "s", tone: "muted" }] : []),
      ],
      footer: [{ type: "text", text: `vswarm ${VERSION} · ${host}`, size: "s", tone: "muted" }],
    },
  };
}

export type Poster = (url: string, init: RequestInit) => Promise<Response>;

/**
 * Sends one event when notify is on; does nothing when it is off. Never throws and never waits more than `timeoutMs`.
 * Returns what happened, for `notify test` and the tests.
 */
export async function send(e: Event, opt: { post?: Poster; timeoutMs?: number; now?: number; force?: boolean } = {}): Promise<"off" | "quiet" | "sent" | string> {
  const cfg = readConfig();
  const tok = token();
  if (!cfg || !tok) return "off";
  const now = opt.now ?? Date.now();
  const gap = QUIET[e.kind];
  if (!opt.force && gap && now - (cfg.sent?.[e.kind] ?? 0) < gap) return "quiet";
  let what: string;
  // A plain timer, not AbortSignal.timeout: that one does not keep the process alive, and on Windows Bun can then wait
  // on the request forever.
  const stop = new AbortController();
  const timer = setTimeout(() => stop.abort(), opt.timeoutMs ?? 4000);
  try {
    const r = await (opt.post ?? fetch)(ENDPOINT, {
      method: "POST",
      headers: { authorization: `Bearer ${tok.value}`, "content-type": "application/json" },
      body: JSON.stringify(card(e)),
      redirect: "error",
      signal: stop.signal,
    });
    // Thak says why in {"error":{"code","message"}}: kept for `notify status`, cut short, never with the token in it.
    const why = r.ok ? "" : await r.json().then((j: any) => [j?.error?.code, j?.error?.message].filter(Boolean).join(": "), () => "");
    what = r.ok ? "sent"
      : r.status === 401 || r.status === 403 ? `refused by Thak (${r.status}): the token is wrong or was revoked`
      : r.status === 429 ? `Thak's limit was reached (${why || "429"}); later alerts are folded into one`
      : `Thak answered ${r.status}${why ? `: ${why.replaceAll(tok.value, "…").slice(0, 200)}` : ""}`;
  } catch (err: any) {
    what = stop.signal.aborted ? "Thak did not answer in time" : `could not reach Thak (${String(err?.message ?? err).replace(tok.value, "…").slice(0, 120)})`;
  } finally {
    clearTimeout(timer);
  }
  const next: Config = { ...cfg, sent: { ...cfg.sent, ...(what === "sent" ? { [e.kind]: now } : {}) } };
  if (what === "sent") delete next.error;
  else next.error = { at: now, what };
  try {
    writePrivate(configFile(), next);
  } catch {}
  return what;
}

/** Whether notify is on (a config and a token). */
export const notifyOn = () => !!readConfig() && !!token();

const verdictWord = (v: string) => ({ pass: "SAFE", warn: "CHECK", block: "STOP" })[v] ?? v.toUpperCase();

/** The watch found something new: how many, how serious, what to run. */
export const verdictEvent = (verdict: string, fresh: { severity: string }[], run: string): Event => ({
  kind: "verdict",
  level: verdict === "block" ? "critical" : "warning",
  title: verdict === "block" ? "vswarm: production access is blocked" : "vswarm: something changed on this machine",
  rows: [
    ["Verdict", verdictWord(verdict)],
    ["New findings", String(fresh.length)],
    ["Most serious", fresh.map((f) => f.severity).sort((a, b) => SEV.indexOf(a) - SEV.indexOf(b))[0]?.toUpperCase() ?? "-"],
  ],
  hint: `On the machine: ${run}`,
});
const SEV = ["critical", "high", "medium", "low", "info"];

/** A gate refused production access. */
export const refusedEvent = (verdict: string): Event => ({
  kind: "refused",
  level: "warning",
  title: "vswarm refused production access",
  rows: [["Verdict", verdictWord(verdict)]],
  hint: "On the machine: vswarm scan, then vswarm why <n>",
});

/** vswarm respond locked production access. */
export const lockedEvent = (incident: string): Event => ({
  kind: "locked",
  level: "critical",
  title: "vswarm locked production access",
  rows: [["Incident", incident]],
  hint: "Evidence is kept on the machine. When it is clean: vswarm unlock",
});

/** A command that weakens protection is waiting for a person; only the command and its first word go out. */
export const askEvent = (cmdline: string): Event => ({
  kind: "ask",
  level: "warning",
  title: "vswarm is asking you to confirm a change",
  rows: [["Command", cmdline.split(/\s+/).slice(0, 3).join(" ")]],
  hint: "Answer on the machine. If you did not start this, say no.",
});

/** Once a day from the watch: where the machine stands. */
export const digestEvent = (verdict: string, counts: Record<string, number>): Event => ({
  kind: "digest",
  level: verdict === "pass" ? "success" : verdict === "block" ? "critical" : "warning",
  title: "vswarm daily check",
  rows: [["Verdict", verdictWord(verdict)], ...SEV.slice(0, 4).filter((s) => counts[s]).map((s) => [s[0].toUpperCase() + s.slice(1), String(counts[s])] as [string, string])],
  hint: verdict === "pass" ? "Nothing needs your attention." : "On the machine: vswarm scan",
});

export async function notifyCommand(action: string, opt: { stdin?: boolean; ask: (q: string, o?: { secret?: boolean }) => Promise<string> }) {
  const { c, line } = await import("./print");
  const when = (ms?: number) => (ms ? new Date(ms).toLocaleString() : "never");
  switch (action) {
    case "thak": {
      const value = (opt.stdin ? await new Response(Bun.stdin.stream()).text() : await opt.ask("Paste the Thak notify token (it is not shown):", { secret: true })).trim();
      if (!value) throw new Error("no token given. In the Thak app: ทักเตือน › สร้างโทเคน, then run vswarm notify thak again");
      if (!validToken(value)) throw new Error("that does not look like a token: one word, 8 to 512 characters");
      // Pointing alerts somewhere else is a change a person makes, not one a program makes quietly.
      const old = token({});
      if (old && old.value !== value) await (await import("./human")).weaken("notify", ["thak"]);
      writePrivate(tokenFile(), `${value}\n`);
      writePrivate(configFile(), { service: "thak", since: readConfig()?.since ?? Date.now(), sent: readConfig()?.sent ?? {} } satisfies Config);
      line(`${c.green("✔")} notify is on: vswarm's alerts also go to Thak ${c.dim("(a summary: verdict, counts, the command to run; no paths or names)")}`);
      const r = await send({ kind: "test", level: "success", title: "vswarm is connected", rows: [["Sends", "blocks, refusals, locks, questions, a daily check"]], hint: "Turn it off on the machine: vswarm notify off" }, { force: true });
      line(r === "sent" ? `${c.green("✔")} a first message is on its way to Thak` : `${c.amber("!")} the first message did not go: ${r}`);
      return;
    }
    case "test": {
      if (!notifyOn()) throw new Error("notify is off. Turn it on: vswarm notify thak");
      const r = await send({ kind: "test", level: "info", title: "vswarm test message", rows: [["From", "vswarm notify test"]] }, { force: true });
      if (r !== "sent") throw new Error(`not sent: ${r}`);
      line(`${c.green("✔")} sent to Thak`);
      return;
    }
    case "status": {
      const cfg = readConfig();
      const tok = token();
      if (!cfg || !tok) {
        line(`${c.dim("○")} notify is off ${c.dim("· turn it on: vswarm notify thak")}`);
        return;
      }
      line(`${c.green("●")} notify is on · Thak ${c.dim(`· token from ${tok.from === "env" ? "THAK_NOTIFY_TOKEN" : "vswarm's folder"} · since ${when(cfg.since)}`)}`);
      const last = Math.max(0, ...Object.values(cfg.sent ?? {}).map(Number));
      line(`  ${c.dim(`last sent ${when(last || undefined)}`)}`);
      if (cfg.error) line(`  ${c.amber("!")} ${cfg.error.what} ${c.dim(`(${when(cfg.error.at)})`)}`);
      return;
    }
    case "off": {
      if (!existsSync(configFile()) && !existsSync(tokenFile())) {
        line(`${c.dim("○")} notify is already off`);
        return;
      }
      await (await import("./human")).weaken("notify", ["off"]);
      for (const f of [configFile(), tokenFile()]) rmSync(f, { force: true });
      line(`${c.green("✔")} notify is off; the token is deleted from this machine ${c.dim("(revoke it in the Thak app too)")}`);
      return;
    }
  }
  throw new Error("usage: vswarm notify thak [--stdin] | test | status | off");
}
