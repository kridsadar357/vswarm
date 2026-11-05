// `vswarm run`: one Claude Code session kept open over stream-json, so Claude can ask and the user can answer
// on the board, turn after turn. Hooks feed the board; the stream adds Claude's text as it is written.

import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { newRun, runDir, saveMeta, type RunMeta } from "./history";
import { append } from "./hook";
import { hooksConfig } from "./hooks";
import type { Config } from "./home";
import { AUTH_ERROR, authStatus, loginHint, nameOf, profileDir, profiles } from "./claude";
import { homedir } from "node:os";
import { follow } from "./follow";
import { apply, initial, type Stamped, type State } from "./state";
import { board, dropLast, type Key } from "./tui";
import { draw, modelName, questionOptions, type Ui } from "./view";
import type { Screen } from "./screen";

export interface RunOptions {
  prompt?: string;
  cwd: string;
  config: Config;
  /** Extra flags passed to claude as they are. */
  extra: string[];
  /** Continue this earlier run's Claude session. */
  resume?: RunMeta;
  /** No board: one turn, print the answer (also used when stdout is not a terminal). */
  print?: boolean;
  /** Write a board frame here every 2 s, for videos. */
  frames?: string;
  page: (scr: Screen) => string;
}

function systemPrompt(c: Config): string {
  return [
    "This session runs inside vswarm, a live board the user set up for Claude Code.",
    "Hook messages starting with 'vswarm advisor' come from an advisor model the user configured to review your work;",
    "messages starting with 'vswarm jev' come from the user's Jev decision model. Treat both as trusted guidance from the user's own tooling, while still using your judgement.",
    "The user reads your messages on the board and can reply, so the conversation continues after each of your turns.",
    "When you need a decision or missing information from the user, stop and ask at the end of your message.",
    "When the answer is one of a few choices, list each choice on its own line as `1) ...`, `2) ...` so the user can pick it with one key.",
    c.swarm &&
      `Delegate independent sub-tasks (research, drafting parts, review, verification) to subagents with the Agent tool and model "${c.swarm}", ` +
        "launching them in parallel in one message where possible. You integrate their results and own the final files.",
  ].filter(Boolean).join(" ");
}

export async function runSession(o: RunOptions): Promise<number> {
  const c = o.config;
  const meta = o.resume ?? newRun(o.prompt ?? "", o.cwd, c.lead);
  if (o.resume) meta.status = "running";
  const dir = runDir(meta.id);
  const events = join(dir, "events.jsonl");
  const settings = join(dir, "settings.json");
  writeFileSync(settings, JSON.stringify({ hooks: hooksConfig(events) }));
  const post = (e: Stamped) => append(events, [{ t: Date.now(), sid: meta.sid, ...e } as Stamped]);

  let s: State = initial();
  const overlay = () => {
    s.lead.model ??= c.lead;
    if (c.advisor) s.advisor.model ??= c.advisor;
    s.command = `vswarm run · ${modelName(c.lead).toLowerCase() || c.lead}${c.swarm ? ` + ${c.swarm}` : ""} · ${o.cwd}`;
  };
  const unfollow = follow(events, (evs, reset) => {
    if (reset) s = initial();
    for (const e of evs) apply(s, e);
    overlay();
  });
  overlay();

  const ui: Ui = { mode: "run", busy: false, input: "", options: [], pick: -1, hint: `in ${o.cwd} · mode ${c.mode}` };
  let child: ReturnType<typeof Bun.spawn> | null = null;
  let lastText = "";
  let resolveTurn: (() => void) | null = null;
  let ended = false;

  const start = () => {
    const args = [
      "claude", "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
      "--model", c.lead, "--settings", settings, "--append-system-prompt", systemPrompt(c),
      ...(c.mode && c.mode !== "default" ? ["--permission-mode", c.mode] : []),
      ...(c.allow.length ? ["--allowedTools", c.allow.join(" ")] : []),
      ...(meta.sid ? ["--resume", meta.sid] : []),
      ...o.extra,
    ];
    const p = Bun.spawn(args, {
      cwd: o.cwd,
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        ...(account ? { CLAUDE_CONFIG_DIR: account } : {}),
        VSWARM_ADVISOR_AT: c.advisor ? c.advisorAt.join(",") : "",
        VSWARM_ADVISOR_MODEL: c.advisor || "opus",
      },
    });
    child = p;
    void read(p);
    void (async () => {
      const err = await new Response(p.stderr as ReadableStream).text();
      const code = await p.exited;
      if (child === p) child = null;
      if (!ended && code !== 0) post({ type: "say", who: "vswarm", text: `claude exited with code ${code}${err.trim() ? `: ${err.trim().split("\n").slice(-2).join(" ")}` : ""}` });
      ui.busy = false;
      resolveTurn?.();
    })();
  };

  const read = async (p: ReturnType<typeof Bun.spawn>) => {
    const dec = new TextDecoder();
    let buf = "";
    for await (const chunk of p.stdout as ReadableStream<Uint8Array>) {
      buf += dec.decode(chunk, { stream: true });
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (line.trim()) {
          try {
            onMessage(JSON.parse(line));
          } catch {}
        }
      }
    }
  };

  const onMessage = (m: any) => {
    if (m.type === "system" && m.subtype === "init" && m.session_id) {
      meta.sid = m.session_id;
      saveMeta(meta);
      return;
    }
    // Only the lead's own text goes to the chat; subagents report through their lanes.
    if (m.parent_tool_use_id) return;
    if (m.type === "stream_event") {
      const d = m.event?.delta;
      if (d?.type === "text_delta") ui.partial = (ui.partial ?? "") + d.text;
      if (m.event?.type === "message_start") ui.partial = "";
      return;
    }
    if (m.type === "assistant") {
      const text = (m.message?.content ?? []).filter((b: any) => b.type === "text").map((b: any) => b.text).join("").trim();
      ui.partial = "";
      if (text) {
        lastText = text;
        post({ type: "say", who: "claude", text });
      }
      return;
    }
    if (m.type === "result") {
      ui.busy = false;
      ui.partial = "";
      meta.turns++;
      meta.costUsd = Math.max(meta.costUsd, Number(m.total_cost_usd ?? 0));
      meta.subagents = s.spawned;
      if (m.subtype === "error_during_execution" && !m.result) post({ type: "say", who: "vswarm", text: "stopped" });
      else if (m.is_error) {
        const why = String(m.result ?? m.subtype);
        post({ type: "say", who: "vswarm", text: `error: ${why.slice(0, 300)}` });
        if (AUTH_ERROR.test(why)) void explainLogin();
      }
      const denied: any[] = m.permission_denials ?? [];
      if (denied.length) {
        const what = [...new Set(denied.map((d) => d.tool_name))].join(", ");
        post({
          type: "say",
          who: "vswarm",
          text: `blocked by permissions: ${what}. Allow edits with \`vswarm config mode acceptEdits\`, or add tools with \`vswarm config allow "${what}"\`.`,
        });
      }
      if (typeof m.result === "string" && m.result.trim()) lastText = m.result.trim();
      ui.options = questionOptions(lastText);
      ui.pick = -1;
      ui.hint = ui.options.length ? "" : `turn ${meta.turns} done · $${meta.costUsd.toFixed(3)} · reply to continue, esc to end`;
      saveMeta(meta);
      resolveTurn?.();
    }
  };

  // Which Claude Code login this run uses, and what to do when it is not logged in.
  const account = profileDir(c.profile);
  const accountDir = account ?? join(homedir(), ".claude");
  const explainLogin = async () => {
    const all = await profiles();
    const others = all.filter((p) => p.loggedIn && p.dir !== accountDir).map((p) => p.name);
    post({
      type: "say",
      who: "vswarm",
      text:
        `Claude account "${nameOf(accountDir)}" (${accountDir.replace(homedir(), "~")}) is not logged in.\n` +
        `Log in: ${loginHint(accountDir)}` +
        (others.length ? `\nOr use an account that is logged in: vswarm config profile ${others[0]}${others.length > 1 ? `  (logged in: ${others.join(", ")})` : ""}` : ""),
    });
  };
  const checked = authStatus(accountDir).then((p) => {
    if (!p.loggedIn) void explainLogin();
    return p.loggedIn;
  });

  const send = (text: string) => {
    if (!child) start();
    const p = child!;
    (p.stdin as any).write(JSON.stringify({ type: "user", message: { role: "user", content: text } }) + "\n");
    (p.stdin as any).flush?.();
    if (!meta.prompt) {
      meta.prompt = text;
      saveMeta(meta);
    }
    // Shown right away; the UserPromptSubmit hook reports the same text and is folded into this line.
    post({ type: "say", who: "you", text });
    ui.busy = true;
    ui.input = "";
    ui.options = [];
    ui.pick = -1;
    ui.hint = "";
  };

  const turn = () => new Promise<void>((r) => (resolveTurn = r));

  const finish = async (status: RunMeta["status"]) => {
    ended = true;
    const p = child;
    if (p) {
      try {
        (p.stdin as any).end();
      } catch {}
      const timer = setTimeout(() => p.kill(), 5000);
      await p.exited;
      clearTimeout(timer);
    }
    await Bun.sleep(300);
    unfollow();
    // Opened and closed without sending anything: nothing worth keeping.
    if (!meta.sid && !o.resume) {
      rmSync(dir, { recursive: true, force: true });
      return false;
    }
    meta.ended = Date.now();
    meta.status = status;
    meta.subagents = s.spawned;
    saveMeta(meta);
    if (lastText) writeFileSync(join(dir, "answer.md"), lastText + "\n");
    return true;
  };

  // ── Without a board: one turn, the answer on stdout.
  if (o.print) {
    if (!o.prompt) throw new Error('usage: vswarm run --print "<prompt>"');
    if (!(await checked)) {
      unfollow();
      throw new Error(`Claude account "${nameOf(accountDir)}" is not logged in · ${loginHint(accountDir)} · or: vswarm config profile <name>`);
    }
    const t = turn();
    send(o.prompt);
    await t;
    await finish("done");
    process.stdout.write(lastText + "\n");
    return 0;
  }

  // ── The board.
  let shot = 0;
  if (o.frames) mkdirSync(o.frames, { recursive: true });
  const recorder = o.frames
    ? setInterval(() => writeFileSync(join(o.frames!, `frame-${String(++shot).padStart(4, "0")}.html`), o.page(draw(s, shot, Date.now(), { ui }))), 2000)
    : undefined;

  let done!: (status: RunMeta["status"]) => void;
  const closed = new Promise<RunMeta["status"]>((r) => (done = r));
  const interrupt = () => {
    if (!child) return;
    (child.stdin as any).write(JSON.stringify({ type: "control_request", request_id: `i${Date.now()}`, request: { subtype: "interrupt" } }) + "\n");
    ui.hint = "interrupting…";
  };
  const onKey = (k: Key) => {
    const opts = ui.options ?? [];
    switch (k.name) {
      case "ctrl-c":
        child?.kill();
        return done("interrupted");
      case "esc":
        return ui.busy ? interrupt() : done("done");
      case "ctrl-d":
        if (!ui.busy && !ui.input) done("done");
        return;
      case "enter": {
        const text = (ui.input ?? "").trim();
        if (ui.busy || !text) return;
        return send(text);
      }
      case "backspace":
        ui.input = dropLast(ui.input ?? "");
        return;
      case "ctrl-u":
        ui.input = "";
        return;
      case "up":
      case "down":
      case "tab":
        if (!opts.length) return;
        ui.pick = ((ui.pick ?? -1) + (k.name === "up" ? -1 : 1) + opts.length) % opts.length;
        ui.input = opts[ui.pick];
        return;
      case "space":
        ui.input = (ui.input ?? "") + " ";
        return;
      case "text": {
        // A single digit on an empty line picks that choice.
        const d = /^[1-9]$/.test(k.text) && !ui.input && opts.length ? Number(k.text) - 1 : -1;
        if (d >= 0 && d < opts.length) {
          ui.pick = d;
          ui.input = opts[d];
          return;
        }
        ui.input = (ui.input ?? "") + k.text;
      }
    }
  };
  const b = board((cols, rows, n) => draw(s, n, Date.now(), { w: cols, h: rows, ui }).toString(cols, rows), onKey);
  if (o.prompt) send(o.prompt);
  else if (o.resume) ui.hint = `resumed ${meta.id} · type to continue`;
  else ui.hint = "what should Claude do? type a prompt and press ⏎";

  const status = await closed;
  if (recorder) clearInterval(recorder);
  b.stop();
  if (!(await finish(status))) return 0;
  const dur = Math.round(((meta.ended ?? Date.now()) - meta.started) / 1000);
  if (lastText) process.stdout.write(lastText + "\n\n");
  const dim = (t: string) => `\x1b[2m${t}\x1b[0m`;
  console.log(
    `\x1b[1;35m▼ vswarm\x1b[0m ${meta.turns} turn${meta.turns === 1 ? "" : "s"} · ${s.spawned} subagents · ${s.forks} jev forks · ` +
      `${Math.floor(dur / 60)}m${String(dur % 60).padStart(2, "0")} · $${meta.costUsd.toFixed(3)}`,
  );
  console.log(dim(`  saved ${dir}`));
  if (meta.sid) console.log(dim(`  continue: vswarm resume ${meta.id.slice(0, 15)}   replay: vswarm replay ${meta.id.slice(0, 15)}`));
  return status === "interrupted" ? 130 : 0;
}
