// `vswarm run`: one Claude Code session kept open over stream-json, so Claude can ask and the user can answer
// on the board, turn after turn. Hooks feed the board; the stream adds Claude's text as it is written.

import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { GROUPS, isGroup, swarmSettings } from "./policy";
import { join } from "node:path";
import { newRun, runDir, saveMeta, type RunMeta } from "./history";
import { append } from "./hook";
import { hooksConfig } from "./hooks";
import { paths, type Config } from "./home";
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
  /** Extra folders Claude may edit (--add-dir). */
  dirs?: string[];
  /** Write a board frame here every 2 s, for videos. */
  frames?: string;
  page: (scr: Screen) => string;
}

/** Local things Claude's reply points at that the user may want to look at: localhost URLs and HTML files. */
export function openables(text: string, cwd: string): string[] {
  const urls = [...text.matchAll(/https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::\d+)?[^\s`'")\]>]*/g)].map((m) => m[0].replace(/[.,;:]+$/, ""));
  const files = [...text.matchAll(/(?:^|[\s`'"(])((?:~|\.{0,2})?\/?[\w./-]+\.html?)\b/g)].map((m) => m[1]);
  const out = [...new Set([...urls, ...files])].map((t) => `/open ${t.replace(/^0\.0\.0\.0/, "localhost")}`);
  return out.slice(0, 3);
}

/** How Claude runs `vswarm shot`: the installed launcher, else bun with this checkout. */
const SHOT = existsSync(join(paths.bin(), process.platform === "win32" ? "vswarm.cmd" : "vswarm"))
  ? join(paths.bin(), process.platform === "win32" ? "vswarm.cmd" : "vswarm")
  : `${process.execPath} ${join(import.meta.dir, "cli.ts")}`;

function systemPrompt(c: Config, cwd: string, dirs: string[]): string {
  const blocked = c.block.filter(isGroup);
  return [
    c.mode === "swarm" &&
      `Permissions: you may edit files and run any local command in ${[cwd, ...dirs].join(", ")} without asking. ` +
        (blocked.length ? `By the user's policy these are blocked: ${blocked.map((g) => GROUPS[g]).join("; ")}. ` : "") +
        (blocked.includes("network") ? `Commands run in a sandbox that only reaches: ${c.domains.join(", ")}. ` : "") +
        "Do not try to work around a block. When a task needs a blocked step, finish the rest and give the user the exact command; " +
        "they can run it themselves by typing `!<command>` on the board. To write outside these folders, ask the user to type `/add-dir <path>`. " +
        "Local ports and localhost work: start dev servers with run_in_background (they never exit), read the real URL from their output, " +
        "and put that URL in your reply so the board shows an open button. " +
        `To see what you built, take a screenshot and look at it: \`${SHOT} shot <localhost URL or file> --out shot.png\` (WebGL works; add --size 1280x800, --wait 6000), ` +
        "then Read the png. Run it as a Bash call of its own, exactly in that form: no `cd`, `&&`, pipes or VAR= prefix, because only that form may leave the sandbox to start Chrome. " +
        "Check visual work this way before you call it done; fix what looks wrong.",
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
  /** Folders besides cwd this run may edit: from config, flags, and /add-dir typed on the board. */
  const dirs = [...new Set([...c.dirs, ...(o.dirs ?? [])].map((d) => resolve(o.cwd, d.replace(/^~(?=$|\/)/, homedir()))))];
  const writeSettings = () =>
    writeFileSync(settings, JSON.stringify({
      hooks: hooksConfig(events),
      ...(c.mode === "swarm" ? swarmSettings(c.block.filter(isGroup), c.domains, dirs, SHOT) : {}),
    }, null, 2));
  writeSettings();
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

  const ui: Ui = { mode: "run", busy: false, input: "", options: [], pick: -1, hint: `in ${o.cwd} · mode ${c.mode} · /help` };
  let child: ReturnType<typeof Bun.spawn> | null = null;
  let lastText = "";
  let resolveTurn: (() => void) | null = null;
  let ended = false;
  let restarting = false;
  /** Output of `!commands` the user ran, handed to Claude with their next message. */
  let ranNote = "";

  const start = () => {
    writeSettings();
    const swarmMode = c.mode === "swarm";
    const args = [
      "claude", "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
      "--model", c.lead, "--settings", settings, "--append-system-prompt", systemPrompt(c, o.cwd, dirs),
      ...(!swarmMode && c.mode && c.mode !== "default" ? ["--permission-mode", c.mode] : []),
      ...(!swarmMode && c.allow.length ? ["--allowedTools", c.allow.join(" ")] : []),
      ...dirs.filter((d) => existsSync(d)).flatMap((d) => ["--add-dir", d]),
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
        VSWARM_BLOCK: swarmMode ? c.block.join(",") : "",
        VSWARM_RUN_EVENTS: events,
      },
    });
    child = p;
    void read(p);
    void (async () => {
      const err = await new Response(p.stderr as ReadableStream).text();
      const code = await p.exited;
      if (child === p) child = null;
      if (!ended && !restarting && code !== 0) post({ type: "say", who: "vswarm", text: `claude exited with code ${code}${err.trim() ? `: ${err.trim().split("\n").slice(-2).join(" ")}` : ""}` });
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

  /** Set while the lead's turn is over but its background subagents are still at work. */
  let waitingSince = 0;
  let confirmEnd = false;
  let lastMessageAt = Date.now();
  // When the last subagent is done and the lead has not started a turn of its own, prompt it to collect the results.
  const nudger = setInterval(() => {
    if (!waitingSince || !child) return;
    if (s.agents.some((a) => a.status === "running")) return;
    if (Date.now() - lastMessageAt < 8000) return;
    waitingSince = 0;
    const p = child;
    (p.stdin as any).write(JSON.stringify({ type: "user", message: { role: "user", content: "All your subagents have finished. Collect their results and continue the task." } }) + "\n");
    (p.stdin as any).flush?.();
    note("subagents finished · asked the lead to continue");
  }, 1000);

  const onMessage = (m: any) => {
    lastMessageAt = Date.now();
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
      waitingSince = 0;
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
      // A file outside the allowed folders: offer the folder as a one-key /add-dir.
      const outside = [...new Set(denied
        .map((d) => String(d.tool_input?.file_path ?? d.tool_input?.notebook_path ?? ""))
        .filter((f) => f.startsWith("/") && ![o.cwd, ...dirs].some((d) => f.startsWith(d + "/")))
        .map((f) => dirname(f)))];
      if (denied.length) {
        const what = [...new Set(denied.map((d) => d.tool_name))].join(", ");
        post({
          type: "say",
          who: "vswarm",
          text: outside.length
            ? `blocked: ${what} outside the allowed folders. Type /add-dir ${outside[0]} (or pick it below) and ask again.`
            : c.mode === "swarm"
              ? `blocked: ${what}. That is outside swarm policy (${c.block.join(", ")}); run it yourself with !<command>, or /unblock <group>.`
              : `blocked by permissions: ${what}. Type /mode swarm to allow everything except deploys and traffic out.`,
        });
      }
      if (typeof m.result === "string" && m.result.trim()) lastText = m.result.trim();
      ui.options = outside.length ? outside.map((d) => `/add-dir ${d}`) : [...openables(lastText, o.cwd), ...questionOptions(lastText)].slice(0, 9);
      ui.pick = -1;
      ui.hint = ui.options.length ? "" : `turn ${meta.turns} done · $${meta.costUsd.toFixed(3)} · reply to continue, esc to end`;
      // Background subagents outlive the lead's turn; the lead picks up their results in a turn of its own.
      const running = s.agents.filter((a) => a.status === "running").length;
      if (running) {
        ui.busy = true;
        waitingSince = Date.now();
        ui.hint = `lead is waiting for ${running} subagent${running > 1 ? "s" : ""}`;
      }
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

  /** Stops the claude process; the next message starts it again on the same session with new settings. */
  const restart = async () => {
    const p = child;
    if (!p) return;
    restarting = true;
    try {
      (p.stdin as any).end();
    } catch {}
    const timer = setTimeout(() => p.kill(), 5000);
    await p.exited;
    clearTimeout(timer);
    child = null;
    restarting = false;
  };

  const note = (text: string) => post({ type: "say", who: "vswarm", text });

  /** `!command`: the user's own shell command, outside Claude's sandbox, with its output kept for Claude. */
  const runLocal = async (cmd: string) => {
    note(`$ ${cmd}`);
    const p = Bun.spawn(process.platform === "win32" ? ["cmd", "/c", cmd] : ["sh", "-c", cmd], { cwd: o.cwd, stdout: "pipe", stderr: "pipe", stdin: "ignore" });
    const timer = setTimeout(() => p.kill(), 120_000);
    const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
    clearTimeout(timer);
    const text = (out + err).trim().split("\n").slice(-30).join("\n");
    note(`${text || "(no output)"}\nexit ${code}`);
    ranNote += `I ran this myself in ${o.cwd}:\n$ ${cmd}\n${text.slice(-3000)}\n(exit ${code})\n\n`;
    ui.hint = "the output goes to Claude with your next message";
  };

  const HELP =
    "!<command>  run a shell command yourself (not sandboxed); Claude sees the output with your next message\n" +
    "/add-dir <path>  let Claude edit another folder (created if missing)\n" +
    "/mode <swarm|acceptEdits|default|plan>  change permissions\n" +
    "/block <group> · /unblock <group>  groups: push, deploy, network, sudo\n" +
    "/open <url|file>  open in the browser or default app\n" +
    "/policy  show what is allowed · /help  this list";

  /** Board commands typed into the reply box. Returns true when the text was one. */
  const command = async (text: string): Promise<boolean> => {
    if (text.startsWith("!")) {
      await runLocal(text.slice(1).trim());
      return true;
    }
    if (!text.startsWith("/")) return false;
    const [cmd, ...rest] = text.slice(1).split(/\s+/);
    const arg = rest.join(" ").trim();
    switch (cmd) {
      case "help":
        note(HELP);
        return true;
      case "add-dir": {
        if (!arg) return note("usage: /add-dir <path>"), true;
        const d = resolve(o.cwd, arg.replace(/^~(?=$|\/)/, homedir()));
        mkdirSync(d, { recursive: true });
        if (!dirs.includes(d)) dirs.push(d);
        await restart();
        note(`Claude may now edit ${d}`);
        ranNote += `The user added ${d} as a folder you may edit.\n\n`;
        return true;
      }
      case "mode":
        if (!["swarm", "acceptEdits", "default", "plan", "auto", "dontAsk"].includes(arg)) return note("usage: /mode swarm|acceptEdits|default|plan"), true;
        c.mode = arg;
        await restart();
        note(`mode ${arg} for this session · keep it: vswarm config mode ${arg}`);
        return true;
      case "block":
      case "unblock": {
        if (!isGroup(arg)) return note("groups: push, deploy, network, sudo"), true;
        c.block = cmd === "block" ? [...new Set([...c.block, arg])] : c.block.filter((g) => g !== arg);
        await restart();
        note(`${cmd === "block" ? "blocking" : "allowing"} ${arg} for this session · now blocked: ${c.block.join(", ") || "nothing"}`);
        return true;
      }
      case "open": {
        if (!arg) return note("usage: /open <url or file>"), true;
        const target = /^[a-z]+:\/\//i.test(arg) ? arg : resolve(o.cwd, arg.replace(/^~(?=$|\/)/, homedir()));
        const opener = process.platform === "darwin" ? ["open", target] : process.platform === "win32" ? ["cmd", "/c", "start", "", target] : ["xdg-open", target];
        const code = await Bun.spawn(opener, { stdout: "ignore", stderr: "ignore" }).exited;
        note(code === 0 ? `opened ${target}` : `could not open ${target} (exit ${code})`);
        return true;
      }
      case "policy":
        note(
          `mode ${c.mode} · folders ${[o.cwd, ...dirs].join(", ")}\n` +
            (c.mode === "swarm"
              ? `blocked: ${c.block.map((g) => `${g} (${GROUPS[g as keyof typeof GROUPS] ?? g})`).join("; ") || "nothing"}\nreachable hosts: ${c.block.includes("network") ? c.domains.join(", ") : "any"}`
              : `allowed tools: ${c.allow.join(" ")}`),
        );
        return true;
    }
    note(`unknown command /${cmd} · /help`);
    return true;
  };

  const send = (shown: string) => {
    if (!child) start();
    const p = child!;
    const text = ranNote ? `${ranNote}${shown}` : shown;
    ranNote = "";
    (p.stdin as any).write(JSON.stringify({ type: "user", message: { role: "user", content: text } }) + "\n");
    (p.stdin as any).flush?.();
    if (!meta.prompt) {
      meta.prompt = text;
      saveMeta(meta);
    }
    // Shown right away; the UserPromptSubmit hook reports the same text and is folded into this line.
    post({ type: "say", who: "you", text: shown });
    ui.busy = true;
    ui.input = "";
    ui.options = [];
    ui.pick = -1;
    ui.hint = "";
  };

  const turn = () => new Promise<void>((r) => (resolveTurn = r));

  const finish = async (status: RunMeta["status"]) => {
    ended = true;
    clearInterval(nudger);
    // Ending the session stops its subagents; say so, or a later resume would wait for them.
    for (const a of s.agents) if (a.status === "running") post({ type: "agent.stop", id: a.id, ok: false });
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
        if (waitingSince) {
          // Ending now would stop subagents mid-work, so it takes a second press.
          if (confirmEnd) return done("interrupted");
          confirmEnd = true;
          ui.hint = "subagents are still working · esc again to stop them and end";
          return;
        }
        return ui.busy ? interrupt() : done("done");
      case "ctrl-d":
        if (!ui.busy && !ui.input) done("done");
        return;
      case "enter": {
        const text = (ui.input ?? "").trim();
        if (!text) return;
        if (text.startsWith("!") || text.startsWith("/")) {
          ui.input = "";
          ui.options = [];
          void command(text);
          return;
        }
        if (ui.busy) return;
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
