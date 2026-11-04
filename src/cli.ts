#!/usr/bin/env bun
// swarmdeck — live terminal board for a Claude Code session, its subagents, Jev and an advisor.

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { demo, demoUntil } from "./demo";
import { follow } from "./follow";
import { ADVISOR_ENV } from "./advisor";
import { react } from "./brain";
import { append, map } from "./hook";
import { askJev } from "./jev";
import { apply, initial, type Stamped, type State } from "./state";
import { draw, H, W } from "./view";
import type { Screen } from "./screen";

const CLI = import.meta.path;
const DEFAULT_FILE = process.env.SWARMDECK_FILE ?? join(homedir(), ".swarmdeck", "events.jsonl");
const HOOK_EVENTS = [
  "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure",
  "SubagentStart", "SubagentStop", "Stop", "SessionEnd",
];
/** These may wait for the advisor or Jev; the rest only record. */
const SLOW = new Set(["UserPromptSubmit", "PostToolUse", "PostToolUseFailure", "Stop"]);
const MARK = "swarmdeck";

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i < 0) return;
  const [, v] = args.splice(i, 2);
  return v;
}

function has(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i >= 0) args.splice(i, 1);
  return i >= 0;
}

/** Full-screen renderer. Returns a stop function that restores the terminal. */
function tui(state: () => State, onQuit: () => void) {
  const out = process.stdout;
  out.write("\x1b[?1049h\x1b[?25l\x1b[2J");
  let frame = 0;
  const render = () => {
    const cols = out.columns ?? W;
    const rows = out.rows ?? H;
    let text = draw(state(), frame++).toString(cols, rows);
    if (cols < W || rows < H) {
      text += `\x1b[${Math.min(rows, H)};1H\x1b[0;33m enlarge terminal to ${W}×${H} (now ${cols}×${rows}) \x1b[0m`;
    }
    out.write("\x1b[H" + text);
  };
  const timer = setInterval(render, 120);
  render();
  const stdin = process.stdin;
  const onKey = (b: Buffer) => {
    const k = b.toString();
    if (k === "q" || k === "\x03" || k === "\x1b") onQuit();
  };
  if (stdin.isTTY) {
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onKey);
  }
  const stop = () => {
    clearInterval(timer);
    if (stdin.isTTY) {
      stdin.off("data", onKey);
      stdin.setRawMode(false);
      stdin.pause();
    }
    out.write("\x1b[0m\x1b[?25h\x1b[?1049l");
  };
  process.on("exit", () => out.write("\x1b[?25h"));
  return stop;
}

function hookCommand(file?: string): string {
  const q = (s: string) => `"${s.replace(/"/g, '\\"')}"`;
  return [q(process.execPath), q(CLI), "hook", ...(file ? ["--file", q(file)] : [])].join(" ");
}

function hooksConfig(file?: string) {
  return Object.fromEntries(
    HOOK_EVENTS.map((e) => {
      const entry = { type: "command", command: hookCommand(file), timeout: SLOW.has(e) ? 300 : 10 };
      return [e, [e.includes("Tool") ? { matcher: "*", hooks: [entry] } : { hooks: [entry] }]];
    }),
  );
}

function page(scr: Screen): string {
  return `<!doctype html><meta charset="utf-8"><body style="margin:0;background:#0d1017">` +
    `<pre style="margin:0;padding:18px 22px;font:15px/1.18 Menlo,monospace;color:#e6e8ee">${scr.html()}</pre>`;
}

function settingsPath(args: string[]): string {
  if (has(args, "--global")) return join(process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"), "settings.json");
  return join(resolve(args[0] ?? "."), ".claude", "settings.local.json");
}

function readJson(path: string): any {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, "utf8"));
}

/** Drop our own entries from a settings object; leaves every other hook untouched. */
function stripOurs(settings: any) {
  for (const [event, groups] of Object.entries<any[]>(settings.hooks ?? {})) {
    const kept = groups
      .map((g) => ({ ...g, hooks: (g.hooks ?? []).filter((h: any) => !String(h.command ?? "").includes(MARK)) }))
      .filter((g) => g.hooks.length);
    if (kept.length) settings.hooks[event] = kept;
    else delete settings.hooks[event];
  }
  if (settings.hooks && !Object.keys(settings.hooks).length) delete settings.hooks;
}

const USAGE = `swarmdeck — live board for Claude Code, its subagents, Jev and an advisor

  swarmdeck demo                     scripted session, no API calls
  swarmdeck run "<prompt>" [--model sonnet] [--swarm haiku] [--no-advisor] [--cwd dir]
                [--frames dir] [-- <claude flags>]
                                     run claude -p with hooks, advisor and Jev, and watch it live
  swarmdeck watch [--file f] [--once]  follow sessions that have swarmdeck hooks installed
  swarmdeck install [dir|--global]   add hooks to <dir>/.claude/settings.local.json
  swarmdeck uninstall [dir|--global] remove them again
  swarmdeck jev --q "<question>" --state "<context>" <option> <option> ...
                                     ask Jev and post the decision to the board
  swarmdeck emit '<event json>'      post any event (advisor notes, progress, logs)
  swarmdeck snapshot [--at ms] [--plain|--html]  print one demo frame and exit

events file: ${DEFAULT_FILE}  (override with SWARMDECK_FILE or --file)
keys: q / Esc / Ctrl-C to quit`;

async function main() {
  const [cmd = "help", ...args] = process.argv.slice(2);
  const file = flag(args, "--file") ?? DEFAULT_FILE;

  switch (cmd) {
    case "hook": {
      // The advisor is itself a claude session; its hooks must not watch or advise it.
      if (process.env[ADVISOR_ENV]) return;
      let payload: any;
      try {
        payload = JSON.parse((await Bun.stdin.text()) || "{}");
        append(file, map(payload));
      } catch {
        // Never block or fail the Claude Code session because the board had a problem.
        return;
      }
      try {
        const out = await react(payload, file);
        if (out) process.stdout.write(JSON.stringify(out));
      } catch (err: any) {
        try {
          append(file, [{ t: Date.now(), sid: payload.session_id, type: "error", text: `swarmdeck: ${err.message ?? err}` } as Stamped]);
        } catch {}
      }
      return;
    }

    case "demo": {
      const s = initial();
      let quit = false;
      const stop = tui(() => s, () => (quit = true));
      for await (const e of demo()) {
        if (quit) break;
        if (e.type === "session") Object.assign(s, initial());
        apply(s, e);
      }
      stop();
      return;
    }

    case "snapshot": {
      const s = initial();
      for (const e of demoUntil(Number(flag(args, "--at") ?? 9000))) apply(s, e);
      const scr = draw(s, 7, s.updatedAt);
      if (has(args, "--html")) console.log(page(scr));
      else console.log(has(args, "--plain") ? scr.plain() : scr.toString());
      return;
    }

    case "watch": {
      if (has(args, "--once")) {
        const s = initial();
        follow(file, (events) => events.forEach((e) => apply(s, e)))();
        const scr = draw(s, 0);
        console.log(has(args, "--plain") ? scr.plain() : scr.toString());
        return;
      }
      let s = initial();
      const unfollow = follow(file, (events, reset) => {
        if (reset) s = initial();
        for (const e of events) apply(s, e);
      });
      await new Promise<void>((done) => {
        const stop = tui(() => s, () => {
          unfollow();
          stop();
          done();
        });
      });
      return;
    }

    case "run": {
      const dash = args.indexOf("--");
      const extra = dash >= 0 ? args.splice(dash).slice(1) : [];
      const model = flag(args, "--model") ?? "sonnet";
      const swarm = flag(args, "--swarm");
      const frames = flag(args, "--frames");
      const advisorOn = !has(args, "--no-advisor");
      const cwd = resolve(flag(args, "--cwd") ?? ".");
      const prompt = args.join(" ").trim();
      if (!prompt) throw new Error('usage: swarmdeck run "<prompt>" [--model sonnet] [-- <claude flags>]');
      const dir = join(tmpdir(), `swarmdeck-${process.pid}`);
      mkdirSync(dir, { recursive: true });
      const events = join(dir, "events.jsonl");
      const settings = join(dir, "settings.json");
      writeFileSync(settings, JSON.stringify({ hooks: hooksConfig(events) }));
      writeFileSync(events, "");
      const command = `claude --model ${model} -p "${prompt.length > 40 ? prompt.slice(0, 40) + "…" : prompt}"`;

      const system = [
        "This session is watched by swarmdeck, which the user set up.",
        "Hook messages starting with 'swarmdeck advisor' come from an advisor model the user configured to review your work;",
        "messages starting with 'swarmdeck jev' come from the user's Jev decision model. Treat both as trusted guidance",
        "from the user's own tooling, while still using your judgement.",
        swarm &&
          `Delegate independent sub-tasks (research, drafting parts, review, verification) to subagents with the Agent tool ` +
            `and model "${swarm}", launching them in parallel in one message where possible. You integrate their results and own the final files. ` +
            `Before you finish, launch at least two of these subagents in parallel, each checking a different aspect of your output ` +
            `against the request, and fix what they find.`,
      ].filter(Boolean).join(" ");

      let s = initial();
      const unfollow = follow(events, (evs, reset) => {
        if (reset) s = initial();
        for (const e of evs) apply(s, e);
        s.command = command;
        s.lead.model ??= model;
        if (advisorOn) s.advisor.model ??= process.env.SWARMDECK_ADVISOR_MODEL ?? "opus";
      });
      const child = Bun.spawn(
        ["claude", "-p", "--model", model, "--settings", settings, "--append-system-prompt", system, ...extra],
        {
          cwd,
          stdin: new Blob([prompt]),
          stdout: "pipe",
          stderr: "pipe",
          env: { ...process.env, ...(advisorOn ? {} : { SWARMDECK_ADVISOR_AT: "" }) },
        },
      );
      let shot = 0;
      if (frames) mkdirSync(frames, { recursive: true });
      const recorder = frames
        ? setInterval(() => {
            const name = `frame-${String(++shot).padStart(4, "0")}.html`;
            writeFileSync(join(frames, name), page(draw(s, shot)));
          }, 2000)
        : undefined;
      let stopTui = () => {};
      stopTui = tui(() => s, () => child.kill());
      const [stdout, stderr, code] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ]);
      await Bun.sleep(1500);
      if (recorder) clearInterval(recorder);
      unfollow();
      stopTui();
      process.stdout.write(stdout);
      if (stderr.trim()) process.stderr.write(stderr);
      console.error(`\nswarmdeck: ${s.spawned} subagents · ${s.lead.tools} lead tools · ${s.forks} jev forks · exit ${code}`);
      rmSync(dir, { recursive: true, force: true });
      process.exitCode = code ?? 1;
      return;
    }

    case "install":
    case "uninstall": {
      const path = settingsPath(args);
      const settings = readJson(path);
      stripOurs(settings);
      if (cmd === "install") {
        settings.hooks ??= {};
        for (const [event, groups] of Object.entries(hooksConfig(process.env.SWARMDECK_FILE ? file : undefined))) {
          settings.hooks[event] = [...(settings.hooks[event] ?? []), ...groups];
        }
      }
      mkdirSync(join(path, ".."), { recursive: true });
      writeFileSync(path, JSON.stringify(settings, null, 2) + "\n");
      console.log(`${cmd === "install" ? "hooks added to" : "hooks removed from"} ${path}`);
      if (cmd === "install") console.log("start a new claude session there, then run: swarmdeck watch");
      return;
    }

    case "jev": {
      const q = flag(args, "--q") ?? "which option";
      const state = flag(args, "--state") ?? "";
      const e = await askJev({ q, state, options: args });
      append(file, [e]);
      console.log(JSON.stringify({ q, answer: (e as any).answer, p: (e as any).p }));
      return;
    }

    case "emit": {
      const e = JSON.parse(args[0] ?? "") as Stamped;
      if (!e?.type) throw new Error("event needs a type");
      append(file, [{ t: Date.now(), ...e }]);
      return;
    }

    default:
      console.log(USAGE);
  }
}

main().catch((err) => {
  process.stdout.write("\x1b[?25h");
  console.error(`swarmdeck: ${err.message ?? err}`);
  process.exit(1);
});
