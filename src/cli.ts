#!/usr/bin/env bun
// vswarm — live board for Claude Code: the lead, its subagents, Jev decisions and an advisor, plus a chat to answer Claude.

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ADVISOR_ENV } from "./advisor";
import { react } from "./brain";
import { demo, demoUntil } from "./demo";
import { follow } from "./follow";
import { findRun, listRuns, runEvents } from "./history";
import { append, map } from "./hook";
import { DEFAULTS, ensureHome, loadConfig, paths, saveConfig, VERSION, type Config } from "./home";
import { globalSettings, hasHooks, projectSettings, setHooks } from "./hooks";
import { askJev, jevKey } from "./jev";
import { GROUPS, isGroup } from "./policy";
import { homedir } from "node:os";
import { activeDir, authStatus, loginHint, profiles } from "./claude";
import type { Screen } from "./screen";
import { runSession } from "./session";
import { ask, banner, c, canAsk, COMMANDS, completion, doctor, install, uninstall, update } from "./setup";
import { apply, initial, type Stamped, type State } from "./state";
import { board, type Key } from "./tui";
import { draw, questionOptions, type Ui } from "./view";

function flag(args: string[], ...names: string[]): string | undefined {
  for (const name of names) {
    const i = args.indexOf(name);
    if (i >= 0) return args.splice(i, 2)[1];
  }
}

function has(args: string[], ...names: string[]): boolean {
  let found = false;
  for (const name of names) {
    const i = args.indexOf(name);
    if (i >= 0) {
      args.splice(i, 1);
      found = true;
    }
  }
  return found;
}

function page(scr: Screen): string {
  return `<!doctype html><meta charset="utf-8"><body style="margin:0;background:#0a0e18">` +
    `<pre style="margin:0;padding:18px 22px;font:15px/1.2 Menlo,monospace;color:#e4e9f5">${scr.html()}</pre>`;
}

/** Shows a state on the board until q; `tick` may change it between frames. */
async function show(ui: Ui, state: () => State, onKey?: (k: Key) => void): Promise<void> {
  await new Promise<void>((done) => {
    const b = board((cols, rows, n) => draw(state(), n, Date.now(), { w: cols, h: rows, ui }).toString(cols, rows), (k) => {
      if (k.name === "ctrl-c" || k.name === "esc" || (k.name === "text" && k.text === "q")) {
        b.stop();
        done();
      } else onKey?.(k);
    });
  });
}

function usage() {
  banner("live board for Claude Code");
  const row = (cmd: string, desc: string) => console.log(`  ${c.cyan(cmd.padEnd(34))}${c.dim(desc)}`);
  console.log(`  ${c.bold("start")}`);
  row("vswarm", "open the board and type a prompt");
  row('vswarm run "<prompt>"', "run a prompt on the board, answer Claude there");
  row("vswarm resume [n|id] [prompt]", "continue an earlier session");
  row('vswarm run -p "<prompt>"', "no board: print the answer (for scripts)");
  console.log(`\n  ${c.bold("look")}`);
  row("vswarm watch", "board for every session that has hooks");
  row("vswarm history", "earlier runs, newest first");
  row("vswarm replay [n|id] [--speed 4]", "play a run back on the board");
  row("vswarm demo", "scripted board, no API calls");
  console.log(`\n  ${c.bold("set up")}`);
  row("vswarm install", "launcher, PATH, completions, config, Jev key");
  row("vswarm doctor", "check the installation");
  row("vswarm config [key value]", "lead swarm advisor advisorAt mode allow jev reset");
  row("vswarm hooks on|off|status [dir|--global]", "show normal claude sessions on watch");
  row("vswarm update · vswarm uninstall", "pull the latest · remove (data kept unless --purge)");
  console.log(`\n  ${c.bold("tools")}`);
  row('vswarm jev --q "<q>" --state "<ctx>" a b', "ask Jev, the decision shows on the board");
  row("vswarm emit '<event json>'", "post any event");
  row("vswarm snapshot [--html|--plain]", "print one demo frame");
  row("vswarm completions zsh|bash", "print a completion script");
  console.log(`\n  ${c.bold("run flags")}  ${c.dim("--model sonnet  --swarm haiku  --advisor opus | --no-advisor  --mode acceptEdits  --profile work")}`);
  console.log(`             ${c.dim("--cwd <dir>  --frames <dir>  -- <any claude flags>")}`);
  console.log(`             ${c.dim("--add-dir <dir> (repeatable)")}`);
  console.log(`  ${c.bold("on the board")}  ${c.dim("⏎ send · 1-9 or ↑↓ pick a choice · esc interrupt, then end · ctrl-c quit")}`);
  console.log(`                ${c.dim("!<cmd> run it yourself · /add-dir <path> · /mode swarm · /unblock network · /policy · /help")}\n`);
}

/** Run flags on top of the saved config. */
function runConfig(args: string[]): Config {
  const cfg = loadConfig();
  const model = flag(args, "--model", "-m");
  const swarm = flag(args, "--swarm");
  const adv = flag(args, "--advisor");
  const mode = flag(args, "--mode");
  const profile = flag(args, "--profile");
  if (profile) cfg.profile = profile === "default" || profile === "auto" ? (profile === "auto" ? "" : "default") : profile;
  if (model) cfg.lead = model;
  if (swarm) cfg.swarm = swarm === "off" ? "" : swarm;
  if (adv) cfg.advisor = adv === "off" ? "" : adv;
  if (has(args, "--no-advisor")) cfg.advisor = "";
  if (mode) cfg.mode = mode;
  return cfg;
}

const MODES = ["swarm", "default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions"];

/** "+a -b" edits a list, anything else replaces it. */
function editList(list: string[], value: string): string[] {
  const items = value.split(/[,\s]+/).filter(Boolean);
  if (!items.every((x) => /^[+-]/.test(x))) return items;
  let out = [...list];
  for (const x of items) {
    out = out.filter((a) => a !== x.slice(1));
    if (x[0] === "+") out.push(x.slice(1));
  }
  return out;
}

async function config(args: string[]) {
  const cfg = loadConfig();
  const [key, ...rest] = args;
  const value = rest.join(" ").trim();
  if (!key) {
    banner("config");
    const row = (k: string, v: string, d: string) => console.log(`  ${c.cyan(k.padEnd(10))}${v.padEnd(44)}${c.dim(d)}`);
    row("profile", cfg.profile || "(CLAUDE_CONFIG_DIR or ~/.claude)", "Claude Code account · vswarm config profile");
    row("lead", cfg.lead, "main session model");
    row("swarm", cfg.swarm || "(lead picks)", "subagent model");
    row("advisor", cfg.advisor || "off", "reviews at checkpoints");
    row("advisorAt", cfg.advisorAt.join(","), "plan, error, done");
    row("mode", cfg.mode, "swarm · default · acceptEdits · plan · auto");
    row("block", cfg.block.join(" ") || "(nothing)", "swarm refuses: push deploy network sudo");
    row("domains", `${cfg.domains.length} hosts`, "sandbox may reach (package registries)");
    row("dirs", cfg.dirs.join(" ") || "(cwd only)", "extra folders runs may edit");
    row("allow", cfg.allow.join(" ") || "(none)", "tools allowed in the Claude Code modes");
    row("jev", jevKey() ? "set" : "not set", "vswarm config jev");
    console.log(c.dim(`\n  ${paths.config()}\n  change: vswarm config <key> <value> · allow +Edit / -Edit · reset\n`));
    return;
  }
  switch (key) {
    case "reset":
      saveConfig({ ...DEFAULTS });
      return console.log(`${c.lime("✔")} config reset`);
    case "jev": {
      let k = value;
      if (!k) {
        if (!canAsk()) throw new Error("usage: vswarm config jev <key>");
        k = await ask("Jev API key:", { secret: true });
      }
      if (!k) return;
      ensureHome();
      writeFileSync(paths.jevKey(), k + "\n", { mode: 0o600 });
      return console.log(`${c.lime("✔")} jev key saved ${c.dim(paths.jevKey())}`);
    }
    case "profile": {
      if (!value) {
        banner("claude accounts");
        const active = activeDir();
        for (const p of await profiles()) {
          const mark = p.dir === active ? c.cyan("▶") : " ";
          const st = p.loggedIn ? c.lime("● logged in") : c.rose("○ logged out");
          console.log(`  ${mark} ${p.name.padEnd(12)}${st.padEnd(24)}${c.dim(p.dir + (p.expires ? ` · until ${p.expires.slice(0, 10)}` : ""))}`);
        }
        console.log(c.dim(`\n  use one: vswarm config profile <name> · back to the default: vswarm config profile auto\n`));
        return;
      }
      cfg.profile = value === "auto" ? "" : value;
      saveConfig(cfg);
      const p = await authStatus(activeDir());
      console.log(`${c.lime("✔")} profile = ${value} ${c.dim(activeDir())}`);
      if (!p.loggedIn) console.log(`${c.amber("!")} that account is not logged in · ${loginHint(activeDir())}`);
      return;
    }
    case "lead":
    case "swarm":
    case "advisor":
      if (!value) return console.log(cfg[key] || "off");
      cfg[key] = value === "off" ? "" : value;
      break;
    case "advisorAt": {
      const v = value.split(/[,\s]+/).filter(Boolean);
      if (v.some((x) => !["plan", "error", "done"].includes(x))) throw new Error("advisorAt takes plan, error, done");
      cfg.advisorAt = v;
      break;
    }
    case "mode":
      if (!MODES.includes(value)) throw new Error(`mode is one of: ${MODES.join(", ")}`);
      cfg.mode = value;
      break;
    case "block": {
      const v = editList(cfg.block, value);
      const bad = v.filter((g) => !isGroup(g));
      if (bad.length) throw new Error(`unknown group ${bad.join(", ")} · groups: ${Object.keys(GROUPS).join(", ")}`);
      cfg.block = v;
      break;
    }
    case "domains":
      if (!value) return console.log(cfg.domains.join("\n"));
      cfg.domains = editList(cfg.domains, value);
      break;
    case "dirs":
      cfg.dirs = editList(cfg.dirs, value).map((d) => resolve(d.replace(/^~(?=$|\/)/, homedir())));
      break;
    case "allow": {
      const items = value.split(/[,\s]+/).filter(Boolean);
      if (items.every((x) => /^[+-]/.test(x))) {
        for (const x of items) {
          const name = x.slice(1);
          cfg.allow = cfg.allow.filter((a) => a !== name);
          if (x[0] === "+") cfg.allow.push(name);
        }
      } else cfg.allow = items;
      break;
    }
    default:
      throw new Error(`unknown config key "${key}" · see: vswarm config`);
  }
  saveConfig(cfg);
  console.log(`${c.lime("✔")} ${key} = ${String((cfg as any)[key] instanceof Array ? (cfg as any)[key].join(" ") : (cfg as any)[key] || "off")}`);
}

function history(args: string[]) {
  const runs = listRuns();
  banner("history");
  if (!runs.length) return console.log(c.dim('  no runs yet · vswarm run "<prompt>"\n'));
  const all = has(args, "--all", "-a");
  const shown = all ? runs : runs.slice(0, 15);
  const when = (t: number) => {
    const d = new Date(t);
    return `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  };
  console.log(c.dim(`  ${"#".padStart(3)}  ${"when".padEnd(12)}${"time".padStart(6)}  turns  lanes      cost  prompt`));
  shown.forEach((r, i) => {
    const dur = Math.round(((r.ended ?? r.started) - r.started) / 1000);
    const st = r.status === "done" ? c.lime("●") : r.status === "running" ? c.cyan("◐") : r.status === "error" ? c.rose("●") : c.amber("●");
    console.log(
      `  ${String(i + 1).padStart(3)}  ${when(r.started).padEnd(12)}${`${Math.floor(dur / 60)}m${String(dur % 60).padStart(2, "0")}`.padStart(6)}  ` +
        `${String(r.turns).padStart(5)}  ${String(r.subagents).padStart(5)}  ${("$" + r.costUsd.toFixed(2)).padStart(8)}  ${st} ${(r.prompt || "(no prompt)").replace(/\s+/g, " ").slice(0, 60)}`,
    );
  });
  if (!all && runs.length > shown.length) console.log(c.dim(`  … ${runs.length - shown.length} more · --all`));
  console.log(c.dim("\n  vswarm replay <#> · vswarm resume <#>\n"));
}

async function replay(args: string[]) {
  const speed = Number(flag(args, "--speed") ?? 4);
  const run = findRun(args[0]);
  const events = runEvents(run.id);
  if (!events.length) throw new Error("this run has no events");
  let s = initial();
  let i = 0;
  let paused = false;
  let quit = false;
  const ui: Ui = { mode: "replay" };
  const play = (async () => {
    while (i < events.length && !quit) {
      if (paused) {
        await Bun.sleep(100);
        continue;
      }
      const e = events[i++];
      apply(s, e);
      const next = events[i];
      // Long quiet stretches are squeezed so the replay keeps moving.
      if (next) await Bun.sleep(Math.min(1500, Math.max(0, ((next.t ?? 0) - (e.t ?? 0)) / speed)));
    }
  })();
  await show(ui, () => s, (k) => {
    if (k.name === "space") paused = !paused;
  });
  quit = true;
  await play;
}

async function main() {
  const argv = process.argv.slice(2);
  let [cmd = process.stdin.isTTY && process.stdout.isTTY ? "run" : "help", ...args] = argv;
  // `vswarm "fix the login bug"` is a run.
  if (/\s/.test(cmd) && !COMMANDS.some(([n]) => n === cmd)) {
    args.unshift(cmd);
    cmd = "run";
  }
  const file = flag(args, "--file") ?? paths.events();

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
          append(file, [{ t: Date.now(), sid: payload.session_id, type: "error", text: `vswarm: ${err.message ?? err}` } as Stamped]);
        } catch {}
      }
      return;
    }

    case "run":
    case "resume": {
      const dash = args.indexOf("--");
      const extra = dash >= 0 ? args.splice(dash).slice(1) : [];
      const cfg = runConfig(args);
      const frames = flag(args, "--frames");
      const print = has(args, "--print", "-p") || !process.stdout.isTTY;
      const cwdFlag = flag(args, "--cwd");
      const addDirs: string[] = [];
      for (let d = flag(args, "--add-dir"); d; d = flag(args, "--add-dir")) addDirs.push(d);
      let resume;
      if (cmd === "resume") {
        resume = findRun(args.shift());
        if (!resume.sid) throw new Error("that run never reached Claude, nothing to resume");
      }
      const cwd = resolve(cwdFlag ?? resume?.cwd ?? ".");
      const prompt = args.join(" ").trim() || undefined;
      ensureHome();
      process.exitCode = await runSession({ prompt, cwd, config: cfg, extra, resume, print, frames, page, dirs: addDirs });
      return;
    }

    case "demo": {
      const s = initial();
      let quit = false;
      const done = show({ mode: "demo" }, () => s).then(() => (quit = true));
      for await (const e of demo()) {
        if (quit) break;
        if (e.type === "session") Object.assign(s, initial());
        apply(s, e);
      }
      await done;
      return;
    }

    case "snapshot": {
      const s = initial();
      for (const e of demoUntil(Number(flag(args, "--at") ?? 9000))) apply(s, e);
      const ui: Ui = has(args, "--run")
        ? { mode: "run", busy: s.phase !== "done", input: "", options: questionOptions(s.chat.at(-1)?.text), pick: 1 }
        : { mode: "demo" };
      const scr = draw(s, 7, s.updatedAt, { ui, w: Number(flag(args, "--w") ?? 0) || undefined, h: Number(flag(args, "--h") ?? 0) || undefined });
      if (has(args, "--html")) console.log(page(scr));
      else console.log(has(args, "--plain") ? scr.plain() : scr.toString(scr.w, scr.h, true));
      return;
    }

    case "watch": {
      let s = initial();
      const unfollow = follow(file, (events, reset) => {
        if (reset) s = initial();
        for (const e of events) apply(s, e);
      });
      if (has(args, "--once")) {
        unfollow();
        console.log(draw(s, 0).plain());
        return;
      }
      await show({ mode: "watch" }, () => s);
      unfollow();
      return;
    }

    case "history":
    case "ls":
      return history(args);
    case "replay":
      return replay(args);

    case "hooks": {
      const action = args.shift() ?? "status";
      const global = has(args, "--global", "-g");
      const path = global ? globalSettings() : projectSettings(args[0] ?? ".");
      if (action === "status") {
        console.log(`${hasHooks(globalSettings()) ? c.lime("● on ") : c.dim("○ off")}  global   ${c.dim(globalSettings())}`);
        if (!global) console.log(`${hasHooks(path) ? c.lime("● on ") : c.dim("○ off")}  project  ${c.dim(path)}`);
        return;
      }
      if (action !== "on" && action !== "off") throw new Error("usage: vswarm hooks on|off|status [dir|--global]");
      setHooks(path, action === "on", process.env.VSWARM_FILE ? file : undefined);
      console.log(`${c.lime("✔")} hooks ${action} · ${c.dim(path)}`);
      if (action === "on") console.log(c.dim("  start a new claude session there, then: vswarm watch"));
      return;
    }

    case "config":
      return config(args);
    case "install":
      return install(args);
    case "uninstall":
      return uninstall(args);
    case "update":
    case "upgrade":
      return update();
    case "doctor": {
      banner("doctor");
      if (!(await doctor())) process.exitCode = 1;
      return;
    }
    case "completions":
      process.stdout.write(completion(args[0] ?? "zsh"));
      return;

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

    case "version":
    case "--version":
    case "-v":
      console.log(VERSION);
      return;

    case "help":
    case "--help":
    case "-h":
      return usage();

    default: {
      const near = COMMANDS.map(([n]) => n).find((n) => n.startsWith(cmd.slice(0, 2)));
      throw new Error(`unknown command "${cmd}"${near ? ` · did you mean: vswarm ${near}` : ""} · vswarm help`);
    }
  }
}

main().catch((err) => {
  if (process.stdout.isTTY) process.stdout.write("\x1b[?25h");
  console.error(`${c.rose("✖")} ${err.message ?? err}`);
  process.exit(1);
});
