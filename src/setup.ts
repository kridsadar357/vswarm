// Installing vswarm on a machine: launcher on PATH, shell completions, data folder, config, optional Jev key
// and hooks. Also `doctor` (check everything), `update` (git pull) and `uninstall`.

import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { DEFAULTS, ensureHome, HOME, loadConfig, paths, saveConfig, VERSION } from "./home";
import { CLI, globalSettings, hasHooks, setHooks } from "./hooks";
import { jevKey } from "./jev";

export const ROOT = resolve(dirname(CLI), "..");
const WIN = process.platform === "win32";

// ── Printing
const tty = process.stdout.isTTY;
const paint = (code: string) => (t: string) => (tty ? `\x1b[${code}m${t}\x1b[0m` : t);
export const c = {
  bold: paint("1"), dim: paint("2"), violet: paint("38;2;180;140;255"), cyan: paint("38;2;79;216;232"),
  lime: paint("38;2;155;227;106"), amber: paint("38;2;245;180;83"), rose: paint("38;2;255;107;139"),
};
export function banner(sub = "") {
  const logo = "V-SWARM";
  const grad = [...logo].map((ch, i) => {
    const t = i / (logo.length - 1);
    const rgb = [79 + (180 - 79) * t, 216 + (140 - 216) * t, 232 + (255 - 232) * t].map(Math.round).join(";");
    return tty ? `\x1b[1;38;2;${rgb}m${ch}` : ch;
  }).join("");
  console.log(`\n  ${c.violet("▼")} ${grad}${tty ? "\x1b[0m" : ""}  ${c.dim("v" + VERSION)}${sub ? "  " + c.dim(sub) : ""}\n`);
}
const ok = (t: string, d = "") => console.log(`  ${c.lime("✔")} ${t}${d ? "  " + c.dim(d) : ""}`);
const warn = (t: string, d = "") => console.log(`  ${c.amber("!")} ${t}${d ? "  " + c.dim(d) : ""}`);
const bad = (t: string, d = "") => console.log(`  ${c.rose("✖")} ${t}${d ? "  " + c.dim(d) : ""}`);
const step = (t: string) => console.log(`\n  ${c.bold(t)}`);

// ── Questions on the terminal
async function ask(question: string, { secret = false } = {}): Promise<string> {
  if (!process.stdin.isTTY) return "";
  process.stdout.write(`  ${c.cyan("?")} ${question} `);
  const stdin = process.stdin;
  stdin.setRawMode(true);
  stdin.resume();
  let value = "";
  return new Promise((done) => {
    const onData = (b: Buffer) => {
      for (const ch of b.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          stdin.off("data", onData);
          stdin.setRawMode(false);
          stdin.pause();
          process.stdout.write("\n");
          return done(value.trim());
        }
        if (ch === "\x03") {
          process.stdout.write("\n");
          process.exit(130);
        }
        if (ch === "\x7f" || ch === "\b") {
          if (value) {
            value = value.slice(0, -1);
            process.stdout.write("\b \b");
          }
          continue;
        }
        if (ch < " ") continue;
        value += ch;
        process.stdout.write(secret ? "•" : ch);
      }
    };
    stdin.on("data", onData);
  });
}

const yes = async (q: string, def = false) => {
  const a = (await ask(`${q} ${c.dim(def ? "[Y/n]" : "[y/N]")}`)).toLowerCase();
  return a ? a.startsWith("y") : def;
};

// ── Launcher and PATH
function launcherPath(): string {
  return join(paths.bin(), WIN ? "vswarm.cmd" : "vswarm");
}

function writeLauncher() {
  mkdirSync(paths.bin(), { recursive: true });
  const bun = process.execPath;
  if (WIN) {
    writeFileSync(launcherPath(), `@echo off\r\n"${bun}" "${CLI}" %*\r\n`);
  } else {
    writeFileSync(launcherPath(), `#!/bin/sh\n# vswarm launcher, written by \`vswarm install\`\nexec "${bun}" "${CLI}" "$@"\n`);
    chmodSync(launcherPath(), 0o755);
  }
}

const BLOCK_START = "# >>> vswarm >>>";
const BLOCK_END = "# <<< vswarm <<<";

function rcFiles(): { file: string; body: string }[] {
  const bin = paths.bin();
  const comp = join(HOME, "completions");
  const shell = (process.env.SHELL ?? "").split("/").pop();
  const out: { file: string; body: string }[] = [];
  const zsh = `export PATH="${bin}:$PATH"\nfpath=("${comp}" $fpath)\nautoload -Uz compinit 2>/dev/null && compinit -C 2>/dev/null`;
  const bash = `export PATH="${bin}:$PATH"\n[ -f "${comp}/vswarm.bash" ] && . "${comp}/vswarm.bash"`;
  if (shell === "zsh" || existsSync(join(homedir(), ".zshrc"))) out.push({ file: join(homedir(), ".zshrc"), body: zsh });
  if (shell === "bash" || existsSync(join(homedir(), ".bashrc"))) out.push({ file: join(homedir(), ".bashrc"), body: bash });
  if (shell === "fish") out.push({ file: join(homedir(), ".config", "fish", "conf.d", "vswarm.fish"), body: `fish_add_path "${bin}"` });
  if (!out.length) out.push({ file: join(homedir(), ".profile"), body: `export PATH="${bin}:$PATH"` });
  return out;
}

function setBlock(file: string, body: string | null) {
  const old = existsSync(file) ? readFileSync(file, "utf8") : "";
  const block = `${BLOCK_START}\n${body}\n${BLOCK_END}\n`;
  if (body !== null && old.includes(block)) return false;
  const re = new RegExp(`\\n?${BLOCK_START}[\\s\\S]*?${BLOCK_END}\\n?`, "g");
  const rest = old.replace(re, "\n").replace(/\n{3,}/g, "\n\n");
  const next = body === null ? rest : rest.trimEnd() + (rest.trim() ? "\n\n" : "") + block;
  if (next === old) return false;
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, next);
  return true;
}

async function windowsPath(add: boolean) {
  const bin = paths.bin();
  const ps = add
    ? `$p=[Environment]::GetEnvironmentVariable('Path','User'); if (-not ($p -split ';' -contains '${bin}')) { [Environment]::SetEnvironmentVariable('Path', ('${bin};' + $p).TrimEnd(';'), 'User') }`
    : `$p=[Environment]::GetEnvironmentVariable('Path','User'); [Environment]::SetEnvironmentVariable('Path', (($p -split ';') | Where-Object { $_ -ne '${bin}' }) -join ';', 'User')`;
  await Bun.spawn(["powershell", "-NoProfile", "-Command", ps], { stdout: "ignore", stderr: "ignore" }).exited;
}

// ── Completions
export const COMMANDS: [string, string][] = [
  ["run", "start a session on the live board"],
  ["resume", "continue an earlier session"],
  ["watch", "board for sessions that have hooks"],
  ["history", "list earlier runs"],
  ["replay", "play an earlier run back on the board"],
  ["demo", "scripted board, no API calls"],
  ["hooks", "turn hooks on/off for a project or globally"],
  ["config", "show or change settings"],
  ["jev", "ask Jev a question"],
  ["doctor", "check the installation"],
  ["install", "set up launcher, PATH, completions, config"],
  ["update", "pull the latest version"],
  ["uninstall", "remove launcher, PATH and hooks"],
  ["emit", "post an event to the board"],
  ["snapshot", "print one demo frame"],
  ["help", "show help"],
];

export function completion(shell: string): string {
  const names = COMMANDS.map(([n]) => n).join(" ");
  if (shell === "bash") {
    return `# vswarm bash completion
_vswarm() {
  local cur="\${COMP_WORDS[COMP_CWORD]}" prev="\${COMP_WORDS[1]}"
  if [ "$COMP_CWORD" -eq 1 ]; then COMPREPLY=( $(compgen -W "${names}" -- "$cur") ); return; fi
  case "$prev" in
    hooks) COMPREPLY=( $(compgen -W "on off status --global" -- "$cur") ) ;;
    config) COMPREPLY=( $(compgen -W "lead swarm advisor advisorAt mode allow jev reset" -- "$cur") ) ;;
    run|resume) COMPREPLY=( $(compgen -W "--model --swarm --advisor --no-advisor --mode --cwd --print --frames" -- "$cur") ) ;;
  esac
}
complete -F _vswarm vswarm
`;
  }
  const lines = COMMANDS.map(([n, d]) => `    '${n}:${d.replace(/'/g, "")}'`).join("\n");
  return `#compdef vswarm
# vswarm zsh completion
_vswarm() {
  local -a cmds
  cmds=(
${lines}
  )
  if (( CURRENT == 2 )); then _describe 'command' cmds; return; fi
  case "\${words[2]}" in
    hooks) _values 'action' on off status --global ;;
    config) _values 'key' lead swarm advisor advisorAt mode allow jev reset ;;
    run|resume) _arguments '--model[lead model]:model:(sonnet opus haiku fable)' '--swarm[subagent model]:model:(haiku sonnet opus)' \\
      '--advisor[advisor model]:model:(opus sonnet fable)' '--no-advisor[no advisor]' '--mode[permission mode]:mode:(default acceptEdits plan auto)' \\
      '--cwd[working directory]:dir:_files -/' '--print[no board, print the answer]' '--frames[save frames]:dir:_files -/' ;;
    replay|resume) _message 'run number or id (see vswarm history)' ;;
  esac
}
_vswarm "$@"
`;
}

function writeCompletions() {
  const dir = join(HOME, "completions");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "_vswarm"), completion("zsh"));
  writeFileSync(join(dir, "vswarm.bash"), completion("bash"));
}

// ── Checks
async function version(cmd: string[]): Promise<string | undefined> {
  try {
    const p = Bun.spawn(cmd, { stdout: "pipe", stderr: "ignore" });
    const out = await new Response(p.stdout).text();
    return (await p.exited) === 0 ? out.trim().split("\n")[0] : undefined;
  } catch {
    return;
  }
}

export async function doctor(): Promise<boolean> {
  let good = true;
  step("runtime");
  ok(`bun ${Bun.version}`, process.execPath);
  const claude = Bun.which("claude");
  const cv = claude ? await version(["claude", "--version"]) : undefined;
  if (cv) ok(`claude ${cv.replace(/\s*\(Claude Code\)/, "")}`, claude!);
  else {
    bad("claude not found", "install Claude Code: https://claude.com/claude-code");
    good = false;
  }
  const git = await version(["git", "--version"]);
  if (git) ok(git);
  else warn("git not found", "needed for vswarm update");

  step("vswarm");
  ok(`app ${ROOT}`);
  ok(`data ${HOME}`);
  const onPath = (process.env.PATH ?? "").split(WIN ? ";" : ":").includes(paths.bin());
  if (existsSync(launcherPath()) && onPath) ok("vswarm on PATH", launcherPath());
  else if (existsSync(launcherPath())) warn("launcher installed, new terminals will have it", `or: export PATH="${paths.bin()}:$PATH"`);
  else {
    warn("launcher not installed", "run: vswarm install");
    good = false;
  }
  const cfg = loadConfig();
  ok(`models  lead ${cfg.lead} · swarm ${cfg.swarm || "(lead picks)"} · advisor ${cfg.advisor || "off"}`);
  ok(`permissions  mode ${cfg.mode} · allow ${cfg.allow.join(" ") || "(none)"}`);
  if (jevKey()) ok("jev key set");
  else warn("no jev key", "optional · vswarm config jev");
  if (hasHooks(globalSettings())) ok("global hooks on", "every Claude Code session shows on vswarm watch");
  else console.log(`  ${c.dim("·")} global hooks off  ${c.dim("vswarm hooks on --global to watch every session")}`);
  console.log();
  return good;
}

// ── Commands
export async function install(args: string[]) {
  const auto = args.includes("--yes") || args.includes("-y") || !process.stdin.isTTY;
  banner("install");
  step("1  files");
  ensureHome();
  for (const d of [paths.runs(), paths.sessions()]) mkdirSync(d, { recursive: true });
  ok("data folder", HOME);
  if (!existsSync(paths.config())) {
    saveConfig({ ...DEFAULTS });
    ok("config written", paths.config());
  } else ok("config kept", paths.config());

  step("2  command");
  writeLauncher();
  ok("launcher", launcherPath());
  writeCompletions();
  ok("completions", join(HOME, "completions"));
  if (!args.includes("--no-path")) {
    if (WIN) {
      await windowsPath(true);
      ok("PATH updated for your user", paths.bin());
    } else {
      for (const { file, body } of rcFiles()) {
        const changed = setBlock(file, body);
        ok(changed ? `PATH added in ${file}` : `PATH already in ${file}`);
      }
    }
  }
  // Hooks written by an earlier install point at the old location; refresh them.
  if (hasHooks(globalSettings())) {
    setHooks(globalSettings(), true);
    ok("global hooks refreshed");
  }

  step("3  options");
  if (!jevKey() && !auto) {
    const key = await ask(`Jev API key ${c.dim("(enter to skip)")}`, { secret: true });
    if (key) {
      writeFileSync(paths.jevKey(), key + "\n", { mode: 0o600 });
      ok("jev key saved", paths.jevKey());
    } else console.log(`  ${c.dim("· skipped · add later: vswarm config jev")}`);
  } else if (jevKey()) ok("jev key found");
  if (!auto && !hasHooks(globalSettings())) {
    if (await yes("Show every Claude Code session on `vswarm watch` (global hooks)?")) {
      setHooks(globalSettings(), true);
      ok("global hooks on", globalSettings());
    }
  }

  await doctor();
  const rc = WIN ? "open a new terminal" : `open a new terminal, or: source ${rcFiles()[0].file}`;
  console.log(`  ${c.bold("next")}  ${c.dim(rc)}`);
  console.log(`        ${c.cyan("vswarm demo")}                  ${c.dim("see the board")}`);
  console.log(`        ${c.cyan('vswarm run "<prompt>"')}        ${c.dim("start a session")}`);
  console.log(`        ${c.cyan("vswarm")}                       ${c.dim("same, and type the prompt on the board")}\n`);
}

export async function uninstall(args: string[]) {
  banner("uninstall");
  if (existsSync(launcherPath())) rmSync(launcherPath());
  ok("launcher removed");
  if (WIN) await windowsPath(false);
  else for (const { file } of rcFiles()) if (setBlock(file, null)) ok(`PATH removed from ${file}`);
  if (hasHooks(globalSettings())) {
    setHooks(globalSettings(), false);
    ok("global hooks removed");
  }
  rmSync(join(HOME, "completions"), { recursive: true, force: true });
  if (args.includes("--purge")) {
    rmSync(HOME, { recursive: true, force: true });
    ok("data removed", HOME);
  } else console.log(`  ${c.dim(`· kept ${HOME} (runs, config, jev key) · remove it too with --purge`)}`);
  console.log(`  ${c.dim("· project hooks stay until: vswarm hooks off <dir> · the app folder stays at " + ROOT)}\n`);
}

export async function update() {
  banner("update");
  if (!existsSync(join(ROOT, ".git"))) throw new Error(`${ROOT} is not a git checkout; download the new version and run vswarm install`);
  const run = async (cmd: string[]) => {
    const p = Bun.spawn(cmd, { cwd: ROOT, stdout: "pipe", stderr: "pipe" });
    const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
    if (code !== 0) throw new Error(`${cmd.join(" ")}: ${err.trim() || out.trim()}`);
    return out.trim();
  };
  const before = await run(["git", "rev-parse", "--short", "HEAD"]);
  await run(["git", "pull", "--ff-only"]);
  const after = await run(["git", "rev-parse", "--short", "HEAD"]);
  if (before === after) ok("already up to date", before);
  else {
    ok(`updated ${before} → ${after}`);
    console.log(c.dim((await run(["git", "log", "--oneline", `${before}..${after}`])).split("\n").map((l) => "    " + l).join("\n")));
  }
  await run([process.execPath, "install", "--production"]);
  writeLauncher();
  writeCompletions();
  if (hasHooks(globalSettings())) setHooks(globalSettings(), true);
  ok("launcher, completions and hooks refreshed\n");
}
