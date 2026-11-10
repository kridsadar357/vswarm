// Installing vswarm on a machine: launcher on PATH, shell completions, data folder, a first baseline, and the
// gate in ~/.ssh/config. Also `doctor` (check the setup), `update` (git pull) and `uninstall`.

import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { ReadStream } from "node:tty";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { ensureHome, GLOBAL_TAG, HOME, paths, VERSION } from "./home";
import { dq, exec, run as quietRun, shq } from "./sec/ctx";
import { blockRegex, files, forgetKey, loadBaseline, lockState, readBaseline, recordManaged, removeBlock, stateKey, stripManaged } from "./sec/store";
import { GUARD_END, GUARD_START, guardBlock, loadGuardConfig, psGuardBlock, saveGuardConfig, type GuardConfig } from "./sec/pkg";
import { fingerprints, PIN, secureUpdate } from "./sec/update";
import { AGENT_END, AGENT_START, blockHosts, cmdWord, GATE_END, GATE_START, refusedLine } from "./sec/sshblocks";
import { cells, colorDepth, dateOf, palette, verdictMark, width, wrap } from "./sec/print";
import { t, type Key } from "./i18n";

export const CLI = resolve(import.meta.dir, "cli.ts");

export const ROOT = resolve(dirname(CLI), "..");
const WIN = process.platform === "win32";

// ── Printing: what these commands print goes to stdout (console.log), coloured as stdout allows (print.ts).
const depth = () => colorDepth(process.stdout);
const p = palette(depth);
export const c = { ...p, lime: p.green, rose: p.red };
export function banner(sub = "") {
  const logo = "V-SWARM";
  const truecolor = depth() === 24;
  const grad = [...logo].map((ch, i) => {
    const k = i / (logo.length - 1);
    const rgb = [79 + (180 - 79) * k, 216 + (140 - 216) * k, 232 + (255 - 232) * k].map(Math.round).join(";");
    return truecolor ? `\x1b[1;38;2;${rgb}m${ch}` : ch;
  }).join("");
  const name = truecolor ? `${grad}\x1b[0m` : c.violet(c.bold(grad));
  console.log(`\n  ${c.violet("▼")} ${name}  ${c.dim("v" + VERSION)}${sub ? "  " + c.dim(sub) : ""}\n`);
}
const ok = (s: string, d = "") => console.log(`  ${c.lime("✔")} ${s}${d ? "  " + c.dim(d) : ""}`);
const warn = (s: string, d = "") => console.log(`  ${c.amber("!")} ${s}${d ? "  " + c.dim(d) : ""}`);
const bad = (s: string, d = "") => console.log(`  ${c.rose("✖")} ${s}${d ? "  " + c.dim(d) : ""}`);
const step = (s: string) => console.log(`\n  ${c.bold(s)}`);

// ── Questions on the terminal
// Keys are read from /dev/tty, not stdin: under `curl … | sh` stdin is the script, and Bun gets no keys
// from a stdin that was redirected from /dev/tty.
// VSWARM_NO_KEYBOARD (set by the tests, test/isolate.ts): no keyboard at all, as under a pipe or in CI. It can only
// take a question away, and a question with no one to answer it gets its default, or for a weakening command a no.
function keyboard(): (NodeJS.ReadStream & { setRawMode(m: boolean): void }) | undefined {
  if (process.env.VSWARM_NO_KEYBOARD) return;
  if (!WIN) {
    try {
      return new ReadStream(openSync("/dev/tty", "r")) as any;
    } catch {}
  }
  return process.stdin.isTTY ? (process.stdin as any) : undefined;
}

export function canAsk(): boolean {
  const k = keyboard();
  if (!k) return false;
  if (k !== (process.stdin as any)) k.destroy();
  return true;
}

export async function ask(question: string, { secret = false } = {}): Promise<string> {
  const k = keyboard();
  if (!k) return "";
  // A long question wraps at the width, under itself, so the answer never lands in the middle of a word.
  const w = width(process.stderr);
  process.stderr.write(`  ${c.cyan("?")} ${wrap(question, w ? w - 5 : 0).join("\n    ")} `);
  k.setRawMode(true);
  k.resume();
  let value = "";
  return new Promise((done) => {
    const close = () => {
      k.off("data", onData);
      k.setRawMode(false);
      if (k === (process.stdin as any)) k.pause();
      else k.destroy();
    };
    const onData = (b: Buffer) => {
      // A paste comes wrapped in bracketed-paste markers.
      const text = b.toString("utf8").replace(/\x1b\[20[01]~/g, "");
      for (const ch of text) {
        if (ch === "\r" || ch === "\n") {
          close();
          process.stderr.write("\n");
          return done(value.trim());
        }
        if (ch === "\x03") {
          close();
          process.stderr.write("\n");
          process.exit(130);
        }
        if (ch === "\x7f" || ch === "\b") {
          if (value) {
            value = [...value].slice(0, -1).join("");
            process.stderr.write("\b \b");
          }
          continue;
        }
        if (ch < " ") continue;
        value += ch;
        process.stderr.write(secret ? "•" : ch);
      }
    };
    k.on("data", onData);
  });
}

/** A yes/no question; the default answer when there is no terminal to ask on. */
export const yes = async (q: string, def = false) => {
  if (!canAsk()) return def;
  const a = (await ask(`${q} ${c.dim(def ? "[Y/n]" : "[y/N]")}`)).toLowerCase();
  return a ? a.startsWith("y") : def;
};

// ── Launcher and PATH
export function launcherPath(): string {
  return join(paths.bin(), WIN ? "vswarm.cmd" : "vswarm");
}

/** The launcher's text: runs vswarm with the Bun that installed it, or says plainly that one of the two has moved. */
export function launcherText(bun: string, cli: string, win = WIN): string {
  // Bun or the checkout gone (moved, upgraded to another path, the folder removed): a sentence that says so, and exit
  // 127, the code a shell gives for a missing program. The ssh blocks and the install guard read it as "cannot run".
  const gone = "vswarm cannot run: Bun or vswarm itself is no longer where it was installed. Reinstall: https://github.com/kridsadar357/vswarm#install";
  if (win) return `@echo off\r\nif not exist "${bun}" goto gone\r\nif not exist "${cli}" goto gone\r\n"${bun}" "${cli}" %*\r\nexit /b %errorlevel%\r\n:gone\r\necho ${gone} 1>&2\r\nexit /b 127\r\n`;
  return `#!/bin/sh\n# vswarm launcher, written by \`vswarm install\`\n[ -x ${dq(bun)} ] && [ -f ${dq(cli)} ] || { echo ${dq(gone)} >&2; exit 127; }\nexec ${dq(bun)} ${dq(cli)} "$@"\n`;
}

function writeLauncher() {
  mkdirSync(paths.bin(), { recursive: true });
  writeFileSync(launcherPath(), launcherText(process.execPath, CLI));
  if (!WIN) chmodSync(launcherPath(), 0o755);
}

/**
 * The launcher, written from this checkout when it is missing, so `watch on`, `guard on` and `agent on` work straight
 * from a clone (bun src/cli.ts …, or .\\vswarm.cmd on Windows) without `vswarm install` first. PATH is not touched.
 */
export function ensureLauncher(say: (t: string) => void = (t) => console.error(t)): string {
  if (existsSync(launcherPath())) return launcherPath();
  ensureHome();
  writeLauncher();
  say(`  ${c.lime("✔")} ${t("cli.install.launcherWritten")} ${c.dim(t("cli.install.launcherWhere", { launcher: launcherPath(), cli: CLI }))}`);
  return launcherPath();
}

const BLOCK_START = "# >>> vswarm >>>";
const BLOCK_END = "# <<< vswarm <<<";

/** A path inside the double quotes of a shell line. Plain paths pass through unchanged: the managed-block hashes depend on the exact text. */
const inDq = (p: string) => p.replace(/[\\"$`]/g, "\\$&");
/** The same for fish, where a backtick is an ordinary character. */
const inFishDq = (p: string) => p.replace(/[\\"$]/g, "\\$&");

export function rcFiles(home = homedir(), bin = paths.bin(), comp = paths.completions()): { file: string; body: string }[] {
  const shell = (process.env.SHELL ?? "").split("/").pop();
  const out: { file: string; body: string }[] = [];
  const [b, c] = [inDq(bin), inDq(comp)];
  const zsh = `export PATH="${b}:$PATH"\nfpath=("${c}" $fpath)\nautoload -Uz compinit 2>/dev/null && compinit -C 2>/dev/null`;
  const bash = `export PATH="${b}:$PATH"\n[ -f "${c}/vswarm.bash" ] && . "${c}/vswarm.bash"`;
  if (shell === "zsh" || existsSync(join(home, ".zshrc"))) out.push({ file: join(home, ".zshrc"), body: zsh });
  if (shell === "bash" || existsSync(join(home, ".bashrc"))) out.push({ file: join(home, ".bashrc"), body: bash });
  if (shell === "fish") out.push({ file: join(home, ".config", "fish", "conf.d", "vswarm.fish"), body: `fish_add_path "${inFishDq(bin)}"` });
  if (!out.length) out.push({ file: join(home, ".profile"), body: `export PATH="${b}:$PATH"` });
  return out;
}

type Enc = "utf8" | "utf8bom" | "utf16le" | "latin1";

/**
 * A file as text, with the encoding to write it back in. PowerShell profiles come as UTF-16 (Windows PowerShell's
 * own redirections), UTF-8 with or without a BOM, or the ANSI code page; a block added to one must not garble the rest.
 */
export function readKept(file: string): { text: string; enc: Enc } | undefined {
  if (!existsSync(file)) return;
  const buf = readFileSync(file);
  if (buf[0] === 0xff && buf[1] === 0xfe) return { text: buf.subarray(2).toString("utf16le"), enc: "utf16le" };
  if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return { text: buf.subarray(3).toString("utf8"), enc: "utf8bom" };
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(buf), enc: "utf8" };
  } catch {
    // Not UTF-8: bytes one to one, so whatever code page it is in comes back unchanged.
    return { text: buf.toString("latin1"), enc: "latin1" };
  }
}

export function writeKept(file: string, text: string, enc: Enc) {
  if (enc === "latin1" && /[^\x00-\xff]/.test(text)) throw new Error(`${file} is not UTF-8 and the new lines are; save it as UTF-8 first`);
  const bom = enc === "utf16le" ? Buffer.from([0xff, 0xfe]) : enc === "utf8bom" ? Buffer.from([0xef, 0xbb, 0xbf]) : Buffer.alloc(0);
  writeFileSync(file, Buffer.concat([bom, Buffer.from(text, enc === "utf16le" ? "utf16le" : enc === "latin1" ? "latin1" : "utf8")]));
}

export function setBlock(file: string, body: string | null, start = BLOCK_START, end = BLOCK_END) {
  const kept = readKept(file);
  const old = kept?.text ?? "";
  // body may carry its own markers (guardBlock does); the managed block is always start…end.
  const block = body?.startsWith(start) ? `${body}\n` : `${start}\n${body}\n${end}\n`;
  if (body !== null && old.includes(block)) return false;
  const rest = removeBlock(old, start, end);
  const next = body === null ? rest : rest.trimEnd() + (rest.trim() ? "\n\n" : "") + block;
  if (next === old) return false;
  mkdirSync(dirname(file), { recursive: true });
  // Windows PowerShell 5.1 reads a UTF-8 file without a BOM as ANSI: new profiles, and non-ASCII paths, get a BOM.
  const ps1 = file.toLowerCase().endsWith(".ps1");
  const enc: Enc = kept ? (ps1 && kept.enc === "utf8" && /[^\x00-\x7f]/.test(next) ? "utf8bom" : kept.enc) : ps1 ? "utf8bom" : "utf8";
  writeKept(file, next, enc);
  if (body !== null) recordManaged(block);
  return true;
}

/** The user's own PATH (not the machine's), through the registry value Windows reads for new terminals. */
async function windowsPath(add: boolean) {
  const { powershell } = await import("./sec/schedule");
  // The folder travels in an environment variable, so no character in it is read as PowerShell.
  const ps = add
    ? `$b=$env:VSWARM_BIN; $p=[Environment]::GetEnvironmentVariable('Path','User'); if (-not (@($p -split ';') -contains $b)) { [Environment]::SetEnvironmentVariable('Path', ($b + ';' + $p).TrimEnd(';'), 'User') }`
    : `$b=$env:VSWARM_BIN; $p=[Environment]::GetEnvironmentVariable('Path','User'); [Environment]::SetEnvironmentVariable('Path', ((@($p -split ';') | Where-Object { $_ -and $_ -ne $b }) -join ';'), 'User')`;
  const r = await exec([powershell(), "-NoProfile", "-NonInteractive", "-Command", ps], { env: { ...process.env, VSWARM_BIN: paths.bin() }, timeoutMs: 30_000 });
  if (r.code !== 0) warn("could not change your PATH", r.err.trim().split("\n")[0] || `exit ${r.code}`);
}

// ── Completions
export const COMMANDS: [string, string][] = [
  ["setup", "set everything up, one question at a time"],
  ["scan", "check this machine now (check is the same)"],
  ["baseline", "remember this machine as clean"],
  ["diff", "what changed since the baseline"],
  ["watch", "check in the background and notify"],
  ["secrets", "long-lived credentials on this machine"],
  ["agents", "MCP servers, hooks and permissions of AI agents"],
  ["mcp", "MCP server for AI agents: read vswarm's state, ask you"],
  ["hook", "Claude Code asks vswarm before shell commands"],
  ["feed", "follow a signed list of dangerous packages and servers"],
  ["preflight", "gate before production access (ssh/aws/kubectl)"],
  ["ui", "open the dashboard in your browser"],
  ["why", "each finding with the command to fix or accept it"],
  ["ok", "accept finding n of the last check"],
  ["fix", "fix finding n of the last check (shows it, asks first)"],
  ["policy", "what WARN does at every gate and in the agent"],
  ["accept", "accept reviewed findings"],
  ["respond", "lock, collect evidence, rotate, quarantine, report"],
  ["report", "write the incident report again"],
  ["unlock", "close an incident once the machine is clean"],
  ["gate", "gate ssh, aws, kubectl and gcloud on preflight"],
  ["guard", "check npm, pip and brew packages before they install"],
  ["pkg", "check what a package-manager command would install"],
  ["try", "run untrusted code in a sandbox and see what it tried"],
  ["ca", "certificate authority for short-lived SSH certificates"],
  ["cert", "issue a short-lived SSH certificate after preflight"],
  ["agent", "ssh agent that signs with protected keys only when this machine passes"],
  ["canary", "plant decoy credentials that alert you when used"],
  ["selftest", "plant fake threats in a sandbox home and measure detection"],
  ["shot", "screenshot a localhost page or local file"],
  ["doctor", "check the installation"],
  ["install", "set up launcher, PATH, completions"],
  ["update", "update vswarm (signature-checked once releases are signed)"],
  ["trust", "release keys updates must be signed with"],
  ["team", "follow a signed team policy"],
  ["uninstall", "remove launcher and PATH"],
  ["lang", "the language of the terminal and the dashboard"],
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
    scan|diff|check) COMPREPLY=( $(compgen -W "--all --json --offline" -- "$cur") ) ;;
    preflight) COMPREPLY=( $(compgen -W "--quiet --strict --fresh --then --json --offline" -- "$cur") ) ;;
    accept|ok) COMPREPLY=( $(compgen -W "--all --list --remove" -- "$cur") ) ;;
    policy) COMPREPLY=( $(compgen -W "warn allow refuse" -- "$cur") ) ;;
    lang) COMPREPLY=( $(compgen -W "th en auto" -- "$cur") ) ;;
    setup) COMPREPLY=( $(compgen -W "--yes --offline" -- "$cur") ) ;;
    baseline) COMPREPLY=( $(compgen -W "--yes --accept-high --offline" -- "$cur") ) ;;
    gate) COMPREPLY=( $(compgen -W "ssh status remove cmd aws kube gcloud az --prune --off" -- "$cur") ) ;;
    guard) COMPREPLY=( $(compgen -W "on off status --ignore-scripts --sandbox --strict" -- "$cur") ) ;;
    agent) COMPREPLY=( $(compgen -W "on off status protect policy unprotect restore add prune log run" -- "$cur") ) ;;
    watch) COMPREPLY=( $(compgen -W "on off status --every" -- "$cur") ) ;;
    team) COMPREPLY=( $(compgen -W "join sync status leave sign --fingerprint --key" -- "$cur") ) ;;
    try) COMPREPLY=( $(compgen -f -W "--net --localhost --list --clean --yes --" -- "$cur") ) ;;
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
    scan|diff|check) _arguments '--all[show low and info findings]' '--json[machine-readable output]' '--offline[no OSV lookup]' ;;
    preflight) _arguments '--quiet[print only on problems]' '--strict[WARN also blocks]' '--fresh[ignore the cached verdict]' '--json[the verdict as JSON]' '--then[run a command when allowed]:command:_command_names' ;;
    accept|ok) _arguments '--all[accept every current finding]' '--list[show accepted]' '--remove[un-accept]:id:' ;;
    policy) _values 'setting' warn allow refuse ;;
    lang) _values 'language' th en auto ;;
    setup) _arguments '--yes[take the recommended answers]' '--offline[no OSV lookup]' ;;
    baseline) _arguments '--yes[do not ask]' '--accept-high[record even over HIGH and CRIT findings]' ;;
    gate) _values 'action' ssh status remove cmd aws kube gcloud az ;;
    guard) _values 'action' on off status ;;
    agent) _values 'action' on off status protect policy unprotect restore add prune log run ;;
    watch) _values 'action' on off status ;;
    team) _values 'action' join sync status leave sign ;;
    try) _arguments '--net[network]:mode:(none registries all)' '--localhost[reach your localhost services]' '--list[earlier tries]' '--clean[remove tries]' '--yes[do not ask]' '*:source:_files' ;;
  esac
}
_vswarm "$@"
`;
}

function writeCompletions() {
  const dir = paths.completions();
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "_vswarm"), completion("zsh"));
  writeFileSync(join(dir, "vswarm.bash"), completion("bash"));
}

// ── Checks
async function version(cmd: string[]): Promise<string | undefined> {
  try {
    const r = await exec(cmd);
    return r.code === 0 ? r.out.trim().split("\n")[0] : undefined;
  } catch {
    return;
  }
}

type Level = "ok" | "warn" | "bad" | "off";
interface DocLine {
  level: Level;
  text: string;
  detail?: string;
}

/** Windows: PowerShell answers, and which parts of the snapshot it could not read. */
async function windowsDoctor(add: (l: DocLine) => void): Promise<boolean> {
  const { winSnapshot, SNAPSHOT_SCRIPT } = await import("./sec/collect/windows");
  const t0 = Date.now();
  const s = await winSnapshot();
  const errors = Object.entries(s.errors ?? {});
  if (errors.some(([k]) => k === "snapshot")) {
    add({ level: "bad", text: t("cli.doc.psFailed"), detail: `${String(s.errors!.snapshot)} · ${t("cli.doc.psByHand", { cmd: `powershell -NoProfile -ExecutionPolicy Bypass -File "${SNAPSHOT_SCRIPT}"` })}` });
    return false;
  }
  const n = (x: unknown) => (Array.isArray(x) ? x.length : x ? 1 : 0);
  add({ level: "ok", text: t("cli.doc.ps", { ms: Date.now() - t0 }), detail: `${n(s.runKeys)} Run values · ${n(s.startup)} Startup entries · ${n(s.tasks)} tasks · ${n(s.services)} services · ${n(s.wmi?.consumers)} WMI consumers` });
  if (s.docs) add({ level: "ok", text: t("cli.doc.docs", { dir: s.docs }), detail: t("cli.doc.docsWhy") });
  for (const [k, v] of errors) add({ level: "warn", text: t("cli.doc.couldNotRead", { what: k }), detail: String(v).slice(0, 160) });
  return true;
}

/**
 * `vswarm doctor`: is vswarm set up, and does what it relies on answer. The state first, in the words of a check
 * (Safe, Check this, Stop), then three groups: this computer, vswarm itself, the protection that is on. False when
 * something needs fixing.
 */
export async function doctor(): Promise<boolean> {
  let good = true;
  const groups: [Key, DocLine[]][] = [["cli.doc.h.computer", []], ["cli.doc.h.vswarm", []], ["cli.doc.h.protection", []]];
  let cur = groups[0][1];
  const add = (l: DocLine) => cur.push(l);
  const ok = (text: string, detail = "") => add({ level: "ok", text, detail });
  const warn = (text: string, detail = "") => add({ level: "warn", text, detail });
  const bad = (text: string, detail = "") => add({ level: "bad", text, detail });
  const off = (text: string, detail = "") => add({ level: "off", text, detail });

  ok(`bun ${Bun.version}`, process.execPath);
  const tools: [string, Key][] = process.platform === "darwin"
    ? [["codesign", "cli.doc.tool.skip"], ["plutil", "cli.doc.tool.skip"], ["lsof", "cli.doc.tool.lsof"], ["ps", "cli.doc.tool.ps"]]
    : WIN ? []
    : [["ss", "cli.doc.tool.ss"], ["bwrap", "cli.doc.tool.bwrap"], ["strace", "cli.doc.tool.strace"]];
  for (const [tool, why] of tools) {
    if (Bun.which(tool)) ok(tool);
    else warn(t("cli.doc.notFound", { tool }), t(why));
  }
  if (WIN && !(await windowsDoctor(add))) good = false;
  const git = await version(["git", "--version"]);
  if (git) ok(git);
  else warn(t("cli.doc.notFound", { tool: "git" }), t("cli.doc.tool.git"));

  cur = groups[1][1];
  ok(t("cli.doc.app", { dir: ROOT }));
  ok(t("cli.doc.data", { dir: HOME }));
  // Windows folder names ignore case, and PATH entries may end in a backslash.
  const norm = (d: string) => (WIN ? d.replace(/[\\/]+$/, "").toLowerCase() : d);
  const onPath = (process.env.PATH ?? "").split(WIN ? ";" : ":").map(norm).includes(norm(paths.bin()));
  if (existsSync(launcherPath()) && onPath) ok(t("cli.doc.onPath"), launcherPath());
  else if (existsSync(launcherPath())) warn(t("cli.doc.newTerminals"), WIN ? t("cli.doc.openNew") : `export PATH="${paths.bin()}:$PATH"`);
  else {
    warn(t("cli.doc.noLauncher"), "vswarm install");
    good = false;
  }
  // The launcher names a Bun and a checkout by path; when either moved, the ssh blocks, the install guard and the
  // background jobs that call it stop working. This vswarm runs, so ask the launcher itself. (The Windows launcher is a
  // .cmd, which only cmd.exe runs; it says the same thing itself when called.)
  if (!WIN && existsSync(launcherPath()) && (await quietRun([launcherPath(), "--version"])) === undefined) {
    bad(t("cli.doc.launcherBroken"), `${launcherPath()} · vswarm install`);
    good = false;
  }
  // The key that seals vswarm's own files, and where it is.
  const k = await stateKey();
  if (k.tampered) {
    bad(t("cli.doc.keyMoved"), `${k.tampered} · ${k.store.where} · vswarm respond`);
    good = false;
  }
  if (!k.key) {
    bad(t("cli.doc.keyUnreadable"), `${k.error} · ${k.store.where}`);
    good = false;
  } else if (k.store.kind === "file" && !process.env.VSWARM_SEC_DIR && !process.env.VSWARM_KEYSTORE) warn(t("cli.doc.keyFile"), `${k.store.where} · ${t("cli.doc.keyFileWhy")}`);
  else ok(t("cli.doc.sealed"), k.store.where);
  const b = await readBaseline();
  const base = b.untrusted ? undefined : b.value;
  if (base) {
    const days = Math.round((Date.now() - base.at) / 86_400_000);
    if (days > 30) warn(t("cli.doc.baselineOld", { at: dateOf(base.at), days }), t("cli.doc.baselineOldHow"));
    else ok(t("cli.doc.baseline", { at: dateOf(base.at) }), t("cli.doc.items", { n: base.items.length }));
  } else if (b.untrusted) {
    bad(t("cli.doc.baselineUntrusted", { why: b.untrusted }), t("cli.doc.baselineUntrustedHow"));
    good = false;
  } else {
    warn(t("cli.doc.noBaseline"), "vswarm setup · vswarm baseline");
    good = false;
  }
  const { lock, why } = await lockState();
  if (lock) bad(t("cli.doc.incident", { incident: lock.incident }), `${why ? `${why} · ` : ""}vswarm unlock`);

  cur = groups[2][1];
  const { watchState } = await import("./sec/schedule");
  const w = watchState();
  if (w.on) ok(t("cli.doc.watch"), `${w.state?.at ? t("cli.watch.last", { at: dateOf(w.state.at) }) : t("cli.doc.noCheckYet")}${w.note ? ` · ${w.note}` : ""}`);
  else off(t("cli.doc.watchOff"), `vswarm watch on${w.note ? ` · ${w.note}` : ""}`);
  if (w.on && w.realtime) ok(t("cli.doc.realtime"), w.state?.quick ? t("cli.watch.lastQuick", { at: dateOf(w.state.quick.at) }) : t("cli.doc.noChangeYet"));
  else if (w.on && !WIN) warn(t("cli.doc.realtimeOff"), t("cli.doc.realtimeOffHow"));
  const sshCfgPath = join(homedir(), ".ssh/config");
  const sshCfg = existsSync(sshCfgPath) ? readFileSync(sshCfgPath, "utf8") : "";
  if (sshCfg.includes(GATE_START)) ok(t("cli.doc.gate"), `~/.ssh/config${GLOBAL_TAG()}`);
  else off(t("cli.doc.gateOff"), 'vswarm gate ssh "prod-*"');
  const health = await hostHealth(sshCfg);
  const { readPolicy } = await import("./sec/policy");
  const pol = await readPolicy();
  add({ level: pol.untrusted ? "bad" : "ok", text: t(pol.warn === "allow" ? "cli.setup.st.policyAllow" : "cli.setup.st.policyRefuse"), detail: pol.untrusted ? `policy.json ${pol.untrusted} · vswarm policy warn allow|refuse` : t("cli.doc.policyChange") });
  const { agentDoctor } = await import("./sec/agent");
  for (const a of await agentDoctor()) {
    if (a.level === "bad") good = false;
    add(a);
  }
  // Command gates (reminders) and gcloud credential hooks: src/sec/cloudgate.ts
  for (const a of await (await import("./sec/cloudgate")).cloudDoctor()) add(a);
  if (await guardOn()) ok(t("cli.doc.guard"), t("cli.doc.guardWhat"));
  else off(t("cli.doc.guardOff"), "vswarm guard on");

  // The state in one line first: Stop for a problem, Check this for something to set up or look at.
  const all = groups.flatMap(([, ls]) => ls);
  const nBad = all.filter((l) => l.level === "bad").length;
  const nWarn = all.filter((l) => l.level === "warn").length;
  const v = nBad ? "block" : nWarn ? "warn" : "pass";
  const mark = verdictMark(v);
  console.log(`  ${mark.slice(0, mark.lastIndexOf(" "))}  ${nBad ? t("cli.doc.head.bad", { n: nBad }) : nWarn ? t("cli.doc.head.warn", { n: nWarn }) : t("cli.doc.head.ok")}`);
  const sign: Record<Level, string> = { ok: c.lime("✔"), warn: c.amber("!"), bad: c.rose("✖"), off: c.dim("·") };
  const w0 = width(process.stdout);
  for (const [head, ls] of groups) {
    console.log(`\n  ${c.bold(t(head))}`);
    for (const l of ls) {
      const text = l.level === "off" ? c.dim(l.text) : l.text;
      const row = `  ${sign[l.level]} ${text}`;
      // The detail beside the text when it fits, under it otherwise.
      if (!l.detail) console.log(row);
      else if (!w0 || cells(row) + 2 + cells(l.detail) <= w0) console.log(`${row}  ${c.dim(l.detail)}`);
      else console.log(`${row}\n${wrap(l.detail, w0 - 6).map((x) => `      ${c.dim(x)}`).join("\n")}`);
    }
    if (head === "cli.doc.h.protection") for (const l of health) console.log(l);
  }
  if (all.some((l) => l.level === "off" || l.level === "warn")) console.log(`\n  ${t("cli.doc.setup")} ${c.cyan(c.bold("vswarm setup"))}`);
  console.log();
  return good;
}

// ── ssh gate
export { cmdWord, GATE_START };

/** The ~/.ssh/config block: hosts matching the patterns connect only when preflight passes. */
export function sshGate(patterns: string[], launcher: string[], opt: { cert?: { key: string; cert: string }; win?: boolean } = {}): string {
  const win = opt.win ?? WIN;
  // Both end up on one line of ~/.ssh/config: a space, quote or newline in a pattern would change what the line means.
  const bad = patterns.find((p) => !/^[\w*?!.:\[\]-]+$/.test(p));
  if (bad !== undefined) throw new Error(`"${bad}" is not an ssh host pattern (letters, digits, . - * ? and !)`);
  if (launcher.some((p) => /["\n]/.test(p))) throw new Error(`cannot put ${launcher.join(" ")} in ~/.ssh/config: it contains a double quote`);
  if (win && opt.cert) throw new Error("short-lived certificates are not on Windows yet; use vswarm gate ssh without --cert");
  // The command sits inside ssh's double quotes; a part with spaces or shell characters gets single quotes of its own
  // (on Windows, cmd.exe escapes). Windows leaves out --host %h: the host name would reach cmd.exe unescaped.
  const q = launcher.map(win ? cmdWord : shq).join(" ");
  const tail = win ? "" : " --host %h";
  return [
    GATE_START,
    `# Hosts below connect only after \`vswarm preflight\` passes. Remove with: vswarm gate remove`,
    // originalhost is the name you typed (ssh vrfix-prod), before any HostName substitution.
    `Match originalhost ${patterns.join(",")} !exec "${q} ${opt.cert ? "cert" : "preflight"} --quiet${tail}"`,
    refusedLine(q, win ? "vswarm: not connecting: this machine did not pass preflight" : "vswarm: not connecting: this machine did not pass preflight (the reason is above)", win),
    // With certificates: log in with the fresh session key and its certificate first.
    ...(opt.cert ? [`Match originalhost ${patterns.join(",")}`, `    IdentityFile ${opt.cert.key}`, `    CertificateFile ${opt.cert.cert}`] : []),
    GATE_END,
  ].join("\n");
}

export async function gate(args: string[], home = homedir()) {
  const action = args.shift() ?? "status";
  // Command wrappers and the gcloud / az gates: src/sec/cmdgate.ts, src/sec/cloudgate.ts
  // Taking a cmd, aws, kube, gcloud or az gate away weakens protection: a person says yes first.
  if (args.includes("--off") && action !== "status") await (await import("./sec/human")).weaken("gate", [action, ...args]);
  if (action === "cmd") return (await import("./sec/cmdgate")).gateCmd(args);
  if (action === "gcloud") return (await import("./sec/cloudgate")).gateGcloud(args);
  if (action === "az") return (await import("./sec/cloudgate")).gateAz(args);
  // aws profiles and kubectl contexts: the credential they hand out runs preflight first (awsgate.ts, kubegate.ts).
  // A profile or context that cannot be gated is said so, and the exit code says it too.
  if (action === "aws" || action === "kube" || action === "kubectl") {
    const done = action === "aws" ? await (await import("./sec/awsgate")).gateAws(args) : await (await import("./sec/kubegate")).gateKube(args);
    if (!done) process.exitCode = 1;
    return;
  }
  const cfgPath = join(home, ".ssh", "config");
  const old = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "";
  if (action === "status") {
    const block = old.match(blockRegex(GATE_START, GATE_END))?.[0];
    console.log(block ? block.trim() : t("cli.gate.none"));
    // Hosts named one by one, in the gate and the agent block: still there? (DNS and the ssh port, 2 s, in parallel)
    for (const l of await hostHealth(old)) console.log(l);
    const { loadCmdGates } = await import("./sec/cmdgate");
    const { loadCloudGates } = await import("./sec/cloudgate");
    const cmds = Object.keys(loadCmdGates().tools).sort();
    const { gcloud, aws, kube } = loadCloudGates();
    const hooks = Object.keys(gcloud);
    if (cmds.length) console.log(`command gates (reminders): ${cmds.join(", ")} · vswarm gate cmd`);
    if (Object.keys(aws).length) console.log(`aws profiles gated: ${Object.keys(aws).join(", ")} · vswarm gate aws`);
    if (Object.keys(kube).length) console.log(`kubectl contexts gated: ${Object.values(kube).flatMap((h) => h.for).join(", ")} · vswarm gate kube`);
    if (hooks.length) console.log(`gcloud credential hooks: ${hooks.join(", ")} · vswarm gate gcloud`);
    return;
  }
  if (action !== "ssh" && action !== "remove") throw new Error('usage: vswarm gate ssh "<host pattern>" [...] | gate aws <profile…> | gate kube <context…> | gate gcloud <configuration> | gate cmd <tool> | gate status | gate remove');
  // Everything that can refuse comes before the backup and the write, so a refused command changes nothing.
  const certAt = args.indexOf("--cert");
  const withCert = certAt >= 0;
  if (withCert) args.splice(certAt, 1);
  // --team: the hosts your team policy names, plus any given here.
  const teamAt = args.indexOf("--team");
  if (teamAt >= 0) {
    args.splice(teamAt, 1);
    const { loadPolicy } = await import("./sec/team");
    const hosts = (await loadPolicy()).policy?.gate?.ssh ?? [];
    if (!hosts.length) throw new Error("the team policy names no ssh hosts (gate.ssh), or this machine follows none: vswarm team status");
    for (const h of hosts) if (!args.includes(h)) args.push(h);
  }
  // --prune: the gate's hosts that no longer answer, offered one by one; the rest stay as they are.
  const pruneAt = args.indexOf("--prune");
  if (pruneAt >= 0) {
    args.splice(pruneAt, 1);
    if (action !== "ssh" || args.length) throw new Error("usage: vswarm gate ssh --prune   (offers the gated hosts that no longer answer, one by one)");
    const current = gatedHostsOf(old);
    const was = /Match originalhost \S+ !exec "[^"]* (preflight|cert) --quiet/.exec(old)?.[1];
    const { pruneHosts } = await import("./sec/probe");
    const keep = await pruneHosts(current, { cfgText: old, ask: (q, d) => yes(q, d), what: "gate" });
    if (!keep) return;
    if (!keep.length) return gate(["remove"], home);
    return gate(["ssh", ...keep, ...(was === "cert" ? ["--cert"] : [])], home);
  }
  if (action === "ssh" && !args.length) throw new Error(t("cli.gate.nameHosts"));
  if (withCert && !existsSync(join(HOME, "ca", "ca_key"))) throw new Error("no CA yet: vswarm ca init");
  const cert = withCert ? { key: join(HOME, "ca", "session"), cert: join(HOME, "ca", "session-cert.pub") } : undefined;
  const rest = removeBlock(old, GATE_START, GATE_END).trimEnd();
  // Removing the gate, or leaving out a host it covers now, weakens it: a person says yes first.
  const dropped = gatedHostsOf(old).filter((h) => action === "remove" || !args.includes(h));
  if (dropped.length) await (await import("./sec/human")).weaken("gate", action === "remove" ? ["remove"] : ["ssh", ...args]);
  // ssh uses the first value it sees for most options, so the gate goes first in the file.
  const block = action === "ssh" ? sshGate(args, existsSync(launcherPath()) ? [launcherPath()] : [process.execPath, CLI], { cert }) : undefined;
  const next = block ? `${block}\n\n${rest}\n` : `${rest}\n`;
  const backup = `${cfgPath}.bak-vswarm-${Date.now()}`;
  if (old) writeFileSync(backup, old, { mode: 0o600 });
  mkdirSync(dirname(cfgPath), { recursive: true, mode: 0o700 });
  writeFileSync(cfgPath, next, { mode: 0o600 });
  // Only the block vswarm wrote is its own; a look-alike block someone else put in the file stays visible to scans.
  if (block) recordManaged(block + "\n");
  ok(action === "ssh" ? t("cli.gate.added", { list: args.join(", ") }) : t("cli.gate.removed"), cfgPath);
  if (old) console.log(`  ${c.dim(t("cli.gate.backup", { file: backup }))}`);
  if (action === "ssh") console.log(`  ${c.dim(t("cli.gate.test", { find: WIN ? "findstr /i" : "grep -i" }))}`);
}

/** Host patterns of the ssh gate block, when there is one. */
const gatedHostsOf = (cfg: string) => blockHosts(cfg, GATE_START, GATE_END);

/**
 * For doctor and gate status: each host the gate and agent blocks name one by one, probed (DNS, then its ssh port;
 * 2 s; all at once), and when the agent last signed a login to it. Only these two commands ask; preflight never does.
 */
export async function hostHealth(cfg: string, deps?: import("./sec/probe").ProbeDeps): Promise<string[]> {
  const { probeAll, dead, probeText, lastUsed } = await import("./sec/probe");
  const { agentHosts } = await import("./sec/agent");
  const { literal } = await import("./sec/sshconfig");
  const hosts = [...new Set([...gatedHostsOf(cfg), ...agentHosts(cfg)])].filter(literal);
  if (!hosts.length) return [];
  const probes = await probeAll(hosts, cfg, deps);
  let days: Record<string, number | undefined> = {};
  try {
    const { readAudit } = await import("./sec/store");
    days = lastUsed(hosts, (await readAudit()).entries);
  } catch {}
  const out: string[] = [];
  for (const p of probes) {
    const d = days[p.host];
    const used = d === undefined ? "" : d === 0 ? " · agent login today" : ` · not used for ${d} day${d === 1 ? "" : "s"}`;
    out.push(`  ${dead(p) ? c.amber("!") : c.lime("✔")} ${p.host}  ${c.dim(probeText(p) + used)}`);
  }
  if (probes.some(dead)) out.push(`  ${c.dim("hosts that do not answer: vswarm gate ssh --prune · vswarm agent prune (asks for each)")}`);
  return out;
}

// ── Install guard: npm, pip, brew … ask vswarm before they install
let docsDir: Promise<string | undefined> | undefined;
/** The real Documents folder (OneDrive may hold it), where PowerShell looks for profiles. */
function windowsDocs(): Promise<string | undefined> {
  return (docsDir ??= (async () => {
    const { powershell } = await import("./sec/schedule");
    const r = await exec([powershell(), "-NoProfile", "-NonInteractive", "-Command", "[Environment]::GetFolderPath('MyDocuments')"], { timeoutMs: 30_000 });
    return r.out.trim() || undefined;
  })());
}

/** Where the guard goes: ~/.zshrc and ~/.bashrc, or on Windows the profile.ps1 of Windows PowerShell and of PowerShell 7. */
export async function guardFiles(adding = false, home = homedir()): Promise<string[]> {
  if (!WIN) return rcFiles(home).map((r) => r.file).filter((f) => /\.(zsh|bash)rc$/.test(f));
  const docs = await windowsDocs();
  if (!docs) throw new Error("could not find your Documents folder, where PowerShell profiles live");
  const ps7 = join(docs, "PowerShell", "profile.ps1");
  // PowerShell 7's profile only where PowerShell 7 is installed; removing looks in both.
  return [join(docs, "WindowsPowerShell", "profile.ps1"), ...(!adding || Bun.which("pwsh") || existsSync(dirname(ps7)) ? [ps7] : [])];
}

export async function guardOn(home = homedir()): Promise<boolean> {
  return (await guardFiles(false, home)).some((f) => (readKept(f)?.text ?? "").includes(GUARD_START));
}

/** Why `guard on --sandbox` cannot be had here, or undefined: the sandbox is promised only where there is one. */
export function sandboxRefusal(platform: NodeJS.Platform, canSandbox: boolean): string | undefined {
  if (platform === "win32") return "--sandbox is not on Windows yet: installs would run outside any sandbox. Use guard on without it (--ignore-scripts works), or WSL";
  if (!canSandbox) return platform === "linux" ? "--sandbox needs bubblewrap, which is not installed: sudo apt install bubblewrap (dnf/pacman: bubblewrap), then guard on --sandbox again" : "--sandbox needs sandbox-exec, which this system does not have";
}

/** PowerShell runs no profile under the Restricted and AllSigned policies (Restricted is the Windows default). */
async function profilesRun(): Promise<{ ok: boolean; policy: string }> {
  const { powershell } = await import("./sec/schedule");
  const r = await exec([powershell(), "-NoProfile", "-NonInteractive", "-Command", "[string](Get-ExecutionPolicy)"], { timeoutMs: 30_000 });
  const policy = r.out.trim() || "unknown";
  return { ok: !/^(Restricted|AllSigned|Undefined|unknown)$/i.test(policy), policy };
}

/** The guard's shell block for these settings: plain, or routing npm/pnpm/yarn/bun installs through `pkg --run`. */
export function guardBody(launcher: string, g: GuardConfig, win = WIN): string {
  return win ? psGuardBlock(process.execPath, CLI, { ignoreScripts: g.ignoreScripts }) : guardBlock(launcher, { run: !!(g.ignoreScripts || g.sandbox) });
}

/** What the guard settings mean, one line each. */
function guardSettings(g: GuardConfig) {
  if (g.ignoreScripts) console.log(`  ${c.dim(`· ${t("cli.guard.scripts")}`)}`);
  if (g.sandbox) console.log(`  ${c.dim(`· ${t(WIN ? "cli.guard.sandboxWin" : "cli.guard.sandbox")}`)}`);
  if (g.strict) console.log(`  ${c.dim(`· ${t("cli.guard.strict")}`)}`);
}

export async function guard(args: string[]) {
  const action = args.shift() ?? "status";
  const want: GuardConfig = { ignoreScripts: args.includes("--ignore-scripts"), sandbox: args.includes("--sandbox"), strict: args.includes("--strict") };
  if (action === "status") {
    if (await guardOn()) ok(t("cli.guard.isOn"), (await guardFiles()).join(", "));
    else console.log(`  ${c.dim("·")} ${t("cli.guard.isOff")}  ${c.dim("vswarm guard on")}`);
    guardSettings(loadGuardConfig());
    return;
  }
  if (action !== "on" && action !== "off") throw new Error("usage: vswarm guard on [--ignore-scripts] [--sandbox] [--strict] | off | status");
  if (action === "off" && (await guardOn())) await (await import("./sec/human")).weaken("guard", ["off"]);
  const launcher = action === "on" ? ensureLauncher() : existsSync(launcherPath()) ? launcherPath() : undefined;
  if (action === "on" && want.sandbox) {
    const why = sandboxRefusal(process.platform, (await import("./sec/try/spawn")).canSandbox());
    if (why) throw new Error(`not changed: ${why}`);
  }
  if (action === "on") saveGuardConfig(want);
  const body = action === "off" ? null : guardBody(launcher!, want);
  for (const f of await guardFiles(action === "on")) {
    const changed = setBlock(f, body, GUARD_START, GUARD_END);
    ok(t(changed ? (action === "on" ? "cli.guard.added" : "cli.guard.removed") : action === "on" ? "cli.guard.alreadyOn" : "cli.guard.alreadyOff", { file: f }));
  }
  if (action === "on") {
    console.log(`  ${c.dim(t("cli.guard.now", { tools: `npm, npx, pnpm, yarn, bun, bunx, pip, pip3, uv, uvx, pipx${WIN ? "" : ", brew"}` }))}`);
    guardSettings(want);
    if (WIN) {
      const p = await profilesRun();
      if (!p.ok) warn(t("cli.guard.psPolicy", { policy: p.policy }), t("cli.guard.psPolicyHow"));
      console.log(`  ${c.dim(t("cli.guard.newPs", { file: (await guardFiles(true))[0] }))}`);
    } else console.log(`  ${c.dim(t("cli.guard.newTerm", { file: (await guardFiles())[0] }))}`);
    console.log(`  ${c.dim(t("cli.guard.try"))}`);
  } else if (WIN) console.log(`  ${c.dim(t("cli.guard.offPs"))}`);
  else console.log(`  ${c.dim(t("cli.guard.offTerm"))}`);
}

/**
 * Blocks vswarm wrote before it kept their hashes (versions before 2.4) are recognised here when they are exactly
 * what vswarm writes today, so scans stop reporting them. Anything that differs is left alone, and stays visible.
 */
export function adoptManagedBlocks() {
  const known: string[] = [];
  for (const { body } of rcFiles()) known.push(`${BLOCK_START}\n${body}\n${BLOCK_END}\n`);
  if (existsSync(launcherPath())) known.push(guardBody(launcherPath(), loadGuardConfig(), false) + "\n");
  const sshCfg = join(homedir(), ".ssh", "config");
  const cfg = existsSync(sshCfg) ? readFileSync(sshCfg, "utf8") : "";
  const m = /Match originalhost (\S+) !exec "(.+) (preflight|cert) --quiet(?: --host %h)?"/.exec(cfg);
  if (m && existsSync(launcherPath())) {
    const cert = m[3] === "cert" ? { key: join(HOME, "ca", "session"), cert: join(HOME, "ca", "session-cert.pub") } : undefined;
    // A pattern sshGate would refuse today was not written by vswarm; that block simply stays visible to scans.
    try {
      known.push(sshGate(m[1].split(","), [launcherPath()], { cert }));
    } catch {}
  }
  const texts = [...rcFiles().map((r) => r.file), sshCfg].filter((f) => existsSync(f)).map((f) => readFileSync(f, "utf8"));
  for (const block of known) if (texts.some((t) => t.includes(block.trimEnd()))) recordManaged(block);
}

/**
 * Once per new version, on the copy the launcher runs: what `vswarm update` cannot do for itself, since the update
 * runs in the old version's code. Today: the launcher's own checks, and the ssh blocks' refusal line. Never from a
 * checkout or a test run (the launcher names another copy, or the test isolation is on).
 */
export function afterUpdate(): void {
  if (process.env.VSWARM_ISOLATED_ROOT) return;
  const stamp = join(HOME, "version");
  try {
    if (!existsSync(launcherPath()) || !readFileSync(launcherPath(), "utf8").includes(CLI)) return;
    if (existsSync(stamp) && readFileSync(stamp, "utf8").trim() === VERSION) return;
    writeLauncher();
    refreshSshBlocks();
    writeFileSync(stamp, VERSION + "\n");
  } catch {}
}

/** The refusal lines vswarm wrote under its ssh blocks before 2.9.1, which blamed the machine when vswarm itself could not run. */
const OLD_REFUSALS: [RegExp, string, string][] = [
  [/!exec "(.+) (?:preflight|cert) --quiet[^"]*"\n    ProxyCommand \/bin\/sh -c 'echo "vswarm: not connecting: this machine did not pass preflight \(the reason is above\) · vswarm why" >&2; exit 1'/, "vswarm: not connecting: this machine did not pass preflight (the reason is above)", "unix"],
  [/!exec "(.+) agent check[^"]*"\n    ProxyCommand \/bin\/sh -c 'echo "vswarm agent: not connecting \(the reason is above\) · vswarm why" >&2; exit 1'/, "vswarm agent: not connecting (the reason is above)", "unix"],
  [/!exec "(.+) (?:preflight|cert) --quiet[^"]*"\r?\n    ProxyCommand cmd\.exe \/d \/c "echo vswarm: not connecting: this machine did not pass preflight; run: vswarm why 1>&2 & exit 1"/, "vswarm: not connecting: this machine did not pass preflight", "win"],
  [/!exec "(.+) agent check[^"]*"\r?\n    ProxyCommand cmd\.exe \/d \/c "echo vswarm agent: not connecting \(the reason is above\); run: vswarm why 1>&2 & exit 1"/, "vswarm agent: not connecting: the machine did not pass", "win"],
];

/**
 * After an update: the ssh blocks vswarm wrote, still exactly as written, get today's refusal line. A block someone
 * edited is left alone (and stays visible to scans). Returns whether ~/.ssh/config changed; a backup is kept.
 */
export function refreshSshBlocks(cfgPath = join(homedir(), ".ssh", "config")): boolean {
  if (!existsSync(cfgPath)) return false;
  const old = readFileSync(cfgPath, "utf8");
  let next = old;
  for (const [start, end] of [[GATE_START, GATE_END], [AGENT_START, AGENT_END]]) {
    const block = next.match(blockRegex(start, end))?.[0];
    if (!block || stripManaged(block).trim()) continue;
    let fresh = block;
    for (const [re, refusal, os] of OLD_REFUSALS) {
      const m = re.exec(fresh);
      if (!m) continue;
      const line = m[0].slice(0, m[0].indexOf("\n") + 1);
      try {
        fresh = fresh.replace(m[0], line + refusedLine(m[1], refusal, os === "win"));
      } catch {}
    }
    if (fresh !== block) {
      next = next.replace(block, fresh);
      recordManaged(fresh.trim() + "\n");
    }
  }
  if (next === old) return false;
  writeFileSync(`${cfgPath}.bak-vswarm-${Date.now()}`, old, { mode: 0o600 });
  writeFileSync(cfgPath, next, { mode: 0o600 });
  return true;
}

/**
 * Whether install changes PATH. Elsewhere it does unless --no-path; on Windows only with --path or a yes on the
 * terminal (no terminal: no), since there it is a registry value every new program inherits.
 */
export async function pathWanted(args: string[], win: boolean, tty: boolean, ask: (q: string, def?: boolean) => Promise<boolean>): Promise<boolean> {
  if (args.includes("--no-path")) return false;
  if (args.includes("--path") || !win) return true;
  if (!tty || args.includes("--yes") || args.includes("-y")) return false;
  return ask(`Add ${paths.bin()} to your PATH (your user's, in the registry)?`, true);
}

// ── Commands
export async function install(args: string[]) {
  banner("install");
  step(`1  ${t("cli.install.files")}`);
  ensureHome();
  ok(t("cli.install.data"), HOME);

  step(`2  ${t("cli.install.command")}`);
  writeLauncher();
  ok(t("cli.install.launcher"), launcherPath());
  writeCompletions();
  ok(t("cli.install.completions"), paths.completions());
  if (!args.includes("--no-path")) {
    if (WIN) {
      // Your PATH in the registry is changed only when you say so: --path, or yes to the question.
      if (await pathWanted(args, WIN, canAsk(), yes)) {
        await windowsPath(true);
        ok(t("cli.install.pathWin"), paths.bin());
      } else console.log(`  ${c.dim(`· ${t("cli.install.pathNot", { launcher: launcherPath() })}`)}`);
    } else {
      for (const { file, body } of rcFiles()) ok(t(setBlock(file, body) ? "cli.install.pathAdded" : "cli.install.pathAlready", { file }));
    }
  }

  // Pin the release key this copy ships with, so later updates only accept releases signed by it.
  if (!existsSync(PIN()) && (await fingerprints(join(ROOT, "trust", "allowed_signers"))).length) {
    await trust(["pin"]);
  }

  adoptManagedBlocks();

  // The rest (a check, the starting point, the watch, the guard, production) is one guided step of its own.
  step(t("cli.install.next"));
  console.log(`  ${c.cyan(c.bold("vswarm setup"))}   ${c.dim(t("cli.install.setup"))}`);
  console.log(`  ${c.dim(WIN ? t("cli.install.newTerminalWin", { launcher: launcherPath() }) : t("cli.install.newTerminal", { rc: rcFiles()[0].file, launcher: launcherPath() }))}\n`);
}

export async function uninstall(args: string[]) {
  await (await import("./sec/human")).weaken("uninstall", args);
  // Refused before anything is removed: --purge would delete keys that live only in the agent's vault.
  const { agentUninstall } = await import("./sec/agent");
  const agentGone = await agentUninstall(args.includes("--purge"));
  banner("uninstall");
  for (const f of agentGone) ok(`removed ${f}`);
  // The background check runs the launcher; it goes first, or it would fail every hour from now on.
  const { watchOff, watchState } = await import("./sec/schedule");
  const w = watchState();
  if (w.on || w.realtime) for (const f of await watchOff()) ok(`removed ${f}`);
  if (existsSync(launcherPath())) rmSync(launcherPath());
  ok("launcher removed");
  if (WIN) await windowsPath(false);
  else for (const { file } of rcFiles()) if (setBlock(file, null)) ok(`PATH removed from ${file}`);
  rmSync(paths.completions(), { recursive: true, force: true });
  const sshCfg = join(homedir(), ".ssh/config");
  if (existsSync(sshCfg) && readFileSync(sshCfg, "utf8").includes(GATE_START)) await gate(["remove"]);
  if (await guardOn()) await guard(["off"]);
  for (const t of await (await import("./sec/cloudgate")).cloudUninstall()) ok(t);
  // Windows: what vswarm try let its sandbox read in your toolchains' folders.
  if (WIN) {
    const { TRY_DIR } = await import("./sec/try");
    const gone = await (await import("./sec/try/windows")).revokeToolchains(join(TRY_DIR(), "acl.json"));
    if (gone.length) ok(`the try sandbox's access removed from ${gone.length} folder${gone.length > 1 ? "s" : ""}`);
  }
  if (args.includes("--purge")) {
    // The sealing key goes too, or a reinstall would find its incident log "deleted" and stay locked.
    await forgetKey();
    rmSync(HOME, { recursive: true, force: true });
    ok("data removed", HOME);
  } else console.log(`  ${c.dim(`· kept ${HOME} (baseline, incidents) · remove it too with --purge`)}`);
  console.log(`  ${c.dim("· the app folder stays at " + ROOT)}\n`);
}

export async function update(args: string[] = []) {
  banner("update");
  if (!existsSync(join(ROOT, ".git"))) throw new Error(`${ROOT} is not a git checkout; download the new version and run vswarm install`);
  const run = async (cmd: string[]) => {
    const { code, out, err } = await exec(cmd, { cwd: ROOT });
    if (code !== 0) throw new Error(`${cmd.join(" ")}: ${err.trim() || out.trim()}`);
    return out.trim();
  };
  const before = await run(["git", "rev-parse", "--short", "HEAD"]);
  // --unsigned: follow the main branch as it is (for development). Everyone else gets signed releases only.
  const r = args.includes("--unsigned") ? ({ status: "unsigned-repo" } as const) : await secureUpdate(ROOT, VERSION);
  if (r.status === "refused") {
    bad(`not updating to ${r.tag}: ${r.why}`);
    console.log(`  ${c.dim("Your current version keeps running. If the release key really changed, see: vswarm trust")}\n`);
    process.exitCode = 3;
    return;
  }
  // Newer tags nobody trusted signed: said out loud, because that is what a tampered repository looks like.
  if (r.status !== "unsigned-repo") for (const t of r.ignored) console.log(`  ${c.amber("!")} ignored ${t}: not signed by a trusted release key`);
  if (r.status === "current") {
    for (const k of r.pinned ?? []) console.log(`  ${c.amber("!")} trusting release key ${c.bold(k.fp)} (${k.who}) from now on`);
    return ok(`already on ${r.at}, signed by a trusted release key\n`);
  }
  if (r.status === "unsigned-repo") {
    warn(args.includes("--unsigned") ? "following main without signature checks (--unsigned)" : "this repository has no signed releases yet; following main without a signature check");
    if ((await run(["git", "rev-parse", "--abbrev-ref", "HEAD"])) === "HEAD") await run(["git", "checkout", "--quiet", "main"]);
    await run(["git", "pull", "--ff-only", "--quiet", "origin", "main"]);
  } else {
    ok(`updated to ${r.to}, signature checked`);
    for (const k of r.pinned ?? []) console.log(`  ${c.amber("!")} first signed release: trusting release key ${c.bold(k.fp)} (${k.who}) from now on`);
    if (r.pinned?.length) console.log(`  ${c.dim("  compare that fingerprint with the one the maintainer publishes (README, SECURITY.md, release page)")}`);
  }
  const after = await run(["git", "rev-parse", "--short", "HEAD"]);
  if (before !== after) console.log(c.dim((await run(["git", "log", "--oneline", `${before}..${after}`])).split("\n").slice(0, 15).map((l) => "    " + l).join("\n")));
  else if (r.status === "unsigned-repo") ok("already up to date", before);
  await run([process.execPath, "install", "--production"]);
  writeLauncher();
  writeCompletions();
  adoptManagedBlocks();
  if (refreshSshBlocks()) ok("~/.ssh/config: vswarm's blocks now say when vswarm itself cannot run (backup kept)");
  ok("launcher and completions refreshed\n");
}

/** vswarm trust: which release keys this machine accepts updates from. */
export async function trust(args: string[]) {
  const action = args.shift() ?? "status";
  const shipped = join(ROOT, "trust", "allowed_signers");
  if (action === "status") {
    const keys = await fingerprints(PIN());
    if (!keys.length) {
      console.log(`  ${c.dim("·")} no release key pinned yet ${c.dim(`(${PIN()})`)}`);
      console.log(`  ${c.dim("  the first signed release you install or update to is pinned; until then updates follow main")}`);
    }
    for (const k of keys) ok(`${k.fp}`, `${k.who} · ${PIN()}`);
    return;
  }
  if (action === "pin") {
    // Pin the keys this checkout ships with. Used by the installer; by hand only after checking the fingerprint.
    const keys = await fingerprints(shipped);
    if (!keys.length) throw new Error(`${shipped} lists no release keys`);
    // A first pin (the installer) asks nobody; replacing keys already pinned decides which releases this copy takes.
    if (existsSync(PIN()) && readFileSync(PIN(), "utf8") !== readFileSync(shipped, "utf8")) await (await import("./sec/human")).confirmWeakening("vswarm trust pin");
    mkdirSync(dirname(PIN()), { recursive: true, mode: 0o700 });
    writeFileSync(PIN(), readFileSync(shipped, "utf8"), { mode: 0o600 });
    for (const k of keys) ok(`pinned ${k.fp}`, k.who);
    return;
  }
  throw new Error("usage: vswarm trust [status] | trust pin");
}
