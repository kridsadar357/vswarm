// Installing vswarm on a machine: launcher on PATH, shell completions, data folder, a first baseline, and the
// gate in ~/.ssh/config. Also `doctor` (check the setup), `update` (git pull) and `uninstall`.

import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { ReadStream } from "node:tty";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { ensureHome, GLOBAL_TAG, HOME, paths, VERSION } from "./home";
import { dq, exec, shq } from "./sec/ctx";
import { blockRegex, files, forgetKey, loadBaseline, lockState, readBaseline, recordManaged, removeBlock, stateKey } from "./sec/store";
import { GUARD_END, GUARD_START, guardBlock, loadGuardConfig, psGuardBlock, saveGuardConfig, type GuardConfig } from "./sec/pkg";
import { fingerprints, PIN, secureUpdate } from "./sec/update";
import { GATE_END, GATE_START } from "./sec/sshblocks";

export const CLI = resolve(import.meta.dir, "cli.ts");

export const ROOT = resolve(dirname(CLI), "..");
const WIN = process.platform === "win32";

// ── Printing
const tty = (process.stdout.isTTY || !!process.env.FORCE_COLOR) && !process.env.NO_COLOR;
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
// Keys are read from /dev/tty, not stdin: under `curl … | sh` stdin is the script, and Bun gets no keys
// from a stdin that was redirected from /dev/tty.
function keyboard(): (NodeJS.ReadStream & { setRawMode(m: boolean): void }) | undefined {
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
  process.stderr.write(`  ${c.cyan("?")} ${question} `);
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

function writeLauncher() {
  mkdirSync(paths.bin(), { recursive: true });
  const bun = process.execPath;
  if (WIN) {
    writeFileSync(launcherPath(), `@echo off\r\n"${bun}" "${CLI}" %*\r\n`);
  } else {
    writeFileSync(launcherPath(), `#!/bin/sh\n# vswarm launcher, written by \`vswarm install\`\nexec ${dq(bun)} ${dq(CLI)} "$@"\n`);
    chmodSync(launcherPath(), 0o755);
  }
}

/**
 * The launcher, written from this checkout when it is missing, so `watch on`, `guard on` and `agent on` work straight
 * from a clone (bun src/cli.ts …, or .\\vswarm.cmd on Windows) without `vswarm install` first. PATH is not touched.
 */
export function ensureLauncher(say: (t: string) => void = (t) => console.error(t)): string {
  if (existsSync(launcherPath())) return launcherPath();
  ensureHome();
  writeLauncher();
  say(`  ${c.lime("✔")} launcher written ${c.dim(`${launcherPath()} · runs ${CLI} · not on your PATH (vswarm install --path adds it)`)}`);
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
  ["scan", "check this machine now (check is the same)"],
  ["baseline", "remember this machine as clean"],
  ["diff", "what changed since the baseline"],
  ["watch", "check in the background and notify"],
  ["secrets", "long-lived credentials on this machine"],
  ["agents", "MCP servers, hooks and permissions of AI agents"],
  ["preflight", "gate before production access (ssh/aws/kubectl)"],
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

/** Windows: PowerShell answers, and which parts of the snapshot it could not read. */
async function windowsDoctor(): Promise<boolean> {
  const { winSnapshot, SNAPSHOT_SCRIPT } = await import("./sec/collect/windows");
  const t0 = Date.now();
  const s = await winSnapshot();
  const errors = Object.entries(s.errors ?? {});
  if (errors.some(([k]) => k === "snapshot")) {
    bad("PowerShell snapshot failed", String(s.errors!.snapshot));
    console.log(`  ${c.dim(`run it by hand: powershell -NoProfile -ExecutionPolicy Bypass -File "${SNAPSHOT_SCRIPT}"`)}`);
    return false;
  }
  const n = (x: unknown) => (Array.isArray(x) ? x.length : x ? 1 : 0);
  ok(`PowerShell snapshot in ${Date.now() - t0} ms`, `${n(s.runKeys)} Run values · ${n(s.startup)} Startup entries · ${n(s.tasks)} tasks · ${n(s.services)} services · ${n(s.wmi?.consumers)} WMI consumers`);
  if (s.docs) ok(`Documents ${s.docs}`, "PowerShell profiles are read from here");
  for (const [k, v] of errors) warn(`could not read ${k}`, String(v).slice(0, 160));
  return true;
}

export async function doctor(): Promise<boolean> {
  let good = true;
  step("runtime");
  ok(`bun ${Bun.version}`, process.execPath);
  const tools: [string, string][] = process.platform === "darwin"
    ? [["codesign", "some checks will be skipped"], ["plutil", "some checks will be skipped"], ["lsof", "connections will not be checked"], ["ps", "processes will not be checked"]]
    : WIN ? []
    : [["ss", "connections will not be checked (iproute2)"], ["bwrap", "vswarm try needs it: sudo apt install bubblewrap"], ["strace", "vswarm try will not see file and connection attempts: sudo apt install strace"]];
  for (const [tool, why] of tools) {
    if (Bun.which(tool)) ok(tool);
    else warn(`${tool} not found`, why);
  }
  if (WIN && !(await windowsDoctor())) good = false;
  const git = await version(["git", "--version"]);
  if (git) ok(git);
  else warn("git not found", "needed for vswarm update");

  step("vswarm");
  ok(`app ${ROOT}`);
  ok(`data ${HOME}`);
  // Windows folder names ignore case, and PATH entries may end in a backslash.
  const norm = (d: string) => (WIN ? d.replace(/[\\/]+$/, "").toLowerCase() : d);
  const onPath = (process.env.PATH ?? "").split(WIN ? ";" : ":").map(norm).includes(norm(paths.bin()));
  if (existsSync(launcherPath()) && onPath) ok("vswarm on PATH", launcherPath());
  else if (existsSync(launcherPath())) warn("launcher installed, new terminals will have it", WIN ? "open a new terminal" : `or: export PATH="${paths.bin()}:$PATH"`);
  else {
    warn("launcher not installed", "run: vswarm install");
    good = false;
  }
  // The key that seals vswarm's own files, and where it is.
  const k = await stateKey();
  if (k.tampered) {
    bad("sealing key moved to a file outside vswarm", `${k.tampered} · vswarm uses ${k.store.where} · treat this machine as suspect: vswarm respond`);
    good = false;
  }
  if (!k.key) {
    bad("sealing key not readable", `${k.error} · ${k.store.where}`);
    good = false;
  } else if (k.store.kind === "file" && !process.env.VSWARM_SEC_DIR && !process.env.VSWARM_KEYSTORE)
    warn("sealing key in a file", `${k.store.where} · no system key store (Keychain, Secret Service, DPAPI) answered; tampering with ~/.vswarm is harder to notice`);
  else ok(`state files sealed`, k.store.where);
  const b = await readBaseline();
  const base = b.untrusted ? undefined : b.value;
  if (base) {
    const days = Math.round((Date.now() - base.at) / 86_400_000);
    (days > 30 ? warn : ok)(`baseline from ${new Date(base.at).toLocaleString()}`, days > 30 ? `${days} days old · refresh it with vswarm baseline once you have reviewed vswarm diff` : `${base.items.length} items`);
  } else if (b.untrusted) {
    bad(`the baseline ${b.untrusted}`, "review vswarm diff, then vswarm baseline");
    good = false;
  } else {
    warn("no baseline", "vswarm baseline on a machine you trust");
    good = false;
  }
  const { lock, why } = await lockState();
  if (lock) bad(`incident ${lock.incident} is open`, `${why ? `${why} · ` : ""}preflight blocks until vswarm unlock`);
  const { watchState } = await import("./sec/schedule");
  const w = watchState();
  if (w.on) ok("background watch on", `${w.state?.at ? `last check ${new Date(w.state.at).toLocaleString()}` : "no check yet"}${w.note ? ` · ${w.note}` : ""}`);
  else console.log(`  ${c.dim("·")} background watch off  ${c.dim(`vswarm watch on${w.note ? ` · ${w.note}` : ""}`)}`);
  if (w.on && w.realtime) ok("real-time watch on", w.state?.quick ? `last real-time check ${new Date(w.state.quick.at).toLocaleString()}` : "no change seen yet");
  else if (w.on && !WIN) warn("real-time watch off", "only the hourly check runs · vswarm watch on again adds it");
  const sshCfgPath = join(homedir(), ".ssh/config");
  const sshCfg = existsSync(sshCfgPath) ? readFileSync(sshCfgPath, "utf8") : "";
  if (sshCfg.includes(GATE_START)) ok("ssh gate installed", `~/.ssh/config${GLOBAL_TAG()}`);
  else console.log(`  ${c.dim("·")} ssh gate not installed  ${c.dim('vswarm gate ssh "prod-*"')}`);
  for (const l of await hostHealth(sshCfg)) console.log(l);
  const { readPolicy, policyLine } = await import("./sec/policy");
  const pol = await readPolicy();
  (pol.untrusted ? bad : ok)(pol.warn === "allow" ? "WARN is let through" : "WARN is refused", policyLine(pol).replace(/^policy: [^,]+, /, ""));
  const { agentDoctor } = await import("./sec/agent");
  for (const a of await agentDoctor()) {
    if (a.level === "bad") good = false;
    if (a.level === "off") console.log(`  ${c.dim("·")} ${a.text}  ${c.dim(a.detail ?? "")}`);
    else (a.level === "ok" ? ok : a.level === "warn" ? warn : bad)(a.text, a.detail);
  }
  // Command gates (reminders) and gcloud credential hooks: src/sec/cloudgate.ts
  for (const a of await (await import("./sec/cloudgate")).cloudDoctor()) {
    if (a.level === "off") console.log(`  ${c.dim("·")} ${a.text}  ${c.dim(a.detail ?? "")}`);
    else (a.level === "ok" ? ok : warn)(a.text, a.detail);
  }
  if (await guardOn()) ok("install guard on", "npm, pip, brew … are checked before installing");
  else console.log(`  ${c.dim("·")} install guard off  ${c.dim("vswarm guard on")}`);
  console.log();
  return good;
}

// ── ssh gate
export { GATE_START };

/** The ~/.ssh/config block: hosts matching the patterns connect only when preflight passes. */
/**
 * One path for cmd.exe, which runs Match exec on Windows OpenSSH. ssh's own tokenizer allows no quotes inside the
 * exec string, so spaces and cmd's special characters are escaped with ^ instead; % (ssh and cmd both expand it)
 * and quotes are refused.
 */
export function cmdWord(p: string): string {
  if (/["%\r\n]/.test(p)) throw new Error(`cannot put ${p} in ~/.ssh/config: it contains % or a double quote`);
  return p.replace(/[ &|<>^()]/g, "^$&");
}

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
    win
      ? `    ProxyCommand cmd.exe /d /c "echo vswarm: not connecting: this machine did not pass preflight; run: vswarm why 1>&2 & exit 1"`
      : `    ProxyCommand /bin/sh -c 'echo "vswarm: not connecting: this machine did not pass preflight (the reason is above) · vswarm why" >&2; exit 1'`,
    // With certificates: log in with the fresh session key and its certificate first.
    ...(opt.cert ? [`Match originalhost ${patterns.join(",")}`, `    IdentityFile ${opt.cert.key}`, `    CertificateFile ${opt.cert.cert}`] : []),
    GATE_END,
  ].join("\n");
}

export async function gate(args: string[], home = homedir()) {
  const action = args.shift() ?? "status";
  // Command wrappers and the gcloud / az gates: src/sec/cmdgate.ts, src/sec/cloudgate.ts
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
    console.log(block ? block.trim() : "no vswarm gate in ~/.ssh/config · add one: vswarm gate ssh \"prod-*\" \"*.internal\"");
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
  if (action === "ssh" && !args.length) throw new Error('name the hosts to guard, e.g. vswarm gate ssh "prod-*" "*.wallet.internal"');
  if (withCert && !existsSync(join(HOME, "ca", "ca_key"))) throw new Error("no CA yet: vswarm ca init");
  const cert = withCert ? { key: join(HOME, "ca", "session"), cert: join(HOME, "ca", "session-cert.pub") } : undefined;
  const rest = removeBlock(old, GATE_START, GATE_END).trimEnd();
  // ssh uses the first value it sees for most options, so the gate goes first in the file.
  const block = action === "ssh" ? sshGate(args, existsSync(launcherPath()) ? [launcherPath()] : [process.execPath, CLI], { cert }) : undefined;
  const next = block ? `${block}\n\n${rest}\n` : `${rest}\n`;
  const backup = `${cfgPath}.bak-vswarm-${Date.now()}`;
  if (old) writeFileSync(backup, old, { mode: 0o600 });
  mkdirSync(dirname(cfgPath), { recursive: true, mode: 0o700 });
  writeFileSync(cfgPath, next, { mode: 0o600 });
  // Only the block vswarm wrote is its own; a look-alike block someone else put in the file stays visible to scans.
  if (block) recordManaged(block + "\n");
  ok(action === "ssh" ? `ssh gate added for ${args.join(", ")}` : "ssh gate removed", cfgPath);
  if (old) console.log(`  ${c.dim(`backup ${backup}`)}`);
  if (action === "ssh") console.log(`  ${c.dim(`test it: ssh -G <a matching host> | ${WIN ? "findstr /i" : "grep -i"} proxycommand  (empty while preflight passes)`)}`);
}

/** Host patterns of the ssh gate block, when there is one. */
const gatedHostsOf = (cfg: string) => /Match originalhost (\S+) !exec "[^"]* (?:preflight|cert) --quiet/.exec(cfg)?.[1].split(",") ?? [];

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
  if (g.ignoreScripts) console.log(`  ${c.dim("· npm, pnpm, yarn and bun installs run with --ignore-scripts; run a package's scripts deliberately with npm rebuild <package>")}`);
  if (g.sandbox) console.log(`  ${c.dim(WIN ? "· --sandbox is set, and Windows has no sandbox yet: npm, pnpm, yarn and bun installs are refused until guard on without --sandbox" : "· those installs run in the sandbox: this folder writable (not .git), the rest of your home hidden, package registries only; where the sandbox is missing they are refused")}`);
  if (g.strict) console.log(`  ${c.dim("· strict: an install is stopped when a registry or OSV does not answer")}`);
}

export async function guard(args: string[]) {
  const action = args.shift() ?? "status";
  const want: GuardConfig = { ignoreScripts: args.includes("--ignore-scripts"), sandbox: args.includes("--sandbox"), strict: args.includes("--strict") };
  if (action === "status") {
    if (await guardOn()) ok("install guard is on", (await guardFiles()).join(", "));
    else console.log(`  ${c.dim("·")} install guard is off  ${c.dim("vswarm guard on")}`);
    guardSettings(loadGuardConfig());
    return;
  }
  if (action !== "on" && action !== "off") throw new Error("usage: vswarm guard on [--ignore-scripts] [--sandbox] [--strict] | off | status");
  const launcher = action === "on" ? ensureLauncher() : existsSync(launcherPath()) ? launcherPath() : undefined;
  if (action === "on" && want.sandbox) {
    const why = sandboxRefusal(process.platform, (await import("./sec/try/spawn")).canSandbox());
    if (why) throw new Error(`not changed: ${why}`);
  }
  if (action === "on") saveGuardConfig(want);
  const body = action === "off" ? null : guardBody(launcher!, want);
  for (const f of await guardFiles(action === "on")) {
    const changed = setBlock(f, body, GUARD_START, GUARD_END);
    ok(changed ? `${action === "on" ? "added to" : "removed from"} ${f}` : `already ${action} in ${f}`);
  }
  if (action === "on") {
    console.log(`  ${c.dim(`npm, npx, pnpm, yarn, bun, bunx, pip, pip3, uv, uvx, pipx${WIN ? "" : " and brew"} now ask vswarm before installing`)}`);
    guardSettings(want);
    if (WIN) {
      const p = await profilesRun();
      if (!p.ok) warn(`PowerShell's execution policy is ${p.policy}: it runs no profile, so the guard stays off`, "allow local scripts for your user: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned");
      console.log(`  ${c.dim("new PowerShell windows have it; this one: . " + (await guardFiles(true))[0])}`);
    } else console.log(`  ${c.dim("new terminals have it; this one: source " + (await guardFiles())[0])}`);
    console.log(`  ${c.dim("try it: npm install axois   (a look-alike of axios; nothing is installed unless you say so)")}`);
  } else if (WIN) console.log(`  ${c.dim("open a new PowerShell window")}`);
  else console.log(`  ${c.dim("open a new terminal, or: unset -f npm npx pnpm yarn bun bunx pip pip3 uv uvx pipx brew")}`);
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
  const auto = args.includes("--yes") || args.includes("-y") || !canAsk();
  banner("install");
  step("1  files");
  ensureHome();
  ok("data folder", HOME);

  step("2  command");
  writeLauncher();
  ok("launcher", launcherPath());
  writeCompletions();
  ok("completions", paths.completions());
  if (!args.includes("--no-path")) {
    if (WIN) {
      // Your PATH in the registry is changed only when you say so: --path, or yes to the question.
      if (await pathWanted(args, WIN, canAsk(), yes)) {
        await windowsPath(true);
        ok("PATH updated for your user", paths.bin());
      } else console.log(`  ${c.dim(`· PATH not changed · run vswarm as ${launcherPath()}, or add it later: vswarm install --path`)}`);
    } else {
      for (const { file, body } of rcFiles()) ok(setBlock(file, body) ? `PATH added in ${file}` : `PATH already in ${file}`);
    }
  }

  // Pin the release key this copy ships with, so later updates only accept releases signed by it.
  if (!existsSync(PIN()) && (await fingerprints(join(ROOT, "trust", "allowed_signers"))).length) {
    await trust(["pin"]);
  }

  adoptManagedBlocks();

  step("3  baseline");
  if (await loadBaseline()) ok("baseline exists", files.baseline());
  else if (!auto && (await yes("Is this machine clean as far as you know? Record it as the baseline now", true))) {
    const p = Bun.spawn([process.execPath, CLI, "baseline", "--yes"], { stdout: "inherit", stderr: "inherit" });
    await p.exited;
  } else console.log(`  ${c.dim("· later: vswarm baseline")}`);

  await doctor();
  const rc = WIN ? "open a new terminal" : `open a new terminal, or: source ${rcFiles()[0].file}`;
  console.log(`  ${c.bold("next")}  ${c.dim(rc)}`);
  console.log(`        ${c.cyan("vswarm scan")}                         ${c.dim("check this machine")}`);
  if (WIN) console.log(`        ${c.cyan("vswarm watch on")}                     ${c.dim("check every hour in the background")}`);
  else console.log(`        ${c.cyan('vswarm gate ssh "prod-*"')}            ${c.dim("guard ssh to production hosts")}`);
  console.log(`        ${c.cyan("vswarm help")}                         ${c.dim("aws and kubectl gates, respond, report")}\n`);
}

export async function uninstall(args: string[]) {
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
    mkdirSync(dirname(PIN()), { recursive: true, mode: 0o700 });
    writeFileSync(PIN(), readFileSync(shipped, "utf8"), { mode: 0o600 });
    for (const k of keys) ok(`pinned ${k.fp}`, k.who);
    return;
  }
  throw new Error("usage: vswarm trust [status] | trust pin");
}
