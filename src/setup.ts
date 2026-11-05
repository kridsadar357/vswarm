// Installing vswarm on a machine: launcher on PATH, shell completions, data folder, a first baseline, and the
// gate in ~/.ssh/config. Also `doctor` (check the setup), `update` (git pull) and `uninstall`.

import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { ReadStream } from "node:tty";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { ensureHome, HOME, paths, VERSION } from "./home";
import { files, loadBaseline, loadLock } from "./sec/store";

export const CLI = resolve(import.meta.dir, "cli.ts");

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
  process.stdout.write(`  ${c.cyan("?")} ${question} `);
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
          process.stdout.write("\n");
          return done(value.trim());
        }
        if (ch === "\x03") {
          close();
          process.stdout.write("\n");
          process.exit(130);
        }
        if (ch === "\x7f" || ch === "\b") {
          if (value) {
            value = [...value].slice(0, -1).join("");
            process.stdout.write("\b \b");
          }
          continue;
        }
        if (ch < " ") continue;
        value += ch;
        process.stdout.write(secret ? "•" : ch);
      }
    };
    k.on("data", onData);
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
  const comp = paths.completions();
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
  ["scan", "check this machine now"],
  ["baseline", "remember this machine as clean"],
  ["diff", "what changed since the baseline"],
  ["secrets", "long-lived credentials on this machine"],
  ["preflight", "gate before production access (ssh/aws/kubectl)"],
  ["accept", "accept reviewed findings"],
  ["respond", "lock, collect evidence, rotate, quarantine, report"],
  ["report", "write the incident report again"],
  ["unlock", "close an incident once the machine is clean"],
  ["gate", "add the preflight gate to ssh"],
  ["try", "run untrusted code in a sandbox and see what it tried"],
  ["selftest", "plant fake threats in a sandbox home and measure detection"],
  ["shot", "screenshot a localhost page or local file"],
  ["doctor", "check the installation"],
  ["install", "set up launcher, PATH, completions"],
  ["update", "pull the latest version"],
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
    scan|diff) COMPREPLY=( $(compgen -W "--all --json --offline" -- "$cur") ) ;;
    preflight) COMPREPLY=( $(compgen -W "--quiet --strict --fresh --then --json --offline" -- "$cur") ) ;;
    accept) COMPREPLY=( $(compgen -W "--all --list --remove" -- "$cur") ) ;;
    gate) COMPREPLY=( $(compgen -W "ssh status remove" -- "$cur") ) ;;
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
    scan|diff) _arguments '--all[show low and info findings]' '--json[machine-readable output]' '--offline[no OSV lookup]' ;;
    preflight) _arguments '--quiet[print only on problems]' '--strict[WARN also blocks]' '--fresh[ignore the cached verdict]' '--then[run a command when allowed]:command:_command_names' ;;
    accept) _arguments '--all[accept every current finding]' '--list[show accepted]' '--remove[un-accept]:id:' ;;
    gate) _values 'action' ssh status remove ;;
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
  for (const tool of process.platform === "darwin" ? ["codesign", "plutil", "lsof", "ps"] : ["lsof", "ps"]) {
    if (Bun.which(tool)) ok(tool);
    else warn(`${tool} not found`, "some checks will be skipped");
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
  const base = loadBaseline();
  if (base) {
    const days = Math.round((Date.now() - base.at) / 86_400_000);
    (days > 30 ? warn : ok)(`baseline from ${new Date(base.at).toLocaleString()}`, days > 30 ? `${days} days old · refresh it with vswarm baseline once you have reviewed vswarm diff` : `${base.items.length} items`);
  } else {
    warn("no baseline", "vswarm baseline on a machine you trust");
    good = false;
  }
  const lock = loadLock();
  if (lock) bad(`incident ${lock.incident} is open`, "preflight blocks until vswarm unlock");
  const sshCfgPath = join(homedir(), ".ssh/config");
  const sshCfg = existsSync(sshCfgPath) ? readFileSync(sshCfgPath, "utf8") : "";
  if (sshCfg.includes(GATE_START)) ok("ssh gate installed", "~/.ssh/config");
  else console.log(`  ${c.dim("·")} ssh gate not installed  ${c.dim('vswarm gate ssh "prod-*"')}`);
  console.log();
  return good;
}

// ── ssh gate
export const GATE_START = "# >>> vswarm gate >>>";
const GATE_END = "# <<< vswarm gate <<<";

/** The ~/.ssh/config block: hosts matching the patterns connect only when preflight passes. */
export function sshGate(patterns: string[], launcher: string[], opt: { cert?: { key: string; cert: string } } = {}): string {
  // The command sits inside ssh's double quotes; a part with spaces gets single quotes of its own.
  const q = launcher.map((p) => (/\s/.test(p) ? `'${p}'` : p)).join(" ");
  return [
    GATE_START,
    `# Hosts below connect only after \`vswarm preflight\` passes. Remove with: vswarm gate remove`,
    // originalhost is the name you typed (ssh vrfix-prod), before any HostName substitution.
    `Match originalhost ${patterns.join(",")} !exec "${q} ${opt.cert ? "cert" : "preflight"} --quiet --host %h"`,
    `    ProxyCommand /bin/sh -c 'echo "vswarm: this machine did not pass preflight; run: vswarm preflight" >&2; exit 1'`,
    // With certificates: log in with the fresh session key and its certificate first.
    ...(opt.cert ? [`Match originalhost ${patterns.join(",")}`, `    IdentityFile ${opt.cert.key}`, `    CertificateFile ${opt.cert.cert}`] : []),
    GATE_END,
  ].join("\n");
}

export async function gate(args: string[]) {
  const action = args.shift() ?? "status";
  const cfgPath = join(homedir(), ".ssh", "config");
  const old = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "";
  const re = new RegExp(`\\n?${GATE_START}[\\s\\S]*?${GATE_END}\\n?`, "g");
  if (action === "status") {
    const block = old.match(re)?.[0];
    console.log(block ? block.trim() : "no vswarm gate in ~/.ssh/config · add one: vswarm gate ssh \"prod-*\" \"*.internal\"");
    return;
  }
  if (action !== "ssh" && action !== "remove") throw new Error('usage: vswarm gate ssh "<host pattern>" [...] | gate status | gate remove');
  if (action === "ssh" && !args.length) throw new Error('name the hosts to guard, e.g. vswarm gate ssh "prod-*" "*.wallet.internal"');
  const backup = `${cfgPath}.bak-vswarm-${Date.now()}`;
  if (old) writeFileSync(backup, old, { mode: 0o600 });
  const rest = old.replace(re, "\n").replace(/\n{3,}/g, "\n\n").trimEnd();
  // ssh uses the first value it sees for most options, so the gate goes first in the file.
  const certAt = args.indexOf("--cert");
  const withCert = certAt >= 0;
  if (withCert) args.splice(certAt, 1);
  if (withCert && !existsSync(join(HOME, "ca", "ca_key"))) throw new Error("no CA yet: vswarm ca init");
  const cert = withCert ? { key: join(HOME, "ca", "session"), cert: join(HOME, "ca", "session-cert.pub") } : undefined;
  const next = action === "ssh" ? `${sshGate(args, existsSync(launcherPath()) ? [launcherPath()] : [process.execPath, CLI], { cert })}\n\n${rest}\n` : `${rest}\n`;
  mkdirSync(dirname(cfgPath), { recursive: true, mode: 0o700 });
  writeFileSync(cfgPath, next, { mode: 0o600 });
  ok(action === "ssh" ? `ssh gate added for ${args.join(", ")}` : "ssh gate removed", cfgPath);
  if (old) console.log(`  ${c.dim(`backup ${backup}`)}`);
  if (action === "ssh") console.log(`  ${c.dim("test it: ssh -G <a matching host> | grep -i proxycommand  (empty while preflight passes)")}`);
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
      await windowsPath(true);
      ok("PATH updated for your user", paths.bin());
    } else {
      for (const { file, body } of rcFiles()) ok(setBlock(file, body) ? `PATH added in ${file}` : `PATH already in ${file}`);
    }
  }

  step("3  baseline");
  if (loadBaseline()) ok("baseline exists", files.baseline());
  else if (!auto && (await yes("Is this machine clean as far as you know? Record it as the baseline now", true))) {
    const p = Bun.spawn([process.execPath, CLI, "baseline", "--yes"], { stdout: "inherit", stderr: "inherit" });
    await p.exited;
  } else console.log(`  ${c.dim("· later: vswarm baseline")}`);

  await doctor();
  const rc = WIN ? "open a new terminal" : `open a new terminal, or: source ${rcFiles()[0].file}`;
  console.log(`  ${c.bold("next")}  ${c.dim(rc)}`);
  console.log(`        ${c.cyan("vswarm scan")}                         ${c.dim("check this machine")}`);
  console.log(`        ${c.cyan('vswarm gate ssh "prod-*"')}            ${c.dim("guard ssh to production hosts")}`);
  console.log(`        ${c.cyan("vswarm help")}                         ${c.dim("aws and kubectl gates, respond, report")}\n`);
}

export async function uninstall(args: string[]) {
  banner("uninstall");
  if (existsSync(launcherPath())) rmSync(launcherPath());
  ok("launcher removed");
  if (WIN) await windowsPath(false);
  else for (const { file } of rcFiles()) if (setBlock(file, null)) ok(`PATH removed from ${file}`);
  rmSync(paths.completions(), { recursive: true, force: true });
  const sshCfg = join(homedir(), ".ssh/config");
  if (existsSync(sshCfg) && readFileSync(sshCfg, "utf8").includes(GATE_START)) await gate(["remove"]);
  if (args.includes("--purge")) {
    rmSync(HOME, { recursive: true, force: true });
    ok("data removed", HOME);
  } else console.log(`  ${c.dim(`· kept ${HOME} (baseline, incidents) · remove it too with --purge`)}`);
  console.log(`  ${c.dim("· the app folder stays at " + ROOT)}\n`);
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
  ok("launcher and completions refreshed\n");
}
