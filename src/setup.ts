// Installing vswarm on a machine: launcher on PATH, shell completions, data folder, a first baseline, and the
// gate in ~/.ssh/config. Also `doctor` (check the setup), `update` (git pull) and `uninstall`.

import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { ReadStream } from "node:tty";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { ensureHome, HOME, paths, VERSION } from "./home";
import { dq, exec, shq } from "./sec/ctx";
import { blockRegex, files, loadBaseline, loadLock, recordManaged, removeBlock } from "./sec/store";
import { GUARD_END, GUARD_START, guardBlock } from "./sec/pkg";
import { fingerprints, PIN, secureUpdate } from "./sec/update";

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

/** A yes/no question; the default answer when there is no terminal to ask on. */
export const yes = async (q: string, def = false) => {
  if (!canAsk()) return def;
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
    writeFileSync(launcherPath(), `#!/bin/sh\n# vswarm launcher, written by \`vswarm install\`\nexec ${dq(bun)} ${dq(CLI)} "$@"\n`);
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

function setBlock(file: string, body: string | null, start = BLOCK_START, end = BLOCK_END) {
  const old = existsSync(file) ? readFileSync(file, "utf8") : "";
  // body may carry its own markers (guardBlock does); the managed block is always start…end.
  const block = body?.startsWith(start) ? `${body}\n` : `${start}\n${body}\n${end}\n`;
  if (body !== null && old.includes(block)) return false;
  const rest = removeBlock(old, start, end);
  const next = body === null ? rest : rest.trimEnd() + (rest.trim() ? "\n\n" : "") + block;
  if (next === old) return false;
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, next);
  if (body !== null) recordManaged(block);
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
  ["watch", "check in the background and notify"],
  ["secrets", "long-lived credentials on this machine"],
  ["agents", "MCP servers, hooks and permissions of AI agents"],
  ["preflight", "gate before production access (ssh/aws/kubectl)"],
  ["accept", "accept reviewed findings"],
  ["respond", "lock, collect evidence, rotate, quarantine, report"],
  ["report", "write the incident report again"],
  ["unlock", "close an incident once the machine is clean"],
  ["gate", "add the preflight gate to ssh"],
  ["guard", "check npm, pip and brew packages before they install"],
  ["pkg", "check what a package-manager command would install"],
  ["try", "run untrusted code in a sandbox and see what it tried"],
  ["ca", "certificate authority for short-lived SSH certificates"],
  ["cert", "issue a short-lived SSH certificate after preflight"],
  ["canary", "plant decoy credentials that alert you when used"],
  ["selftest", "plant fake threats in a sandbox home and measure detection"],
  ["shot", "screenshot a localhost page or local file"],
  ["doctor", "check the installation"],
  ["install", "set up launcher, PATH, completions"],
  ["update", "move to the newest signed release"],
  ["trust", "release keys updates must be signed with"],
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
    guard) COMPREPLY=( $(compgen -W "on off status" -- "$cur") ) ;;
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
    guard) _values 'action' on off status ;;
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

export async function doctor(): Promise<boolean> {
  let good = true;
  step("runtime");
  ok(`bun ${Bun.version}`, process.execPath);
  const tools: [string, string][] = process.platform === "darwin"
    ? [["codesign", "some checks will be skipped"], ["plutil", "some checks will be skipped"], ["lsof", "connections will not be checked"], ["ps", "processes will not be checked"]]
    : [["ss", "connections will not be checked (iproute2)"], ["bwrap", "vswarm try needs it: sudo apt install bubblewrap"], ["strace", "vswarm try will not see file and connection attempts: sudo apt install strace"]];
  for (const [tool, why] of tools) {
    if (Bun.which(tool)) ok(tool);
    else warn(`${tool} not found`, why);
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
  const { watchState } = await import("./sec/schedule");
  const w = watchState();
  if (w.on) ok("background watch on", w.state ? `last check ${new Date(w.state.at).toLocaleString()}` : "no check yet");
  else console.log(`  ${c.dim("·")} background watch off  ${c.dim("vswarm watch on")}`);
  if (guardOn()) ok("install guard on", "npm, pip, brew … are checked before installing");
  else console.log(`  ${c.dim("·")} install guard off  ${c.dim("vswarm guard on")}`);
  console.log();
  return good;
}

// ── ssh gate
export const GATE_START = "# >>> vswarm gate >>>";
const GATE_END = "# <<< vswarm gate <<<";

/** The ~/.ssh/config block: hosts matching the patterns connect only when preflight passes. */
export function sshGate(patterns: string[], launcher: string[], opt: { cert?: { key: string; cert: string } } = {}): string {
  // Both end up on one line of ~/.ssh/config: a space, quote or newline in a pattern would change what the line means.
  const bad = patterns.find((p) => !/^[\w*?!.:\[\]-]+$/.test(p));
  if (bad !== undefined) throw new Error(`"${bad}" is not an ssh host pattern (letters, digits, . - * ? and !)`);
  if (launcher.some((p) => /["\n]/.test(p))) throw new Error(`cannot put ${launcher.join(" ")} in ~/.ssh/config: it contains a double quote`);
  // The command sits inside ssh's double quotes; a part with spaces or shell characters gets single quotes of its own.
  const q = launcher.map(shq).join(" ");
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

export async function gate(args: string[], home = homedir()) {
  const action = args.shift() ?? "status";
  const cfgPath = join(home, ".ssh", "config");
  const old = existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "";
  if (action === "status") {
    const block = old.match(blockRegex(GATE_START, GATE_END))?.[0];
    console.log(block ? block.trim() : "no vswarm gate in ~/.ssh/config · add one: vswarm gate ssh \"prod-*\" \"*.internal\"");
    return;
  }
  if (action !== "ssh" && action !== "remove") throw new Error('usage: vswarm gate ssh "<host pattern>" [...] | gate status | gate remove');
  // Everything that can refuse comes before the backup and the write, so a refused command changes nothing.
  const certAt = args.indexOf("--cert");
  const withCert = certAt >= 0;
  if (withCert) args.splice(certAt, 1);
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
  if (action === "ssh") console.log(`  ${c.dim("test it: ssh -G <a matching host> | grep -i proxycommand  (empty while preflight passes)")}`);
}

// ── Install guard: npm, pip, brew … ask vswarm before they install
function guardFiles(): string[] {
  return rcFiles().map((r) => r.file).filter((f) => /\.(zsh|bash)rc$/.test(f));
}

export function guardOn(): boolean {
  return guardFiles().some((f) => existsSync(f) && readFileSync(f, "utf8").includes(GUARD_START));
}

export async function guard(args: string[]) {
  const action = args.shift() ?? "status";
  if (action === "status") {
    if (guardOn()) ok("install guard is on", guardFiles().join(", "));
    else console.log(`  ${c.dim("·")} install guard is off  ${c.dim("vswarm guard on")}`);
    return;
  }
  if (action !== "on" && action !== "off") throw new Error("usage: vswarm guard on | off | status");
  const launcher = existsSync(launcherPath()) ? launcherPath() : undefined;
  if (action === "on" && !launcher) throw new Error("install the launcher first: vswarm install");
  for (const f of guardFiles()) {
    const changed = setBlock(f, action === "on" ? guardBlock(launcher!) : null, GUARD_START, GUARD_END);
    ok(changed ? `${action === "on" ? "added to" : "removed from"} ${f}` : `already ${action} in ${f}`);
  }
  if (action === "on") {
    console.log(`  ${c.dim("npm, npx, pnpm, yarn, bun, bunx, pip, pip3, uv, uvx, pipx and brew now ask vswarm before installing")}`);
    console.log(`  ${c.dim("new terminals have it; this one: source " + guardFiles()[0])}`);
    console.log(`  ${c.dim("try it: npm install axois   (a look-alike of axios; nothing is installed unless you say so)")}`);
  } else console.log(`  ${c.dim("open a new terminal, or: unset -f npm npx pnpm yarn bun bunx pip pip3 uv uvx pipx brew")}`);
}

/**
 * Blocks vswarm wrote before it kept their hashes (versions before 2.4) are recognised here when they are exactly
 * what vswarm writes today, so scans stop reporting them. Anything that differs is left alone, and stays visible.
 */
export function adoptManagedBlocks() {
  const known: string[] = [];
  for (const { body } of rcFiles()) known.push(`${BLOCK_START}\n${body}\n${BLOCK_END}\n`);
  if (existsSync(launcherPath())) known.push(guardBlock(launcherPath()) + "\n");
  const sshCfg = join(homedir(), ".ssh", "config");
  const cfg = existsSync(sshCfg) ? readFileSync(sshCfg, "utf8") : "";
  const m = /Match originalhost (\S+) !exec "(.+) (preflight|cert) --quiet --host %h"/.exec(cfg);
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

  // Pin the release key this copy ships with, so later updates only accept releases signed by it.
  if (!existsSync(PIN()) && (await fingerprints(join(ROOT, "trust", "allowed_signers"))).length) {
    await trust(["pin"]);
  }

  adoptManagedBlocks();

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
  if (guardOn()) await guard(["off"]);
  if (args.includes("--purge")) {
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
  if (r.status === "current") {
    for (const k of r.pinned ?? []) console.log(`  ${c.amber("!")} trusting release key ${c.bold(k.fp)} (${k.who}) from now on`);
    return ok(`already on ${r.at}, signed by a trusted release key\n`);
  }
  if (r.status === "unsigned-repo") {
    warn(args.includes("--unsigned") ? "following main without signature checks (--unsigned)" : "this repository has no signed releases yet; following main as before");
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
