// Commands that weaken this machine's protection ask a person first: marking findings as yours, a new baseline,
// unlocking, letting WARN through, taking a gate, the install guard, the watch or a canary away, loosening a
// protected key, leaving a team, removing vswarm. An AI agent (Claude Code, Codex, Gemini …) can run vswarm too, and
// one that reads a poisoned README or issue could be talked into switching vswarm off; this is where that stops.
//
// How it asks: on a terminal a person is at (stdin and stderr are terminals, and no agent says it is running), a
// question there; anywhere else a dialog on the desktop (agent.ts askOnDesktop), which a program typing into a pipe
// or a pseudo-terminal cannot answer. No way to ask means no. There is no flag or variable that skips it: anything a
// person could set, an agent could set too.
//
// It protects the real home. A run whose home and every vswarm folder point elsewhere (tests, a scratch scan) changes
// nothing that protects you, so it is not asked about. The real home comes from the system's user database, never
// from HOME, which a caller sets.
//
// What it is not: a wall against a program that already runs as you and means harm. Such a program can edit
// ~/.ssh/config or your shell rc itself; vswarm's own blocks are recognised by hash, so the next check says a gate or
// the guard was changed by hand.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve, isAbsolute } from "node:path";
import { HOME } from "../home";
import { t } from "../i18n";
import { run } from "./ctx";

/** The command line as it is shown in a question: printable, short. */
export const shown = (cmd: string, args: string[]) => `vswarm ${[cmd, ...args].join(" ")}`.replace(/[\x00-\x1f\x7f-\x9f]/g, " ").slice(0, 200);

/** Asks before `vswarm <cmd> <args>`, which weakens protection; called right before it changes anything. */
export const weaken = (cmd: string, args: string[] = []) => confirmWeakening(shown(cmd, args));

/** The home directory the system has for this user, whatever HOME says; undefined when it cannot be read. */
export async function realHome(): Promise<string | undefined> {
  if (process.platform === "win32") {
    const out = await run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "[Environment]::GetFolderPath('UserProfile')"], 10_000);
    return out?.trim() || undefined;
  }
  const uid = process.getuid?.();
  if (uid === undefined) return;
  if (process.platform === "darwin") {
    const name = (await run(["/usr/bin/id", "-un"], 5000))?.trim();
    const out = name ? await run(["/usr/bin/dscl", ".", "-read", `/Users/${name}`, "NFSHomeDirectory"], 5000) : undefined;
    return /NFSHomeDirectory:\s*(\S.*)$/m.exec(out ?? "")?.[1]?.trim();
  }
  const line = (await run(["getent", "passwd", String(uid)], 5000)) ?? (existsSync("/etc/passwd") ? readFileSync("/etc/passwd", "utf8").split("\n").find((l) => l.split(":")[2] === String(uid)) : undefined);
  return line?.trim().split(":")[5] || undefined;
}

const inside = (dir: string, root: string) => {
  const r = relative(resolve(root), resolve(dir));
  return r === "" || (!r.startsWith("..") && !isAbsolute(r));
};

/** The places a weakening command changes: the home it edits and vswarm's own folders. */
function places(env: Record<string, string | undefined>): string[] {
  const home = env.HOME ?? env.USERPROFILE ?? homedir();
  const vs = env.VSWARM_HOME ?? (env === process.env ? HOME : join(home, ".vswarm"));
  return [home, vs, ...["VSWARM_SEC_DIR", "VSWARM_AGENT_DIR", "VSWARM_GATE_DIR", "VSWARM_BACKUP_DIR", "VSWARM_TEAM_DIR", "VSWARM_CA_DIR"].map((k) => env[k] ?? join(vs, "x"))];
}

/** Whether this run changes the real home (or cannot tell, which counts as yes). */
export async function touchesRealHome(env: Record<string, string | undefined> = process.env, real?: string): Promise<boolean> {
  const r = real ?? (await realHome());
  if (!r) return true;
  return places(env).some((p) => inside(p, r));
}

// Variables coding agents set in the shells they run. A hint only: an agent that sets none still gets the dialog when
// it has no terminal, and one that drives a terminal of its own is why the dialog is preferred whenever in doubt.
const AGENT_VARS = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "GEMINI_CLI", "CURSOR_TRACE_ID", "AIDER_MODEL", "OPENCODE"];
export const agentSaysSo = (env: Record<string, string | undefined>) => AGENT_VARS.some((k) => !!env[k]);

export interface Asker {
  terminal: (q: string) => Promise<string>;
  desktop: (q: string) => Promise<boolean>;
  canDesktop: () => boolean;
}

let injected: ((cmdline: string) => Promise<boolean>) | undefined;
/** Tests answer the question themselves (in this process only; nothing outside it can reach this). */
export function answerWith(f: ((cmdline: string) => Promise<boolean>) | undefined) {
  injected = f;
}

/** Whether a dialog can be shown here: always on macOS and Windows, on Linux with a display and askpass or zenity. */
export function desktopAvailable(env: Record<string, string | undefined> = process.env): boolean {
  if (process.platform === "darwin" || process.platform === "win32") return true;
  if (!env.DISPLAY && !env.WAYLAND_DISPLAY) return false;
  return !!(env.SSH_ASKPASS && existsSync(env.SSH_ASKPASS)) || !!Bun.which("zenity");
}

async function defaultAsker(): Promise<Asker> {
  const { ask } = await import("../setup");
  const { askOnDesktop } = await import("./agent");
  return { terminal: (q) => ask(q), desktop: (q) => askOnDesktop(q, "vswarm"), canDesktop: () => desktopAvailable() };
}

/**
 * Asks a person before a command that weakens protection; throws when they say no or nobody can be asked.
 * `io` and `env` are for tests; the real run uses the terminal, the desktop and process.env.
 */
export async function confirmWeakening(cmdline: string, opt: { env?: Record<string, string | undefined>; tty?: boolean; io?: Asker; real?: string } = {}): Promise<void> {
  const env = opt.env ?? process.env;
  if (!(await touchesRealHome(env, opt.real))) return;
  if (injected && !opt.io) {
    if (await injected(cmdline)) return;
    throw new Error(t("cli.human.refused", { cmd: cmdline }));
  }
  const io = opt.io ?? (await defaultAsker());
  const tty = opt.tty ?? (!!process.stdin.isTTY && !!process.stderr.isTTY);
  if (tty && !agentSaysSo(env)) {
    const a = (await io.terminal(t("cli.human.askTerm", { cmd: cmdline }))).trim().toLowerCase();
    if (/^(y|yes|ใช่|ช)$/.test(a)) return;
    throw new Error(t("cli.human.refused", { cmd: cmdline }));
  }
  if (!io.canDesktop()) throw new Error(t("cli.human.noWay", { cmd: cmdline }));
  if (await io.desktop(t("cli.human.askDesktop", { cmd: cmdline }))) return;
  throw new Error(t("cli.human.refused", { cmd: cmdline }));
}
