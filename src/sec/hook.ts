// `vswarm hook`: a check in front of an AI agent's shell commands, before they run. Claude Code calls it as a
// PreToolUse hook with the command it is about to run (JSON on stdin); vswarm answers on stdout.
//
//   a command that reaches production (ssh, aws, kubectl, deploy tools, a gated tool)
//       and this machine does not pass          → deny, with why and what the person does
//   a command that weakens vswarm (vswarm ok, unlock, policy warn allow, editing ~/.vswarm or the ssh gate by hand)
//                                               → deny: the person runs it themselves, in their own terminal
//   anything else                               → nothing: the agent's own permissions decide
//
// Weakening is denied rather than asked about: in Claude Code's auto mode an "ask" can be answered for the person, and
// a deny holds in every mode. The hook never answers "allow": it can only make the agent more careful, never skip a
// question the person set up.
// It is a first line, not the wall: the ssh gate, the vault and the gated tools refuse on their own whatever an
// agent runs, and this hook gives the agent the reason in words before it tries another way.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { shellLine } from "../commands";

/** Programs that reach production or deploy. Some count only with certain words after them. */
const PROD: Record<string, RegExp | true> = {
  ssh: true, scp: true, sftp: true, mosh: true, rsync: /\S+:/, aws: true, kubectl: true, helm: true, k9s: true, gcloud: true, az: true,
  eksctl: true, terraform: /\b(apply|destroy|import)\b/, tofu: /\b(apply|destroy|import)\b/, pulumi: /\b(up|destroy)\b/,
  vercel: /(^|\s)(deploy|--prod)\b/, fly: /\bdeploy\b/, flyctl: /\bdeploy\b/, firebase: /\bdeploy\b/, heroku: true, wrangler: /\b(deploy|publish)\b/,
  netlify: /\bdeploy\b/, ansible: true, "ansible-playbook": true, doctl: true,
};

/** vswarm commands that weaken protection (the ones human.ts asks about), installed or run from a checkout (cli.ts). */
const WEAKEN = /(?:\bvswarm|\bcli\.ts)\s+(?:ok|accept|baseline|unlock|uninstall|setup)\b|(?:\bvswarm|\bcli\.ts)\s+policy\s+warn\s+allow\b|(?:\bvswarm|\bcli\.ts)\s+(?:gate|guard|watch|agent|team|canary|feed|trust|hook)\b[^;&|\n]*\b(?:remove|off|unprotect|leave|pin|--off|--allow-warn)\b/;
/** vswarm's own folder, or the ssh config where the gate and the agent blocks are. Quotes around a word are ignored. */
const PROTECTED = (word: string) => /(^|\/)\.vswarm(\/|$)|(^|\/)\.ssh\/config$/.test(word.replace(/^['"]|['"]$/g, "").replace(/^(\$HOME|\$\{HOME\})/, "~"));
/** Commands that change every path they are given; those that change only the last one (the destination); in place with -i. */
const CHANGES_ALL = new Set(["rm", "rmdir", "unlink", "shred", "truncate", "touch", "chmod", "chown", "chflags", "ln", "mv", "tee"]);
const CHANGES_LAST = new Set(["cp", "rsync", "install", "ditto"]);
const IN_PLACE = new Set(["sed", "gsed", "perl"]);

/**
 * Whether a line writes to vswarm's files or the ssh config: a redirection into one, or a command that changes one
 * (rm, mv, chmod … on it, cp or rsync onto it, sed -i on it, dd of= it). Reading them (cat, grep, cp from, git -C) is
 * fine. A script that writes them (python, node) is not seen here; the next check sees the change (vswarm knows its
 * own blocks by hash).
 */
export function writesProtected(line: string): boolean {
  for (const m of line.matchAll(/(?:^|[^<>&\d])\d?>>?\|?\s*(\S+)/g)) if (PROTECTED(m[1])) return true;
  for (const w of commandsOf(line)) {
    const name = w[0].split("/").pop()!;
    const args = w.slice(1).filter((a) => !/^\d?>/.test(a));
    const paths = args.filter((a) => !a.startsWith("-"));
    if (CHANGES_ALL.has(name) && paths.some(PROTECTED)) return true;
    if (CHANGES_LAST.has(name) && paths.length > 1 && PROTECTED(paths[paths.length - 1])) return true;
    if (IN_PLACE.has(name) && args.some((a) => /^-[a-zA-Z]*i/.test(a)) && paths.some(PROTECTED)) return true;
    if (name === "dd" && args.some((a) => a.startsWith("of=") && PROTECTED(a.slice(3)))) return true;
  }
  return false;
}

/** The commands of a shell line: split on ; && || | and new lines, leading VAR=x, sudo, env, exec and time dropped. */
export function commandsOf(line: string): string[][] {
  return line.split(/;|&&|\|\||\||\n|\$\(|`|\(|\)/).map((part) => {
    const w = part.trim().split(/\s+/).filter(Boolean);
    while (w.length && (/^[A-Za-z_]\w*=/.test(w[0]) || ["sudo", "env", "exec", "time", "nohup", "command", "then", "do", "else", "!"].includes(w[0]))) w.shift();
    return w;
  }).filter((w) => w.length);
}

export type Verdict = { kind: "prod"; what: string } | { kind: "weaken"; what: string } | undefined;

/** What a command line is to vswarm. `gated` are the tools `vswarm gate cmd` guards (psql, mysql …). */
export function classify(line: string, gated: string[] = []): Verdict {
  // Listing what was accepted only reads.
  line = line.replace(/(?:\bvswarm|\bcli\.ts)\s+(?:ok|accept)\s+--list\b/g, "");
  if (WEAKEN.test(line)) return { kind: "weaken", what: "it weakens vswarm's protection" };
  if (writesProtected(line)) return { kind: "weaken", what: "it changes vswarm's files or the ssh gate by hand" };
  for (const w of commandsOf(line)) {
    const name = w[0].split("/").pop()!;
    const rule = PROD[name];
    const rest = w.slice(1).join(" ");
    if (rule === true || (rule && rule.test(rest)) || gated.includes(name)) return { kind: "prod", what: name };
  }
}

/** Claude Code's PreToolUse answer. */
const answer = (decision: "deny", reason: string) => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason } });

/**
 * The hook itself: Claude Code's event in, its answer out (undefined: say nothing). `verdict` is the gate's verdict
 * and whether it lets this through; `reason` says why it does not.
 */
export async function onTool(event: any, opt: { gated?: string[]; gate: () => Promise<{ allowed: boolean }>; reason: (cmd: string) => Promise<string> }): Promise<object | undefined> {
  if (event?.tool_name !== "Bash") return;
  const cmd = typeof event?.tool_input?.command === "string" ? event.tool_input.command : "";
  const v = classify(cmd, opt.gated);
  if (!v) return;
  if (v.kind === "weaken")
    return answer("deny", `vswarm: not run, because ${v.what}. That is the person's decision, not the agent's. Tell the user what you wanted to do and why; if they agree, they run it themselves in their own terminal. Do not try another way to do the same.`);
  if ((await opt.gate()).allowed) return;
  return answer("deny", `${await opt.reason(cmd)}\n\nIf you are an AI agent: vswarm stopped this on purpose. Do not try another way in (another host name, an API token, a different tool). Tell the user.`);
}

/** `vswarm hook claude`: reads the event on stdin, answers on stdout; never fails the agent's tool call itself. */
export async function hookClaude(input: string): Promise<string> {
  let event: any;
  try {
    event = JSON.parse(input);
  } catch {
    return "";
  }
  const { loadCmdGates } = await import("./cmdgate");
  const { gateVerdict } = await import("./gate");
  const { refusalText } = await import("./serve");
  let gated: string[] = [];
  try {
    gated = Object.keys(loadCmdGates().tools);
  } catch {}
  // The gate's own lines go to stderr, which Claude Code shows the person; the answer is the one line on stdout.
  const out = await onTool(event, { gated, gate: () => gateVerdict({ quiet: true }), reason: refusalText });
  return out ? JSON.stringify(out) : "";
}

// ── installing it into Claude Code

export const settingsFile = (home = homedir()) => join(home, ".claude", "settings.json");
const isOurs = (h: any) => typeof h?.command === "string" && /\bhook claude$/.test(h.command) && /vswarm|cli\.ts/.test(h.command);

/** Whether vswarm's hook is in Claude Code's user settings. */
export function hookInstalled(file = settingsFile()): boolean {
  try {
    const j = JSON.parse(readFileSync(file, "utf8"));
    return (j.hooks?.PreToolUse ?? []).some((m: any) => (m?.hooks ?? []).some(isOurs));
  } catch {
    return false;
  }
}

/**
 * Adds the hook to Claude Code's user settings, keeping everything else in the file; a vswarm hook already there with
 * another command (an older install, a moved checkout) is replaced. Returns the backup, if any.
 */
export function installHook(self: string[], file = settingsFile(), backup?: (f: string) => string): { changed: boolean; backup?: string } {
  let j: any = {};
  if (existsSync(file)) {
    try {
      j = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      throw new Error(`${file} is not valid JSON; fix it first, vswarm will not overwrite it`);
    }
  }
  const command = `${shellLine(self)} hook claude`;
  const pre: any[] = Array.isArray(j.hooks?.PreToolUse) ? j.hooks.PreToolUse : [];
  const ours = pre.flatMap((m: any) => (m?.hooks ?? []).filter(isOurs));
  if (ours.length === 1 && ours[0].command === command) return { changed: false };
  const others = pre.map((m: any) => ({ ...m, hooks: (m?.hooks ?? []).filter((h: any) => !isOurs(h)) })).filter((m: any) => m.hooks.length);
  j.hooks ??= {};
  j.hooks.PreToolUse = [...others, { matcher: "Bash", hooks: [{ type: "command", command, timeout: 60 }] }];
  const copy = existsSync(file) && backup ? backup(file) : undefined;
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(j, null, 2)}\n`, { mode: 0o600 });
  return { changed: true, backup: copy };
}

/** Takes vswarm's hook out again, and nothing else. */
export function removeHook(file = settingsFile(), backup?: (f: string) => string): { changed: boolean; backup?: string } {
  if (!hookInstalled(file)) return { changed: false };
  const j = JSON.parse(readFileSync(file, "utf8"));
  j.hooks.PreToolUse = j.hooks.PreToolUse.map((m: any) => ({ ...m, hooks: (m?.hooks ?? []).filter((h: any) => !isOurs(h)) })).filter((m: any) => m.hooks.length);
  if (!j.hooks.PreToolUse.length) delete j.hooks.PreToolUse;
  if (!Object.keys(j.hooks).length) delete j.hooks;
  const copy = backup?.(file);
  writeFileSync(file, `${JSON.stringify(j, null, 2)}\n`, { mode: 0o600 });
  return { changed: true, backup: copy };
}

const USAGE = "usage: vswarm hook install claude | remove claude | status · Claude Code runs vswarm hook claude itself";

export async function hookCommand(args: string[]) {
  const [action, agent] = args;
  if (action === "claude" && args.length === 1) {
    process.stdout.write(await hookClaude(await new Response(Bun.stdin.stream()).text()));
    return;
  }
  const { c, line } = await import("./print");
  if (action === "status" || action === undefined) {
    line(hookInstalled() ? `${c.green("✔")} Claude Code: vswarm checks shell commands before they run (${settingsFile().replace(homedir(), "~")})` : `  ${c.dim("·")} Claude Code: no vswarm hook · vswarm hook install claude`);
    return;
  }
  if (agent !== "claude" || args.length !== 2) throw new Error(USAGE);
  const { backupCopy } = await import("./fix");
  const { launcherPath } = await import("../setup");
  const keep = (f: string) => backupCopy(f, "claude-settings");
  if (action === "install") {
    const { runningSelf } = await import("../commands");
    const { self, older } = await runningSelf();
    const r = installHook(self, settingsFile(), keep);
    if (older) line(c.amber(`  The installed vswarm (${launcherPath().replace(homedir(), "~")}) is ${older}, not this one, and may not know this command: the hook runs this copy instead. After you reinstall, run vswarm hook install claude again.`));
    if (!r.changed) return line(`${c.green("✔")} already there`);
    line(`${c.green("✔")} Claude Code now asks vswarm before shell commands that reach production or weaken vswarm`);
    if (r.backup) line(c.dim(`  backup ${r.backup.replace(homedir(), "~")}`));
    line(c.dim("  The next check lists this hook as new, like any agent hook: vswarm ok <n> once you see it is this one."));
    return;
  }
  if (action === "remove") {
    if (!hookInstalled()) return line(`  ${c.dim("·")} no vswarm hook in Claude Code`);
    await (await import("./human")).weaken("hook", ["remove", "claude"]);
    const r = removeHook(settingsFile(), keep);
    line(`${c.green("✔")} vswarm's hook is out of Claude Code${r.backup ? c.dim(` · backup ${r.backup.replace(homedir(), "~")}`) : ""}`);
    return;
  }
  throw new Error(USAGE);
}
