// `vswarm hook`: a check in front of an AI agent's shell commands, before they run. Claude Code calls it as a
// PreToolUse hook with the command it is about to run (JSON on stdin); vswarm answers on stdout.
//
//   a command that reaches production (ssh, aws, kubectl, deploy tools, a gated tool)
//       and this machine does not pass          → deny, with why and what the person does
//   a command that weakens vswarm (vswarm ok, unlock, policy warn allow, editing ~/.vswarm or the ssh gate by hand)
//                                               → ask: Claude Code asks the person before it runs
//   anything else                               → nothing: the agent's own permissions decide
//
// The hook never answers "allow": it can only make the agent more careful, never skip a question the person set up.
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
/** Writing to vswarm's own files or the ssh config (where the gate is) by hand. */
const BY_HAND = /(?:\.vswarm\b|\.ssh\/config\b|vswarm-gate|vswarm agent)/;
const WRITES = /(?:>>?|\btee\b|\bsed\s+-i|\bperl\s+-[a-z]*i|\brm\b|\bmv\b|\bcp\b|\btruncate\b|\bchmod\b|\bln\b|\bpython3?\b|\bnode\b)/;

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
  if (WEAKEN.test(line)) return { kind: "weaken", what: "it weakens vswarm's protection" };
  if (BY_HAND.test(line) && WRITES.test(line)) return { kind: "weaken", what: "it changes vswarm's files or the ssh gate by hand" };
  for (const w of commandsOf(line)) {
    const name = w[0].split("/").pop()!;
    const rule = PROD[name];
    const rest = w.slice(1).join(" ");
    if (rule === true || (rule && rule.test(rest)) || gated.includes(name)) return { kind: "prod", what: name };
  }
}

/** Claude Code's PreToolUse answer. */
const answer = (decision: "deny" | "ask", reason: string) => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason } });

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
    return answer("ask", `vswarm: ${v.what}. That is the person's decision, not the agent's; vswarm will also ask them itself. If the person did not ask for this, do not run it.`);
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
