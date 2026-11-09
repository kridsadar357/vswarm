// The marker lines of the blocks vswarm writes into ~/.ssh/config, in one place: setup.ts (the gate), agent.ts (the
// agent) and sshconfig.ts (reading them back) all need them, and none of those may import the others for it. Also
// the one escape both blocks need for Windows OpenSSH.

export const GATE_START = "# >>> vswarm gate >>>";
export const GATE_END = "# <<< vswarm gate <<<";
export const AGENT_START = "# >>> vswarm agent >>>";
export const AGENT_END = "# <<< vswarm agent <<<";

/**
 * One path for cmd.exe, which runs Match exec on Windows OpenSSH. ssh's own tokenizer allows no quotes inside the
 * exec string, so spaces and cmd's special characters are escaped with ^ instead; % (ssh and cmd both expand it)
 * and quotes are refused.
 */
export function cmdWord(p: string): string {
  if (/["%\r\n]/.test(p)) throw new Error(`cannot put ${p} in ~/.ssh/config: it contains % or a double quote`);
  return p.replace(/[ &|<>^()]/g, "^$&");
}

/**
 * The line under a block's Match exec, run when the check before a login did not exit 0. That happens when the machine
 * did not pass, and also when vswarm cannot run at all (its folder removed, Bun moved): the line tells the two apart by
 * asking the launcher for its version, so nobody is told their machine failed a check that never ran. `q` is the
 * launcher as the Match exec line quotes it. Windows says both in one sentence: cmd.exe offers no safe way to nest it.
 */
export function refusedLine(q: string, refusal: string, win: boolean): string {
  if (win) return `    ProxyCommand cmd.exe /d /c "echo ${refusal}, or vswarm itself cannot run; run: vswarm why 1>&2 & exit 1"`;
  // q sits inside the double quotes of sh -c: $, ` and \ would mean something there. (The '\'' that single-quotes an
  // apostrophe passes through double quotes unchanged.)
  if (/[$`\\]/.test(q.replaceAll("'\\''", ""))) throw new Error(`cannot put ${q} in ~/.ssh/config: it contains $, \` or \\`);
  // Both messages sit in single quotes: no apostrophes in them.
  const broken = "vswarm: not connecting: vswarm itself cannot run (removed, or Bun moved). Reinstall it from github.com/kridsadar357/vswarm, or remove the vswarm blocks from ~/.ssh/config";
  return `    ProxyCommand /bin/sh -c "if ${q} --version >/dev/null 2>&1; then echo '${refusal} · vswarm why' >&2; else echo '${broken}' >&2; fi; exit 1"`;
}

/** The host patterns on the first Match originalhost line between two markers; [] when the block is not there. */
export function blockHosts(text: string, start: string, end: string): string[] {
  const i = text.indexOf(start);
  const j = i < 0 ? -1 : text.indexOf(end, i);
  if (i < 0 || j < 0) return [];
  return /Match originalhost (\S+)/.exec(text.slice(i, j))?.[1].split(",") ?? [];
}
