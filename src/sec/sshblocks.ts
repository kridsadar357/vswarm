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
