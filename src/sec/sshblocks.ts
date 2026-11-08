// The marker lines of the blocks vswarm writes into ~/.ssh/config, in one place: setup.ts (the gate), agent.ts (the
// agent) and sshconfig.ts (reading them back) all need them, and none of those may import the others for it.

export const GATE_START = "# >>> vswarm gate >>>";
export const GATE_END = "# <<< vswarm gate <<<";
export const AGENT_START = "# >>> vswarm agent >>>";
export const AGENT_END = "# <<< vswarm agent <<<";
