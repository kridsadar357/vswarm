// Loaded before every test file (bunfig.toml): whatever a test forgets to point elsewhere lands in a temp folder of
// this run, never in your own ~/.vswarm. Tests that need a state folder of their own still set VSWARM_SEC_DIR and the
// others themselves, and put back what was here when they are done (reset). The sealing key is then a file there.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const VARS = [["VSWARM_SEC_DIR", "sec"], ["VSWARM_AGENT_DIR", "agent"], ["VSWARM_BACKUP_DIR", "backups"], ["VSWARM_TRY_DIR", "try"], ["VSWARM_CA_DIR", "ca"], ["VSWARM_GATE_DIR", "gate"]] as const;

// Words in English, whatever this machine's language or saved choice: tests that need Thai ask for it.
process.env.VSWARM_LANG = "en";

if (!process.env.VSWARM_ISOLATED_ROOT) {
  const root = mkdtempSync(join(tmpdir(), "vs-test-run-"));
  process.env.VSWARM_ISOLATED_ROOT = root;
  for (const [k, dir] of VARS) {
    process.env[k] ??= join(root, dir);
    process.env[`VSWARM_ISOLATED_${k}`] = process.env[k];
  }
}

/** Puts a variable back to what this run started with (a temp folder), where a test would otherwise delete it. */
export function reset(name: (typeof VARS)[number][0]) {
  const v = process.env[`VSWARM_ISOLATED_${name}`];
  if (v) process.env[name] = v;
  else delete process.env[name];
}
