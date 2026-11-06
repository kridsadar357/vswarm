// Where vswarm keeps its files:
//   ~/.vswarm/bin/          the `vswarm` launcher
//   ~/.vswarm/completions/  shell completions
//   ~/.vswarm/sec/          baseline, last check, accepted findings, incidents (owner-only)

import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const VERSION = "2.2.0";

export const HOME = process.env.VSWARM_HOME ?? join(homedir(), ".vswarm");

export function ensureHome(): string {
  if (!existsSync(HOME)) mkdirSync(HOME, { recursive: true, mode: 0o700 });
  return HOME;
}

export const paths = {
  bin: () => join(HOME, "bin"),
  completions: () => join(HOME, "completions"),
};
