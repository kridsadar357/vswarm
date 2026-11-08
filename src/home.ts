// Where vswarm keeps its files:
//   ~/.vswarm/bin/          the `vswarm` launcher
//   ~/.vswarm/completions/  shell completions
//   ~/.vswarm/sec/          baseline, last check, accepted findings, incidents (owner-only)

import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import pkg from "../package.json";

// One place for the version: a release bumps package.json, and scripts/release.sh checks the tag against it.
export const VERSION: string = pkg.version;

export const HOME = process.env.VSWARM_HOME ?? join(homedir(), ".vswarm");

/**
 * With VSWARM_HOME set, vswarm's own files live there, but some things stay the user's, whatever folder vswarm uses:
 * ~/.ssh/config, the LaunchAgents and systemd user units, the shell rc files. Status lines about them say so.
 */
export const GLOBAL_TAG = () => (process.env.VSWARM_HOME ? " (system-wide, not in VSWARM_HOME)" : "");

export function ensureHome(): string {
  if (!existsSync(HOME)) mkdirSync(HOME, { recursive: true, mode: 0o700 });
  return HOME;
}

export const paths = {
  bin: () => join(HOME, "bin"),
  completions: () => join(HOME, "completions"),
};
