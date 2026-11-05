// Where vswarm keeps its files, and the user's settings.
//   ~/.vswarm/config.json   models, advisor moments, permission mode
//   ~/.vswarm/jev.key       Jev API key (or JEV_API_KEY)
//   ~/.vswarm/events.jsonl  events from sessions with hooks installed
//   ~/.vswarm/runs/<id>/    one folder per `vswarm run`: events, meta, final answer
//   ~/.vswarm/sessions/     per-session memory for the advisor and Jev

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const VERSION = "1.0.0";

export const HOME = process.env.VSWARM_HOME ?? join(homedir(), ".vswarm");

/** Earlier names of the data folder; the first one found is moved to HOME once. */
const OLD_HOMES = [join(homedir(), ".v-swarm"), join(homedir(), ".swarmdeck")];

export function ensureHome(): string {
  if (!existsSync(HOME)) {
    const old = OLD_HOMES.find(existsSync);
    if (old && !process.env.VSWARM_HOME) renameSync(old, HOME);
    else mkdirSync(HOME, { recursive: true });
  }
  return HOME;
}

export const paths = {
  config: () => join(HOME, "config.json"),
  jevKey: () => join(HOME, "jev.key"),
  events: () => process.env.VSWARM_FILE ?? join(HOME, "events.jsonl"),
  runs: () => join(HOME, "runs"),
  sessions: () => join(HOME, "sessions"),
  bin: () => join(HOME, "bin"),
};

export interface Config {
  /** Claude Code account: "" follows CLAUDE_CONFIG_DIR / ~/.claude, "work" means ~/.claude-work, or a folder path. */
  profile: string;
  /** Model for the main session. */
  lead: string;
  /** Model subagents are asked to use; empty lets the lead choose. */
  swarm: string;
  /** Advisor model; empty turns the advisor off. */
  advisor: string;
  /** When the advisor is called: plan, error, done. */
  advisorAt: string[];
  /**
   * Permission mode for `vswarm run`. "swarm" (vswarm's own) allows everything on this machine except the
   * `block` groups, inside the Claude Code sandbox; the rest are Claude Code's: default, acceptEdits, plan, auto, dontAsk.
   */
  mode: string;
  /** Tools allowed without asking in the Claude Code modes (claude --allowedTools). */
  allow: string[];
  /** What swarm mode refuses: push, deploy, network, sudo. */
  block: string[];
  /** Hosts the sandbox lets commands reach in swarm mode (package registries). */
  domains: string[];
  /** Folders besides the working directory that runs may edit (claude --add-dir). */
  dirs: string[];
}

export const DEFAULTS: Config = {
  profile: "",
  lead: "sonnet",
  swarm: "haiku",
  advisor: "opus",
  advisorAt: ["plan", "error", "done"],
  mode: "swarm",
  allow: ["Agent", "Read", "Grep", "Glob", "WebSearch", "WebFetch"],
  block: ["push", "deploy", "network", "sudo"],
  domains: [
    "registry.npmjs.org", "*.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
    "crates.io", "*.crates.io", "proxy.golang.org", "sum.golang.org", "jsr.io", "deno.land",
  ],
  dirs: [],
};

export function loadConfig(): Config {
  try {
    return { ...DEFAULTS, ...JSON.parse(readFileSync(paths.config(), "utf8")) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function saveConfig(c: Config) {
  ensureHome();
  writeFileSync(paths.config(), JSON.stringify(c, null, 2) + "\n");
}
