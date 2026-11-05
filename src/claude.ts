// Which Claude Code account vswarm runs as. Claude Code keeps each login in a config folder
// (CLAUDE_CONFIG_DIR): ~/.claude by default, and people with several accounts keep ~/.claude-work, ~/.claude-personal …

import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "./home";

export interface Profile {
  /** Short name: "default", or the folder suffix ("personal" for ~/.claude-personal). */
  name: string;
  dir: string;
  loggedIn: boolean;
  /** Why it cannot be used, when it cannot. */
  problem?: string;
  method?: string;
  expires?: string;
}

/** "personal" → ~/.claude-personal, "default" → ~/.claude, a path stays a path, "" → whatever the environment says. */
export function profileDir(value: string): string | undefined {
  if (!value) return process.env.CLAUDE_CONFIG_DIR || undefined;
  if (value === "default") return join(homedir(), ".claude");
  if (value.includes("/") || value.includes("\\")) return value.replace(/^~(?=$|[/\\])/, homedir());
  return join(homedir(), `.claude-${value}`);
}

/** Folder of the account vswarm uses now (the config's profile, else CLAUDE_CONFIG_DIR, else ~/.claude). */
export function activeDir(): string {
  return profileDir(loadConfig().profile) ?? join(homedir(), ".claude");
}

/** Environment for a claude child process that should run as the configured account. */
export function claudeEnv(): Record<string, string> {
  const dir = profileDir(loadConfig().profile);
  return dir ? { CLAUDE_CONFIG_DIR: dir } : {};
}

export function nameOf(dir: string): string {
  const base = dir.replace(/[/\\]+$/, "").split(/[/\\]/).pop() ?? dir;
  if (base === ".claude") return "default";
  return base.startsWith(".claude-") ? base.slice(".claude-".length) : dir;
}

export async function authStatus(dir: string): Promise<Profile> {
  const p: Profile = { name: nameOf(dir), dir, loggedIn: false, problem: "no response from claude auth status" };
  try {
    const child = Bun.spawn(["claude", "auth", "status"], {
      env: { ...process.env, CLAUDE_CONFIG_DIR: dir },
      stdout: "pipe",
      stderr: "ignore",
    });
    const timer = setTimeout(() => child.kill(), 20_000);
    const out = await new Response(child.stdout).text();
    clearTimeout(timer);
    const j = JSON.parse(out);
    p.loggedIn = Boolean(j.loggedIn);
    p.method = j.authMethod;
    p.expires = j.loginExpiresAt ?? undefined;
    if (p.loggedIn && p.expires && Date.parse(p.expires) < Date.now()) p.loggedIn = false;
    p.problem = p.loggedIn ? undefined : j.loggedIn ? "login expired" : "not logged in";
  } catch {}
  return p;
}

/** Every Claude Code config folder in the home directory, with its login state. */
export async function profiles(): Promise<Profile[]> {
  const home = homedir();
  const dirs = readdirSync(home)
    .filter((d) => d === ".claude" || /^\.claude-[\w.-]+$/.test(d))
    .map((d) => join(home, d))
    .filter((d) => existsSync(join(d, "settings.json")) || existsSync(join(d, ".credentials.json")) || existsSync(join(d, "projects")));
  const all = await Promise.all(dirs.map(authStatus));
  // Usable accounts first, then by name.
  return all.sort((a, b) => Number(b.loggedIn) - Number(a.loggedIn) || a.name.localeCompare(b.name));
}

/** How to log in again for one account, as the user would type it. */
export function loginHint(dir: string): string {
  const name = nameOf(dir);
  return name === "default" ? "claude  then /login" : `CLAUDE_CONFIG_DIR=${dir.replace(homedir(), "~")} claude  then /login`;
}

export const AUTH_ERROR = /authenticat|oauth|log ?in|401|invalid api key|credential/i;
