// The swarm permission policy: the session may do anything on this machine except ship code out or send traffic out.
// Enforced by the PreToolUse hook, so it covers the lead and every subagent, and the user can approve one call.
// It reads the whole command (pipes, `&&`, `bash -c '…'`, `$(…)`), but a determined program can still open a
// socket in ways no pattern sees; the Claude Code sandbox (network allowlist) is the hard boundary.

export type Group = "push" | "deploy" | "network" | "sudo";

export const GROUPS: Record<Group, string> = {
  push: "git push, changing remotes, GitHub CLI",
  deploy: "publishing packages, images and cloud deploys",
  network: "requests to outside hosts: curl, wget, ssh, scp, rsync, URLs, WebFetch, MCP tools",
  sudo: "running as root",
};

const BASH: [Group, RegExp, string][] = [
  ["push", /\bgit\b[^;&|]*\bpush\b/, "git push"],
  ["push", /\bgit\b[^;&|]*\bremote\s+(add|set-url)\b/, "changing a git remote"],
  ["push", /(^|[\s;&|(`])gh\s+\S/, "GitHub CLI"],
  ["deploy", /\b(npm|pnpm|yarn|bun)\s+(publish|unpublish|deprecate|login|adduser)\b/, "publishing a package"],
  ["deploy", /\b(twine\s+upload|cargo\s+publish|gem\s+push|poetry\s+publish|uv\s+publish)\b/, "publishing a package"],
  ["deploy", /\b(docker|podman)\s+(push|login)\b/, "pushing an image"],
  ["deploy", /(^|[\s;&|(`])(kubectl|helm|terraform|pulumi|ansible-playbook|vercel|netlify|flyctl|heroku|wrangler|surge|railway|doctl|aws|gcloud|gsutil|az)(\s|$)/, "cloud / deploy CLI"],
  ["deploy", /\b(firebase|fly|eas|supabase)\s+(deploy|launch|submit|update|functions:deploy|db\s+push)\b/, "deploying"],
  ["network", /(^|[\s;&|(`])(curl|wget|xh|httpie|ssh|scp|sftp|ftp|rsync|telnet|nc|ncat|socat|mosh)(\s|$)/, "outbound connection"],
  ["network", /https?:\/\/(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])([:/]|$))/, "a URL to an outside host"],
  ["network", /\b(urllib|requests\.(get|post|put)|http\.client|httpx|aiohttp|fetch\(|axios|XMLHttpRequest|net\.connect|https?\.request|socket\.(socket|create_connection)|Net::HTTP|LWP::)/, "a script that opens a connection"],
  ["sudo", /(^|[\s;&|(`])(sudo|doas|su)\s/, "running as root"],
];

/** Commands that do need the network but only to fetch dependencies or source, which the swarm may do. */
const FETCH_OK = /^\s*(git\s+(clone|fetch|pull|ls-remote|submodule)|npm\s+(i|install|ci|add)|pnpm\s+(i|install|add)|yarn(\s+(install|add))?|bun\s+(i|install|add)|pip3?\s+install|uv\s+(pip\s+install|add|sync)|poetry\s+(install|add)|cargo\s+(build|fetch|add)|go\s+(get|mod\s+download)|brew\s+install|npx\s+(-y\s+)?create-)\b/;

const URL_RE = /\b(?:https?|wss?):\/\/[^\s'"`)]+/g;
const LOCAL_URL = /^(?:https?|wss?):\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])([:/]|$)/;
const SANDBOXED = process.platform !== "win32";

/**
 * A connection that stays on this machine: every URL in the command is localhost, or (where the sandbox stops
 * anything else) a script that names no URL at all. ssh/scp/rsync/nc are never treated as local.
 */
function localOnly(part: string): boolean {
  if (/(^|[\s;&|(`])(ssh|scp|sftp|ftp|rsync|telnet|nc|ncat|socat|mosh)(\s|$)/.test(part)) return false;
  const urls = part.match(URL_RE) ?? [];
  if (urls.length) return urls.every((u) => LOCAL_URL.test(u));
  const tool = /(^|[\s;&|(`])(curl|wget|xh|httpie)(\s|$)/.test(part);
  if (tool) return /\b(localhost|127\.0\.0\.1|\[::1\])\b/.test(part) && !/\b[\w-]+\.(com|net|org|io|dev|app|co|ai|th)\b/.test(part);
  return SANDBOXED;
}

export interface Verdict {
  group: Group;
  why: string;
}

/** Why a tool call is outside the swarm policy, or undefined when it is fine. */
export function check(tool: string, input: any, blocked: Group[]): Verdict | undefined {
  const on = new Set(blocked);
  if (tool === "Bash") {
    const cmd = String(input?.command ?? "");
    // Each part of a compound command is judged on its own, so `npm i && curl x` is still caught.
    const parts = cmd.split(/&&|\|\||;|\n/);
    for (const [group, re, why] of BASH) {
      if (!on.has(group)) continue;
      for (const part of parts) {
        if (group === "network" && FETCH_OK.test(part) && !/\b(curl|wget|ssh|scp|rsync|nc)\b/.test(part)) continue;
        if (group === "network" && localOnly(part)) continue;
        if (re.test(part)) return { group, why: `${why}: ${part.trim().slice(0, 120)}` };
      }
    }
    return;
  }
  if (on.has("network") && tool === "WebFetch") {
    const url = String(input?.url ?? "");
    if (!/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])([:/]|$)/.test(url)) return { group: "network", why: `WebFetch ${url.slice(0, 120)}` };
  }
  // MCP tools reach other services (Slack, Drive, email …); they count as traffic out.
  if (on.has("network") && tool.startsWith("mcp__")) return { group: "network", why: `MCP tool ${tool}` };
  return;
}

/** Tools swarm mode allows without asking. WebSearch runs on Anthropic's side; WebFetch would reach any host. */
const SWARM_ALLOW = [
  "Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "Read", "Grep", "Glob", "LS", "Agent", "Task",
  "TodoWrite", "WebSearch", "Skill", "BashOutput", "KillShell",
];

/** Matched by Claude Code itself, before the hook, and also in subagents. */
const DENY: Record<Group, string[]> = {
  push: ["Bash(git push *)", "Bash(git remote add *)", "Bash(git remote set-url *)", "Bash(gh *)"],
  deploy: [
    "Bash(npm publish *)", "Bash(pnpm publish *)", "Bash(yarn publish *)", "Bash(bun publish *)", "Bash(docker push *)",
    "Bash(kubectl *)", "Bash(helm *)", "Bash(terraform apply *)", "Bash(vercel *)", "Bash(netlify *)", "Bash(flyctl *)",
    "Bash(heroku *)", "Bash(wrangler *)", "Bash(firebase deploy *)", "Bash(aws *)", "Bash(gcloud *)", "Bash(az *)",
  ],
  // curl and wget stay usable against localhost; the hook and the sandbox refuse them for outside hosts.
  network: ["WebFetch", "mcp__*", "Bash(ssh *)", "Bash(scp *)", "Bash(rsync *)", "Bash(nc *)"],
  sudo: ["Bash(sudo *)", "Bash(su *)"],
};

const LOCAL_HOSTS = ["localhost", "127.0.0.1", "::1", "[::1]"];

const CACHES = [
  "~/.npm", "~/.bun/install/cache", "~/.cache", "~/Library/Caches", "~/.yarn", "~/.pnpm-store", "~/Library/pnpm",
  "~/.cargo/registry", "~/.cargo/git", "~/go/pkg/mod", "~/.deno", "/tmp", "/private/tmp",
];

/**
 * Claude Code settings for one swarm run: allow rules, deny rules for the blocked groups, extra folders, and the
 * sandbox, which is what actually stops traffic out (only `domains` are reachable) and writes outside the folders.
 */
export function swarmSettings(blocked: Group[], domains: string[], dirs: string[]) {
  const sandboxed = process.platform !== "win32";
  return {
    permissions: {
      defaultMode: "acceptEdits",
      allow: SWARM_ALLOW,
      deny: blocked.flatMap((g) => DENY[g] ?? []),
      additionalDirectories: dirs,
    },
    ...(sandboxed && blocked.includes("network")
      ? {
          sandbox: {
            enabled: true,
            autoAllowBashIfSandboxed: true,
            allowUnsandboxedCommands: false,
            failIfUnavailable: true,
            // Package managers keep caches in the home folder; without these an install fails with EPERM.
            filesystem: { allowWrite: [...dirs, ...CACHES] },
            // Dev servers bind local ports, and checking them goes to localhost; neither leaves the machine.
            network: { allowedDomains: [...domains, ...LOCAL_HOSTS], allowLocalBinding: true },
          },
        }
      : {}),
  };
}

export function isGroup(g: string): g is Group {
  return g in GROUPS;
}
