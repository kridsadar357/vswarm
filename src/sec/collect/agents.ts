// AI coding agents run code on your behalf, and their settings say what they may run without asking:
//   MCP servers   programs (or remote URLs) an agent starts and talks to: Claude Code, Claude Desktop, Cursor,
//                 Windsurf, VS Code, Gemini CLI, Codex
//   hooks         shell commands that run on agent events (Claude Code hooks, statusLine)
//   permissions   whether the agent may skip asking (bypassPermissions, Bash(*) allow rules)
// A malicious MCP server or hook is persistence with the agent's access: your repos, your shell, your tokens.

import { join } from "node:path";
import { ls, readJson, readText, sha256, type Ctx } from "../ctx";
import type { Item } from "../types";

interface Server {
  command?: string;
  args?: string[];
  url?: string;
  type?: string;
  env?: Record<string, string>;
  headers?: Record<string, string>;
}

/** Names of env vars and headers that carry a literal secret (not a ${VAR} reference). Never the values. */
export function literalSecrets(s: Server): string[] {
  const out: string[] = [];
  for (const [k, v] of [...Object.entries(s.env ?? {}), ...Object.entries(s.headers ?? {})]) {
    if (typeof v !== "string" || v.length < 12 || /^\$\{?[A-Z_]+\}?$|^\$\{env:/.test(v)) continue;
    if (/token|secret|key|password|auth|bearer|credential/i.test(k) || /^(Bearer\s+)?(sk-|ghp_|gho_|github_pat_|xox[bp]-|AKIA|eyJ)/.test(v)) out.push(k);
  }
  return out;
}

function serverItem(app: string, file: string, name: string, s: Server): Item {
  const command = [s.command, ...(s.args ?? [])].filter(Boolean).join(" ");
  const def = JSON.stringify({ command: s.command, args: s.args, url: s.url ?? (s as any).httpUrl ?? (s as any).serverUrl, env: Object.keys(s.env ?? {}).sort() });
  return {
    kind: "mcp", id: `${app}:${name}`, name, source: app, path: file, hash: sha256(def),
    meta: { command: command.slice(0, 300) || undefined, url: s.url ?? (s as any).httpUrl ?? (s as any).serverUrl, secrets: literalSecrets(s).join(",") || undefined },
  };
}

function servers(app: string, file: string, map: unknown, prefix = ""): Item[] {
  if (!map || typeof map !== "object") return [];
  return Object.entries(map as Record<string, Server>).filter(([, s]) => s && typeof s === "object").map(([n, s]) => serverItem(app, file, prefix + n, s));
}

/** Claude Code keeps its settings in ~/.claude, or in another folder per profile (CLAUDE_CONFIG_DIR). */
function claudeDirs(home: string): string[] {
  return ls(home).filter((d) => /^\.claude([\w.-]*)$/.test(d) && !d.endsWith(".json")).map((d) => join(home, d));
}

function claude(home: string): Item[] {
  const out: Item[] = [];
  const configs = [join(home, ".claude.json"), ...claudeDirs(home).map((d) => join(d, ".claude.json"))];
  for (const f of configs) {
    const j = readJson(f);
    if (!j) continue;
    const app = f === join(home, ".claude.json") ? "claude-code" : `claude-code:${f.split("/").at(-2)}`;
    out.push(...servers(app, f, j.mcpServers));
    for (const [proj, p] of Object.entries<any>(j.projects ?? {})) out.push(...servers(app, f, p?.mcpServers, `${proj.replace(home, "~")} › `));
  }
  for (const dir of claudeDirs(home)) {
    for (const name of ["settings.json", "settings.local.json"]) {
      const f = join(dir, name);
      const j = readJson(f);
      if (!j) continue;
      const app = `claude-code:${dir.split("/").pop()}`;
      for (const [event, matchers] of Object.entries<any>(j.hooks ?? {})) {
        (Array.isArray(matchers) ? matchers : []).forEach((m: any, i: number) =>
          (m?.hooks ?? []).forEach((h: any, k: number) => {
            if (typeof h?.command !== "string") return;
            out.push({ kind: "agent-hook", id: `${f}:${event}:${m.matcher ?? ""}:${i}.${k}`, name: `${app} ${event}${m.matcher ? ` (${m.matcher})` : ""}`, source: app, path: f, hash: sha256(h.command), meta: { command: h.command.slice(0, 300) } });
          }));
      }
      if (typeof j.statusLine?.command === "string")
        out.push({ kind: "agent-hook", id: `${f}:statusLine`, name: `${app} statusLine`, source: app, path: f, hash: sha256(j.statusLine.command), meta: { command: j.statusLine.command.slice(0, 300) } });
      const allow: string[] = Array.isArray(j.permissions?.allow) ? j.permissions.allow : [];
      const wide = allow.filter((a) => /^(Bash|Bash\(\*\)|Bash\(:\*\)|\*|mcp__\*)$/.test(a));
      const bypass = j.permissions?.defaultMode === "bypassPermissions" || j.skipDangerousModePermissionPrompt === true;
      out.push({ kind: "agent-perm", id: f, name: `${app} ${name}`, source: app, path: f, hash: sha256(JSON.stringify({ wide, bypass })), meta: { bypass, wide: wide.join(",") || undefined } });
      for (const p of Object.keys(j.enabledPlugins ?? {})) if (j.enabledPlugins[p]) out.push({ kind: "agent-plugin", id: `${app}:${p}`, name: p, source: app, path: f });
    }
  }
  return out;
}

export async function agents(ctx: Ctx): Promise<Item[]> {
  const h = ctx.home;
  const mac = (rel: string) => join(h, "Library/Application Support", rel);
  const out: Item[] = [...claude(h)];
  const plain: [string, string, string][] = [
    ["claude-desktop", mac("Claude/claude_desktop_config.json"), "mcpServers"],
    ["claude-desktop", join(h, ".config/Claude/claude_desktop_config.json"), "mcpServers"],
    ["cursor", join(h, ".cursor/mcp.json"), "mcpServers"],
    ["windsurf", join(h, ".codeium/windsurf/mcp_config.json"), "mcpServers"],
    ["gemini", join(h, ".gemini/settings.json"), "mcpServers"],
    ["vscode", mac("Code/User/mcp.json"), "servers"],
    ["vscode", join(h, ".config/Code/User/mcp.json"), "servers"],
    ["vscode", mac("Code/User/settings.json"), "mcp.servers"],
    ["vscode", join(h, ".config/Code/User/settings.json"), "mcp.servers"],
  ];
  for (const [app, f, key] of plain) {
    const j = readJson(f);
    if (j) out.push(...servers(app, f, key === "mcp.servers" ? j["mcp"]?.servers ?? j["mcp.servers"] : j[key]));
  }
  // Codex: TOML, [mcp_servers.<name>] tables with command / args / url.
  const codexFile = join(h, ".codex/config.toml");
  const toml = readText(codexFile);
  if (toml) {
    for (const m of toml.matchAll(/^\[mcp_servers\.("?)([\w.-]+)\1\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/gm)) {
      if (m[2].includes(".env") || m[2].endsWith(".headers")) continue;
      const body = m[3];
      const str = (k: string) => new RegExp(`^${k}\\s*=\\s*"([^"]*)"`, "m").exec(body)?.[1];
      const args = /^args\s*=\s*\[([^\]]*)\]/m.exec(body)?.[1];
      out.push(serverItem("codex", codexFile, m[2], { command: str("command"), url: str("url"), args: args ? [...args.matchAll(/"([^"]*)"/g)].map((a) => a[1]) : undefined }));
    }
  }
  return [...new Map(out.map((i) => [`${i.kind}:${i.id}`, i])).values()];
}
