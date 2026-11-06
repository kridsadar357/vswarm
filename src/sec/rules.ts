// From what a scan saw to what deserves attention. Two kinds of rule:
//   always   things that are wrong whatever the history (known-malicious package, code running from /tmp)
//   change   things that appeared or changed since the baseline you marked as clean

import { redact } from "./ctx";
import { lookAlike, signature, type Malicious, type Signature } from "./intel";
import { suspiciousLocation } from "./collect/system";
import { stockWmi, winLaunchRisk } from "./collect/windows";
import { ADDED_KINDS, type Finding, type Item, type Scan, type Severity } from "./types";

/** Lines in a shell startup file that fetch, decode or start something in the background. */
/** The command that names a process's parent, for the system vswarm runs on. */
const parentOf = (pid: unknown) =>
  process.platform === "win32" ? `Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid) || "PID"}" | Select-Object ParentProcessId` : `ps -o ppid= -p ${Number(pid) || "PID"}`;
const RISKY_LINE = /\b(curl|wget|nc|ncat|socat|base64|openssl\s+enc|eval|osascript|python3?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e|nohup|launchctl|chmod\s+\+x)\b|&\s*$|\|\s*(ba|z)?sh\b|\/tmp\/|\.cache\//;

/**
 * The same for PowerShell profiles: run code from a string, fetch it, decode it, start it hidden, or switch off
 * Defender for a folder. Case-insensitive like PowerShell itself; only profile scripts are held to it.
 */
const RISKY_PS = /\b(invoke-expression|iex|downloadstring|downloadfile|frombase64string)\b|\b(invoke-webrequest|iwr|invoke-restmethod|irm)\b.*\|\s*(iex|invoke-expression)\b|\s-(encodedcommand|enc|ec|e)\s|\bstart-process\b.*\s-w(indowstyle)?\s+h(idden)?\b|\badd-mppreference\b.*-exclusion|\bset-mppreference\b.*-disable/i;

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** The program an MCP server or hook runs, and the package it pulls when it is started through npx/uvx/bunx. */
function launcher(cmd: string, home: string): { exe?: string; pkg?: { eco: "npm" | "pip"; name: string } } {
  const parts = cmd.split(/\s+/).filter(Boolean);
  const exe = parts.find((p) => p.startsWith("/") || p.startsWith("~/"))?.replace(/^~/, home);
  const runner = parts.findIndex((p) => /(^|\/)(npx|bunx|pnpx|uvx|pipx)$/.test(p) || p === "dlx");
  if (runner < 0) return { exe };
  const eco = /uvx|pipx/.test(parts[runner]) ? "pip" : "npm";
  // Skip flags and their values (--from x, -y, --offline); the package is the first plain word after that.
  let name: string | undefined;
  for (let i = runner + 1; i < parts.length; i++) {
    if (parts[i] === "--from") return { exe, pkg: { eco, name: parts[i + 1]?.replace(/[=@<>].*$/, "") } };
    if (parts[i].startsWith("-")) continue;
    name = parts[i];
    break;
  }
  return { exe, pkg: name ? { eco, name: name.replace(/(?<=.)@[^/]*$/, "").replace(/[=<>].*$/, "") } : undefined };
}

function key(i: Item) {
  return `${i.kind}|${i.id}`;
}

function addedLines(before: string | undefined, after: string | undefined): string[] {
  if (after === undefined) return [];
  const old = new Set((before ?? "").split("\n").map((l) => l.trim()));
  return after.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !old.has(l));
}

export interface RuleInput {
  scan: Scan;
  baseline?: Scan;
  malicious: Malicious[];
  secrets: Finding[];
  /** Overridable for tests. */
  sign?: (path: string) => Promise<Signature>;
}

/** Checks the baseline did not cover yet, by name, so the summary can say so. */
export function uncovered(scan: Scan, baseline?: Scan): string[] {
  if (!baseline) return [];
  const kinds = new Set(scan.items.map((i) => i.kind));
  const names = [...kinds].filter((k) => (baseline.covers ? !baseline.covers.includes(k) : ADDED_KINDS[k])).map((k) => ADDED_KINDS[k] ?? k);
  return [...new Set(names)];
}

export async function evaluate(input: RuleInput): Promise<Finding[]> {
  const { scan, baseline } = input;
  const sign = input.sign ?? signature;
  const home = scan.home;
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);
  const before = new Map((baseline?.items ?? []).map((i) => [key(i), i]));
  // A baseline from before a check existed says nothing about what that check finds.
  const covered = (kind: string) => (baseline?.covers ? baseline.covers.includes(kind) : !ADDED_KINDS[kind]);
  const isNew = (i: Item) => baseline !== undefined && covered(i.kind) && !before.has(key(i));
  const changed = (i: Item) => {
    const b = before.get(key(i));
    return b !== undefined && b.hash !== undefined && i.hash !== undefined && b.hash !== i.hash;
  };
  const newBins = new Set(scan.items.filter((i) => i.kind === "bin" && isNew(i)).map((i) => i.path));

  // ── always
  for (const m of input.malicious) {
    add({
      id: `malicious:${m.item.kind}:${m.item.name}@${m.item.version}`, rule: "malicious", severity: "critical",
      title: `Known-malicious package installed: ${m.item.name}@${m.item.version} (${m.item.kind})`,
      detail: [m.ids.join(", "), m.item.path ?? ""].filter(Boolean),
      fix: "Treat this machine as compromised: vswarm respond", item: m.item,
    });
  }
  for (const i of scan.items) {
    if (i.kind === "proc") {
      add({ id: `proc:${i.id}`, rule: "proc-location", severity: "high", title: `Program running from an unusual place: ${i.path}`,
        detail: [String(i.meta?.where ?? ""), `pid ${i.meta?.pid}`], fix: `Find out what started it (${parentOf(i.meta?.pid)}); if you do not know it, vswarm respond`, item: i });
    }
    if (i.kind === "conn") {
      const where = i.meta?.where as string | undefined;
      const fresh = i.path && newBins.has(i.path);
      if (where || fresh) {
        add({ id: `conn:${i.id}`, rule: "conn", severity: "high",
          title: `${i.name} is connected to other machines${where ? ` and ${where}` : " and is new since the baseline"}`,
          detail: [`remotes: ${i.meta?.remotes}`, i.path ?? ""], fix: "If you do not recognise it, disconnect from the network and run vswarm respond", item: i });
      }
    }
    if (i.kind === "mcp" || i.kind === "agent-hook") {
      const cmd = String(i.meta?.command ?? "");
      const what = i.kind === "mcp" ? `MCP server ${i.name} (${i.source})` : `Agent hook ${i.name}`;
      const l = launcher(cmd, home);
      const where = l.exe ? suspiciousLocation(l.exe, home) : undefined;
      const like = l.pkg ? lookAlike(l.pkg.eco, l.pkg.name) : undefined;
      if (where || like || (cmd && RISKY_LINE.test(cmd.replace(/\.cache\//g, "")))) {
        add({ id: `agent-risky:${i.kind}:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-risky", severity: "high",
          title: `${what} ${where ? `starts a program that ${where}` : like ? `runs ${l.pkg!.name}, which looks like ${like}` : "runs a command that downloads, decodes or backgrounds something"}`,
          detail: [redact(cmd.slice(0, 200)), i.path ?? ""], fix: "An agent runs this with your access. Remove it unless you set it up yourself; then vswarm respond", item: i });
      }
      const url = String(i.meta?.url ?? "");
      // Read the host with a regex: a URL that does not parse ("http://") must not stop the whole check.
      if (/^http:\/\//.test(url) && !/^http:\/\/(localhost|127\.|\[::1\])/.test(url)) {
        // Shown, not stored: a password in the URL's userinfo or a token in its query is masked.
        const shown = redact(url);
        add({ id: `agent-http:${i.id}`, rule: "agent-http", severity: "medium", title: `${what} talks to ${/^http:\/\/([^/?#]+)/.exec(shown)?.[1] ?? shown} without TLS`, detail: [shown], fix: "Anyone on the network path can read or change what the agent sends and gets; use https", item: i });
      }
      if (i.meta?.secrets)
        add({ id: `agent-secret:${i.id}`, rule: "secret", severity: "medium", title: `${what} keeps a token in plain text: ${i.meta.secrets}`, detail: [i.path ?? ""],
          fix: "Reference an environment variable or the OS keychain instead of pasting the value into the config", item: i });
    }
    if (i.kind === "agent-perm" && i.meta?.bypass)
      add({ id: `agent-bypass:${i.id}`, rule: "agent-perm", severity: "low", title: `${i.name}: the agent may run commands without asking (bypass permissions)`, detail: [i.path ?? ""], item: i });
    if (i.kind === "preload") {
      add({ id: `preload:${i.hash?.slice(0, 12)}`, rule: "preload", severity: "high", title: "/etc/ld.so.preload makes every program load a library first",
        detail: [`libraries: ${i.meta?.libs}`, "Almost no normal system uses this file; Linux rootkits and credential stealers do."],
        fix: "Unless your own security or debugging tool put it there, vswarm respond", item: i });
    }
    if (i.kind === "launch") {
      const prog = String(i.meta?.program ?? "");
      // Windows entries (Run values, tasks, services, Startup) say what they are, and their command lines are Windows'.
      const what = i.meta?.what ? capital(String(i.meta.what)) : undefined;
      if (what) {
        const r = winLaunchRisk(prog, home);
        if (r.risky || r.where) {
          add({ id: `launch-location:${i.id}`, rule: "launch-location", severity: "high", title: `${what} ${i.name} ${r.risky ?? `starts a program that ${r.where}`}`,
            detail: [i.path ?? "", redact(prog.slice(0, 300))], fix: "Unless you set this up yourself, vswarm respond", item: i });
        }
      } else {
        const exe = prog.split(" ").find((p) => p.startsWith("/") && !/^\/(bin|usr\/bin)\/(ba|z)?sh$/.test(p) && !/^\/usr\/bin\/(env|python3?|osascript|open)$/.test(p)) ?? "";
        const where = exe ? suspiciousLocation(exe, home) : undefined;
        if (where) {
          add({ id: `launch-location:${i.id}`, rule: "launch-location", severity: "high", title: `Login job ${i.name} starts a program that ${where}`,
            detail: [i.path ?? "", prog], fix: "Unless you set this up yourself, vswarm respond", item: i });
        }
      }
    }
    if (i.kind === "wmi" && !stockWmi(i)) {
      // A permanent subscription runs on its own whenever its event fires, as SYSTEM: fileless persistence.
      const runs = i.meta?.type === "CommandLineEventConsumer" || i.meta?.type === "ActiveScriptEventConsumer";
      add({ id: `wmi:${i.id}:${i.hash?.slice(0, 12)}`, rule: "wmi", severity: runs ? "high" : "medium",
        title: runs ? `WMI subscription runs a ${i.meta?.type === "ActiveScriptEventConsumer" ? "script" : "command"} on an event: ${i.name}` : `WMI subscription that Windows does not ship: ${i.name} (${i.meta?.type})`,
        detail: [i.meta?.command ? redact(String(i.meta.command).slice(0, 200)) : "", i.meta?.filter ? `when: ${i.meta.filter}` : "not bound to an event filter"].filter(Boolean),
        fix: "Almost no software uses these; unless you know this one, vswarm respond", item: i });
    }
  }

  // ── change (only with a baseline)
  if (baseline) {
    const newTaps = scan.items.filter((i) => i.kind === "brew-tap" && isNew(i) && !i.meta?.official);
    for (const t of newTaps) {
      const formulas = scan.items.filter((i) => i.kind === "brew" && i.source === t.name).map((i) => `${i.name} ${i.version ?? ""}`.trim());
      add({ id: `tap:${t.id}`, rule: "brew-tap", severity: "high", title: `New third-party Homebrew tap: ${t.name}`,
        detail: [`from ${t.source ?? "unknown remote"}`, formulas.length ? `installed from it: ${formulas.join(", ")}` : "nothing installed from it yet"],
        fix: "If you did not mean to trust this publisher: brew untap " + t.name + " and remove what came from it", item: t });
    }
    for (const i of scan.items) {
      if (!isNew(i) && !changed(i)) continue;
      const fresh = isNew(i);
      switch (i.kind) {
        case "brew":
          if (!i.meta?.official && fresh && !newTaps.some((t) => t.name === i.source)) {
            add({ id: `brew:${i.id}`, rule: "brew-thirdparty", severity: "medium", title: `New package from third-party tap ${i.source}: ${i.name}`, detail: [i.path ?? ""], item: i });
          }
          break;
        case "npm":
        case "pip":
        case "cargo": {
          if (!fresh) break;
          const like = lookAlike(i.kind === "npm" ? "npm" : i.kind === "pip" ? "pip" : "", i.name);
          if (like) {
            add({ id: `lookalike:${i.kind}:${i.name}`, rule: "lookalike", severity: "high", title: `New ${i.kind} package ${i.name} looks like "${like}"`,
              detail: [`${i.name}@${i.version ?? "?"}`, i.path ?? ""], fix: `Check you meant ${i.name}, not ${like}; if not, remove it and vswarm respond`, item: i });
          } else if (i.kind === "npm" && i.meta?.scripts) {
            add({ id: `npm-scripts:${i.id}`, rule: "install-scripts", severity: "medium", title: `New global npm package runs scripts at install: ${i.name}`,
              detail: [`scripts: ${i.meta.scripts}`, `${i.name}@${i.version ?? "?"}`], fix: "Make sure you installed it on purpose and know its publisher", item: i });
          } else {
            add({ id: `pkg:${i.kind}:${i.id}`, rule: "new-package", severity: "low", title: `New ${i.kind} package: ${i.name}@${i.version ?? "?"}`, detail: [], item: i });
          }
          break;
        }
        case "editor-ext":
          if (fresh) add({ id: `ext:${i.id}`, rule: "editor-ext", severity: "low", title: `New ${i.source} extension: ${i.name} ${i.version ?? ""}`, detail: [i.path ?? ""], item: i });
          break;
        case "browser-ext": {
          if (!fresh) break;
          const perms = String(i.meta?.permissions ?? "");
          const wide = /<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/|cookies|webRequest|debugger|nativeMessaging/.test(perms);
          add({ id: `bext:${i.id}`, rule: "browser-ext", severity: wide ? "medium" : "low", title: `New browser extension (${i.source}): ${i.name}`,
            detail: [wide ? `can read or change pages/cookies: ${perms}` : perms].filter(Boolean), fix: wide ? "Remove it unless you know the publisher" : undefined, item: i });
          break;
        }
        case "launch":
          add({ id: `launch:${i.id}:${i.hash?.slice(0, 12)}`, rule: fresh ? "launch-new" : "launch-changed", severity: fresh ? "high" : "medium",
            title: `${fresh ? "New" : "Changed"} ${i.meta?.what ?? "login job"}: ${i.name}`, detail: [i.path ?? "", `runs: ${i.meta?.program ?? "?"}`],
            fix: "If you did not install software that needs this, vswarm respond", item: i });
          break;
        case "rc":
        case "ssh":
        case "cron":
        case "hosts": {
          const lines = addedLines(baseline.texts[i.id], scan.texts[i.id]);
          const ps = /\.ps1$/i.test(i.id);
          const risky = lines.filter((l) => RISKY_LINE.test(l) || (ps && RISKY_PS.test(l)));
          const authKeys = i.id === ".ssh/authorized_keys";
          // Only lines removed: less risky than anything added, but still a change you should recognise.
          const sev: Severity = authKeys || risky.length || i.kind === "cron" ? "high" : lines.length ? "medium" : "low";
          add({ id: `file:${i.id}:${i.hash?.slice(0, 12)}`, rule: "startup-file", severity: sev,
            title: authKeys ? "~/.ssh/authorized_keys changed: someone may have added a way to log in" : `${i.id === "crontab" ? "crontab" : /^(\/|[A-Za-z]:[\\/])/.test(i.name) ? i.name : "~/" + i.name} changed`,
            detail: (risky.length ? risky : lines).slice(0, 6).map((l) => `+ ${l.slice(0, 160)}`).concat(lines.length > 6 ? [`… ${lines.length - 6} more added lines`] : []),
            fix: risky.length ? "These lines download, decode or start something in the background; remove them unless you wrote them" : "Check the change is yours", item: i });
          break;
        }
        case "wmi":
          if (!stockWmi(i))
            add({ id: `wmi-new:${i.id}:${i.hash?.slice(0, 12)}`, rule: fresh ? "wmi-new" : "wmi-changed", severity: "medium", title: `${fresh ? "New" : "Changed"} WMI subscription: ${i.name} (${i.meta?.type})`,
              detail: [i.meta?.command ? redact(String(i.meta.command).slice(0, 200)) : "", i.meta?.filter ? `when: ${i.meta.filter}` : ""].filter(Boolean), fix: "If you did not install software that needs this, vswarm respond", item: i });
          break;
        case "mcp":
          add({ id: `agent-mcp:${i.id}:${i.hash?.slice(0, 12)}`, rule: fresh ? "agent-mcp-new" : "agent-mcp-changed", severity: "medium",
            title: `${fresh ? "New" : "Changed"} MCP server for ${i.source}: ${i.name}`, detail: [redact(String(i.meta?.command ?? i.meta?.url ?? "")), i.path ?? ""],
            fix: "An MCP server acts with the agent's access to your files and shell; keep it only if you added it", item: i });
          break;
        case "agent-hook":
          add({ id: `agent-hook:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-hook", severity: "medium",
            title: `${fresh ? "New" : "Changed"} agent hook: ${i.name}`, detail: [redact(String(i.meta?.command ?? "")), i.path ?? ""],
            fix: "Hooks run shell commands on their own, every time the agent starts or uses a tool; keep it only if you wrote it", item: i });
          break;
        case "agent-perm":
          if (i.meta?.bypass || i.meta?.wide)
            add({ id: `agent-perm:${i.id}:${i.hash?.slice(0, 12)}`, rule: "agent-perm-wider", severity: "medium", title: `${i.name}: the agent was given more freedom`,
              detail: [i.meta?.bypass ? "bypass permissions is on" : "", i.meta?.wide ? `allows without asking: ${i.meta.wide}` : "", i.path ?? ""].filter(Boolean), fix: "Check you changed this yourself", item: i });
          break;
        case "agent-plugin":
          if (fresh) add({ id: `agent-plugin:${i.id}`, rule: "agent-plugin", severity: "low", title: `New agent plugin (${i.source}): ${i.name}`, detail: [], item: i });
          break;
        case "git-hooks":
          if (fresh) add({ id: `hook:${i.id}`, rule: "git-hook", severity: "medium", title: `New global git hook: ${i.name}`, detail: [i.path ?? ""], item: i });
          break;
        case "bin": {
          if (!fresh) break;
          const link = String(i.meta?.link ?? "");
          // Formulae link into the Cellar; their origin is judged by the tap rules above.
          if (link.includes("/Cellar/") || link.includes("/Caskroom/")) break;
          const sig = await sign(i.path!);
          if (sig.kind === "developer-id" || sig.kind === "apple") {
            add({ id: `bin:${i.id}`, rule: "new-bin", severity: "info", title: `New signed program on PATH: ${i.name}`, detail: [`${sig.who}`, i.path ?? ""], item: i });
          } else if (sig.kind === "script") {
            add({ id: `bin:${i.id}`, rule: "new-bin", severity: "low", title: `New script on PATH: ${i.name}`, detail: [i.path ?? ""], item: i });
          } else {
            add({ id: `bin:${i.id}`, rule: "new-bin", severity: "medium", title: `New ${sig.kind === "unsigned" ? "unsigned" : sig.kind === "adhoc" ? "self-signed (ad-hoc)" : "unverified"} program on PATH: ${i.name}`,
              detail: [i.path ?? "", link ? `→ ${link}` : ""].filter(Boolean), fix: "Make sure you know where it came from", item: i });
          }
          break;
        }
      }
    }
  }

  out.push(...input.secrets);
  return out;
}
