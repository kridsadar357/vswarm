// What a scan sees, and what vswarm concludes from it.

/** Something on the machine that can run code, keep itself running, or hold access. */
export interface Item {
  /** Collector family: brew, brew-tap, npm, pip, cargo, editor-ext, browser-ext, launch, rc, cron, git-hooks, bin, proc, conn, ssh-config, hosts, wmi. */
  kind: string;
  /** Stable key within the kind, used to match the same item across scans. */
  id: string;
  name: string;
  version?: string;
  /** Where it came from: tap, registry, publisher, profile. */
  source?: string;
  path?: string;
  /** Content fingerprint for files whose change matters (rc files, plists). */
  hash?: string;
  /** Small extra facts the rules read (signed, scripts, program, remote …). */
  meta?: Record<string, string | number | boolean | undefined>;
}

export interface Scan {
  version: 1;
  host: string;
  user: string;
  home: string;
  at: number;
  items: Item[];
  /** Text of files whose added lines are worth showing (shell rc, crontab). Kept only on this machine. */
  texts: Record<string, string>;
  /** Collectors that failed, with why; a scan with gaps says so instead of passing quietly. */
  gaps: Record<string, string>;
  /** Item kinds this scan's collectors look for. A kind a baseline did not cover is not "new" against it. */
  covers?: string[];
}

/** Kinds that vswarm 2.3 and earlier did not record, for baselines saved before `covers` existed. */
export const ADDED_KINDS: Record<string, string> = {
  mcp: "AI agents and MCP", "agent-hook": "AI agents and MCP", "agent-perm": "AI agents and MCP", "agent-plugin": "AI agents and MCP",
  wmi: "Windows WMI subscriptions",
  "shell-d": "shell start-up folders (fish conf.d, /etc/profile.d)", "app-agent": "login items inside apps", sysext: "system and kernel extensions",
};

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  /** Stable across runs, so a finding can be accepted once: rule + item key. */
  id: string;
  rule: string;
  severity: Severity;
  title: string;
  detail: string[];
  /** What to do about it, in one line. */
  fix?: string;
  item?: Item;
}

export type Verdict = "pass" | "warn" | "block";

export const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function verdictOf(findings: Finding[]): Verdict {
  const top = Math.max(-1, ...findings.map((f) => RANK[f.severity]));
  return top >= RANK.high ? "block" : top >= RANK.medium ? "warn" : "pass";
}
