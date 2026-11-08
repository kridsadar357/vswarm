// A finding in plain words, for the terminal and the dashboard alike: which of the three groups it belongs to, a
// plain title and why it matters (rule.<rule>.what / .why / .todo in the catalog), and the one thing to do next.
// vswarm's own technical title and details stay as they are, for whoever wants them.

import { basename } from "node:path";
import type { Finding, Severity } from "../sec/types";
import { catalogs, fill, lang, needs, type Key, type Lang } from ".";

/** Findings about vswarm's own files (engine.ts STATE_RULE). */
const STATE = "vswarm-state";

/** Needs action (could be an attack), worth a look (new or changed), or just for your information. */
export type Group = "action" | "look" | "fyi";

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function groupOf(f: Pick<Finding, "rule" | "severity">): Group {
  if (f.rule === STATE || SEV_RANK[f.severity] >= SEV_RANK.high) return "action";
  return f.severity === "medium" ? "look" : "fyi";
}

/** The dashboard's names for the same groups. */
export const UI_GROUP: Record<Group, "action" | "yours" | "info"> = { action: "action", look: "yours", fyi: "info" };

export const AGENT_NAMES: Record<string, string> = { "claude-code": "Claude Code", "claude-desktop": "Claude Desktop", cursor: "Cursor", windsurf: "Windsurf", vscode: "VS Code", gemini: "Gemini CLI", codex: "Codex" };

/** The values a rule's plain sentence can name: the item's name and the app it is in. */
export function paramsOf(f: Finding): Record<string, string> {
  const i = f.item;
  const source = String(i?.source ?? "");
  const p: Record<string, string> = {};
  if (i?.name) p.name = i.kind === "mcp" ? i.name : basename(String(i.name));
  if (source) p.source = AGENT_NAMES[source] ?? source;
  if (f.meta?.file) p.file = basename(f.meta.file);
  return p;
}

/** Credentials are one rule with several kinds; each kind has words of its own (rule.secret.<kind>.*). */
function kindOf(f: Finding): string | undefined {
  if (f.rule !== "secret") return;
  if (f.id.startsWith("agent-secret:")) return "agent";
  const m = /^secret:([a-z-]+)/.exec(f.id);
  if (!m) return;
  if (m[1] === "ssh") return f.meta?.production ? "sshProd" : "ssh";
  return ["aws", "kube", "docker", "gcp-sa", "rc", "env-files"].includes(m[1]) ? m[1] : undefined;
}

export interface Plain {
  /** One plain line; vswarm's technical title where the catalog has no words for this rule. */
  title: string;
  /** Whether `title` is the plain sentence (and the technical one is worth showing beside it). */
  plain: boolean;
  why: string;
  todo: string;
}

export function plainOf(f: Finding, l: Lang = lang()): Plain {
  const p = paramsOf(f);
  const g = UI_GROUP[groupOf(f)];
  const kind = kindOf(f);
  const bases = [...(kind ? [`rule.secret.${kind}`] : []), `rule.${f.rule}`];
  const pick = (part: string): string | undefined => {
    for (const b of bases) {
      const s = catalogs[l][`${b}.${part}`] ?? catalogs.en[`${b}.${part}`];
      if (s !== undefined && needs(s).every((n) => p[n])) return fill(s, p);
    }
  };
  const what = pick("what");
  return {
    title: what ?? f.title,
    plain: what !== undefined,
    why: pick("why") ?? fill(catalogs[l][`rule._${g}.why`] ?? catalogs.en[`rule._${g}.why`], p),
    todo: pick("todo") ?? fill(catalogs[l][`rule._${g}.todo`] ?? catalogs.en[`rule._${g}.todo`], p),
  };
}

/**
 * The one thing to do next about finding n, as a command to copy: fix it where vswarm can, look closer where it could
 * be an attack, say it is yours where it is new or changed. Rules that cannot be accepted have their own way out.
 */
export function actionOf(f: Finding, n: number | undefined, fixable: boolean): { label: Key; cmd: string } | undefined {
  if (f.rule === "malicious" || f.rule === "pkg-malicious") return { label: "cli.act.respond", cmd: "vswarm respond" };
  if (f.rule === "team-require") return { label: "cli.act.team", cmd: "vswarm team status" };
  if (n === undefined) return;
  if (fixable) return { label: "cli.act.fix", cmd: `vswarm fix ${n}` };
  if (f.rule === STATE || groupOf(f) === "action") return { label: "cli.act.why", cmd: `vswarm why ${n}` };
  return { label: "cli.act.ok", cmd: `vswarm ok ${n}` };
}
