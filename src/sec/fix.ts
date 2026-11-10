// `vswarm fix <n>`: the safe automatic fix for finding n of the last check, shown exactly before it runs and run only
// on yes; where there is none, the steps to take by hand. Also the line removal that `vswarm respond` uses.
//
//   SSH key without a passphrase   production key: vswarm agent protect (it tries the key first); otherwise, or when
//                                  you say no: ssh-keygen -p, which asks for the new passphrase itself
//   unsafe package source          the lines that name it are taken out of the file (a copy goes to ~/.vswarm/backups)
//   lines added to a startup file  the same, for the risky lines the finding lists
//   everything else                what to do, and how to accept it instead

import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { HOME } from "../home";
import { shq } from "./ctx";
import { t } from "../i18n";
import { plainOf } from "../i18n/findings";
import { c, line } from "./print";
import type { Finding } from "./types";

/** Where vswarm keeps copies of files it changes for you (gates, fixes). Owner-only. */
export const backupDir = () => process.env.VSWARM_BACKUP_DIR ?? (process.env.VSWARM_SEC_DIR ? join(process.env.VSWARM_SEC_DIR, "backups") : join(HOME, "backups"));

/**
 * A copy of `file` in the backup folder, named after what made it, the file and the time (aws-config-1731…); returns
 * its path. Never beside the file: in gcloud's configurations/ a copy is itself read as a configuration.
 */
export function backupCopy(file: string, tag: string): string {
  mkdirSync(backupDir(), { recursive: true, mode: 0o700 });
  const base = join(backupDir(), `${tag}-${basename(file).replace(/^\./, "")}-${Date.now()}`);
  let to = base;
  for (let i = 2; existsSync(to); i++) to = `${base}-${i}`;
  copyFileSync(file, to);
  try {
    chmodSync(to, 0o600);
  } catch {}
  return to;
}

/**
 * Takes out of `file` every line that is, trimmed, one of `lines` (what a finding recorded). Returns how many lines
 * actually went: a line edited since the check is not one of them, and is left alone.
 */
export function removeLines(file: string, lines: string[], keepCopy?: string): { removed: number; missing: string[] } {
  const want = new Set(lines.map((l) => l.trim()).filter(Boolean));
  const text = readFileSync(file, "utf8");
  const nl = text.includes("\r\n") ? "\r\n" : "\n";
  const all = text.split(/\r?\n/);
  const kept = all.filter((l) => !want.has(l.trim()));
  const removed = all.length - kept.length;
  const found = new Set(all.map((l) => l.trim()));
  const missing = [...want].filter((l) => !found.has(l));
  if (removed) {
    if (keepCopy) copyFileSync(file, keepCopy);
    writeFileSync(file, kept.join(nl));
  }
  return { removed, missing };
}

export interface FixPlan {
  /** What will be done, in one line, and the commands or changes exactly. */
  what: string;
  exact: string[];
  run?: () => Promise<string>;
  /** Asked when the first plan is declined (the production key: ssh-keygen -p instead of agent protect). */
  instead?: FixPlan;
  /** No automatic fix: what to do by hand. */
  manual?: string[];
}

const short = (p: string, home = homedir()) => p.replace(home, "~");

async function runTty(cmd: string[]): Promise<number> {
  return Bun.spawn(cmd, { stdin: "inherit", stdout: "inherit", stderr: "inherit" }).exited;
}

/** A command as you would paste it: POSIX quoting, or on Windows double quotes only where a word has a space. */
const pasteable = (cmd: string[], platform: NodeJS.Platform) => cmd.map((w) => (platform === "win32" ? (/[\s"']/.test(w) ? `"${w.replace(/"/g, '\\"')}"` : w) : shq(w))).join(" ");

/** The fix for one finding. `self` is how to start this vswarm (for agent protect). */
export function fixFor(f: Finding, opt: { n: number; self: string[]; home?: string; platform?: NodeJS.Platform }): FixPlan {
  const home = opt.home ?? homedir();
  const platform = opt.platform ?? process.platform;
  const accept = t("cli.fix.orOk", { n: opt.n });
  const file = f.meta?.file;
  if (f.id.startsWith("secret:ssh:") && file) {
    const keygen: FixPlan = {
      what: t("cli.fix.passphrase", { key: short(file, home) }),
      exact: [pasteable(["ssh-keygen", "-p", "-f", file], platform)],
      run: async () => ((await runTty(["ssh-keygen", "-p", "-f", file])) === 0 ? t("cli.fix.passphraseDone", { key: short(file, home) }) : t("cli.fix.passphraseNot")),
    };
    if (f.meta?.production && platform !== "win32")
      return {
        what: t("cli.fix.vault", { key: short(file, home) }),
        exact: [pasteable([...opt.self, "agent", "protect", file], platform)],
        run: async () => ((await runTty([...opt.self, "agent", "protect", file])) === 0 ? t("cli.fix.done") : t("cli.fix.vaultStopped")),
        instead: keygen,
      };
    return keygen;
  }
  const lines = f.meta?.lines ?? [];
  const path = f.item?.path;
  if ((f.rule === "pkg-source" || f.rule === "startup-file") && lines.length && path && existsSync(path) && !f.id.includes("authorized_keys")) {
    return {
      what: t("cli.fix.lines", { n: lines.length, file: short(path, home), dir: short(backupDir(), home) }),
      exact: lines.map((l) => `- ${l}`),
      run: async () => {
        const copy = join(backupDir(), `${basename(path).replace(/^\./, "")}.before-fix-${Date.now()}`);
        mkdirSync(backupDir(), { recursive: true, mode: 0o700 });
        const r = removeLines(path, lines, copy);
        return r.removed
          ? t("cli.fix.linesDone", { n: r.removed, file: short(path, home), copy: short(copy, home), missing: r.missing.length ? t("cli.fix.linesMissing", { n: r.missing.length }) : "" })
          : t("cli.fix.linesGone", { file: short(path, home) });
      },
    };
  }
  // Saying it is yours is no way out for a known-malicious package, vswarm's own files (engine.ts STATE_RULE) or a team requirement.
  const okable = !["malicious", "pkg-malicious", "vswarm-state", "team-require"].includes(f.rule);
  return { what: t("cli.fix.none"), exact: [], manual: [f.fix ?? t("cli.fix.lookAt"), ...(okable ? [accept] : [])] };
}

/** Shows the plan, asks, runs. Returns the exit code. */
export async function fixCommand(f: Finding, n: number, opt: { self: string[]; yes: (q: string, def?: boolean) => Promise<boolean> }): Promise<number> {
  const plan = fixFor(f, { n, self: opt.self });
  const p = plainOf(f);
  line(`${c.bold(String(n))}  ${p.title}`);
  if (p.plain && p.title !== f.title) line(`   ${c.dim(f.title)}`);
  const offer = async (p: FixPlan): Promise<number | undefined> => {
    line(`  ${c.cyan("→")} ${p.what}`);
    for (const e of p.exact) line(`      ${c.dim(e)}`);
    if (!p.run) return;
    if (!(await opt.yes(t("cli.fix.ask"), false))) return;
    line(`  ${c.green("✔")} ${await p.run()}`);
    return 0;
  };
  if (plan.manual) {
    line(`  ${c.dim(t("cli.fix.manual"))}`);
    for (const m of plan.manual) line(`  ${c.cyan("→")} ${m}`);
    return 0;
  }
  const first = await offer(plan);
  if (first !== undefined) return first;
  if (plan.instead) {
    const second = await offer(plan.instead);
    if (second !== undefined) return second;
  }
  line(c.dim(`  ${t("cli.fix.nothing", { n })}`));
  return 0;
}
