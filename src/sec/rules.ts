// From what a scan saw to what deserves attention. Two kinds of rule:
//   always   things that are wrong whatever the history (known-malicious package, code running from /tmp)
//   change   things that appeared or changed since the baseline you marked as clean

import { lookAlike, signature, type Malicious, type Signature } from "./intel";
import { suspiciousLocation } from "./collect/system";
import type { Finding, Item, Scan, Severity } from "./types";

/** Lines in a shell startup file that fetch, decode or start something in the background. */
const RISKY_LINE = /\b(curl|wget|nc|ncat|socat|base64|openssl\s+enc|eval|osascript|python3?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e|nohup|launchctl|chmod\s+\+x)\b|&\s*$|\|\s*(ba|z)?sh\b|\/tmp\/|\.cache\//;

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

export async function evaluate(input: RuleInput): Promise<Finding[]> {
  const { scan, baseline } = input;
  const sign = input.sign ?? signature;
  const home = scan.home;
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);
  const before = new Map((baseline?.items ?? []).map((i) => [key(i), i]));
  const isNew = (i: Item) => baseline !== undefined && !before.has(key(i));
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
        detail: [String(i.meta?.where ?? ""), `pid ${i.meta?.pid}`], fix: "Find out what started it (ps -o ppid= -p PID); if you do not know it, vswarm respond", item: i });
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
    if (i.kind === "launch") {
      const prog = String(i.meta?.program ?? "");
      const exe = prog.split(" ").find((p) => p.startsWith("/") && !/^\/(bin|usr\/bin)\/(ba|z)?sh$/.test(p) && !/^\/usr\/bin\/(env|python3?|osascript|open)$/.test(p)) ?? "";
      const where = exe ? suspiciousLocation(exe, home) : undefined;
      if (where) {
        add({ id: `launch-location:${i.id}`, rule: "launch-location", severity: "high", title: `Login job ${i.name} starts a program that ${where}`,
          detail: [i.path ?? "", prog], fix: "Unless you set this up yourself, vswarm respond", item: i });
      }
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
            title: `${fresh ? "New" : "Changed"} login job: ${i.name}`, detail: [i.path ?? "", `runs: ${i.meta?.program ?? "?"}`],
            fix: "If you did not install software that needs this, vswarm respond", item: i });
          break;
        case "rc":
        case "ssh":
        case "cron":
        case "hosts": {
          const lines = addedLines(baseline.texts[i.id], scan.texts[i.id]);
          const risky = lines.filter((l) => RISKY_LINE.test(l));
          const authKeys = i.id === ".ssh/authorized_keys";
          const sev: Severity = authKeys || risky.length || i.kind === "cron" ? "high" : "medium";
          add({ id: `file:${i.id}:${i.hash?.slice(0, 12)}`, rule: "startup-file", severity: sev,
            title: authKeys ? "~/.ssh/authorized_keys changed: someone may have added a way to log in" : `${i.kind === "cron" ? "crontab" : i.name.startsWith("/") ? i.name : "~/" + i.name} changed`,
            detail: (risky.length ? risky : lines).slice(0, 6).map((l) => `+ ${l.slice(0, 160)}`).concat(lines.length > 6 ? [`… ${lines.length - 6} more added lines`] : []),
            fix: risky.length ? "These lines download, decode or start something in the background; remove them unless you wrote them" : "Check the change is yours", item: i });
          break;
        }
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
