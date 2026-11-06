// `vswarm watch`: the check runs on its own every hour and tells you when something new appears, so you hear about
// a planted login job the day it lands, not the day you next ssh to production.
//   macOS  a LaunchAgent (~/Library/LaunchAgents/dev.vswarm.watch.plist), notifications through osascript
//   Linux  a systemd user timer (~/.config/systemd/user/vswarm-watch.{service,timer}), notifications through notify-send
// The job's files are recorded as vswarm's own, so the scan does not report them as a new login job.

import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { readJson, realCtx, run } from "./ctx";
import { check } from "./engine";
import { recordManagedFile, SEC, writePrivate } from "./store";
import { RANK, type Finding } from "./types";

const LABEL = "dev.vswarm.watch";
const mac = () => process.platform === "darwin";
const plistPath = (home = homedir()) => join(home, "Library/LaunchAgents", `${LABEL}.plist`);
const unitDir = (home = homedir()) => join(home, ".config/systemd/user");
const stateFile = () => join(SEC(), "watch.json");

interface State {
  at: number;
  verdict: string;
  /** Findings already notified, so each one is announced once. */
  told: string[];
  last?: string;
}

const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
// systemd splits ExecStart on whitespace and expands %-specifiers; a plain path needs neither quotes nor escapes.
const unitWord = (s: string) => (/^[A-Za-z0-9_./-]+$/.test(s) ? s : `"${s.replace(/[\\"]/g, "\\$&").replace(/%/g, "%%")}"`);

export function jobFiles(launcher: string, everyMinutes = 60, home = homedir()): Record<string, string> {
  if (mac())
    return {
      [plistPath(home)]: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${LABEL}</string>
<key>ProgramArguments</key><array><string>${xml(launcher)}</string><string>watch</string><string>run</string></array>
<key>StartInterval</key><integer>${everyMinutes * 60}</integer>
<key>RunAtLoad</key><true/>
<key>LowPriorityIO</key><true/>
<key>Nice</key><integer>10</integer>
<key>StandardErrorPath</key><string>${xml(join(SEC(), "watch.log"))}</string>
</dict></plist>
`,
    };
  return {
    [join(unitDir(home), "vswarm-watch.service")]: `[Unit]\nDescription=vswarm: check this machine\n\n[Service]\nType=oneshot\nNice=10\nExecStart=${unitWord(launcher)} watch run\n`,
    [join(unitDir(home), "vswarm-watch.timer")]: `[Unit]\nDescription=vswarm: check this machine every ${everyMinutes} minutes\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=${everyMinutes}min\n\n[Install]\nWantedBy=timers.target\n`,
  };
}

export async function watchOn(launcher: string, everyMinutes = 60): Promise<string[]> {
  const done: string[] = [];
  for (const [path, text] of Object.entries(jobFiles(launcher, everyMinutes))) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
    recordManagedFile(text);
    done.push(path);
  }
  if (mac()) {
    const uid = process.getuid?.() ?? 501;
    await run(["launchctl", "bootout", `gui/${uid}/${LABEL}`], 10_000);
    await run(["launchctl", "bootstrap", `gui/${uid}`, plistPath()], 10_000);
  } else {
    await run(["systemctl", "--user", "daemon-reload"], 10_000);
    await run(["systemctl", "--user", "enable", "--now", "vswarm-watch.timer"], 10_000);
  }
  return done;
}

export async function watchOff(): Promise<string[]> {
  const gone: string[] = [];
  if (mac()) {
    await run(["launchctl", "bootout", `gui/${process.getuid?.() ?? 501}/${LABEL}`], 10_000);
    if (existsSync(plistPath())) (rmSync(plistPath()), gone.push(plistPath()));
  } else {
    await run(["systemctl", "--user", "disable", "--now", "vswarm-watch.timer"], 10_000);
    for (const f of ["vswarm-watch.service", "vswarm-watch.timer"]) if (existsSync(join(unitDir(), f))) (rmSync(join(unitDir(), f)), gone.push(join(unitDir(), f)));
    await run(["systemctl", "--user", "daemon-reload"], 10_000);
  }
  return gone;
}

export function watchState(): { on: boolean; state?: State } {
  const on = mac() ? existsSync(plistPath()) : existsSync(join(unitDir(), "vswarm-watch.timer"));
  return { on, state: readJson<State>(stateFile()) };
}

/** A desktop notification; silently nothing where there is no desktop. */
export async function notify(title: string, body: string) {
  if (mac()) {
    const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    await run(["osascript", "-e", `display notification ${q(body)} with title ${q(title)} sound name "Basso"`], 10_000);
  } else if (Bun.which("notify-send")) {
    await run(["notify-send", "-u", "critical", "-a", "vswarm", title, body], 10_000);
  }
}

/** One background check: notify about findings (medium and above) that were not announced before. */
export async function watchRun(): Promise<{ fresh: Finding[]; verdict: string }> {
  const r = await check(realCtx(), {});
  const prev = watchState().state;
  const told = new Set(prev?.told ?? []);
  const fresh = r.findings.filter((f) => RANK[f.severity] >= RANK.medium && !told.has(f.id) && f.rule !== "secret");
  if (fresh.length) {
    const top = fresh.sort((a, b) => RANK[b.severity] - RANK[a.severity])[0];
    await notify(
      r.verdict === "block" ? "vswarm: production access blocked" : "vswarm: something changed",
      `${top.title}${fresh.length > 1 ? ` (+${fresh.length - 1} more)` : ""}. Run: vswarm diff`,
    );
  }
  const state: State = { at: Date.now(), verdict: r.verdict, told: [...new Set([...told, ...fresh.map((f) => f.id)])].slice(-500), last: fresh[0]?.title ?? prev?.last };
  writePrivate(stateFile(), state);
  return { fresh, verdict: r.verdict };
}
