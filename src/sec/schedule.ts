// `vswarm watch`: the check runs on its own and tells you when something new appears, so you hear about a planted
// login job when it lands, not the day you next ssh to production.
//   macOS   a LaunchAgent every hour (~/Library/LaunchAgents/dev.vswarm.watch.plist), and one that launchd starts
//           when a watched path changes (dev.vswarm.watch.paths.plist, WatchPaths); notifications through osascript
//   Linux   a systemd user timer (~/.config/systemd/user/vswarm-watch.{service,timer}), and a path unit
//           (vswarm-watch.path, PathModified=) that starts vswarm-watch-quick.service; notifications through notify-send
//   Windows a scheduled task \vswarm\watch for this user (its definition kept in ~/.vswarm/sec/watch-task.xml), toast
//           notifications; on the schedule only
// No daemon of vswarm's own: launchd and systemd do the watching and start a short check. The job files are recorded
// as vswarm's own, so the scan does not report them as a new login job.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { GLOBAL_TAG, HOME, paths } from "../home";
import { exec, ls, powershell, readJson, readText, realCtx, run, type Ctx } from "./ctx";
import { RC_FILES } from "./collect/system";
import { TOOL_CONFIGS } from "./collect/tools";
import { check, type Check } from "./engine";
import { c, line, VERDICT } from "./print";
import { ensureSec, recordManagedFile, SEC, writePrivate } from "./store";
import { RANK, type Finding, type Verdict } from "./types";

const LABEL = "dev.vswarm.watch";
const PATHS_LABEL = "dev.vswarm.watch.paths";
const mac = () => process.platform === "darwin";
const win = () => process.platform === "win32";
// The task itself lives in Task Scheduler; this copy of its definition is what `watch status` looks at.
const taskXml = () => join(SEC(), "watch-task.xml");
export const WIN_TASK = { path: "\\vswarm\\", name: "watch" };
const plistPath = (home = homedir(), label = LABEL) => join(home, "Library/LaunchAgents", `${label}.plist`);
const unitDir = (home = homedir()) => join(home, ".config/systemd/user");
const stateFile = () => join(SEC(), "watch.json");

interface State {
  at: number;
  verdict: string;
  /** Findings already notified, so each one is announced once. */
  told: string[];
  last?: string;
  /** What the watched paths looked like at the last check (time, size, inode): which of them a real-time trigger was about. */
  seen?: Record<string, number>;
  /** The last real-time check: when, which parts of the scan, how long. */
  quick?: { at: number; parts: string[]; ms: number };
}

const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
// systemd splits ExecStart on whitespace and expands %-specifiers; a plain path needs neither quotes nor escapes.
const unitWord = (s: string) => (/^[A-Za-z0-9_./-]+$/.test(s) ? s : `"${s.replace(/[\\"]/g, "\\$&").replace(/%/g, "%%")}"`);

/**
 * The scheduled task's one action, exactly as Get-ScheduledTask reports it (Execute + " " + Arguments), so the scan
 * recognises the task as vswarm's own. conhost --headless keeps a console window from flashing up every hour.
 */
export function winTaskAction(launcher: string): { execute: string; args: string } {
  if (/["\r\n]/.test(launcher)) throw new Error(`cannot schedule ${launcher}: it contains a double quote`);
  return { execute: "conhost.exe", args: `--headless "${launcher}" watch run` };
}

/** Task Scheduler XML: every n minutes as this user, catching up after sleep, never two at once, at most 10 minutes. */
export function winTaskXml(launcher: string, everyMinutes: number): string {
  const a = winTaskAction(launcher);
  const x = (s: string) => xml(s).replace(/"/g, "&quot;");
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>vswarm: check this machine every ${everyMinutes} minutes</Description></RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Repetition><Interval>PT${everyMinutes}M</Interval></Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>${x(a.execute)}</Command><Arguments>${x(a.args)}</Arguments></Exec></Actions>
</Task>
`;
}

export { powershell };

/** PowerShell with its inputs in environment variables: nothing from a path or a message is parsed as code. */
async function ps(script: string, env: Record<string, string>) {
  return exec([powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], { env: { ...process.env, ...env }, timeoutMs: 30_000 });
}

/** Either separator as /, so paths from join() compare the same on every system. */
const slash = (p: string) => p.replace(/\\/g, "/");

const TASK_ARGS = `-TaskPath '${WIN_TASK.path}' -TaskName '${WIN_TASK.name}'`;

// ── real time: what to watch, and which part of the scan reads it

/**
 * The places persistence and supply-chain tricks write to, by the part of the scan that reads them (scan.ts), for
 * this platform. Paths are absolute; a real-time trigger runs only the parts whose paths changed.
 */
export function watchTable(home: string, os: NodeJS.Platform = process.platform): { part: string; paths: string[] }[] {
  const h = (...rel: string[]) => rel.map((r) => join(home, r));
  const sites = [
    ...ls(join(home, "Library/Python")).map((v) => join(home, "Library/Python", v, "lib/python/site-packages")),
    ...ls(join(home, ".local/lib")).filter((d) => /^python\d/.test(d)).map((v) => join(home, ".local/lib", v, "site-packages")),
  ];
  const table = [
    { part: "launchd", paths: h("Library/LaunchAgents") },
    { part: "login items inside apps", paths: h("Applications") },
    { part: "systemd and autostart", paths: h(".config/systemd/user", ".config/autostart") },
    // ~/.ssh as a folder too: an authorized_keys or rc that did not exist yet appears there (known_hosts aside, see seen).
    { part: "startup files", paths: [...RC_FILES.map((f) => join(home, f)), ...h(".ssh", ".config/fish/conf.d")] },
    { part: "package manager and session config", paths: [...TOOL_CONFIGS.map((f) => join(home, f)), ...h(".config/pip", ".config/environment.d")] },
    { part: "programs other tools run", paths: [...h(".kube/config", ".aws/config", ".docker/config.json", ".docker/contexts/meta", "Library/Application Support/Code/User/tasks.json", ".config/Code/User/tasks.json", "Library/Application Support/Cursor/User/tasks.json", ".config/Cursor/User/tasks.json"), ...sites] },
    { part: "AI agents and MCP", paths: h(".claude.json", ".claude/settings.json", ".claude/settings.local.json", ".cursor/mcp.json", "Library/Application Support/Claude/claude_desktop_config.json", ".config/Claude/claude_desktop_config.json", ".codeium/windsurf/mcp_config.json", ".gemini/settings.json", "Library/Application Support/Code/User/mcp.json", ".config/Code/User/mcp.json", ".codex/config.toml") },
    { part: "editor extensions", paths: h(".vscode/extensions", ".cursor/extensions", ".windsurf/extensions", ".vscode-oss/extensions") },
    { part: "PATH executables", paths: h(".local/bin", "bin") },
    { part: "npm", paths: h(".npm-global/lib/node_modules", ".bun/install/global/node_modules") },
  ];
  // Each system only where it keeps things; and never vswarm's own folder, whose writes would trigger it again.
  // Judged on the path inside the home, with / as separator: a home that sits in AppData or a Library folder (a test's,
  // or a Windows runner's) must not take every path with it.
  const other = os === "darwin" ? /^\/\.config\/(systemd|autostart|environment\.d|Code|Cursor|Claude)\b|^\/\.local\/lib\b|^\/\.xprofile$|^\/\.xinitrc$/ : /^\/Library\/|^\/Applications$/;
  const rel = (p: string) => slash(p).slice(slash(home).replace(/\/+$/, "").length);
  const own = (p: string) => slash(p) === slash(HOME) || slash(p).startsWith(slash(HOME) + "/") || slash(p).startsWith(slash(SEC()));
  return table.map((t) => ({ ...t, paths: t.paths.filter((p) => !other.test(rel(p)) && !/^\/AppData\//.test(rel(p)) && !own(p)) })).filter((t) => t.paths.length);
}

/**
 * The paths a real-time job watches. launchd watches a path only while it exists (it opens it, and opens it again
 * after each run), so on macOS only what exists now is listed and `watch run` lists again when that changes; systemd
 * watches a missing path's parent until it appears, so on Linux every path is listed.
 */
export function watchPaths(home: string, os: NodeJS.Platform = process.platform): string[] {
  const all = [...new Set(watchTable(home, os).flatMap((t) => t.paths))];
  return os === "darwin" ? all.filter((p) => existsSync(p)) : all;
}

/** The parts of the scan that read these changed paths (a path, or something inside a watched folder). */
export function partsFor(changed: string[], home: string, os: NodeJS.Platform = process.platform): string[] {
  const table = watchTable(home, os);
  const ch = changed.map(slash);
  return table.filter((t) => t.paths.map(slash).some((p) => ch.some((c) => c === p || c.startsWith(p + "/")))).map((t) => t.part);
}

/**
 * What each watched path looks like: when it last changed (the later of its modification and status-change times; the
 * second cannot be set back by hand, so a file put back to its old mtime still counts as changed), with its size and
 * inode: Linux keeps these times in coarse ticks, and two writes within one tick give the same times. A folder changes
 * when an entry is added, removed or renamed. ~/.ssh is told by the names in it, known_hosts and its temporary and
 * .old copies aside: ssh rewrites those on its own at every new host, and that is not worth a check.
 */
function stampOf(p: string, sshDir: string): number | undefined {
  try {
    const st = statSync(p);
    if (p === sshDir && st.isDirectory()) {
      const names = readdirSync(p).filter((n) => !/^known_hosts/.test(n)).sort().join("\0");
      return parseInt(createHash("sha256").update(names).digest("hex").slice(0, 12), 16);
    }
    const t = Math.round(Math.max(st.mtimeMs, st.ctimeMs));
    return parseInt(createHash("sha256").update(`${t}:${st.size}:${st.ino}`).digest("hex").slice(0, 12), 16);
  } catch {
    return;
  }
}

function seen(home: string): Record<string, number> {
  const out: Record<string, number> = {};
  const sshDir = join(home, ".ssh");
  for (const p of [...new Set(watchTable(home).flatMap((t) => t.paths))]) {
    const t = stampOf(p, sshDir);
    if (t !== undefined) out[p] = t;
  }
  return out;
}

/** Remembers what the watched paths look like now, so the first real-time trigger reads only the part that changed. */
export function markSeen(home = homedir()) {
  const prev = watchState().state;
  writePrivate(stateFile(), { at: prev?.at ?? 0, verdict: prev?.verdict ?? "", told: prev?.told ?? [], ...prev, seen: seen(home) } satisfies State);
}

// launchd's WatchPaths and systemd's PathModified= fire on a write; a burst of writes (an installer, an editor's save)
// is one check: the job waits this long before it reads anything, and checks again if more changed meanwhile.
const DEBOUNCE_MS = 1500;
const plistFor = (launcher: string, label: string, keys: string) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array><string>${xml(launcher)}</string><string>watch</string><string>${label === LABEL ? "run" : "quick"}</string></array>
${keys}
<key>LowPriorityIO</key><true/>
<key>Nice</key><integer>10</integer>
<key>StandardErrorPath</key><string>${xml(join(SEC(), "watch.log"))}</string>
</dict></plist>
`;
// %-specifiers expand in unit files; a path in PathModified= is taken whole, spaces included.
const unitPath = (p: string) => p.replace(/%/g, "%%");

/**
 * The job definitions for this home: the hourly check and, on macOS and Linux, the real-time one. Windows' Task
 * Scheduler has no trigger for a changed file that works without auditing set up by an administrator, so Windows
 * stays on the schedule.
 */
export function jobFiles(launcher: string, everyMinutes = 60, home = homedir(), os: NodeJS.Platform = process.platform): Record<string, string> {
  if (!Number.isInteger(everyMinutes) || everyMinutes < 1) throw new Error("--every needs a whole number of minutes");
  if (os === "win32") return { [taskXml()]: winTaskXml(launcher, everyMinutes) };
  const watched = watchPaths(home, os);
  if (os === "darwin")
    return {
      [plistPath(home)]: plistFor(launcher, LABEL, `<key>StartInterval</key><integer>${everyMinutes * 60}</integer>\n<key>RunAtLoad</key><true/>`),
      [plistPath(home, PATHS_LABEL)]: plistFor(launcher, PATHS_LABEL,
        `<key>WatchPaths</key><array>\n${watched.map((p) => `  <string>${xml(p)}</string>`).join("\n")}\n</array>\n<key>ThrottleInterval</key><integer>10</integer>\n<key>ProcessType</key><string>Background</string>`),
    };
  return {
    [join(unitDir(home), "vswarm-watch.service")]: `[Unit]\nDescription=vswarm: check this machine\n\n[Service]\nType=oneshot\nNice=10\nExecStart=${unitWord(launcher)} watch run\n`,
    [join(unitDir(home), "vswarm-watch.timer")]: `[Unit]\nDescription=vswarm: check this machine every ${everyMinutes} minutes\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=${everyMinutes}min\n\n[Install]\nWantedBy=timers.target\n`,
    [join(unitDir(home), "vswarm-watch-quick.service")]: `[Unit]\nDescription=vswarm: check what just changed\n\n[Service]\nType=oneshot\nNice=10\nExecStart=${unitWord(launcher)} watch quick\n`,
    [join(unitDir(home), "vswarm-watch.path")]: `[Unit]\nDescription=vswarm: check within seconds when a login job, shell file, ssh, package or agent config changes\n\n[Path]\n${watched.map((p) => `PathModified=${unitPath(p)}`).join("\n")}\nUnit=vswarm-watch-quick.service\n\n[Install]\nWantedBy=default.target\n`,
  };
}

const REALTIME_FILES = (home: string) => (mac() ? [plistPath(home, PATHS_LABEL)] : [join(unitDir(home), "vswarm-watch.path"), join(unitDir(home), "vswarm-watch-quick.service")]);

/** systemctl --user, with what it said when it fails (no user manager in this session, an old systemd). */
async function systemctl(...args: string[]): Promise<string | undefined> {
  try {
    const r = await exec(["systemctl", "--user", ...args], { timeoutMs: 10_000 });
    return r.code === 0 ? undefined : r.err.trim().split("\n")[0] || `exit ${r.code}`;
  } catch (e: any) {
    return String(e?.message ?? e);
  }
}

export async function watchOn(launcher: string, everyMinutes = 60): Promise<{ done: string[]; notes: string[]; info: string[] }> {
  const done: string[] = [];
  const notes: string[] = [];
  // How it works here, not something wrong.
  const info: string[] = [];
  const first = mac() && !existsSync(plistPath(homedir()));
  for (const [path, text] of Object.entries(jobFiles(launcher, everyMinutes))) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
    recordManagedFile(text);
    done.push(path);
  }
  // Said once, the first time: macOS announces a new LaunchAgent, and people take it for something foreign.
  if (first) info.push('macOS will show "Background Items Added: vswarm" (or a notice naming bun): that is this LaunchAgent, and it is expected · System Settings → General → Login Items & Extensions lists it');
  if (process.env.VSWARM_HOME && !win()) info.push(`the job files are your user's${GLOBAL_TAG()}`);
  markSeen();
  if (win()) {
    const a = winTaskAction(launcher);
    recordManagedFile(`${a.execute} ${a.args}`);
    const r = await ps(`Register-ScheduledTask ${TASK_ARGS} -Xml ([IO.File]::ReadAllText($env:VSWARM_TASK_XML)) -Force | Out-Null`, { VSWARM_TASK_XML: taskXml() });
    if (r.code !== 0) throw new Error(`could not register the scheduled task: ${r.err.trim().split("\n")[0] || `exit ${r.code}`}`);
    done.push(`Task Scheduler ${WIN_TASK.path}${WIN_TASK.name}`);
    info.push("Windows checks on the schedule only: Task Scheduler cannot start a task when a file changes (use --every for more often)");
  } else if (mac()) {
    const uid = process.getuid?.() ?? 501;
    for (const label of [LABEL, PATHS_LABEL]) {
      await run(["launchctl", "bootout", `gui/${uid}/${label}`], 10_000);
      await run(["launchctl", "bootstrap", `gui/${uid}`, plistPath(homedir(), label)], 10_000);
    }
  } else {
    await systemctl("daemon-reload");
    const timer = await systemctl("enable", "--now", "vswarm-watch.timer");
    if (timer) notes.push(`systemd's user manager did not take the timer (${timer}): nothing will run in the background in this session`);
    const path = timer ?? (await systemctl("enable", "--now", "vswarm-watch.path"));
    if (path) {
      // Without a user manager that watches paths, the real-time job is taken out again: the timer, where it runs, stays.
      for (const f of REALTIME_FILES(homedir())) if (existsSync(f)) rmSync(f);
      if (!timer) notes.push(`real-time watch is off (${path}); the timer checks every ${everyMinutes} minutes`);
    }
  }
  return { done, notes, info };
}

export async function watchOff(): Promise<string[]> {
  const gone: string[] = [];
  if (win()) {
    const r = await ps(`$t = Get-ScheduledTask ${TASK_ARGS} -ErrorAction SilentlyContinue; if ($t) { $t | Unregister-ScheduledTask -Confirm:$false; 'gone' }`, {});
    if (r.out.includes("gone")) gone.push(`Task Scheduler ${WIN_TASK.path}${WIN_TASK.name}`);
    if (existsSync(taskXml())) (rmSync(taskXml()), gone.push(taskXml()));
  } else if (mac()) {
    for (const label of [LABEL, PATHS_LABEL]) {
      await run(["launchctl", "bootout", `gui/${process.getuid?.() ?? 501}/${label}`], 10_000);
      if (existsSync(plistPath(homedir(), label))) (rmSync(plistPath(homedir(), label)), gone.push(plistPath(homedir(), label)));
    }
  } else {
    await systemctl("disable", "--now", "vswarm-watch.timer", "vswarm-watch.path");
    for (const f of ["vswarm-watch.service", "vswarm-watch.timer", "vswarm-watch-quick.service", "vswarm-watch.path"]) if (existsSync(join(unitDir(), f))) (rmSync(join(unitDir(), f)), gone.push(join(unitDir(), f)));
    await systemctl("daemon-reload");
  }
  return gone;
}

/** Whether the background job is installed for the user whose home this is. */
export const watchInstalled = (home = homedir()) => (win() ? existsSync(taskXml()) : mac() ? existsSync(plistPath(home)) : existsSync(join(unitDir(home), "vswarm-watch.timer")));
/** Whether the real-time job is installed too (never on Windows). */
export const realtimeInstalled = (home = homedir()) => !win() && REALTIME_FILES(home).every((f) => existsSync(f));

/**
 * The background job as this vswarm sees it. The LaunchAgent, systemd units and scheduled task are the user's,
 * whatever VSWARM_HOME says; one that runs another vswarm's launcher is not this one's, and `note` says so.
 */
export function watchState(home = homedir()): { on: boolean; realtime: boolean; state?: State; note?: string } {
  const on = watchInstalled(home), realtime = realtimeInstalled(home);
  const state = readJson<State>(stateFile());
  if (!process.env.VSWARM_HOME || !on || win()) return { on, realtime, state };
  const job = readText(mac() ? plistPath(home) : join(unitDir(home), "vswarm-watch.service")) ?? "";
  const launcher = join(paths.bin(), "vswarm");
  if (job.includes(launcher)) return { on, realtime, state, note: `the job files are your user's${GLOBAL_TAG()}` };
  return { on: false, realtime: false, state, note: `a watch job is installed, but for another vswarm, not this VSWARM_HOME${GLOBAL_TAG()}` };
}

/** A desktop notification; silently nothing where there is no desktop. */
export async function notify(title: string, body: string) {
  if (win()) {
    // A toast under Windows PowerShell's own app id, which every Windows has registered.
    await ps(
      `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$t = $x.GetElementsByTagName('text')
[void]$t.Item(0).AppendChild($x.CreateTextNode($env:VSWARM_TOAST_TITLE))
[void]$t.Item(1).AppendChild($x.CreateTextNode($env:VSWARM_TOAST_BODY))
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))`,
      { VSWARM_TOAST_TITLE: title, VSWARM_TOAST_BODY: body },
    ).catch(() => {});
  } else if (mac()) {
    const q = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    await run(["osascript", "-e", `display notification ${q(body)} with title ${q(title)} sound name "Basso"`], 10_000);
  } else if (Bun.which("notify-send")) {
    await run(["notify-send", "-u", "critical", "-a", "vswarm", title, body], 10_000);
  }
}


// ── one check at a time

const lockFile = () => join(SEC(), "watch.lock");

/** The watch's lock: one check at a time, and a lock left by a run that died is taken over. */
function takeLock(): boolean {
  ensureSec();
  const take = () => {
    try {
      writeFileSync(lockFile(), `${process.pid} ${Date.now()}`, { flag: "wx", mode: 0o600 });
      return true;
    } catch {
      return false;
    }
  };
  if (take()) return true;
  const [pid, at] = (readText(lockFile()) ?? "").split(" ").map(Number);
  let alive = false;
  try {
    alive = Number.isInteger(pid) && pid > 0 && process.kill(pid, 0);
  } catch {}
  if (alive && Date.now() - at < 10 * 60_000) return false;
  rmSync(lockFile(), { force: true });
  return take();
}
const dropLock = () => rmSync(lockFile(), { force: true });

/** Notifies about findings (medium and above) not announced before, and remembers them. */
async function announce(r: Check, tell: (title: string, body: string) => Promise<void>, prev?: State): Promise<{ fresh: Finding[]; told: string[] }> {
  const told = new Set(prev?.told ?? []);
  const fresh = r.findings.filter((f) => RANK[f.severity] >= RANK.medium && !told.has(f.id) && f.rule !== "secret");
  if (fresh.length) {
    const top = fresh.sort((a, b) => RANK[b.severity] - RANK[a.severity])[0];
    await tell(
      r.verdict === "block" ? "vswarm: production access blocked" : "vswarm: something changed",
      `${top.title}${fresh.length > 1 ? ` (+${fresh.length - 1} more)` : ""}. Run: ${top.rule === "mcp-drift" || top.rule === "mcp-changed" ? "vswarm agents --inspect" : "vswarm diff"}`,
    );
  }
  return { fresh, told: [...new Set([...told, ...fresh.map((f) => f.id)])].slice(-500) };
}

/** One background check: notify about findings (medium and above) that were not announced before. */
export async function watchRun(): Promise<{ fresh: Finding[]; verdict: string }> {
  // A real-time check under way finishes first (at most a minute); the hourly one looks at everything anyway.
  for (let i = 0; i < 120 && !takeLock(); i++) await Bun.sleep(500);
  try {
    const ctx = realCtx();
    const now = seen(ctx.home);
    const r = await check(ctx, {});
    const prev = watchState().state;
    const a = await announce(r, notify, prev);
    writePrivate(stateFile(), { ...prev, at: Date.now(), verdict: r.verdict, told: a.told, last: a.fresh[0]?.title ?? prev?.last, seen: now } satisfies State);
    await refreshRealtime();
    return { fresh: a.fresh, verdict: r.verdict };
  } finally {
    dropLock();
  }
}

/**
 * launchd watches only paths that existed when the job was loaded. When that list has changed (an agent installed
 * since, a config file created), the hourly run writes the real-time job again and reloads it.
 */
export async function refreshRealtime(opt: { home?: string; os?: NodeJS.Platform; run?: (cmd: string[], timeoutMs: number) => Promise<unknown> } = {}): Promise<boolean> {
  const home = opt.home ?? homedir(), os = opt.os ?? process.platform;
  const file = plistPath(home, PATHS_LABEL);
  if (os !== "darwin" || !existsSync(file)) return false;
  const launcher = /<string>([^<]+)<\/string><string>watch<\/string>/.exec(readText(file) ?? "")?.[1]?.replace(/&lt;/g, "<").replace(/&amp;/g, "&");
  if (!launcher) return false;
  const want = jobFiles(launcher, 60, home, os)[file];
  if (!want || want === readText(file)) return false;
  const before = seen(home);
  writeFileSync(file, want);
  recordManagedFile(want);
  const uid = process.getuid?.() ?? 501;
  await (opt.run ?? run)(["launchctl", "bootout", `gui/${uid}/${PATHS_LABEL}`], 10_000);
  await (opt.run ?? run)(["launchctl", "bootstrap", `gui/${uid}`, file], 10_000);
  // This write, and launchd loading the job again, must not set off the job itself: what it changed among the watched
  // paths is taken as seen. Anything else that changed since the last check still counts.
  const after = seen(home);
  const st = watchState().state;
  const mine = Object.fromEntries(Object.keys({ ...before, ...after }).filter((p) => before[p] !== after[p]).map((p) => [p, after[p]]));
  const merged = { ...(st?.seen ?? {}), ...mine };
  for (const p of Object.keys(mine)) if (after[p] === undefined) delete merged[p];
  writePrivate(stateFile(), { at: st?.at ?? 0, verdict: st?.verdict ?? "", told: st?.told ?? [], ...st, seen: merged } satisfies State);
  return true;
}

/**
 * What the real-time job runs when a watched path changes: waits for the burst of writes to settle, works out which
 * paths changed, checks only the parts of the scan that read them (offline, so no network wait), notifies about new
 * findings, and goes again if more changed meanwhile. vswarm's own writes (its blocks, its job files, its state
 * folder, which is never watched) raise nothing, so they cannot set off a loop.
 */
export async function watchQuick(opt: { ctx?: Ctx; debounceMs?: number; notify?: (title: string, body: string) => Promise<void> } = {}): Promise<{ ran: boolean; fresh: Finding[]; parts: string[] }> {
  const ctx = opt.ctx ?? realCtx();
  const wait = opt.debounceMs ?? Number(process.env.VSWARM_WATCH_DEBOUNCE_MS ?? DEBOUNCE_MS);
  // Another check is running: it reads the paths again when it finishes, so this trigger is covered.
  if (!takeLock()) return { ran: false, fresh: [], parts: [] };
  try {
    const fresh: Finding[] = [];
    const parts = new Set<string>();
    let before = watchState().state?.seen;
    for (let round = 0; round < 3; round++) {
      await Bun.sleep(wait);
      const now = seen(ctx.home);
      const changed = [...new Set([...Object.keys(now), ...Object.keys(before ?? {})])].filter((p) => now[p] !== before?.[p]);
      // Nothing changed among the watched paths: a known_hosts write in ~/.ssh, launchd loading the job again. A
      // deletion changes them too (the path is gone), and a write cannot hide: status-change times cannot be set back.
      if (before && !changed.length) break;
      // Nothing to compare with (a first run): every file-based part, still offline.
      const these = before ? partsFor(changed, ctx.home) : watchTable(ctx.home).map((t) => t.part);
      const t0 = Date.now();
      const r = await check(ctx, { offline: true, only: these });
      const prev = watchState().state;
      const a = await announce(r, opt.notify ?? notify, prev);
      fresh.push(...a.fresh);
      these.forEach((p) => parts.add(p));
      writePrivate(stateFile(), { ...prev, at: prev?.at ?? Date.now(), verdict: prev?.verdict ?? r.verdict, told: a.told, last: a.fresh[0]?.title ?? prev?.last, seen: now, quick: { at: Date.now(), parts: these, ms: Date.now() - t0 } } satisfies State);
      before = now;
      const after = seen(ctx.home);
      if (Object.keys({ ...now, ...after }).every((p) => now[p] === after[p])) break;
    }
    return { ran: true, fresh, parts: [...parts] };
  } finally {
    dropLock();
  }
}

/** `vswarm watch on|off|status|run|quick`. */
export async function watchCommand(action: string, opt: { every: number }) {
  if (action === "run" || action === "quick") {
    const r = action === "run" ? { ran: true, ...(await watchRun()) } : await watchQuick();
    if (!r.ran) return line(c.dim("another check is running; it covers this change"));
    line(`${"verdict" in r ? `${VERDICT[r.verdict as Verdict]} ` : ""}${c.dim(r.fresh.length ? `${r.fresh.length} new finding${r.fresh.length > 1 ? "s" : ""}, notified` : "nothing new")}`);
    return;
  }
  if (action === "on") {
    // Written from this checkout when missing (a clone, never installed): watch on works without vswarm install.
    const launcher = (await import("../setup")).ensureLauncher((t) => line(t));
    const every = opt.every;
    const r = await watchOn(launcher, every);
    for (const f of r.done) line(`${c.green("✔")} ${f.replace(homedir(), "~")}`);
    for (const n of r.notes) line(`  ${c.amber("!")} ${n}`);
    for (const n of r.info) line(c.dim(`  · ${n}`));
    const realtime = realtimeInstalled();
    line(`  ${c.dim(`checks every ${every} minutes${realtime ? `, and within seconds when one of ${watchPaths(homedir()).length} watched paths changes` : ""}; notifies you about anything new · vswarm watch off to stop`)}`);
    await notify("vswarm watch is on", realtime ? `Checked every ${every} minutes, and when a login job, shell file, ssh or agent config changes.` : `This machine is checked every ${every} minutes.`);
    return;
  }
  if (action === "off") {
    for (const f of await watchOff()) line(`${c.green("✔")} removed ${f.replace(homedir(), "~")}`);
    return;
  }
  if (action === "status") {
    const s = watchState();
    if (s.note) line(c.dim(`  ${s.note}`));
    line(s.on ? `${c.green("●")} watch is on${s.realtime ? " · real-time" : win() ? " · on the schedule (Windows)" : ` · ${c.amber("real-time off")} (vswarm watch on adds it)`}` : `${c.dim("○")} watch is off · vswarm watch on`);
    if (s.state?.at) line(`  ${c.dim(`last check ${new Date(s.state.at).toLocaleString()} · ${s.state.verdict.toUpperCase()}${s.state.last ? ` · last notified: ${s.state.last}` : ""}`)}`);
    if (s.state?.quick) line(`  ${c.dim(`last real-time check ${new Date(s.state.quick.at).toLocaleString()} · ${s.state.quick.parts.join(", ")} · ${s.state.quick.ms} ms`)}`);
    return;
  }
  throw new Error("usage: vswarm watch on [--every minutes] | off | status | run");
}
