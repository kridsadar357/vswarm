// `vswarm watch`: the check runs on its own every hour and tells you when something new appears, so you hear about
// a planted login job the day it lands, not the day you next ssh to production.
//   macOS  a LaunchAgent (~/Library/LaunchAgents/dev.vswarm.watch.plist), notifications through osascript
//   Linux  a systemd user timer (~/.config/systemd/user/vswarm-watch.{service,timer}), notifications through notify-send
//   Windows a scheduled task \vswarm\watch for this user (its definition kept in ~/.vswarm/sec/watch-task.xml), toast notifications
// The job's files are recorded as vswarm's own, so the scan does not report them as a new login job.

import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { paths } from "../home";
import { exec, readJson, realCtx, run } from "./ctx";
import { check } from "./engine";
import { c, line, VERDICT } from "./print";
import { recordManagedFile, SEC, writePrivate } from "./store";
import { RANK, type Finding, type Verdict } from "./types";

const LABEL = "dev.vswarm.watch";
const mac = () => process.platform === "darwin";
const win = () => process.platform === "win32";
// The task itself lives in Task Scheduler; this copy of its definition is what `watch status` looks at.
const taskXml = () => join(SEC(), "watch-task.xml");
export const WIN_TASK = { path: "\\vswarm\\", name: "watch" };
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

/** Windows PowerShell by full path, so a powershell.exe planted earlier on PATH is not the one that runs. */
export function powershell(): string {
  const full = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  return existsSync(full) ? full : "powershell.exe";
}

/** PowerShell with its inputs in environment variables: nothing from a path or a message is parsed as code. */
async function ps(script: string, env: Record<string, string>) {
  return exec([powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], { env: { ...process.env, ...env }, timeoutMs: 30_000 });
}

const TASK_ARGS = `-TaskPath '${WIN_TASK.path}' -TaskName '${WIN_TASK.name}'`;

export function jobFiles(launcher: string, everyMinutes = 60, home = homedir()): Record<string, string> {
  if (!Number.isInteger(everyMinutes) || everyMinutes < 1) throw new Error("--every needs a whole number of minutes");
  if (win()) return { [taskXml()]: winTaskXml(launcher, everyMinutes) };
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
  if (win()) {
    const a = winTaskAction(launcher);
    recordManagedFile(`${a.execute} ${a.args}`);
    const r = await ps(`Register-ScheduledTask ${TASK_ARGS} -Xml ([IO.File]::ReadAllText($env:VSWARM_TASK_XML)) -Force | Out-Null`, { VSWARM_TASK_XML: taskXml() });
    if (r.code !== 0) throw new Error(`could not register the scheduled task: ${r.err.trim().split("\n")[0] || `exit ${r.code}`}`);
    done.push(`Task Scheduler ${WIN_TASK.path}${WIN_TASK.name}`);
  } else if (mac()) {
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
  if (win()) {
    const r = await ps(`$t = Get-ScheduledTask ${TASK_ARGS} -ErrorAction SilentlyContinue; if ($t) { $t | Unregister-ScheduledTask -Confirm:$false; 'gone' }`, {});
    if (r.out.includes("gone")) gone.push(`Task Scheduler ${WIN_TASK.path}${WIN_TASK.name}`);
    if (existsSync(taskXml())) (rmSync(taskXml()), gone.push(taskXml()));
  } else if (mac()) {
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
  const on = win() ? existsSync(taskXml()) : mac() ? existsSync(plistPath()) : existsSync(join(unitDir(), "vswarm-watch.timer"));
  return { on, state: readJson<State>(stateFile()) };
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

/** `vswarm watch on|off|status|run`. */
export async function watchCommand(action: string, opt: { every: number }) {
  if (action === "run") {
    const r = await watchRun();
    line(`${VERDICT[r.verdict as Verdict]} ${c.dim(r.fresh.length ? `${r.fresh.length} new finding${r.fresh.length > 1 ? "s" : ""}, notified` : "nothing new")}`);
    return;
  }
  if (action === "on") {
    const launcher = join(paths.bin(), win() ? "vswarm.cmd" : "vswarm");
    if (!existsSync(launcher)) throw new Error("install the launcher first: vswarm install");
    const every = opt.every;
    for (const f of await watchOn(launcher, every)) line(`${c.green("✔")} ${f.replace(homedir(), "~")}`);
    line(`  ${c.dim(`checks every ${every} minutes and notifies you about anything new · vswarm watch off to stop`)}`);
    await notify("vswarm watch is on", `This machine is checked every ${every} minutes.`);
    return;
  }
  if (action === "off") {
    for (const f of await watchOff()) line(`${c.green("✔")} removed ${f.replace(homedir(), "~")}`);
    return;
  }
  if (action === "status") {
    const s = watchState();
    line(s.on ? `${c.green("●")} watch is on` : `${c.dim("○")} watch is off · vswarm watch on`);
    if (s.state) line(`  ${c.dim(`last check ${new Date(s.state.at).toLocaleString()} · ${s.state.verdict.toUpperCase()}${s.state.last ? ` · last notified: ${s.state.last}` : ""}`)}`);
    return;
  }
  throw new Error("usage: vswarm watch on [--every minutes] | off | status | run");
}
