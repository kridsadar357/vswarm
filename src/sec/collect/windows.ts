// Windows (phase 1): the places Windows starts programs from, read in one PowerShell pass (windows-snapshot.ps1)
// and turned into the same items the macOS and Linux collectors produce, so the same rules apply:
//   Run / RunOnce values, Startup folders, scheduled tasks, services   → "launch"
//   WMI permanent event subscriptions                                  → "wmi"
//   PowerShell profiles                                                → "rc" (added lines show in a diff)
//   processes and connections                                          → "proc" / "conn"
// Everything after the snapshot is a pure function of it, so it is tested on any platform with fixture JSON.

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { exec, fileHash, sha256, type Ctx } from "../ctx";
import { isManagedFile, stripManaged } from "../store";
import type { Item } from "../types";
import { suspiciousLocation, WIN_PATH } from "./system";

export interface WinSnapshot {
  v?: number;
  runKeys?: { hive: string; key: string; name: string; command: string }[];
  startup?: { scope: string; file: string; path?: string; target?: string; arguments?: string }[];
  tasks?: { path: string; name: string; state?: string; actions?: string[] }[];
  services?: { name: string; displayName?: string; pathName: string; startName?: string; state?: string }[];
  wmi?: {
    filters?: { name: string; query: string }[];
    consumers?: { name: string; class: string; commandLine?: string; executable?: string; scriptFile?: string; scriptText?: string }[];
    bindings?: { filter: string; consumer: string }[];
  };
  processes?: { pid: number; name?: string; exe?: string; mine?: boolean }[];
  connections?: { pid: number; remote: string; port: number }[];
  /** The real Documents folder ([Environment]::GetFolderPath('MyDocuments')); often redirected into OneDrive. */
  docs?: string;
  pshome?: string;
  /**
   * The Windows user's home the paths in the snapshot are relative to, when it is not the scan's home: a snapshot of a
   * Windows machine judged elsewhere (vswarm selftest on macOS and Linux). The snapshot script leaves it out.
   */
  home?: string;
  /** Sections that failed, with why. Each one becomes a gap. */
  errors?: Record<string, string>;
}

// PowerShell 5.1 turns a one-element list into a bare object, an empty one into null, and may wrap a list as
// {"value": [...], "Count": n}; accept every shape.
const unwrap = (x: any) => (x && typeof x === "object" && !Array.isArray(x) && Array.isArray(x.value) && "Count" in x ? x.value : x);
const arr = <T>(x: T[] | T | undefined | null): T[] => {
  const v = unwrap(x);
  return (Array.isArray(v) ? v : v == null ? [] : [v]).filter((e) => e && typeof e === "object");
};
const str = (x: unknown) => (typeof x === "string" ? x : x == null ? "" : String(x));

// ── running the snapshot (the only Windows-only code in this file)

/** Runs the script from a scriptblock: no quoting of its text on the command line, and no execution policy on a file. */
const BOOT = "& ([scriptblock]::Create([IO.File]::ReadAllText($env:VSWARM_SNAPSHOT_PS1)))";
export const SNAPSHOT_SCRIPT = join(import.meta.dir, "windows-snapshot.ps1");

export function parseSnapshot(out: string): WinSnapshot | undefined {
  const a = out.indexOf("{");
  const b = out.lastIndexOf("}");
  if (a < 0 || b < a) return;
  try {
    const j = JSON.parse(out.slice(a, b + 1));
    return j && typeof j === "object" && !Array.isArray(j) ? j : undefined;
  } catch {
    return;
  }
}

/** One snapshot of this machine. A failure comes back as a snapshot with only `errors`, so it is reported as a gap. */
export async function winSnapshot(timeoutMs = 30_000): Promise<WinSnapshot> {
  // The full path, so a powershell.exe planted earlier on PATH is not the one that answers.
  const full = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const t0 = Date.now();
  try {
    const r = await exec([existsSync(full) ? full : "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", BOOT], {
      env: { ...process.env, VSWARM_SNAPSHOT_PS1: SNAPSHOT_SCRIPT }, timeoutMs,
    });
    const snap = parseSnapshot(r.out);
    if (snap) return snap;
    if (Date.now() - t0 >= timeoutMs) return { errors: { snapshot: `PowerShell did not finish within ${Math.round(timeoutMs / 1000)} s` } };
    const why = r.err.trim().split("\n")[0]?.slice(0, 200);
    return { errors: { snapshot: `PowerShell gave no snapshot (exit ${r.code}${why ? `: ${why}` : ""})` } };
  } catch (e: any) {
    return { errors: { snapshot: `could not start PowerShell: ${e?.message ?? e}` } };
  }
}

// ── reading command lines

const EXT = "exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|scr|pif|lnk|msi|dll|cpl|ocx";
/** A file path with a drive letter somewhere in a command line, up to its extension (it may contain spaces). */
const FILE_IN = new RegExp(`[A-Za-z]:[\\\\/][^"'<>|*?\\r\\n,;]*?\\.(?:${EXT})(?![\\w])`, "i");

/** %VAR% in a command line, for the variables that point into the home and system folders. Unknown ones stay. */
export function expandEnv(s: string, home: string): string {
  const drive = /^[A-Za-z]:/.exec(home)?.[0] ?? "C:";
  const v: Record<string, string> = {
    userprofile: home, appdata: `${home}\\AppData\\Roaming`, localappdata: `${home}\\AppData\\Local`,
    temp: `${home}\\AppData\\Local\\Temp`, tmp: `${home}\\AppData\\Local\\Temp`, public: `${drive}\\Users\\Public`,
    programdata: `${drive}\\ProgramData`, allusersprofile: `${drive}\\ProgramData`, systemroot: `${drive}\\Windows`, windir: `${drive}\\Windows`,
    programfiles: `${drive}\\Program Files`, "programfiles(x86)": `${drive}\\Program Files (x86)`, systemdrive: drive, homedrive: drive,
  };
  return s.replace(/%([^%\s]+)%/g, (m, k: string) => v[k.toLowerCase()] ?? m);
}

/** The program a command line starts: "quoted", an unquoted path with spaces up to its extension, or the first word. */
function program(cmd: string): { prog: string; rest: string } {
  const s = cmd.trim();
  const q = /^"([^"]*)"?\s*/.exec(s);
  if (q) return { prog: q[1], rest: s.slice(q[0].length) };
  const spaced = new RegExp(`^([A-Za-z]:\\\\[^"]*?\\.(?:${EXT}))(?=\\s|$)\\s*`, "i").exec(s);
  if (spaced) return { prog: spaced[1], rest: s.slice(spaced[0].length) };
  const w = /^(\S+)\s*/.exec(s);
  return { prog: w?.[1] ?? "", rest: s.slice(w?.[0].length ?? 0) };
}

/** Windows' own programs that run whatever they are handed; what they are handed is the interesting part. */
const LOLBIN = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|conhost|explorer|msiexec|forfiles|cmstp|installutil|regasm|regsvcs|msbuild)$/;

const base = (p: string) => p.split(/[\\/]/).pop() ?? p;
const stem = (p: string) => base(p).toLowerCase().replace(/\.(exe|com)$/, "");

/** The executable a Windows command line really runs: the program, or the file a LOLBin is told to run or load. */
export function commandExe(cmd: string, home: string): { exe: string; via?: string } {
  const full = expandEnv(cmd, home);
  const { prog, rest } = program(full);
  if (LOLBIN.test(stem(prog))) {
    const target = FILE_IN.exec(rest)?.[0];
    if (target) return { exe: target, via: stem(prog) };
  }
  return { exe: prog };
}

const PS_HOST = /(^|[\\/\s"'&|(])(powershell|pwsh)(\.exe)?(?=[\s"']|$)/i;
// -e, -ec, -en, -enc … -EncodedCommand; not -ex (ExecutionPolicy) or -ep.
const PS_ENCODED = /\s[-/]e(c|n[a-z]*)?\s+\S/i;
const PS_FETCH = /\b(iex|invoke-expression|downloadstring|downloadfile|downloaddata|frombase64string|net\.webclient|invoke-webrequest|iwr|invoke-restmethod|irm|start-bitstransfer)\b/i;

/**
 * Why a login job's command line is dangerous, if it is: a LOLBin used the way malware uses it (risky), or a program
 * in a place software is not installed to (where).
 */
export function winLaunchRisk(cmd: string, home: string): { risky?: string; where?: string } {
  const full = expandEnv(cmd, home);
  if (PS_HOST.test(full) && PS_ENCODED.test(full)) return { risky: "runs PowerShell with an encoded command" };
  if (PS_HOST.test(full) && PS_FETCH.test(full)) return { risky: "runs PowerShell that downloads, decodes or evaluates code" };
  if (/(^|[\\/\s"'])mshta(\.exe)?["']?\s+["']?(https?:|javascript:|vbscript:|about:)/i.test(full)) return { risky: "runs mshta with a script from the web or inline" };
  if (/(^|[\\/\s"'])rundll32(\.exe)?["']?\s+["']?[^"]*javascript:/i.test(full)) return { risky: "runs inline script through rundll32" };
  if (/(^|[\\/\s"'])regsvr32(\.exe)?["']?\s.*(\/i:\s*["']?(https?:|\\\\)|scrobj\.dll)/i.test(full)) return { risky: "registers a remote scriptlet through regsvr32" };
  if (/(^|[\\/\s"'])certutil(\.exe)?["']?\s.*[-/](urlcache|decode|decodehex)\b/i.test(full) || /(^|[\\/\s"'])bitsadmin(\.exe)?["']?\s.*\/transfer\b/i.test(full))
    return { risky: "downloads or decodes a file with a Windows tool (certutil / bitsadmin)" };
  const { exe, via } = commandExe(full, home);
  if (!exe || !WIN_PATH.test(exe)) return {};
  const where = suspiciousLocation(exe, home);
  if (where) return { where: via ? `${where} (through ${via})` : where };
  // Script hosts and DLL loaders handed a file from AppData: how loaders hide in a profile.
  if (via && /^(wscript|cscript|mshta|rundll32|regsvr32)$/.test(via) && /[\\/]appdata[\\/]/i.test(exe)) return { risky: `starts ${via} with ${base(exe)} from AppData` };
  return {};
}

// ── items

/** The WMI subscription every Windows installs (Service Control Manager events into the event log). */
export function stockWmi(i: Item): boolean {
  const norm = (s: unknown) => str(s).toLowerCase().replace(/\s+/g, " ").trim();
  return i.name === "SCM Event Log Consumer" && i.meta?.type === "NTEventLogEventConsumer" && i.meta?.filterName === "SCM Event Log Filter"
    && norm(i.meta?.filter) === "select * from msft_scmeventlogevent";
}

/** A script file as text: PowerShell 5.1 writes UTF-16 (`>>`, Out-File), sometimes appended to a UTF-8 file. */
export function readScript(path: string, max = 1_000_000): string | undefined {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > max) return;
    const buf = readFileSync(path);
    if (buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString("utf16le");
    if (buf[0] === 0xfe && buf[1] === 0xff) return Buffer.from(buf.subarray(2)).swap16().toString("utf16le");
    const t = buf.toString("utf8").replace(/^\uFEFF/, "");
    // UTF-16 lines appended to a UTF-8 file read as letters with NULs between them.
    return t.includes("\u0000") ? t.replace(/\u0000/g, "") : t;
  } catch {
    return;
  }
}

export interface WinItems {
  items: Item[];
  texts: Record<string, string>;
  gaps: Record<string, string>;
}

/** Everything a snapshot shows, as items. Pure apart from reading the profile scripts and Startup files it names. */
export function windowsItems(snap: WinSnapshot, home: string, read: (path: string) => string | undefined = readScript): WinItems {
  const items: Item[] = [];
  const texts: Record<string, string> = {};
  const gaps: Record<string, string> = {};
  for (const [k, v] of Object.entries(snap.errors ?? {})) gaps[`Windows ${k}`] = str(v).slice(0, 300);
  // The rules read %TEMP% and ~\.hidden against the Windows home, which is the scan's own except for a fixture.
  const winHome = WIN_PATH.test(str(snap.home)) && str(snap.home) !== home ? str(snap.home) : undefined;
  const launch = (id: string, name: string, what: string, source: string, program: string, path?: string, extra = "") => {
    const i: Item = { kind: "launch", id, name, path, source, hash: sha256(program + extra), meta: { program: program.slice(0, 400), what, ...(winHome ? { home: winHome } : {}) } };
    items.push(i);
    return i;
  };

  for (const r of arr(snap.runKeys)) {
    const hive = str(r.hive).toUpperCase();
    const key = str(r.key);
    const name = str(r.name) || "(default)";
    const once = /RunOnce$/i.test(key) ? "RunOnce" : "Run";
    launch(`reg:${hive}\\${key}\\${name}`, name, `${hive} ${once}${/WOW6432Node/i.test(key) ? " (32-bit)" : ""} value`, hive === "HKCU" ? "user" : "system-agent", str(r.command), `${hive}\\${key}`);
  }
  for (const s of arr(snap.startup)) {
    const scope = str(s.scope) === "all" ? "all" : "user";
    const file = str(s.file);
    const path = str(s.path) || undefined;
    const lnk = /\.lnk$/i.test(file);
    const target = str(s.target);
    const program = lnk ? (target ? `"${target}" ${str(s.arguments)}`.trim() : file) : path ?? file;
    // A script dropped in the folder itself can change without its name changing.
    launch(`startup:${scope}\\${file}`, file, "startup folder entry", scope === "user" ? "user" : "system-agent", program, path, lnk || !path ? "" : fileHash(path) ?? "");
  }
  for (const t of arr(snap.tasks)) {
    const name = `${str(t.path)}${str(t.name)}`;
    const raw = unwrap(t.actions);
    const actions = (Array.isArray(raw) ? raw : raw != null ? [raw] : []).map(str).filter(Boolean);
    // The state is shown, not hashed: a task switched off and on again is the same task.
    launch(`task:${name}`, name, "scheduled task", "system-agent", actions.join(" ; ") || "(no action)").meta!.state = str(t.state) || undefined;
  }
  for (const s of arr(snap.services)) {
    const name = str(s.name);
    launch(`svc:${name}`, name, "service", "system-daemon", str(s.pathName), undefined, `|${str(s.startName)}`).meta!.display = str(s.displayName) || undefined;
  }

  const wmi = snap.wmi && typeof snap.wmi === "object" ? snap.wmi : {};
  const filters = arr(wmi.filters);
  const bindings = arr(wmi.bindings);
  for (const c of arr(wmi.consumers)) {
    const name = str(c.name);
    const type = str(c.class) || "__EventConsumer";
    const bound = new Set(bindings.filter((b) => str(b.consumer) === name).map((b) => str(b.filter)));
    const fs = filters.filter((f) => bound.has(str(f.name)));
    const command = str(c.commandLine) || str(c.executable) || str(c.scriptFile) || str(c.scriptText);
    items.push({
      kind: "wmi", id: `${type}:${name}`, name, source: type,
      hash: sha256(JSON.stringify({ type, command, script: str(c.scriptText), filters: fs.map((f) => [str(f.name), str(f.query)]) })),
      meta: {
        type, command: command.slice(0, 300) || undefined, bound: fs.length > 0,
        filter: fs.map((f) => str(f.query)).join(" ; ").slice(0, 300) || undefined, filterName: fs.map((f) => str(f.name)).join(", ") || undefined,
      },
    });
  }

  // PowerShell profiles run at every PowerShell start: the Windows counterpart of ~/.zshrc.
  const docs = str(snap.docs);
  const pshome = str(snap.pshome);
  const profiles = [
    ...(docs ? ["WindowsPowerShell", "PowerShell"].flatMap((d) => [join(docs, d, "profile.ps1"), join(docs, d, "Microsoft.PowerShell_profile.ps1")]) : []),
    ...(pshome ? [join(pshome, "profile.ps1"), join(pshome, "Microsoft.PowerShell_profile.ps1")] : []),
  ];
  if (!docs && !snap.errors?.docs && !snap.errors?.snapshot) gaps["Windows PowerShell profiles"] = "the Documents folder is unknown";
  for (const p of profiles) {
    const t = read(p);
    if (t === undefined) continue;
    items.push({ kind: "rc", id: p, name: p, path: p, hash: sha256(t), meta: { lines: t.split("\n").length } });
    texts[p] = t;
  }
  return { items, texts, gaps };
}

const LOOPBACK = /^(127\.|::1$|::ffff:127\.|0\.0\.0\.0$|::$)/;

/** What runs from an odd place right now, and which programs talk to other machines. */
export function winLive(snap: WinSnapshot, home: string): Item[] {
  if (WIN_PATH.test(str(snap.home))) home = str(snap.home);
  const out = new Map<string, Item>();
  const exeOf = new Map<number, string>();
  for (const p of arr(snap.processes)) {
    const exe = str(p.exe) || str(p.name);
    exeOf.set(Number(p.pid), exe);
    // Only this logon session: other users' and services' paths are not ours to judge (and mostly not readable).
    if (!p.mine || !WIN_PATH.test(exe)) continue;
    const where = suspiciousLocation(exe, home);
    if (where) out.set(`proc:${exe.toLowerCase()}`, { kind: "proc", id: exe, name: base(exe), path: exe, meta: { where, pid: Number(p.pid) } });
  }
  const remotes = new Map<string, Set<string>>();
  for (const c of arr(snap.connections)) {
    const addr = str(c.remote);
    if (!addr || LOOPBACK.test(addr)) continue;
    const exe = exeOf.get(Number(c.pid)) || `pid ${c.pid}`;
    if (!remotes.has(exe)) remotes.set(exe, new Set());
    remotes.get(exe)!.add(addr.includes(":") ? `[${addr}]:${c.port}` : `${addr}:${c.port}`);
  }
  for (const [exe, set] of remotes) {
    out.set(`conn:${exe.toLowerCase()}`, {
      kind: "conn", id: exe, name: base(exe), path: WIN_PATH.test(exe) ? exe : undefined,
      meta: { remotes: [...set].slice(0, 6).join(" "), count: set.size, where: WIN_PATH.test(exe) ? suspiciousLocation(exe, home) : undefined },
    });
  }
  return [...out.values()];
}

/** The scan's Windows part: nothing unless the context has a snapshot to give (Windows, or a test that injects one). */
export async function windows(ctx: Ctx): Promise<{ items: Item[]; texts: Record<string, string> }> {
  if (!ctx.win) return { items: [], texts: {} };
  const snap = await ctx.win();
  if (!snap) {
    ctx.gap?.("Windows snapshot", "PowerShell gave no answer");
    return { items: [], texts: {} };
  }
  const r = windowsItems(snap, ctx.home);
  for (const [k, v] of Object.entries(r.gaps)) ctx.gap?.(k, v);
  // vswarm's own blocks in a PowerShell profile (the install guard) are left out, as in ~/.zshrc.
  const texts: Record<string, string> = {};
  const onlyOurs = new Set<string>();
  for (const [p, t] of Object.entries(r.texts)) {
    texts[p] = stripManaged(t);
    // A profile vswarm created for the guard, with nothing else in it, is not a new profile.
    if (texts[p] !== t && !texts[p].trim()) (onlyOurs.add(p), delete texts[p]);
  }
  const items = r.items.filter((i) => !ownWatchTask(i) && !(i.kind === "rc" && onlyOurs.has(i.id))).map((i) => (i.kind === "rc" && texts[i.id] !== undefined ? { ...i, hash: sha256(texts[i.id]) } : i));
  return { items, texts };
}

/** vswarm's own background check (vswarm watch), with exactly the action vswarm registered. */
export function ownWatchTask(i: Item): boolean {
  return i.kind === "launch" && i.id === "task:\\vswarm\\watch" && isManagedFile(sha256(String(i.meta?.program ?? "")));
}

// ── containment, as commands to paste (phase 1 never changes a Windows machine by itself)

/** One literal word for PowerShell: single quotes, with PowerShell's four single-quote characters doubled. */
export function psq(s: string): string {
  return `'${s.replace(/['\u2018\u2019\u201a\u201b]/g, "$&$&")}'`;
}

/** How to stop one Windows item by hand, in PowerShell. Undefined for kinds that are not Windows-specific. */
export function winContainment(i: Item, quarantine: string): { what: string; manual: string }[] | undefined {
  const admin = (s: string) => `${s}   # from an administrator PowerShell`;
  if (i.kind === "launch" && i.id.startsWith("reg:")) {
    const hive = i.id.slice(4, 8);
    const key = (i.path ?? "").slice(5);
    const cmd = `Remove-ItemProperty -LiteralPath ${psq(`${hive}:\\${key}`)} -Name ${psq(i.name)}`;
    return [{ what: `remove the ${hive} ${key.split("\\").pop()} value ${i.name}`, manual: hive === "HKLM" ? admin(cmd) : cmd }];
  }
  if (i.kind === "launch" && i.id.startsWith("task:")) {
    const at = i.name.lastIndexOf("\\");
    return [{ what: `disable scheduled task ${i.name}`, manual: `Disable-ScheduledTask -TaskPath ${psq(i.name.slice(0, at + 1) || "\\")} -TaskName ${psq(i.name.slice(at + 1))}` }];
  }
  if (i.kind === "launch" && i.id.startsWith("svc:")) {
    return [{ what: `stop service ${i.name} and keep it from starting`, manual: admin(`Stop-Service -Name ${psq(i.name)} -Force; Set-Service -Name ${psq(i.name)} -StartupType Disabled`) }];
  }
  if (i.kind === "launch" && i.id.startsWith("startup:")) {
    const cmd = `New-Item -ItemType Directory -Force ${psq(quarantine)} | Out-Null; Move-Item -LiteralPath ${psq(i.path ?? i.name)} -Destination ${psq(quarantine)}`;
    return [{ what: `move startup entry ${i.name} to quarantine`, manual: i.source === "user" ? cmd : admin(cmd) }];
  }
  if (i.kind === "wmi") {
    const cls = /^\w+$/.test(String(i.meta?.type ?? "")) ? String(i.meta!.type) : "__EventConsumer";
    const ns = "-Namespace root\\subscription";
    return [{
      what: `remove WMI subscription ${i.name} (the consumer and its bindings)`,
      manual: admin(`Get-CimInstance ${ns} -ClassName __FilterToConsumerBinding | Where-Object { $_.Consumer.Name -eq ${psq(i.name)} } | Remove-CimInstance; `
        + `Get-CimInstance ${ns} -ClassName ${cls} | Where-Object { $_.Name -eq ${psq(i.name)} } | Remove-CimInstance`),
    }];
  }
  if ((i.kind === "proc" || i.kind === "conn" || i.kind === "bin") && i.path) {
    const move = `New-Item -ItemType Directory -Force ${psq(quarantine)} | Out-Null; Move-Item -LiteralPath ${psq(i.path)} -Destination ${psq(quarantine)}`;
    return [
      ...(i.kind !== "bin" && i.meta?.pid ? [{ what: `stop process ${i.meta.pid} (${i.name})`, manual: `Stop-Process -Id ${Number(i.meta.pid)} -Force` }] : []),
      { what: `move ${i.path} to quarantine`, manual: move },
    ];
  }
  if ((i.kind === "rc" || i.kind === "ssh" || i.kind === "cron" || i.kind === "hosts") && i.path) {
    return [{ what: `remove the added lines from ${i.path} (they are listed above)`, manual: `notepad ${psq(i.path)}` }];
  }
  if (i.kind === "npm") return [{ what: `uninstall global npm package ${i.name}`, manual: i.source === "bun-global" ? `bun remove -g ${psq(i.name)}` : `npm uninstall -g ${psq(i.name)}` }];
  if (i.kind === "pip") return [{ what: `uninstall Python package ${i.name}`, manual: `python -m pip uninstall ${psq(i.name)}` }];
  if (i.kind === "mcp" || i.kind === "agent-hook") return [{ what: `remove ${i.name} from ${i.source}`, manual: `notepad ${psq(i.path ?? "")}` }];
}
