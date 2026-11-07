// The real-time watch: what launchd and systemd are told to watch, which part of the scan a change wakes, that a
// burst of writes is one check, that vswarm's own writes raise nothing, and how long a planted LaunchAgent takes to
// reach a notification. Nothing is loaded into launchd or systemd: the job files are checked as text (and with
// plutil -lint where it exists), and fs.watch stands in for launchd's own file watching. Every path is a temp folder.
import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, watch, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { jobFiles, markSeen, partsFor, watchPaths, watchQuick, watchState, watchTable } from "../src/sec/schedule";
import { forBaseline, scan } from "../src/sec/scan";
import { files, recordManagedFile, saveBaseline, SEC } from "../src/sec/store";
import { plist } from "../src/sec/selftest-cases";
import type { Ctx } from "../src/sec/ctx";

const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-watch-${tag}-`));
const put = (p: string, t: string) => (mkdirSync(dirname(p), { recursive: true }), writeFileSync(p, t));
const ctxFor = (home: string): Ctx => ({ home, pathDirs: [join(home, ".local/bin")], system: false, host: "t", user: "t", run: async () => undefined });

/** A fake home with its state folder, a baseline of it, and the test's body run with VSWARM_SEC_DIR pointing there. */
async function withHome<T>(fn: (home: string, ctx: Ctx) => Promise<T>): Promise<T> {
  const root = tmp("root");
  const home = join(root, "home");
  const prev = process.env.VSWARM_SEC_DIR;
  process.env.VSWARM_SEC_DIR = join(root, "sec");
  try {
    put(join(home, ".zshrc"), "alias ll='ls -la'\n");
    for (const d of ["Library/LaunchAgents", ".config/systemd/user"]) mkdirSync(join(home, d), { recursive: true });
    mkdirSync(join(home, ".local/bin"), { recursive: true });
    const ctx = ctxFor(home);
    await saveBaseline(forBaseline(await scan(ctx, { live: false })));
    // What `watch on` does once: remember the watched paths as they are.
    markSeen(home);
    return await fn(home, ctx);
  } finally {
    if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
    else process.env.VSWARM_SEC_DIR = prev;
  }
}

describe("real-time watch: job files", () => {
  test("macOS: the hourly job and a WatchPaths job, both under the home, watching what exists and never vswarm's own folder", () => {
    const home = tmp("mac");
    put(join(home, ".zshrc"), "x\n");
    put(join(home, ".ssh/config"), "Host *\n");
    put(join(home, ".cursor/mcp.json"), "{}");
    for (const d of ["Library/LaunchAgents", ".config/systemd/user"]) mkdirSync(join(home, d), { recursive: true });
    const jf = jobFiles("/Users/a&b/.vswarm/bin/vswarm", 60, home, "darwin");
    const [hourly, paths] = Object.keys(jf);
    expect(hourly).toBe(join(home, "Library/LaunchAgents/dev.vswarm.watch.plist"));
    expect(paths).toBe(join(home, "Library/LaunchAgents/dev.vswarm.watch.paths.plist"));
    const text = jf[paths];
    expect(text).toContain("<string>/Users/a&amp;b/.vswarm/bin/vswarm</string><string>watch</string><string>quick</string>");
    expect(text).toContain("<key>ThrottleInterval</key><integer>10</integer>");
    expect(text).not.toContain("RunAtLoad");
    const watched = [...text.matchAll(/^  <string>([^<]+)<\/string>$/gm)].map((m) => m[1]);
    expect(watched).toEqual(expect.arrayContaining([join(home, ".zshrc"), join(home, ".ssh"), join(home, ".ssh/config"), join(home, ".cursor/mcp.json"), join(home, "Library/LaunchAgents")]));
    // Only what exists: launchd cannot watch a path that is not there.
    expect(watched.every((p) => existsSync(p))).toBe(true);
    expect(watched.some((p) => p.includes(".vswarm") || p.startsWith(SEC()))).toBe(false);
    expect(jf[hourly]).toContain("<key>StartInterval</key><integer>3600</integer>");
  });

  test.skipIf(!existsSync("/usr/bin/plutil"))("macOS: both plists pass plutil -lint", () => {
    const home = tmp("lint");
    put(join(home, ".zshrc"), "x\n");
    const dir = tmp("plists");
    for (const [p, text] of Object.entries(jobFiles("/Users/a b/<x>/vswarm", 15, home, "darwin"))) {
      const f = join(dir, p.split("/").pop()!);
      writeFileSync(f, text);
      const r = Bun.spawnSync(["/usr/bin/plutil", "-lint", f]);
      expect([f, r.exitCode, r.stdout.toString().trim()]).toEqual([f, 0, `${f}: OK`]);
    }
  });

  test("Linux: timer and path unit, every watched path listed (systemd waits for missing ones), % escaped, the quick service named", () => {
    const home = tmp("linux") + "/50%";
    mkdirSync(home, { recursive: true });
    const jf = jobFiles("/home/a b/.vswarm/bin/vswarm", 60, home, "linux");
    // join(), so the expectations use this system's separator like the job files do.
    expect(Object.keys(jf)).toEqual(["vswarm-watch.service", "vswarm-watch.timer", "vswarm-watch-quick.service", "vswarm-watch.path"].map((f) => join(home, ".config/systemd/user", f)));
    const path = jf[join(home, ".config/systemd/user/vswarm-watch.path")];
    expect(path).toContain("Unit=vswarm-watch-quick.service");
    expect(path).toContain("WantedBy=default.target");
    expect(path).toContain(`PathModified=${join(home, ".zshrc").replace("%", "%%")}\n`);
    expect(path).toContain(`PathModified=${join(home, ".config/systemd/user").replace("%", "%%")}\n`);
    expect(path).not.toContain("Library/");
    expect(jf[join(home, ".config/systemd/user/vswarm-watch-quick.service")]).toContain('ExecStart="/home/a b/.vswarm/bin/vswarm" watch quick');
  });

  test("Windows: the scheduled task only; Task Scheduler has no trigger for a changed file", () => {
    const jf = jobFiles("C:\\Users\\nok\\.vswarm\\bin\\vswarm.cmd", 60, "C:\\Users\\nok", "win32");
    expect(Object.keys(jf)).toEqual([join(SEC(), "watch-task.xml")]);
    expect(Object.values(jf)[0]).toContain("<TimeTrigger>");
  });

  test("a changed path wakes only the part of the scan that reads it", () => {
    const h = "/Users/a";
    expect(partsFor([`${h}/Library/LaunchAgents/com.x.plist`], h, "darwin")).toEqual(["launchd"]);
    expect(partsFor([`${h}/.zshrc`, `${h}/.ssh/authorized_keys`], h, "darwin")).toEqual(["startup files"]);
    expect(partsFor([`${h}/.cursor/mcp.json`], h, "darwin")).toEqual(["AI agents and MCP"]);
    expect(partsFor([`${h}/.config/pip/pip.conf`], h, "darwin")).toEqual(["package manager and session config"]);
    expect(partsFor([`${h}/.vscode/extensions/x.y-1.0.0`], h, "darwin")).toEqual(["editor extensions"]);
    expect(partsFor(["/home/a/.config/systemd/user/x.service"], "/home/a", "linux")).toEqual(["systemd and autostart"]);
    expect(partsFor([`${h}/Downloads/x`], h, "darwin")).toEqual([]);
    // Every part named here is one the scan knows (it refuses unknown ones).
    for (const t of watchTable(h, "darwin").concat(watchTable("/home/a", "linux"))) expect(() => scan(ctxFor(tmp("p")), { only: [t.part], live: false })).not.toThrow();
  });

  test("a part the scan does not have is refused, not silently skipped", async () => {
    await expect(scan(ctxFor(tmp("x")), { only: ["launch agents"] })).rejects.toThrow("no such part");
  });
});

// The login-job folder of this system: a LaunchAgent on macOS, a systemd user service on Linux.
const MAC = process.platform === "darwin";
const OS = MAC ? "darwin" : "linux";
const JOBS = MAC ? "Library/LaunchAgents" : ".config/systemd/user";
const JOB_PART = MAC ? "launchd" : "systemd and autostart";
const job = (home: string, name: string) =>
  MAC ? put(join(home, JOBS, `${name}.plist`), plist(name, join(home, ".cache/.n", name))) : put(join(home, JOBS, `${name}.service`), `[Service]\nExecStart=%h/.cache/.n/${name}\n`);

// Windows has no real-time watch (Task Scheduler cannot trigger on a file); its scheduled task is tested in windows.test.ts.
describe.skipIf(process.platform === "win32")("real-time watch: the quick check", () => {
  test("a planted login job reaches a notification within seconds; only that part of the scan is read; the gate's cached verdict is not touched", async () => {
    await withHome(async (home, ctx) => {
      const agents = join(home, JOBS);
      const told: { at: number; title: string; body: string }[] = [];
      let quick: Promise<unknown> | undefined;
      // fs.watch stands in for launchd's WatchPaths (both are kqueue / FSEvents underneath on macOS, inotify on Linux).
      const trigger = () => (quick ??= watchQuick({ ctx, debounceMs: 300, notify: async (title, body) => void told.push({ at: Date.now(), title, body }) }));
      const w = watch(agents, trigger);
      const t0 = Date.now();
      job(home, "com.apple.updater.helper");
      // fs.watch in a long test run sometimes gives no event; then the trigger comes from here, a second late.
      for (let i = 0; i < 20 && !quick; i++) await Bun.sleep(50);
      if (!quick) (console.log("fs.watch gave no event; triggered directly"), trigger());
      for (let i = 0; i < 100 && !told.length; i++) await Bun.sleep(50);
      w.close();
      await quick;
      expect(told.length).toBe(1);
      expect(told[0].title).toBe("vswarm: production access blocked");
      expect(told[0].body).toContain("com.apple.updater.helper");
      const ms = told[0].at - t0;
      console.log(`planted login job → notification: ${ms} ms (300 ms debounce here; the job's own is 1500 ms, and launchd or systemd adds its start-up)`);
      expect(ms).toBeLessThan(5000);
      expect(watchState().state?.quick?.parts).toEqual([JOB_PART]);
      expect(existsSync(files.last())).toBe(false);
    });
  }, 20_000);

  test("a burst of writes is one check and one notification; a second trigger during it is covered, not run twice", async () => {
    await withHome(async (home, ctx) => {
      const told: string[] = [];
      const runs: Promise<{ ran: boolean }>[] = [];
      const tell = async (_t: string, body: string) => void told.push(body);
      runs.push(watchQuick({ ctx, debounceMs: 400, notify: tell }));
      for (let i = 0; i < 5; i++) {
        job(home, `com.burst.${i}`);
        runs.push(watchQuick({ ctx, debounceMs: 400, notify: tell }));
        await Bun.sleep(20);
      }
      const r = await Promise.all(runs);
      expect(r.filter((x) => x.ran).length).toBe(1);
      expect(told.length).toBe(1);
      expect(told[0]).toContain("(+");
    });
  }, 20_000);

  test("vswarm's own writes raise nothing: its job files and its managed block in ~/.zshrc", async () => {
    await withHome(async (home, ctx) => {
      for (const [p, text] of Object.entries(jobFiles(join(home, ".vswarm/bin/vswarm"), 60, home, OS))) (put(p, text), recordManagedFile(text));
      const block = "# >>> vswarm path >>>\nexport PATH=\"$HOME/.vswarm/bin:$PATH\"\n# <<< vswarm path <<<\n";
      const { recordManaged } = await import("../src/sec/store");
      recordManaged(block);
      writeFileSync(join(home, ".zshrc"), readFileSync(join(home, ".zshrc"), "utf8") + block);
      const told: string[] = [];
      const r = await watchQuick({ ctx, debounceMs: 0, notify: async (_t, b) => void told.push(b) });
      expect(r.ran).toBe(true);
      expect(r.parts.sort()).toEqual([JOB_PART, "startup files"].sort());
      expect(told).toEqual([]);
    });
  }, 20_000);

  test("watched paths and the state folder never overlap, so the check's own state writes cannot trigger it", () => {
    for (const os of ["darwin", "linux"] as const) for (const p of watchPaths("/Users/a", os)) expect([p, p.startsWith(SEC())]).toEqual([p, false]);
  });
});
