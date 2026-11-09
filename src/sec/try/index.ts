// `vswarm try <folder | git URL | archive | file> [-- command]`
// Runs code you do not trust (an interview "assignment", a repo from a stranger, an installer) in a sandbox, then
// reports what it tried. Your original files are never touched: the code runs on a copy.

import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { HOME } from "../../home";
import { readJson, run } from "../ctx";
import { c, finding as printFinding, line, verdictMark } from "../print";
import { RANK, verdictOf, type Finding, type Verdict } from "../types";
import { allowedBy, startProxy } from "./proxy";
import { bwrapArgs, FORWARDER, freshProc, inner, INNER_PORT, NO_FRESH_PROC, traceDenials } from "./linux";
import { cleanEnv, listeningPorts, profile, toolchains, type Box } from "./sandbox";
import { staticCheck } from "./static";
import { behaviour, denials, network, plantedFiles } from "./watch";
import { containerSid, grantBox, grantToolchains, loopbackExempt, PROFILE, revokeBox, winCommandLine, winEnv, winToolchains } from "./windows";

export const TRY_DIR = () => process.env.VSWARM_TRY_DIR ?? join(HOME, "try");
export type Net = "none" | "registries" | "all";

export interface TryResult {
  box: Box;
  source: string;
  command: string[];
  exit: number | null;
  staticFindings: Finding[];
  runFindings: Finding[];
  verdict: Verdict;
  leftovers: string[];
  logRead: boolean;
}

function stamp() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

const isGitUrl = (s: string) => /^(https?:\/\/|git@|ssh:\/\/|git:\/\/)/.test(s) || /^github\.com\//.test(s);

/** Puts a copy of the code in the box. Downloading and unpacking happen outside the sandbox but run no code. */
export async function prepare(source: string, box: Box): Promise<string> {
  mkdirSync(box.work, { recursive: true, mode: 0o700 });
  if (isGitUrl(source)) {
    const url = source.startsWith("github.com/") ? `https://${source}` : source;
    // No hooks, no submodules, no LFS filters: a clone must not run anything.
    const out = await run(["git", "-c", "core.hooksPath=/dev/null", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
      "clone", "--depth", "1", "--no-recurse-submodules", url, box.work], 300_000);
    if (out === undefined) throw new Error(`git clone failed for ${url}`);
    return `git ${url}`;
  }
  const p = resolve(source);
  if (!existsSync(p)) throw new Error(`not found: ${source}`);
  const st = statSync(p);
  if (st.isDirectory()) {
    cpSync(p, box.work, { recursive: true, filter: (src) => !/[\\/]node_modules[\\/]/.test(src) || !/[\\/]\.bin$/.test(src) });
    return `folder ${p}`;
  }
  if (/\.(zip)$/i.test(p)) {
    // Windows: its own tar (bsdtar) reads zip.
    const unpacked = process.platform === "win32"
      ? (await run(["tar", "-xf", p, "-C", box.work], 300_000)) !== undefined
      : (await run(["ditto", "-x", "-k", p, box.work], 300_000)) !== undefined || (await run(["unzip", "-q", p, "-d", box.work], 300_000)) !== undefined;
    if (!unpacked) throw new Error("could not unpack the zip");
    return `zip ${p}`;
  }
  if (/\.(tar|tgz|tar\.gz|tar\.bz2|tar\.xz)$/i.test(p)) {
    if ((await run(["tar", "-xf", p, "-C", box.work], 300_000)) === undefined) throw new Error("could not unpack the archive");
    return `archive ${p}`;
  }
  cpSync(p, join(box.work, basename(p)));
  return `file ${p}`;
}

const SEED: Record<string, string> = {
  ".zshrc": `PS1='%F{magenta}(vswarm try)%f %1~ %# '\n`,
  ".bashrc": `PS1='(vswarm try) \\W \\$ '\n`,
  ".gitconfig": `[user]\n\tname = vswarm try\n\temail = try@localhost\n`,
};

function seedHome(home: string) {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  for (const [rel, text] of Object.entries(SEED)) writeFileSync(join(home, rel), text);
}

/** A fresh box under the try folder (`<prefix>XXXXXX`): an empty work/, a seeded fake home, tmp/. The caller removes it. */
export function makeBox(prefix: string): Box {
  mkdirSync(TRY_DIR(), { recursive: true, mode: 0o700 });
  // Real paths: the sandbox matches /private/var, not /var.
  const dir = realpathSync(mkdtempSync(join(TRY_DIR(), prefix)));
  const box: Box = { dir, work: join(dir, "work"), home: join(dir, "home"), tmp: join(dir, "tmp"), netlog: join(dir, "tmp", "netlog.jsonl") };
  for (const d of [box.work, box.tmp]) mkdirSync(d, { recursive: true, mode: 0o700 });
  seedHome(box.home);
  return box;
}

/** Windows: what the launcher found still in the job when the command ended (it stopped them). */
function winLeftovers(file: string): { pid: number; command: string }[] {
  return (readJson<{ left: { pid: number; image: string }[] }>(file)?.left ?? []).map((l) => ({ pid: l.pid, command: l.image || "(program not readable)" }));
}

/** Processes the run left behind (daemons it started). They stay sandboxed, but should not linger. */
async function leftovers(rootPid: number, box: Box, seen: Set<number>): Promise<{ pid: number; command: string }[]> {
  const ps = await run(["ps", "-axww", "-o", "pid=,ppid=,command="], 10_000);
  const rows = (ps ?? "").split("\n").map((l) => /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(l)).filter(Boolean).map((m) => ({ pid: Number(m![1]), ppid: Number(m![2]), command: m![3] }));
  const kids = new Set<number>([rootPid]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const r of rows) if (!kids.has(r.pid) && kids.has(r.ppid)) (kids.add(r.pid), (grew = true));
  }
  return rows.filter((r) => r.pid !== process.pid && r.pid !== rootPid && (kids.has(r.pid) || seen.has(r.pid) || r.command.includes(box.dir)));
}

/** Windows, a network beyond none: the sandbox's loopback exemption, asked for once (an administrator approves it). */
async function windowsLoopback(opt: { ask: (q: string) => Promise<boolean>; yes?: boolean }) {
  const { askLoopbackExempt, exemptCommand } = await import("./windows");
  const sid = containerSid();
  if (await loopbackExempt(sid)) return;
  line(`${c.amber("!")} On Windows the sandbox reaches the network only through vswarm's proxy on this computer, and Windows lets it do that only after an administrator allows it, once.`);
  line(c.dim("  With it, the code can also reach services listening on this computer's localhost. Without it, use --net none."));
  if (!opt.yes && !(await opt.ask("  Ask Windows for that approval now?"))) throw new Error(`not run: the sandbox has no network on this computer yet · allow it in an administrator terminal: ${exemptCommand(sid)} · or run with --net none`);
  if (!(await askLoopbackExempt(sid))) throw new Error(`Windows did not allow it · in an administrator terminal: ${exemptCommand(sid)} · or run with --net none`);
  line(`  ${c.green("✔")} the sandbox may reach vswarm's proxy on this computer`);
}

export async function tryIt(source: string, command: string[], opt: { net: Net; ask: (q: string) => Promise<boolean>; yes?: boolean; quiet?: boolean; localhost?: boolean }): Promise<TryResult> {
  const linux = process.platform === "linux";
  const win = process.platform === "win32";
  const bwrap = linux ? Bun.which("bwrap") : undefined;
  const strace = linux ? Bun.which("strace") ?? undefined : undefined;
  if (linux && !bwrap) throw new Error("vswarm try on Linux needs bubblewrap: sudo apt install bubblewrap strace  (dnf/pacman: bubblewrap strace)");
  if (!linux && !win && (process.platform !== "darwin" || !existsSync("/usr/bin/sandbox-exec"))) throw new Error("vswarm try needs macOS (sandbox-exec), Linux (bubblewrap) or Windows");
  // Windows: the network beyond none goes through vswarm's proxy on loopback, which an AppContainer reaches only with
  // an exemption, given once by an administrator. Asked here, before anything is copied.
  if (win && opt.net !== "none") await windowsLoopback(opt);
  // `vswarm try .` names the folder after the project, not after the dot.
  const name = basename(isGitUrl(source) ? source.replace(/\.git$/, "").replace(/\/+$/, "") : resolve(source)) || "code";
  const want = join(TRY_DIR(), `${stamp()}-${name.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 40)}`);
  mkdirSync(want, { recursive: true, mode: 0o700 });
  // The sandbox matches real paths (/var → /private/var); a symlinked path would lock the code out of its own folder.
  const dir = realpathSync(want);
  const box: Box = { dir, work: join(dir, "work"), home: join(dir, "home"), tmp: join(dir, "tmp"), netlog: join(dir, "tmp", "netlog.jsonl") };
  mkdirSync(box.tmp, { recursive: true, mode: 0o700 });
  seedHome(box.home);

  line(`${c.violet("▼ vswarm try")} ${c.dim(`· ${dir}`)}`);
  const what = await prepare(source, box);
  line(`  ${c.green("✔")} copied ${what} ${c.dim("→ work/ (your original is not touched)")}`);

  // 1 · read before running
  const staticFindings = staticCheck(box.work);
  line(`\n${c.bold("1  before running")} ${c.dim("· what in this code is set up to run on its own")}`);
  if (!staticFindings.length) line(`  ${c.green("✔")} nothing that runs on its own or looks like a hidden loader`);
  for (const f of staticFindings.sort((a, b) => RANK[b.severity] - RANK[a.severity]).slice(0, 15)) printFinding({ ...f, id: "" }, false);
  if (staticFindings.length > 15) line(c.dim(`  … ${staticFindings.length - 15} more in the report`));

  // 2 · run in the sandbox
  const shell = command.length === 0;
  const sh = win ? process.env.ComSpec ?? "C:\\Windows\\System32\\cmd.exe" : [process.env.SHELL, "/bin/zsh", "/bin/bash", "/bin/sh"].find((x) => x && existsSync(x))!;
  const cmd = shell ? (win ? [sh] : [sh, "-i"]) : command;
  const serious = staticFindings.some((f) => RANK[f.severity] >= RANK.high);
  const netSay = opt.net === "none" ? (win ? "blocked (Windows does not record the attempts)" : "blocked (attempts recorded)") : opt.net === "registries" ? "package registries only" : "open, every host recorded";
  const hostSay = win ? (opt.net !== "none" ? " · services on this computer's localhost are reachable too (Windows has no per-port rule for the sandbox)" : "")
    : opt.localhost ? (linux ? " · your localhost reachable through the proxy only, HTTP and HTTPS (--localhost; the sandbox has its own network)" : " · your localhost services reachable (--localhost)") : "";
  line(`\n${c.bold("2  run in the sandbox")} ${c.dim(`· network: ${netSay}${hostSay} · no access to your ${win ? "profile, other programs or the clipboard" : "home, keychain or clipboard"}`)}`);
  if (serious && !opt.yes && !(await opt.ask(`  ${c.red("This code has red flags above.")} Run it in the sandbox to see what it does?`))) {
    line(c.dim("  not run · the copy stays in " + box.work));
    return { box, source: what, command: cmd, exit: null, staticFindings, runFindings: [], verdict: verdictOf(staticFindings), leftovers: [], logRead: false };
  }
  // What the AppContainer cannot give Node: named pipes, which child_process talks to its children through.
  if (win) line(c.dim("  · on Windows a program that starts others through pipes (npm install scripts, most Node build tools) fails in this sandbox; to see what those do, run vswarm try inside WSL"));
  if (shell) line(c.dim(win
    ? "  a command prompt opens in a window of its own, inside the sandbox in work\\ (never in this terminal, which it could type into) · try the code there · type exit when done"
    : "  a shell opens inside the sandbox in work/ · try the code (npm install, npm test, python main.py …) · type exit when done"));
  const o = await observe(box, cmd, {
    net: opt.net, localhost: opt.localhost, interactive: shell, say: line,
    onRunEnd: () => line(`\n${c.bold("3  what it tried")} ${c.dim(win ? "" : linux ? (strace ? "· reading the strace log …" : "") : "· reading the sandbox log …")}`),
    onLeftovers: async (left) => {
      line(`  ${c.amber("!")} ${left.length} process${left.length > 1 ? "es" : ""} still running after it exited (it started something in the background)`);
      for (const l of left.slice(0, 5)) line(`      ${c.dim(`${l.pid} ${l.command.slice(0, 120)}`)}`);
      return opt.yes || (await opt.ask("  Stop them?"));
    },
  });
  const { exit, left, runFindings } = o;
  // A run that failed early may simply not have reached the bad part; never call that clean.
  const failed = exit !== 0 && exit !== null;
  if (!runFindings.length) line(`  ${c.green("✔")} nothing suspicious: no reads of your secrets, no planted files, no outside connections`);
  for (const f of runFindings.sort((a, b) => RANK[b.severity] - RANK[a.severity])) printFinding({ ...f, id: "" }, true);
  if (!o.logRead) line(c.dim(win ? "  · Windows keeps no record of what the sandbox refused: reads of your files were blocked, but are not listed" : linux ? "  · strace is not installed, so file and connection attempts are not included: sudo apt install strace" : "  · could not read the macOS sandbox log; file and keychain attempts are not included"));
  if (linux && exit !== 0 && /* bwrap's own failure, before the code ran */ !existsSync(join(box.tmp, "forwarder.ready")))
    line(c.amber("  ! the sandbox did not start (see bwrap's message above). \"Permission denied\" or \"No permissions to create new namespace\" means this kernel limits user namespaces (Ubuntu 24.04: sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0, or an AppArmor profile for bwrap); in Docker, run the container with --security-opt seccomp=unconfined --security-opt apparmor=unconfined."));

  if (win && failed) line(c.amber("  ! on Windows this may be the sandbox, not the code: a program that starts others through pipes fails here. For the full picture: vswarm try inside WSL"));

  const all = [...staticFindings, ...runFindings];
  const verdict = verdictOf(all);
  const result: TryResult = { box, source: what, command: cmd, exit, staticFindings, runFindings, verdict, leftovers: left.map((l) => `${l.pid} ${l.command}`), logRead: o.logRead };
  writeTryReport(result);
  // The one vocabulary (Safe, Check this, Stop) with try's own word as the tag; a run that failed early is Check this.
  const label = verdictMark(failed && verdict === "pass" ? "warn" : verdict, verdict === "block" ? "DANGEROUS" : verdict === "warn" ? "SUSPICIOUS" : failed ? "INCONCLUSIVE" : "NOTHING SEEN");
  line(`\n${label} ${c.dim(verdict === "block" ? "· do not run this outside the sandbox; report it (see report.md)" : verdict === "warn" ? "· read the findings before running it for real" : "· in this run, under these conditions; it is not a guarantee")}`);
  line(c.dim(`  report ${join(dir, "report.md")} · copy ${box.work} · remove: vswarm try --clean`));
  return result;
}

export interface Observed {
  exit: number | null;
  runFindings: Finding[];
  left: { pid: number; command: string }[];
  /** The sandbox log (macOS) or the strace log (Linux) was read, so file and keychain attempts are included. */
  logRead: boolean;
  /** The end of what the command printed, when it was not shown on the terminal. */
  output: string;
  timedOut: boolean;
}

/** Credentials seeded into the fake home, so code that goes looking for keys is seen looking. None of them is real. */
export const DECOYS: Record<string, string> = {
  ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nvswarm decoy, not a key\n-----END OPENSSH PRIVATE KEY-----\n",
  ".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\nvswarm decoy, not a key\n-----END OPENSSH PRIVATE KEY-----\n",
  ".aws/credentials": "[default]\naws_access_key_id = VSWARMDECOYNOTAKEY00\naws_secret_access_key = vswarm-decoy-not-a-secret\n",
};

/**
 * Runs a command in box.work under the try sandbox and turns what it tried into findings: files it reached for, hosts
 * it contacted, processes it left behind, files it planted in the fake home. `interactive` hands it the terminal (the
 * shell of `vswarm try`); otherwise it gets no input, its output is kept, it has a time limit, and what it leaves
 * running is stopped. `decoys` seeds fake credentials into the fake home; on macOS reading them is denied and logged.
 */
export async function observe(box: Box, cmd: string[], opt: {
  net: Net; localhost?: boolean; interactive?: boolean; env?: Record<string, string>; timeoutMs?: number; decoys?: boolean;
  say?: (t: string) => void; onRunEnd?: () => void; onLeftovers?: (left: { pid: number; command: string }[]) => Promise<boolean>;
}): Promise<Observed> {
  const linux = process.platform === "linux";
  const win = process.platform === "win32";
  const bwrap = linux ? Bun.which("bwrap") ?? undefined : undefined;
  const strace = linux ? Bun.which("strace") ?? undefined : undefined;
  if (linux && !bwrap) throw new Error("the sandbox on Linux needs bubblewrap: sudo apt install bubblewrap strace  (dnf/pacman: bubblewrap strace)");
  if (!linux && !win && (process.platform !== "darwin" || !existsSync("/usr/bin/sandbox-exec"))) throw new Error("the sandbox needs macOS (sandbox-exec), Linux (bubblewrap) or Windows");
  const decoys = opt.decoys ? Object.keys(DECOYS) : [];
  for (const rel of decoys) {
    mkdirSync(join(box.home, rel, ".."), { recursive: true, mode: 0o700 });
    writeFileSync(join(box.home, rel), DECOYS[rel], { mode: 0o600 });
  }
  const proxy = startProxy(allowedBy(opt.net), { ...(linux ? { unix: join(box.tmp, "proxy.sock") } : {}), localhost: opt.localhost });
  let argv: string[];
  let sid: string | undefined;
  if (win) {
    // The launcher (winbox.ts) starts the command in the AppContainer and waits; see windows.ts for what it may do.
    sid = containerSid();
    if (opt.net !== "none" && !(await loopbackExempt(sid))) {
      proxy.stop();
      throw new Error("the sandbox has no network on this computer yet (it needs a loopback exemption): vswarm try asks for it, or use --net none");
    }
    // The command line first: one that cmd.exe would misread is refused before anything is opened to the sandbox.
    let cmdline: string;
    try {
      cmdline = winCommandLine(cmd);
    } catch (e) {
      proxy.stop();
      throw e;
    }
    await grantToolchains(sid, winToolchains(homedir()), join(TRY_DIR(), "acl.json"), homedir());
    for (const d of [join(box.home, "AppData", "Roaming"), join(box.home, "AppData", "Local")]) mkdirSync(d, { recursive: true });
    await grantBox(box.dir, sid);
    try {
      const spec = { profile: PROFILE, cmdline, cwd: box.work, interactive: !!opt.interactive, env: { ...winEnv(box, opt.net === "none" ? undefined : proxy.port), ...opt.env }, result: join(box.tmp, "winbox-result.json") };
      writeFileSync(join(box.tmp, "winbox.json"), JSON.stringify(spec, null, 1) + "\n");
      writeFileSync(join(box.dir, "sandbox.json"), JSON.stringify(spec, null, 1) + "\n");
    } catch (e) {
      await revokeBox(box.dir, sid);
      proxy.stop();
      throw e;
    }
    argv = [process.execPath, join(import.meta.dir, "winbox.ts"), join(box.tmp, "winbox.json")];
  } else if (linux) {
    writeFileSync(join(box.tmp, "forwarder.js"), FORWARDER);
    if (!(await freshProc(bwrap!))) {
      proxy.stop();
      throw new Error(`the sandbox did not start: ${NO_FRESH_PROC}`);
    }
    argv = [bwrap!, ...bwrapArgs(homedir(), box, { tools: toolchains(homedir()), bun: process.execPath, interactive: !!opt.interactive }), "--", ...inner(box, process.execPath, cmd, strace)];
    writeFileSync(join(box.dir, "sandbox.json"), JSON.stringify(argv, null, 1) + "\n");
  } else {
    // Services already listening on this machine (databases, the Docker API, dev servers) are denied one by one;
    // --localhost keeps them reachable. Linux needs nothing here: bubblewrap gives the sandbox its own network namespace.
    const hidden = opt.localhost ? [] : await listeningPorts();
    const profilePath = join(box.dir, "sandbox.sb");
    writeFileSync(profilePath, profile(homedir(), box, proxy.port, [], hidden, undefined, decoys.map((d) => join(box.home, d))));
    argv = ["/usr/bin/sandbox-exec", "-f", profilePath, ...cmd];
  }
  const t0 = Date.now();
  const tree = { pids: new Set<number>(), names: new Set<string>() };
  const io = opt.interactive ? "inherit" : "pipe";
  let p: ReturnType<typeof Bun.spawn>;
  try {
    p = Bun.spawn(argv, {
      cwd: box.work,
      // Windows: the environment is the launcher's (vswarm's own); the code's is in the spec.
      env: win ? process.env : { ...cleanEnv(box, linux ? INNER_PORT : proxy.port, homedir()), ...opt.env },
      stdin: opt.interactive ? "inherit" : "ignore",
      stdout: io,
      stderr: io,
    });
  } catch (e) {
    // The box is never left open to the sandbox after a run that did not start.
    if (win) await revokeBox(box.dir, sid!);
    proxy.stop();
    throw e;
  }
  let timedOut = false;
  const timer = opt.timeoutMs ? setTimeout(() => ((timedOut = true), p.kill(9)), opt.timeoutMs) : undefined;
  const output = opt.interactive ? Promise.resolve("")
    : Promise.all([new Response(p.stdout as ReadableStream).text(), new Response(p.stderr as ReadableStream).text()]).then(([a, b]) => (a + b).slice(-4000)).catch(() => "");
  // Follow the run's process tree, so daemons it starts are known even after they detach.
  tree.pids.add(p.pid);
  // Linux: the pid namespace ends everything with the sandbox, and strace sees every process; Windows: the job object
  // holds every process the code starts. No polling needed on either.
  let polling = !linux && !win;
  const poll = (async () => {
    while (polling) {
      const ps = await run(["ps", "-axo", "pid=,ppid=,comm="], 5000);
      for (const l of (ps ?? "").split("\n")) {
        const m = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(l);
        if (m && tree.pids.has(Number(m[2])) && Number(m[1]) !== process.pid) {
          tree.pids.add(Number(m[1]));
          tree.names.add(m[3].split("/").pop()!.slice(0, 32));
        }
      }
      await Bun.sleep(150);
    }
  })();
  const exit = await p.exited;
  clearTimeout(timer);
  await Bun.sleep(300);
  polling = false;
  await poll;
  opt.onRunEnd?.();

  // Windows: the launcher listed what the job still held, and stopped it.
  const left = win ? winLeftovers(join(box.tmp, "winbox-result.json")) : linux ? [] : await leftovers(p.pid, box, tree.pids);
  if (!win && left.length && (!opt.onLeftovers || (await opt.onLeftovers(left)))) for (const l of left) await run(["kill", "-9", String(l.pid)]);
  if (win) await revokeBox(box.dir, sid!);
  if (!linux && !win) await Bun.sleep(1500); // the log is written a moment after the denials
  let d = win ? undefined : linux ? (strace ? traceDenials(join(box.tmp, "trace.log"), homedir(), box) : undefined) : await denials(t0, p.pid, tree);
  // A decoy read in the fake home is a read of your key, as far as the code could tell.
  if (!linux && d) d = d.map((x) => (x.target.startsWith(box.home + "/") ? { ...x, proc: `${x.proc}, via $HOME`, target: homedir() + x.target.slice(box.home.length) } : x));
  proxy.stop();
  const seeded = { ...SEED, ...Object.fromEntries(decoys.map((k) => [k, DECOYS[k]])) };
  const planted = plantedFiles(box.home, new Set(Object.keys(seeded)), seeded);
  const net = network(proxy.hits, box.netlog);
  const runFindings = behaviour(d, planted, net, homedir());
  if (left.length) runFindings.push({ id: "try:leftover", rule: "try-run", severity: "medium", title: `Left ${left.length} process${left.length > 1 ? "es" : ""} running in the background${win ? " (stopped)" : ""}`, detail: left.slice(0, 5).map((l) => `${l.pid} ${l.command.slice(0, 120)}`) });
  if (timedOut) runFindings.push({ id: "try:timeout", rule: "try-run", severity: "low", title: `Stopped after ${Math.round(opt.timeoutMs! / 1000)} seconds`, detail: ["It was still running; what it would have done later is not included."] });
  // A run that failed early may simply not have reached the bad part; never call that clean.
  else if (exit !== 0) {
    runFindings.push({ id: "try:exit", rule: "try-run", severity: "low", title: `The command exited with code ${exit}`,
      detail: ["A run that fails early may not reach the code that misbehaves; check the output above and try again (e.g. after npm install)."] });
  }
  return { exit: timedOut ? null : exit, runFindings, left, logRead: d !== undefined, output: await output, timedOut };
}

export function writeTryReport(r: TryResult) {
  const sec = (title: string, fs: Finding[]) => [
    `## ${title}`, "",
    ...(fs.length ? fs.flatMap((f) => [`- **${f.severity.toUpperCase()}** ${f.title}`, ...f.detail.map((d) => `  - ${d}`)]) : ["- nothing found"]), "",
  ];
  const md = [
    `# vswarm try · ${basename(r.box.dir)}`, "",
    `| | |`, `|---|---|`,
    `| Source | ${r.source} |`,
    `| Command | \`${r.command.join(" ")}\` |`,
    `| Exit code | ${r.exit ?? "not run"} |`,
    `| Verdict | ${r.verdict === "block" ? "DANGEROUS" : r.verdict === "warn" ? "SUSPICIOUS" : "nothing seen"} |`,
    `| Sandbox log read | ${r.logRead ? "yes" : "no (file and keychain attempts missing)"} |`, "",
    ...sec("Before running", r.staticFindings),
    ...sec("While running", r.runFindings),
    "## If this came from a job interview or a stranger", "",
    "- Do not run it outside the sandbox.",
    "- Report the account to the platform it came from (LinkedIn, the job site, GitHub: https://github.com/contact/report-abuse).",
    "- If you already ran it on your machine: `vswarm scan`, then `vswarm respond`.", "",
  ].join("\n");
  writeFileSync(join(r.box.dir, "report.md"), md, { mode: 0o600 });
  writeFileSync(join(r.box.dir, "report.json"), JSON.stringify(r, null, 2), { mode: 0o600 });
}

export function listTries(): { id: string; verdict?: string; source?: string }[] {
  if (!existsSync(TRY_DIR())) return [];
  return readdirSync(TRY_DIR()).sort().map((id) => {
    const j = readJson(join(TRY_DIR(), id, "report.json"));
    return { id, verdict: j?.verdict, source: j?.source };
  });
}

export function cleanTries(id?: string) {
  if (!existsSync(TRY_DIR())) return 0;
  // Only a name from --list: `--clean ..` must not remove the folder above.
  if (id !== undefined && (!/^[A-Za-z0-9._-]+$/.test(id) || id.startsWith(".") || !existsSync(join(TRY_DIR(), id)))) throw new Error(`no try ${id} · vswarm try --list`);
  const ids = id ? [id] : readdirSync(TRY_DIR());
  for (const x of ids) rmSync(join(TRY_DIR(), x), { recursive: true, force: true });
  return ids.length;
}
