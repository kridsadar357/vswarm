// `vswarm try <folder | git URL | archive | file> [-- command]`
// Runs code you do not trust (an interview "assignment", a repo from a stranger, an installer) in a sandbox, then
// reports what it tried. Your original files are never touched: the code runs on a copy.

import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { HOME } from "../../home";
import { run } from "../ctx";
import { c, finding as printFinding, line } from "../print";
import { RANK, verdictOf, type Finding, type Verdict } from "../types";
import { allowedBy, startProxy } from "./proxy";
import { bwrapArgs, FORWARDER, freshProc, inner, INNER_PORT, traceDenials } from "./linux";
import { cleanEnv, profile, toolchains, type Box } from "./sandbox";
import { staticCheck } from "./static";
import { behaviour, denials, network, plantedFiles } from "./watch";

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
    cpSync(p, box.work, { recursive: true, filter: (src) => !src.includes("/node_modules/") || !src.endsWith("/.bin") });
    return `folder ${p}`;
  }
  if (/\.(zip)$/i.test(p)) {
    if ((await run(["ditto", "-x", "-k", p, box.work], 300_000)) === undefined && (await run(["unzip", "-q", p, "-d", box.work], 300_000)) === undefined) throw new Error("could not unpack the zip");
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

export async function tryIt(source: string, command: string[], opt: { net: Net; ask: (q: string) => Promise<boolean>; yes?: boolean; quiet?: boolean }): Promise<TryResult> {
  const linux = process.platform === "linux";
  const bwrap = linux ? Bun.which("bwrap") : undefined;
  const strace = linux ? Bun.which("strace") ?? undefined : undefined;
  if (linux && !bwrap) throw new Error("vswarm try on Linux needs bubblewrap: sudo apt install bubblewrap strace  (dnf/pacman: bubblewrap strace)");
  if (!linux && (process.platform !== "darwin" || !existsSync("/usr/bin/sandbox-exec"))) throw new Error("vswarm try needs macOS (sandbox-exec) or Linux (bubblewrap)");
  const name = basename(source.replace(/\.git$/, "").replace(/\/+$/, "")) || "code";
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
  const sh = [process.env.SHELL, "/bin/zsh", "/bin/bash", "/bin/sh"].find((x) => x && existsSync(x))!;
  const cmd = shell ? [sh, "-i"] : command;
  const serious = staticFindings.some((f) => RANK[f.severity] >= RANK.high);
  line(`\n${c.bold("2  run in the sandbox")} ${c.dim(`· network: ${opt.net === "none" ? "blocked (attempts recorded)" : opt.net === "registries" ? "package registries only" : "open, every host recorded"} · no access to your home, keychain or clipboard`)}`);
  if (serious && !opt.yes && !(await opt.ask(`  ${c.red("This code has red flags above.")} Run it in the sandbox to see what it does?`))) {
    line(c.dim("  not run · the copy stays in " + box.work));
    return { box, source: what, command: cmd, exit: null, staticFindings, runFindings: [], verdict: verdictOf(staticFindings), leftovers: [], logRead: false };
  }
  if (shell) line(c.dim(`  a shell opens inside the sandbox in work/ · try the code (npm install, npm test, python main.py …) · type exit when done`));
  const proxy = startProxy(allowedBy(opt.net), linux ? { unix: join(box.tmp, "proxy.sock") } : {});
  let argv: string[];
  if (linux) {
    writeFileSync(join(box.tmp, "forwarder.js"), FORWARDER);
    const hostProc = !(await freshProc(bwrap!));
    if (hostProc) line(c.dim("  · this system does not allow a private /proc (a container?); the sandbox sees the host's /proc read-only"));
    argv = [bwrap!, ...bwrapArgs(homedir(), box, { tools: toolchains(homedir()), bun: process.execPath, interactive: shell, hostProc }), "--", ...inner(box, process.execPath, cmd, strace)];
    writeFileSync(join(dir, "sandbox.json"), JSON.stringify(argv, null, 1) + "\n");
  } else {
    const profilePath = join(dir, "sandbox.sb");
    writeFileSync(profilePath, profile(homedir(), box, proxy.port));
    argv = ["/usr/bin/sandbox-exec", "-f", profilePath, ...cmd];
  }
  const t0 = Date.now();
  const tree = { pids: new Set<number>(), names: new Set<string>() };
  const p = Bun.spawn(argv, {
    cwd: box.work,
    env: cleanEnv(box, linux ? INNER_PORT : proxy.port, homedir()),
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  // Follow the run's process tree, so daemons it starts are known even after they detach.
  tree.pids.add(p.pid);
  // Linux: the pid namespace ends everything with the sandbox, and strace sees every process; no polling needed.
  let polling = !linux;
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
  await Bun.sleep(300);
  polling = false;
  await poll;

  // 3 · what it tried
  line(`\n${c.bold("3  what it tried")} ${c.dim(linux ? (strace ? "· reading the strace log …" : "") : "· reading the sandbox log …")}`);
  const left = linux ? [] : await leftovers(p.pid, box, tree.pids);
  if (left.length) {
    line(`  ${c.amber("!")} ${left.length} process${left.length > 1 ? "es" : ""} still running after it exited (it started something in the background)`);
    for (const l of left.slice(0, 5)) line(`      ${c.dim(`${l.pid} ${l.command.slice(0, 120)}`)}`);
    if (opt.yes || (await opt.ask("  Stop them?"))) for (const l of left) await run(["kill", "-9", String(l.pid)]);
  }
  if (!linux) await Bun.sleep(1500); // the log is written a moment after the denials
  const d = linux ? (strace ? traceDenials(join(box.tmp, "trace.log"), homedir(), box) : undefined) : await denials(t0, p.pid, tree);
  proxy.stop();
  const planted = plantedFiles(box.home, new Set(Object.keys(SEED)), SEED);
  const net = network(proxy.hits, box.netlog);
  const runFindings = behaviour(d, planted, net, homedir());
  if (left.length) runFindings.push({ id: "try:leftover", rule: "try-run", severity: "medium", title: `Left ${left.length} process${left.length > 1 ? "es" : ""} running in the background`, detail: left.slice(0, 5).map((l) => `${l.pid} ${l.command.slice(0, 120)}`) });
  // A run that failed early may simply not have reached the bad part; never call that clean.
  const failed = exit !== 0 && exit !== null;
  if (failed) {
    runFindings.push({ id: "try:exit", rule: "try-run", severity: "low", title: `The command exited with code ${exit}`,
      detail: ["A run that fails early may not reach the code that misbehaves; check the output above and try again (e.g. after npm install)."] });
  }
  if (!runFindings.length) line(`  ${c.green("✔")} nothing suspicious: no reads of your secrets, no planted files, no outside connections`);
  for (const f of runFindings.sort((a, b) => RANK[b.severity] - RANK[a.severity])) printFinding({ ...f, id: "" }, true);
  if (d === undefined) line(c.dim(linux ? "  · strace is not installed, so file and connection attempts are not included: sudo apt install strace" : "  · could not read the macOS sandbox log; file and keychain attempts are not included"));
  if (linux && exit !== 0 && /* bwrap's own failure, before the code ran */ !existsSync(join(box.tmp, "forwarder.ready")))
    line(c.amber("  ! the sandbox did not start (see bwrap's message above). \"Permission denied\" or \"No permissions to create new namespace\" means this kernel limits user namespaces (Ubuntu 24.04: sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0, or an AppArmor profile for bwrap); in Docker, run the container with --security-opt seccomp=unconfined --security-opt apparmor=unconfined."));

  const all = [...staticFindings, ...runFindings];
  const verdict = verdictOf(all);
  const result: TryResult = { box, source: what, command: cmd, exit, staticFindings, runFindings, verdict, leftovers: left.map((l) => `${l.pid} ${l.command}`), logRead: d !== undefined };
  writeTryReport(result);
  const label = verdict === "block" ? c.red(c.bold("DANGEROUS")) : verdict === "warn" ? c.amber(c.bold("SUSPICIOUS")) : failed ? c.amber(c.bold("INCONCLUSIVE")) : c.green(c.bold("NOTHING SEEN"));
  line(`\n${label} ${c.dim(verdict === "block" ? "· do not run this outside the sandbox; report it (see report.md)" : verdict === "warn" ? "· read the findings before running it for real" : "· in this run, under these conditions; it is not a guarantee")}`);
  line(c.dim(`  report ${join(dir, "report.md")} · copy ${box.work} · remove: vswarm try --clean`));
  return result;
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
    try {
      const j = JSON.parse(readFileSync(join(TRY_DIR(), id, "report.json"), "utf8"));
      return { id, verdict: j.verdict, source: j.source };
    } catch {
      return { id };
    }
  });
}

export function cleanTries(id?: string) {
  if (!existsSync(TRY_DIR())) return 0;
  const ids = id ? [id] : readdirSync(TRY_DIR());
  for (const x of ids) rmSync(join(TRY_DIR(), x), { recursive: true, force: true });
  return ids.length;
}
