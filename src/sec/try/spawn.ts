// One sandboxed process with pipes, for when vswarm itself has to run something it does not trust (an MCP server it
// inspects). Same walls as `vswarm try`: no home, keychain or clipboard, a fake HOME, network only through the
// recording proxy. The caller talks to it over stdin/stdout and calls stop() when done.

import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { TRY_DIR, type Net } from "./index";
import { bwrapArgs, FORWARDER, freshProc, inner, INNER_PORT, NO_FRESH_PROC } from "./linux";
import { allowedBy, startProxy, type ProxyHit } from "./proxy";
import { cleanEnv, listeningPorts, profile, toolchains, type Box } from "./sandbox";

export interface Sandboxed {
  proc: ReturnType<typeof Bun.spawn<"pipe", "pipe", "pipe">>;
  hits: ProxyHit[];
  box: Box;
  stop(): void;
}

export function canSandbox(): boolean {
  return process.platform === "darwin" ? Bun.file("/usr/bin/sandbox-exec").size > 0 : process.platform === "linux" && !!Bun.which("bwrap");
}

/**
 * Folders in your home that the command itself lives in (`node ~/mcp/weather/dist/index.js`): the project around each
 * such path, read-only, so the server can load its own code. Nothing else of your home becomes visible.
 */
export function ownCode(cmd: string[], home = homedir()): string[] {
  const out = new Set<string>();
  for (const a of cmd) {
    const p = a.replace(/^~(?=\/)/, home);
    if (!p.startsWith(home + "/") || !existsSync(p)) continue;
    let dir = statSync(p).isDirectory() ? p : dirname(p);
    for (let d = dir; d.startsWith(home + "/"); d = dirname(d))
      if (["package.json", "pyproject.toml", "setup.py", "go.mod", "Cargo.toml", ".git"].some((m) => existsSync(join(d, m)))) {
        dir = d;
        break;
      }
    out.add(dir);
  }
  return [...out];
}

export async function sandboxSpawn(cmd: string[], opt: { net: Net; env?: Record<string, string> }): Promise<Sandboxed> {
  mkdirSync(TRY_DIR(), { recursive: true, mode: 0o700 });
  const dir = realpathSync(mkdtempSync(join(TRY_DIR(), "inspect-")));
  const box: Box = { dir, work: join(dir, "work"), home: join(dir, "home"), tmp: join(dir, "tmp"), netlog: join(dir, "tmp", "netlog.jsonl") };
  for (const d of [box.work, box.home, box.tmp]) mkdirSync(d, { recursive: true, mode: 0o700 });
  const linux = process.platform === "linux";
  const own = ownCode(cmd);
  const proxy = startProxy(allowedBy(opt.net), linux ? { unix: join(box.tmp, "proxy.sock") } : {});
  let argv: string[];
  if (linux) {
    writeFileSync(join(box.tmp, "forwarder.js"), FORWARDER);
    if (!(await freshProc(Bun.which("bwrap")!))) {
      proxy.stop();
      rmSync(dir, { recursive: true, force: true });
      throw new Error(NO_FRESH_PROC);
    }
    argv = [Bun.which("bwrap")!, ...bwrapArgs(homedir(), box, { tools: [...toolchains(homedir()), ...own], bun: process.execPath, interactive: false }), "--", ...inner(box, process.execPath, cmd)];
  } else {
    const sb = join(dir, "sandbox.sb");
    // An MCP server under inspection gets no local databases or Docker API either (Linux: its own network namespace).
    writeFileSync(sb, profile(homedir(), box, proxy.port, own, await listeningPorts()));
    argv = ["/usr/bin/sandbox-exec", "-f", sb, ...cmd];
  }
  const env = { ...cleanEnv(box, linux ? INNER_PORT : proxy.port, homedir()), ...opt.env };
  const proc = Bun.spawn(argv, { cwd: box.work, env, stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  return {
    proc, hits: proxy.hits, box,
    stop() {
      try {
        proc.kill(9);
      } catch {}
      proxy.stop();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** The sandbox walls for an install in a folder of yours: that folder writable, its .git read-only. */
export function projectWalls(cwd: string): { dir: string; readOnly: string[] } {
  const dir = realpathSync(cwd);
  return { dir, readOnly: [join(dir, ".git")].filter((p) => existsSync(p)) };
}

/**
 * Runs a command in the sandbox on your terminal, inside a real folder of yours (an install guarded with
 * `guard on --sandbox`): that folder is writable except its .git, the rest of your home is out of sight, the network
 * is the package registries only. Returns the exit code and the hosts it was refused.
 */
export async function sandboxRun(cmd: string[], opt: { cwd: string; env?: Record<string, string>; extraRead?: string[]; extraHosts?: string[] }): Promise<{ code: number; refused: string[] }> {
  mkdirSync(TRY_DIR(), { recursive: true, mode: 0o700 });
  const dir = realpathSync(mkdtempSync(join(TRY_DIR(), "install-")));
  const box: Box = { dir, work: join(dir, "work"), home: join(dir, "home"), tmp: join(dir, "tmp"), netlog: join(dir, "tmp", "netlog.jsonl") };
  for (const d of [box.work, box.home, box.tmp]) mkdirSync(d, { recursive: true, mode: 0o700 });
  const project = projectWalls(opt.cwd);
  const linux = process.platform === "linux";
  const registries = allowedBy("registries");
  const extra = opt.extraHosts ?? [];
  const proxy = startProxy((h) => registries(h) || extra.some((x) => h === x || h.endsWith("." + x)), linux ? { unix: join(box.tmp, "proxy.sock") } : {});
  const home = homedir();
  const extraRead = (opt.extraRead ?? []).filter((d) => d.startsWith(home + "/"));
  let argv: string[];
  if (linux) {
    writeFileSync(join(box.tmp, "forwarder.js"), FORWARDER);
    if (!(await freshProc(Bun.which("bwrap")!))) throw new Error(NO_FRESH_PROC);
    argv = [Bun.which("bwrap")!, ...bwrapArgs(home, box, { tools: [...toolchains(home), ...extraRead], bun: process.execPath, interactive: true, project }), "--", ...inner(box, process.execPath, cmd)];
  } else {
    const sb = join(dir, "sandbox.sb");
    writeFileSync(sb, profile(home, box, proxy.port, extraRead, await listeningPorts(), project));
    argv = ["/usr/bin/sandbox-exec", "-f", sb, ...cmd];
  }
  try {
    const p = Bun.spawn(argv, { cwd: project.dir, env: { ...cleanEnv(box, linux ? INNER_PORT : proxy.port, homedir()), ...opt.env }, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
    const code = await p.exited;
    return { code, refused: [...new Set(proxy.hits.filter((h) => !h.allowed).map((h) => h.host))] };
  } finally {
    proxy.stop();
    rmSync(dir, { recursive: true, force: true });
  }
}
