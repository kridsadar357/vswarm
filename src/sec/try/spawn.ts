// One sandboxed process with pipes, for when vswarm itself has to run something it does not trust (an MCP server it
// inspects). Same walls as `vswarm try`: no home, keychain or clipboard, a fake HOME, network only through the
// recording proxy. The caller talks to it over stdin/stdout and calls stop() when done.

import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { TRY_DIR, type Net } from "./index";
import { bwrapArgs, FORWARDER, freshProc, inner, INNER_PORT } from "./linux";
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
    const hostProc = !(await freshProc(Bun.which("bwrap")!));
    argv = [Bun.which("bwrap")!, ...bwrapArgs(homedir(), box, { tools: [...toolchains(homedir()), ...own], bun: process.execPath, interactive: false, hostProc }), "--", ...inner(box, process.execPath, cmd)];
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
