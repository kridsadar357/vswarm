// The Linux sandbox for `vswarm try`: bubblewrap for the walls, strace for what the code tried against them.
//   files    the system read-only; your home (and every other home) replaced by an empty folder, except toolchains
//            read-only and the try's own folder; /run hidden (Docker, D-Bus, keyring and agent sockets live there)
//   network  a private network namespace: nothing gets out except through the vswarm proxy, reached via a unix
//            socket and a small forwarder inside the sandbox
//   process  its own pid namespace: anything it leaves running ends with the sandbox
// strace (optional) records every path it tried to open and every address it tried to connect to, which is what
// the macOS sandbox log gives on a Mac.

import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { exec, shq } from "../ctx";
import type { Box } from "./sandbox";
import type { Denial } from "./watch";

/** Port the forwarder listens on inside the sandbox's own network namespace. */
export const INNER_PORT = 3128;

/** Inside the sandbox: 127.0.0.1:INNER_PORT → the proxy's unix socket outside. Plain bytes, no parsing. */
export const FORWARDER = `const [port, sock, ready] = process.argv.slice(2);
Bun.listen({ hostname: "127.0.0.1", port: Number(port), socket: {
  open(c) { c.data = { q: [], up: null };
    Bun.connect({ unix: sock, socket: {
      open(u) { u.data = c; c.data.up = u; for (const b of c.data.q) u.write(b); c.data.q = []; },
      data(u, d) { u.data.write(d); }, close(u) { u.data.end(); }, error(u) { u.data && u.data.end(); },
    } }).catch(() => c.end()); },
  data(c, d) { if (c.data.up) c.data.up.write(d); else c.data.q.push(Buffer.from(d)); },
  close(c) { if (c.data.up) c.data.up.end(); }, error() {},
} });
require("fs").writeFileSync(ready, "1");
`;

/**
 * Whether bwrap can mount a fresh /proc. Inside Docker it usually cannot (Docker masks parts of /proc); the
 * sandbox then shows the host's /proc read-only, which still keeps its pid namespace.
 */
export async function freshProc(bwrap: string): Promise<boolean> {
  return (await exec([bwrap, "--unshare-pid", "--unshare-net", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"])).code === 0;
}

export function bwrapArgs(realHome: string, box: Box, opt: { tools: string[]; bun: string; interactive: boolean; hostProc?: boolean }): string[] {
  const a = ["--die-with-parent", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try", "--unshare-net", "--hostname", "vswarm-try",
    "--ro-bind", "/", "/", "--dev", "/dev", ...(opt.hostProc ? ["--ro-bind", "/proc", "/proc"] : ["--proc", "/proc"]), "--tmpfs", "/tmp", "--tmpfs", "/var/tmp"];
  // Every home folder, then the real one in case it lives elsewhere.
  for (const h of ["/home", "/root", "/Users", "/run", "/mnt", "/media"]) if (existsSync(h)) a.push("--tmpfs", h);
  if (![ "/home", "/root"].some((h) => realHome.startsWith(h + "/") || realHome === h)) a.push("--tmpfs", realHome);
  for (const t of opt.tools) a.push("--ro-bind", t, t);
  // bun runs the forwarder; it may live in the home that was just hidden.
  const bunDir = dirname(opt.bun);
  if (bunDir.startsWith(realHome + "/") && !opt.tools.some((t) => bunDir.startsWith(t))) a.push("--ro-bind", bunDir, bunDir);
  a.push("--bind", box.dir, box.dir, "--chdir", box.work);
  // A new session stops TIOCSTI keystroke injection into your terminal; an interactive shell needs the terminal.
  if (!opt.interactive) a.push("--new-session");
  return a;
}

/**
 * The command bwrap runs: start the forwarder, wait until it listens, run the code (under strace when present), and
 * finish as soon as the code itself exits. strace would otherwise wait for every process the code left running in
 * the background; those end with the sandbox's pid namespace instead. strace gets TERM first so its log is complete.
 */
export function inner(box: Box, bun: string, command: string[], strace?: string): string[] {
  const t = (f: string) => shq(join(box.tmp, f));
  const trace = strace ? `${shq(strace)} -f -qq -I 1 -s 300 -e trace=%file,connect,setsid -e signal=none -o ${t("trace.log")} --` : "";
  const script = [
    `"$0" ${t("forwarder.js")} ${INNER_PORT} ${t("proxy.sock")} ${t("forwarder.ready")} &`,
    `i=0; while [ ! -e ${t("forwarder.ready")} ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done`,
    // A background job gets /dev/null as stdin; fd 3 keeps the terminal for an interactive shell.
    `exec 3<&0`,
    // The exit file is the inner shell's $0, so its path never has to sit inside the quoted script.
    `${trace} /bin/sh -c '"$@"; echo $? > "$0"' ${t("exit")} "$@" <&3 & S=$!`,
    `while [ ! -e ${t("exit")} ] && kill -0 $S 2>/dev/null; do sleep 0.1; done`,
    `sleep 0.2; kill -TERM $S 2>/dev/null; wait $S 2>/dev/null`,
    `exit $(cat ${t("exit")} 2>/dev/null || echo 1)`,
  ].join("\n");
  return ["/bin/sh", "-c", script, bun, ...command];
}

/** In the fake home, only what nothing but a thief reads. */
const FAKE_HOME_LOOT = /^\/\.ssh\/id_|^\/\.ssh\/.*\.pem$|^\/\.aws\/credentials$|^\/\.config\/(google-chrome|chromium|BraveSoftware|microsoft-edge)\/|^\/\.mozilla\/|^\/\.config\/(Exodus|Electrum|atomic)\/|^\/\.electrum\/|^\/\.local\/share\/keyrings\/|^\/\.gnupg\/private|^\/\.(bash|zsh)_history$|^\/Library\/(Keychains|Application Support\/(Google|BraveSoftware|Exodus))/;

/** What the run tried, from strace's log, in the same shape as the macOS sandbox log. */
export function traceDenials(log: string, realHome: string, box: Box): Denial[] {
  let text = "";
  try {
    text = readFileSync(log, "utf8");
  } catch {
    return [];
  }
  const names = new Map<number, string>();
  const out: Denial[] = [];
  const seen = new Set<string>();
  const add = (d: Denial) => {
    const k = `${d.op} ${d.target}`;
    if (!seen.has(k)) (seen.add(k), out.push(d));
  };
  for (const l of text.split("\n")) {
    const m = /^(\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?/.exec(l);
    if (!m) continue;
    const [, pidS, call, args, ret, errno] = m;
    const pid = Number(pidS);
    const proc = names.get(pid) ?? "?";
    if (call === "execve" || call === "execveat") {
      const p = /"([^"]+)"/.exec(args)?.[1];
      if (p && ret === "0") names.set(pid, basename(p));
      continue;
    }
    if (call === "setsid") {
      if (ret !== "-1") add({ proc, pid, op: "setsid", target: proc });
      continue;
    }
    if (call === "connect") {
      const ip = /sin6?_addr=inet_(?:addr|pton)\((?:AF_INET6, )?"([^"]+)"/.exec(args)?.[1];
      const port = /sin6?_port=htons\((\d+)\)/.exec(args)?.[1];
      const unix = /sun_path=@?"([^"]+)"/.exec(args)?.[1];
      if (ip && !/^(127\.|::1$|::ffff:127\.)/.test(ip)) add({ proc, pid, op: "network-outbound", target: `${ip}:${port}` });
      else if (unix && !unix.startsWith(box.dir)) add({ proc, pid, op: "unix-connect", target: unix });
      continue;
    }
    // The first quoted argument is the path for every %file call strace prints.
    const path = /"([^"]*)"/.exec(args)?.[1];
    if (!path || !path.startsWith("/")) continue;
    if (path.startsWith(box.home + "/")) {
      // The code cannot tell the home is fake: going for keys, cloud credentials, browser or wallet data there is the
      // same intent. Config files every tool reads (.npmrc, .netrc, .ssh/config, .gitconfig) are left out.
      const rel = path.slice(box.home.length);
      if (/^\/(open|openat|openat2|access|faccessat2?|stat|lstat|newfstatat|statx)$/.test("/" + call) && FAKE_HOME_LOOT.test(rel))
        add({ proc: `${proc}, via $HOME`, pid, op: "file-read", target: realHome + rel });
      continue;
    }
    if (path.startsWith(box.dir)) continue;
    const writes = /^(mkdir|mkdirat|unlink|unlinkat|rename|renameat2?|creat|symlink|symlinkat|link|linkat|chmod|fchmodat|chown|truncate|utimensat)$/.test(call) ||
      (/^open/.test(call) && /O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)/.test(args));
    if (writes) {
      // Opening a file that is not there, without creating it, is a lookup (tools walk up looking for package.json).
      const probe = ret === "-1" && errno === "ENOENT" && !/O_CREAT/.test(args) && /^open/.test(call);
      // The hidden home is an empty, writable tmpfs: a write there succeeds and vanishes, so it counts either way.
      // Elsewhere the system is read-only, and only a refused write means anything; /tmp, /dev, /proc, /sys are private or noise.
      const inHome = path.startsWith(realHome + "/");
      if (!probe && (inHome || (ret === "-1" && !/^\/(tmp|var\/tmp|dev|proc|sys)\//.test(path)))) add({ proc, pid, op: "file-write", target: path });
      continue;
    }
    // A program that looks for your keys by their real path, not through $HOME, is looking past the fake home.
    if (path.startsWith(realHome + "/") && /^(open|openat|openat2|access|faccessat2?|stat|lstat|newfstatat|statx)$/.test(call)) add({ proc, pid, op: "file-read", target: path });
  }
  // A process usually detaches (setsid) before it runs its program; name it by what it ran next.
  for (const d of out) if (d.op === "setsid" && d.proc === "?") d.proc = d.target = names.get(d.pid) ?? "?";
  return out;
}
