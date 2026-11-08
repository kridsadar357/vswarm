// Are the hosts behind vswarm's gate and agent still there? For each host the blocks name one by one (no wildcard),
// a DNS lookup and a TCP connection to its ssh port, 2 seconds each, all at once. Only `vswarm doctor` and
// `vswarm gate status` ask, and `gate ssh --prune` / `agent prune`; never preflight, never a scan: these are network
// connections to your own hosts, made when you ask about them. Nothing is sent: the connection is closed once open.

import { lookup } from "node:dns/promises";
import { connect, isIP } from "node:net";
import { c, line } from "./print";
import { hostView, literal } from "./sshconfig";

export interface Probe {
  host: string;
  /** What was resolved and reached: the HostName and Port ~/.ssh/config gives the host, else the host on 22. */
  target: string;
  port: number;
  addresses: string[];
  dns?: string;
  tcp: "open" | "refused" | "timeout" | "skipped";
  ms: number;
}

export interface ProbeDeps {
  timeoutMs?: number;
  resolve?: (name: string) => Promise<string[]>;
  connect?: (ip: string, port: number, timeoutMs: number) => Promise<"open" | "refused" | "timeout">;
}

const within = <T>(p: Promise<T>, ms: number, late: T) => Promise.race([p, new Promise<T>((done) => setTimeout(() => done(late), ms).unref?.())]);

async function realResolve(name: string): Promise<string[]> {
  return (await lookup(name, { all: true })).map((a) => a.address);
}

/** A connection that is closed as soon as it opens, and given up (closed, not left pending) at the time limit. */
function realConnect(ip: string, port: number, timeoutMs: number): Promise<"open" | "refused" | "timeout"> {
  return new Promise((done) => {
    const s = connect({ host: ip, port });
    s.unref();
    const end = (v: "open" | "refused" | "timeout") => {
      clearTimeout(t);
      s.destroy();
      done(v);
    };
    const t = setTimeout(() => end("timeout"), timeoutMs);
    s.once("connect", () => end("open"));
    s.once("error", () => end("refused"));
  });
}

export async function probeHost(host: string, opt: { hostname?: string; port?: number } & ProbeDeps = {}): Promise<Probe> {
  const t0 = Date.now();
  const ms = opt.timeoutMs ?? 2000;
  const target = opt.hostname ?? host;
  const port = opt.port ?? 22;
  const p: Probe = { host, target, port, addresses: [], tcp: "skipped", ms: 0 };
  if (isIP(target)) p.addresses = [target];
  else {
    const r: { a?: string[]; e?: string } = await within((opt.resolve ?? realResolve)(target).then((a) => ({ a }), (e: any) => ({ e: String(e?.code ?? e?.message ?? e) })), ms, { e: `no DNS answer in ${ms / 1000} s` });
    if (r.e) p.dns = r.e === "ENOTFOUND" ? "no such name (DNS)" : r.e;
    else p.addresses = r.a ?? [];
  }
  if (p.addresses.length) p.tcp = await within((opt.connect ?? realConnect)(p.addresses[0], port, ms), ms + 100, "timeout");
  p.ms = Date.now() - t0;
  return p;
}

/** Whether a probe found nothing listening: no name, or no answer on the port. */
export const dead = (p: Probe) => !!p.dns || p.tcp === "refused" || p.tcp === "timeout";

export const probeText = (p: Probe) =>
  p.dns ? `${p.target}: ${p.dns}` : p.tcp === "open" ? `${p.target}:${p.port} answers` : `${p.target}:${p.port} ${p.tcp === "timeout" ? "does not answer in 2 s" : "refuses the connection"}`;

/** The hosts the blocks name one by one, each probed at the address ~/.ssh/config gives it; all at once. */
export function probeAll(hosts: string[], cfgText: string, deps: ProbeDeps = {}): Promise<Probe[]> {
  const one = [...new Set(hosts.filter(literal))];
  return Promise.all(one.map((h) => {
    const v = hostView(cfgText, h, { withoutOwn: true });
    return probeHost(h, { hostname: v.hostname, port: v.port, ...deps });
  }));
}

/** When the agent last signed a login to each host (the audit log names it since 2.8), in days; undefined: never seen. */
export function lastUsed(hosts: string[], entries: { at: number; event: string; reason?: string }[]): Record<string, number | undefined> {
  const out: Record<string, number | undefined> = {};
  for (const h of hosts) {
    const re = new RegExp(`ssh login as \\S+ to ${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}( |$)`);
    const at = entries.filter((e) => e.event === "sign" && re.test(e.reason ?? "")).at(-1)?.at;
    out[h] = at === undefined ? undefined : Math.floor((Date.now() - at) / 86_400_000);
  }
  return out;
}

/**
 * The hosts to keep: every host is probed, the ones that do not answer are offered for removal one by one, and the
 * ones you confirm are left out. Undefined when nothing changes. Patterns (prod-*) are never offered.
 */
export async function pruneHosts(hosts: string[], opt: { cfgText: string; ask: (q: string, def?: boolean) => Promise<boolean>; what: "gate" | "agent"; deps?: ProbeDeps; say?: (t: string) => void }): Promise<string[] | undefined> {
  const say = opt.say ?? line;
  if (!hosts.length) {
    say(c.dim(`  no ${opt.what === "gate" ? "ssh gate" : "agent block"} in ~/.ssh/config`));
    return;
  }
  const probes = await probeAll(hosts, opt.cfgText, opt.deps);
  const gone: string[] = [];
  for (const p of probes) {
    if (!dead(p)) {
      say(`  ${c.green("✔")} ${p.host} ${c.dim(probeText(p))}`);
      continue;
    }
    if (await opt.ask(`${p.host}: ${probeText(p)}. Remove it from the ${opt.what === "gate" ? "ssh gate" : "agent's hosts"}?`, false)) gone.push(p.host);
    else say(c.dim(`  kept ${p.host}`));
  }
  const patterns = hosts.filter((h) => !literal(h));
  if (patterns.length) say(c.dim(`  patterns are kept as they are: ${patterns.join(", ")}`));
  if (!gone.length) {
    say(c.dim("  nothing removed"));
    return;
  }
  const keep = hosts.filter((h) => !gone.includes(h));
  say(`${c.green("✔")} removed ${gone.join(", ")}${keep.length ? "" : " (none left)"}`);
  return keep;
}
