// A small HTTP(S) proxy on localhost. Sandboxed code may only reach the network through it, so every host it tries
// to contact is recorded, and only the allowed ones get through (none by default).
//
// Even an allowed name must not lead back into this machine or its cloud: a name is resolved first, every address it
// resolves to is checked, and the connection goes to the address that was checked (a second lookup could answer
// differently: DNS rebinding). Loopback is refused unless `try --localhost`; link-local and the cloud metadata
// addresses (169.254.169.254, fd00:ec2::254, 100.100.100.200) always.

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export interface ProxyHit {
  at: number;
  host: string;
  port: number;
  allowed: boolean;
}

export interface Proxy {
  port: number;
  hits: ProxyHit[];
  stop(): void;
}

/** Hosts package managers need when `--net registries` is chosen. */
export const REGISTRIES = [
  "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "pypi.org", "files.pythonhosted.org",
  "crates.io", "index.crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org", "jsr.io", "deno.land",
];

/** Why an address must not be reached from the sandbox, or undefined. `localhost` lets loopback through. */
export function forbiddenAddress(ip: string, localhost = false): string | undefined {
  const a = ip.toLowerCase().replace(/^\[|\]$/g, "");
  const v4 = /^(?:::ffff:)?(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(a);
  if (v4) {
    const [o1, o2] = [Number(v4[1]), Number(v4[2])];
    if (a.endsWith("169.254.169.254") || a.endsWith("100.100.100.200")) return "a cloud metadata address";
    if (o1 === 169 && o2 === 254) return "a link-local address";
    if (o1 === 127 || o1 === 0) return localhost ? undefined : "this machine (loopback)";
    return;
  }
  if (a === "fd00:ec2::254") return "a cloud metadata address";
  if (/^fe[89ab][0-9a-f]:/.test(a)) return "a link-local address";
  if (a === "::1" || a === "::") return localhost ? undefined : "this machine (loopback)";
}

export type Resolve = (host: string) => Promise<string[]>;
const realResolve: Resolve = async (host) => (await lookup(host, { all: true, verbatim: true })).map((x) => x.address);

export function allowedBy(mode: "none" | "registries" | "all") {
  return (host: string) => mode === "all" || (mode === "registries" && REGISTRIES.some((r) => host === r || host.endsWith("." + r)));
}

/** Listens on 127.0.0.1, or on a unix socket (Linux: the sandbox has its own network and reaches it through a file). */
export function startProxy(allow: (host: string) => boolean, opt: { unix?: string; localhost?: boolean; resolve?: Resolve } = {}): Proxy {
  const hits: ProxyHit[] = [];
  type State = { buf: Buffer; up?: any; open: boolean; closed: boolean; pending: Buffer[] };
  const handlers = {
      open(s: import("bun").Socket<State>) {
        s.data = { buf: Buffer.alloc(0), open: false, closed: false, pending: [] };
      },
      data(s: import("bun").Socket<State>, chunk: Buffer) {
        const st = s.data;
        if (st.up) {
          if (st.open) st.up.write(chunk);
          else st.pending.push(Buffer.from(chunk));
          return;
        }
        st.buf = Buffer.concat([st.buf, Buffer.from(chunk)]);
        const end = st.buf.indexOf("\r\n\r\n");
        if (end < 0) {
          if (st.buf.length > 16_384) s.end();
          return;
        }
        const head = st.buf.subarray(0, end).toString("latin1");
        const rest = st.buf.subarray(end + 4);
        const [method, target] = head.split(/\s+/);
        let host = "", port = 80, tunnel = false;
        if (method === "CONNECT") {
          // host:port, [v6]:port, or a bare host (no port): the colon inside [v6] is not the separator.
          const i = target.lastIndexOf(":");
          const withPort = i > target.lastIndexOf("]");
          host = (withPort ? target.slice(0, i) : target).replace(/^\[|\]$/g, "");
          port = (withPort ? Number(target.slice(i + 1)) : 0) || 443;
          tunnel = true;
        } else {
          try {
            const u = new URL(target);
            host = u.hostname;
            port = Number(u.port) || 80;
          } catch {
            s.end("HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
          }
        }
        const ok = allow(host);
        const hit: ProxyHit = { at: Date.now(), host, port, allowed: ok };
        hits.push(hit);
        if (!ok) {
          s.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nblocked by vswarm try: ${host}\n`);
          return;
        }
        st.up = true;
        // Resolved once, here: the address checked is the address connected to.
        (isIP(host) ? Promise.resolve([host]) : (opt.resolve ?? realResolve)(host)).then((ips) => {
          const why = ips.map((ip) => forbiddenAddress(ip, opt.localhost)).find(Boolean);
          if (!ips.length || why) {
            hit.allowed = false;
            s.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nblocked by vswarm try: ${host} ${why ? `is ${why}` : "does not resolve"}\n`);
            return;
          }
          connectTo(ips[0]);
        }, () => s.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
        const connectTo = (ip: string) => Bun.connect<{ client: typeof s }>({
          hostname: ip,
          port,
          socket: {
            open(up) {
              up.data = { client: s };
              st.up = up;
              st.open = true;
              // The client gave up while this connection was being opened; do not leave it hanging.
              if (st.closed) {
                up.end();
                return;
              }
              if (tunnel) s.write("HTTP/1.1 200 Connection Established\r\n\r\n");
              else {
                // Plain HTTP: forward the request as it came (origin servers accept absolute-form).
                up.write(Buffer.concat([st.buf.subarray(0, end + 4)]));
              }
              if (rest.length && tunnel) up.write(rest);
              for (const p of st.pending) up.write(p);
              st.pending = [];
            },
            data(up, d) {
              up.data.client.write(d);
            },
            close(up) {
              up.data.client.end();
            },
            error(up) {
              up.data?.client.end();
            },
          },
        }).catch(() => s.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
      },
      close(s: import("bun").Socket<State>) {
        if (!s.data) return;
        s.data.closed = true;
        if (s.data.up && s.data.open) s.data.up.end();
      },
      error() {},
  } satisfies import("bun").SocketHandler<State>;
  const server = opt.unix ? Bun.listen<State>({ unix: opt.unix, socket: handlers }) : Bun.listen<State>({ hostname: "127.0.0.1", port: 0, socket: handlers });
  return { port: opt.unix ? 0 : (server as any).port, hits, stop: () => server.stop(true) };
}
