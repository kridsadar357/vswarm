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

/**
 * Bun's sockets take what they can and return how much: the rest is the caller's to send when the socket drains. A
 * download through the proxy (an npm tarball) would otherwise lose bytes whenever the sandboxed side reads slowly.
 */
type Out = { backlog?: Buffer; endWhenDrained?: boolean };
function send(sock: { write(b: Buffer): number }, out: Out, data: Buffer) {
  if (!data.length) return;
  if (out.backlog?.length) {
    out.backlog = Buffer.concat([out.backlog, data]);
    return;
  }
  const n = sock.write(data);
  if (n < data.length) out.backlog = data.subarray(Math.max(n, 0));
}
function drained(sock: { write(b: Buffer): number; end(): void }, out: Out) {
  const b = out.backlog;
  out.backlog = undefined;
  if (b) send(sock, out, b);
  if (!out.backlog && out.endWhenDrained) sock.end();
}
/** Ends a socket once everything written to it has gone out. */
function endAfter(sock: { end(): void }, out: Out) {
  if (out.backlog?.length) out.endWhenDrained = true;
  else sock.end();
}

/** Listens on 127.0.0.1, or on a unix socket (Linux: the sandbox has its own network and reaches it through a file). */
export function startProxy(allow: (host: string) => boolean, opt: { unix?: string; localhost?: boolean; resolve?: Resolve } = {}): Proxy {
  const hits: ProxyHit[] = [];
  // toUp: bytes on their way to the server; toClient: to the sandboxed code.
  type State = { buf: Buffer; up?: any; open: boolean; closed: boolean; pending: Buffer[]; toUp: Out; toClient: Out };
  const handlers = {
      open(s: import("bun").Socket<State>) {
        s.data = { buf: Buffer.alloc(0), open: false, closed: false, pending: [], toUp: {}, toClient: {} };
      },
      data(s: import("bun").Socket<State>, chunk: Buffer) {
        const st = s.data;
        if (st.up) {
          if (st.open) send(st.up, st.toUp, Buffer.from(chunk));
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
              if (tunnel) send(s, st.toClient, Buffer.from("HTTP/1.1 200 Connection Established\r\n\r\n"));
              // Plain HTTP: the request as it came, header and body (origin servers accept absolute-form); a tunnel:
              // what came after its header. Then what arrived while this connection was opening. One write, and what
              // the socket did not take yet goes out when it drains: a write can be partial, and the rest was lost.
              send(up, st.toUp, Buffer.concat([tunnel ? rest : st.buf, ...st.pending]));
              st.pending = [];
            },
            drain(up) {
              drained(up, st.toUp);
            },
            data(up, d) {
              send(up.data.client, st.toClient, Buffer.from(d));
            },
            close(up) {
              endAfter(up.data.client, st.toClient);
            },
            error(up) {
              up.data?.client.end();
            },
          },
        }).catch(() => s.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
      },
      drain(s: import("bun").Socket<State>) {
        if (s.data) drained(s, s.data.toClient);
      },
      close(s: import("bun").Socket<State>) {
        if (!s.data) return;
        s.data.closed = true;
        if (s.data.up && s.data.open) endAfter(s.data.up, s.data.toUp);
      },
      error() {},
  } satisfies import("bun").SocketHandler<State>;
  const server = opt.unix ? Bun.listen<State>({ unix: opt.unix, socket: handlers }) : Bun.listen<State>({ hostname: "127.0.0.1", port: 0, socket: handlers });
  return { port: opt.unix ? 0 : (server as any).port, hits, stop: () => server.stop(true) };
}
