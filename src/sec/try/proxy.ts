// A small HTTP(S) proxy on localhost. Sandboxed code may only reach the network through it, so every host it tries
// to contact is recorded, and only the allowed ones get through (none by default).

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

export function allowedBy(mode: "none" | "registries" | "all") {
  return (host: string) => mode === "all" || (mode === "registries" && REGISTRIES.some((r) => host === r || host.endsWith("." + r)));
}

export function startProxy(allow: (host: string) => boolean): Proxy {
  const hits: ProxyHit[] = [];
  type State = { buf: Buffer; up?: any; open: boolean; pending: Buffer[] };
  const server = Bun.listen<State>({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      open(s) {
        s.data = { buf: Buffer.alloc(0), open: false, pending: [] };
      },
      data(s, chunk) {
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
          const i = target.lastIndexOf(":");
          host = target.slice(0, i).replace(/^\[|\]$/g, "");
          port = Number(target.slice(i + 1)) || 443;
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
        hits.push({ at: Date.now(), host, port, allowed: ok });
        if (!ok) {
          s.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nblocked by vswarm try: ${host}\n`);
          return;
        }
        st.up = true;
        Bun.connect<{ client: typeof s }>({
          hostname: host,
          port,
          socket: {
            open(up) {
              up.data = { client: s };
              st.up = up;
              st.open = true;
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
      close(s) {
        if (s.data?.up && s.data.open) s.data.up.end();
      },
      error() {},
    },
  });
  return { port: server.port, hits, stop: () => server.stop(true) };
}
