// `vswarm ui`: a local page that shows the machine's state in plain words.
//
// Who can talk to it: only this machine, and only a page that holds this run's token.
//   - Bun.serve binds 127.0.0.1 on a random free port; there is no option for any other address.
//   - A random 256-bit token per run, handed to the browser in the URL fragment (#t=…), which browsers never send to
//     the server and servers never log. The page sends it back as `Authorization: Bearer …` on every API request.
//     It lives in this process's memory only.
//   - Every request: the Host header must be exactly 127.0.0.1:<port> (DNS rebinding), and an Origin or
//     Sec-Fetch-Site header, when sent, must say same-origin (CSRF). No CORS headers are ever sent, so another site's
//     page cannot read an answer or send the Authorization header.
//   - What changes anything is a POST with the token and a JSON body; a GET never changes state.
//   - The static files (page, script, style, language files) hold no data about the machine and are the same for
//     everyone; everything about the machine is under /api and needs the token.
//   - Strict CSP (no inline script), nosniff, no referrer, no caching, no framing.
// It stops after 30 minutes without use, and on Ctrl+C.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Ctx } from "../sec/ctx";
import { realCtx } from "../sec/ctx";
import { check } from "../sec/engine";
import { c, line } from "../sec/print";
import { loadAccepted, saveAccepted } from "../sec/store";
import { acceptable, dashboard, findingOf, langNow, setLang, type Lang } from "./state";

export const IDLE_MS = 30 * 60_000;

export const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const BASE_HEADERS: Record<string, string> = {
  "Content-Security-Policy": CSP,
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cache-Control": "no-store",
};

const DIR = import.meta.dir;
const STATIC: Record<string, [string, string]> = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/index.html": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/app.css": ["app.css", "text/css; charset=utf-8"],
  "/i18n/en.json": ["i18n/en.json", "application/json; charset=utf-8"],
  "/i18n/th.json": ["i18n/th.json", "application/json; charset=utf-8"],
};

export interface UiOpt {
  /** The machine to check when the page asks; the real one unless a test or a demo hands in another. */
  ctx?: () => Ctx;
  home?: string;
  idleMs?: number;
  /** Where actions are echoed; stderr by default. */
  log?: (t: string) => void;
  offline?: boolean;
  /** Fixed port, for tests only; 0 (a free one) otherwise. */
  port?: number;
}

export interface Ui {
  url: string;
  port: number;
  token: string;
  hostname: string;
  stop: () => void;
  /** Resolves when the server stopped (idle, or stop()). */
  done: Promise<"idle" | "stopped">;
}

const sha = (s: string) => createHash("sha256").update(s).digest();

export function startUi(opt: UiOpt = {}): Ui {
  const token = randomBytes(32).toString("base64url");
  const tokenHash = sha(token);
  const say = opt.log ?? ((t: string) => line(t));
  const home = opt.home ?? homedir();
  const idleMs = opt.idleMs ?? IDLE_MS;
  const files = new Map(Object.entries(STATIC).map(([p, [f, type]]) => [p, { body: readFileSync(join(DIR, f)), type }]));
  let lastUse = Date.now();
  let checking: Promise<unknown> | undefined;
  let notes: string[] | undefined;
  let finish: (why: "idle" | "stopped") => void = () => {};
  const done = new Promise<"idle" | "stopped">((r) => (finish = r));

  const reply = (body: BodyInit | null, status = 200, type = "application/json; charset=utf-8") =>
    new Response(body, { status, headers: { ...BASE_HEADERS, ...(body === null ? {} : { "Content-Type": type }) } });
  const json = (v: unknown, status = 200) => reply(JSON.stringify(v), status);
  const deny = (status: number, why: string) => json({ error: why }, status);

  const authed = (req: Request) => {
    const m = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(req.headers.get("authorization") ?? "");
    return !!m && timingSafeEqual(sha(m[1]), tokenHash);
  };

  const state = async () => dashboard({ home, notes });

  async function body(req: Request): Promise<any> {
    if (!/^application\/json\b/i.test(req.headers.get("content-type") ?? "")) throw new Error("expected JSON");
    const t = await req.text();
    if (t.length > 4096) throw new Error("too large");
    return t ? JSON.parse(t) : {};
  }

  async function api(req: Request, path: string): Promise<Response> {
    if (req.method === "GET" && path === "/api/state") return json(await state());
    if (req.method !== "POST") return deny(405, "this needs POST");
    let b: any;
    try {
      b = await body(req);
    } catch (e: any) {
      return deny(400, String(e?.message ?? e));
    }
    if (path === "/api/check") {
      if (checking) return deny(409, "a check is already running");
      say(`${c.violet("▸ vswarm ui")} the page asked for a check · running it now`);
      try {
        const r = await (checking = check((opt.ctx ?? realCtx)(), { offline: opt.offline }));
        notes = r.notes;
        say(`  ${r.verdict === "pass" ? c.green("PASS") : r.verdict === "warn" ? c.amber("WARN") : c.red("BLOCK")} ${c.dim(`${r.findings.length} finding${r.findings.length === 1 ? "" : "s"} · ${r.ms} ms`)}`);
      } finally {
        checking = undefined;
      }
      return json(await state());
    }
    if (path === "/api/accept") {
      const ref = typeof b?.ref === "string" ? b.ref : "";
      const f = ref ? await findingOf(ref) : undefined;
      if (!f) return deny(404, "no such finding in the last check");
      if (!acceptable(f)) return deny(403, "this one cannot be marked as yours from the page");
      const acc = await loadAccepted();
      acc[f.id] = { at: Date.now(), title: f.title };
      await saveAccepted(acc);
      say(`${c.violet("▸ vswarm ui")} marked as yours (same as vswarm accept): ${f.title} ${c.dim(`· undo: vswarm accept --remove ${f.id}`)}`);
      return json(await state());
    }
    if (path === "/api/lang") {
      const lang = b?.lang === "th" || b?.lang === "en" ? (b.lang as Lang) : undefined;
      if (!lang) return deny(400, "lang is th or en");
      setLang(lang);
      say(`${c.violet("▸ vswarm ui")} language: ${lang === "th" ? "ไทย" : "English"}`);
      return json({ lang });
    }
    return deny(404, "no such action");
  }

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: opt.port ?? 0,
    // A check of a real machine can take a while; Bun's default would cut it off.
    idleTimeout: 255,
    async fetch(req) {
      const url = new URL(req.url);
      const self = `127.0.0.1:${server.port}`;
      // DNS rebinding: a page on evil.example resolved to 127.0.0.1 still says Host: evil.example.
      if (req.headers.get("host") !== self) return deny(403, "wrong host");
      const origin = req.headers.get("origin");
      if (origin !== null && origin !== `http://${self}`) return deny(403, "cross-origin");
      const site = req.headers.get("sec-fetch-site");
      if (site !== null && site !== "same-origin" && site !== "none") return deny(403, "cross-site");
      if (url.pathname.startsWith("/api/")) {
        if (!authed(req)) return deny(401, "this needs the link printed in the terminal");
        // The page's own refresh does not count as use, so an open tab nobody looks at still lets it stop.
        if (req.headers.get("x-vswarm-poll") !== "1") lastUse = Date.now();
        try {
          return await api(req, url.pathname);
        } catch (e: any) {
          say(c.red(`  vswarm ui: ${e?.message ?? e}`));
          return deny(500, "vswarm could not do that; the terminal says why");
        }
      }
      if (req.method !== "GET" && req.method !== "HEAD") return deny(405, "read-only");
      const f = files.get(url.pathname);
      if (!f) return deny(404, "not found");
      return reply(req.method === "HEAD" ? null : f.body, 200, f.type);
    },
  });

  const timer = setInterval(() => {
    if (Date.now() - lastUse > idleMs) stop("idle");
  }, Math.min(30_000, Math.max(50, Math.floor(idleMs / 4))));
  let stopped = false;
  function stop(why: "idle" | "stopped" = "stopped") {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    server.stop(true);
    finish(why);
  }

  const port = server.port!;
  return { url: `http://127.0.0.1:${port}/#t=${token}`, port, token, hostname: server.hostname ?? "127.0.0.1", stop: () => stop("stopped"), done };
}

/** Opens the page in the default browser; false when there is none to ask (the URL is printed either way). */
export async function openBrowser(url: string): Promise<boolean> {
  const cmd = process.platform === "darwin" ? ["open", url]
    : process.platform === "win32" ? ["cmd.exe", "/d", "/c", "start", "", url]
    : process.env.DISPLAY || process.env.WAYLAND_DISPLAY ? ["xdg-open", url] : undefined;
  if (!cmd || (process.platform !== "win32" && !Bun.which(cmd[0]))) return false;
  try {
    const p = Bun.spawn(cmd, { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
    return (await p.exited) === 0;
  } catch {
    return false;
  }
}

/** `vswarm ui [--no-open]`. */
export async function uiCommand(opt: { open: boolean; offline?: boolean }) {
  const ui = startUi({ offline: opt.offline });
  line(`${c.violet("▼ vswarm ui")} ${c.dim("· this machine only (127.0.0.1) · stops after 30 minutes unused, or Ctrl+C")}`);
  line(`  ${c.bold(ui.url)}`);
  line(c.dim(`  The link holds a one-time key for this run; keep it to yourself. Language: ${langNow() === "th" ? "ไทย" : "English"} (switch on the page, or VSWARM_LANG=th|en).`));
  if (opt.open && !(await openBrowser(ui.url))) line(c.dim("  no browser could be opened from here: open the link above"));
  const stop = () => {
    ui.stop();
    line(c.dim("\n  vswarm ui stopped"));
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  const why = await ui.done;
  line(c.dim(why === "idle" ? "  vswarm ui stopped after 30 minutes unused · vswarm ui to open it again" : "  vswarm ui stopped"));
}
