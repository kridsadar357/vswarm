// vswarm ui: the localhost security model, what leaves the server, and the static report. Every server here runs on
// a fake machine in a temp folder (test/ui-fixture.ts); no browser is opened.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { files, loadAccepted, loadLast, saveLast, useKeyStore } from "../src/sec/store";
import type { Finding } from "../src/sec/types";
import { CSP, startUi, type Ui } from "../src/ui/server";
import { dashboard, groupOf, langNow, refOf, scrub } from "../src/ui/state";
import { reportHtml, scriptJson } from "../src/ui/report";
import { checkNow, fakeMachine, type FakeMachine } from "./ui-fixture";

const saved = { sec: process.env.VSWARM_SEC_DIR, agent: process.env.VSWARM_AGENT_DIR, lang: process.env.VSWARM_LANG };
const root = mkdtempSync(join(tmpdir(), "vs-ui-"));
let m: FakeMachine;
let ui: Ui;
const logged: string[] = [];

const TOKEN_LIKE = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7c";
const planted: Finding[] = [];

beforeAll(async () => {
  delete process.env.VSWARM_LANG;
  m = await fakeMachine(root);
  await checkNow(m);
  // A finding whose detail carries a credential and a home path, as a collector could get wrong.
  const last = (await loadLast())!;
  planted.push(
    { id: `secret:${m.home}/.config/tool/token`, rule: "secret", severity: "medium", title: `Token in ${m.home}/.config/tool/token`, detail: [`${m.home}/.config/tool/token`, `value ${TOKEN_LIKE}`, `https://deploy:hunter2secret@git.example.com/x.git`], fix: "rotate it" },
    { id: "malicious:npm:evil@1.0.0", rule: "malicious", severity: "critical", title: "Known-malicious package evil@1.0.0", detail: [] },
    { id: "launch-new:dev.example.helper", rule: "launch-new", severity: "high", title: "New login job dev.example.helper", detail: [] },
  );
  await saveLast({ ...last, findings: [...planted, ...last.findings], verdict: "block", at: Date.now() });
  ui = startUi({ ctx: () => m.ctx, home: m.home, offline: true, log: (t) => logged.push(t) });
});

afterAll(() => {
  ui?.stop();
  for (const [k, v] of [["VSWARM_SEC_DIR", saved.sec], ["VSWARM_AGENT_DIR", saved.agent], ["VSWARM_LANG", saved.lang]] as const) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  useKeyStore(undefined);
  rmSync(root, { recursive: true, force: true });
});

const base = () => `http://127.0.0.1:${ui.port}`;
const auth = () => ({ Authorization: `Bearer ${ui.token}` });
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(base() + path, { method: "POST", headers: { ...auth(), "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });

describe("vswarm ui: who can talk to it", () => {
  test("it listens on 127.0.0.1 only, on a port of its own", async () => {
    expect(ui.hostname).toBe("127.0.0.1");
    expect(ui.port).toBeGreaterThan(0);
    expect(ui.url).toBe(`http://127.0.0.1:${ui.port}/#t=${ui.token}`);
    expect((await fetch(`${base()}/`)).status).toBe(200);
    // Not on IPv6 loopback, nor on any other address of this machine.
    const others = Object.values(networkInterfaces()).flat().filter((a) => a && !a.internal && a.family === "IPv4").map((a) => a!.address);
    for (const addr of ["[::1]", ...others.slice(0, 3)]) {
      const r = await fetch(`http://${addr}:${ui.port}/`, { signal: AbortSignal.timeout(3000) }).then((x) => x.status, () => "refused");
      expect(r).toBe("refused");
    }
  });

  test("the token is 256 bits and new each run", () => {
    expect(Buffer.from(ui.token, "base64url").length).toBe(32);
    const other = startUi({ ctx: () => m.ctx, home: m.home, log: () => {} });
    try {
      expect(other.token).not.toBe(ui.token);
      expect(other.port).not.toBe(ui.port);
    } finally {
      other.stop();
    }
  });

  test("a wrong Host header is refused (DNS rebinding)", async () => {
    for (const host of ["evil.example", `evil.example:${ui.port}`, `localhost:${ui.port}`, "127.0.0.1", `127.0.0.1:${ui.port + 1}`]) {
      expect((await fetch(`${base()}/api/state`, { headers: { ...auth(), Host: host } })).status).toBe(403);
      expect((await fetch(`${base()}/`, { headers: { Host: host } })).status).toBe(403);
    }
  });

  test("a foreign Origin or a cross-site fetch is refused (CSRF)", async () => {
    for (const origin of ["http://evil.example", "null", `http://localhost:${ui.port}`, `https://127.0.0.1:${ui.port}`]) {
      expect((await fetch(`${base()}/api/state`, { headers: { ...auth(), Origin: origin } })).status).toBe(403);
      expect((await post("/api/check", {}, { Origin: origin })).status).toBe(403);
    }
    for (const site of ["cross-site", "same-site"]) expect((await fetch(`${base()}/api/state`, { headers: { ...auth(), "Sec-Fetch-Site": site } })).status).toBe(403);
    // The page itself: same origin.
    expect((await fetch(`${base()}/api/state`, { headers: { ...auth(), Origin: base(), "Sec-Fetch-Site": "same-origin" } })).status).toBe(200);
  });

  test("no token, or a wrong one, gets 401", async () => {
    expect((await fetch(`${base()}/api/state`)).status).toBe(401);
    expect((await fetch(`${base()}/api/state`, { headers: { Authorization: `Bearer ${"A".repeat(43)}` } })).status).toBe(401);
    expect((await fetch(`${base()}/api/state`, { headers: { Authorization: ui.token } })).status).toBe(401);
    expect((await fetch(`${base()}/api/state?t=${ui.token}`)).status).toBe(401);
    // A cookie is not a way in either.
    expect((await fetch(`${base()}/api/state`, { headers: { Cookie: `t=${ui.token}` } })).status).toBe(401);
  });

  test("a POST without the token changes nothing", async () => {
    const before = statSync(files.last()).mtimeMs;
    const acc = JSON.stringify(await loadAccepted());
    for (const path of ["/api/check", "/api/accept", "/api/lang"]) {
      const r = await fetch(base() + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ref: refOf(planted[2].id), lang: "th" }) });
      expect(r.status).toBe(401);
    }
    expect(statSync(files.last()).mtimeMs).toBe(before);
    expect(JSON.stringify(await loadAccepted())).toBe(acc);
    expect(existsSync(join(m.sec, "ui.json"))).toBe(false);
  });

  test("a GET never changes state, even with the token", async () => {
    const before = statSync(files.last()).mtimeMs;
    for (const path of ["/api/check", "/api/accept", "/api/lang"]) {
      const r = await fetch(`${base()}${path}?ref=${refOf(planted[2].id)}&lang=th`, { headers: auth() });
      expect(r.status).toBe(405);
    }
    expect((await fetch(`${base()}/api/check`, { method: "PUT", headers: auth() })).status).toBe(405);
    expect(statSync(files.last()).mtimeMs).toBe(before);
    expect(Object.keys(await loadAccepted())).toHaveLength(0);
  });

  test("a POST that a plain HTML form could send (not JSON) is refused", async () => {
    const r = await fetch(`${base()}/api/accept`, { method: "POST", headers: { ...auth(), "Content-Type": "text/plain" }, body: JSON.stringify({ ref: refOf(planted[2].id) }) });
    expect(r.status).toBe(400);
    expect(Object.keys(await loadAccepted())).toHaveLength(0);
  });

  test("every answer has the security headers and no CORS", async () => {
    for (const r of [await fetch(`${base()}/`), await fetch(`${base()}/app.js`), await fetch(`${base()}/api/state`, { headers: auth() }), await fetch(`${base()}/api/state`), await fetch(`${base()}/api/state`, { headers: { ...auth(), Origin: "http://evil.example" } })]) {
      expect(r.headers.get("content-security-policy")).toBe(CSP);
      expect(r.headers.get("x-content-type-options")).toBe("nosniff");
      expect(r.headers.get("referrer-policy")).toBe("no-referrer");
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("x-frame-options")).toBe("DENY");
      for (const h of ["access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-headers", "set-cookie"]) expect(r.headers.get(h)).toBeNull();
    }
    expect(CSP).toContain("script-src 'self'");
    expect(CSP).toContain("frame-ancestors 'none'");
    expect(CSP).not.toContain("unsafe-inline");
    // Preflight requests get no CORS answer either.
    const opt = await fetch(`${base()}/api/check`, { method: "OPTIONS", headers: { Origin: "http://evil.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization" } });
    expect(opt.status).toBe(403);
    expect(opt.headers.get("access-control-allow-origin")).toBeNull();
  });

  test("the static files hold no machine data, and the page builds no HTML from strings", async () => {
    const page = await (await fetch(`${base()}/`)).text();
    expect(page).not.toContain(m.home);
    expect(page).not.toContain("dev-mbp");
    expect(page).not.toMatch(/<script>[^<]/);
    expect(page).not.toMatch(/\sstyle="/);
    const js = readFileSync(join(import.meta.dir, "../src/ui/app.js"), "utf8");
    expect(js).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
    // replaceChildren and append take nodes, not a list: a list passed whole shows as "[object HTMLDivElement],…".
    // Every .map( directly inside one must be spread.
    for (const m of js.matchAll(/\.(?:replaceChildren|append)\(([^;]*?)\);/gs)) {
      let depth = 0;
      const args = m[1];
      for (let i = 0; i < args.length; i++) {
        if ("([{".includes(args[i])) depth++;
        else if (")]}".includes(args[i])) depth--;
        else if (depth === 0 && args.startsWith(".map(", i)) expect(args.slice(Math.max(0, i - 40), i + 5)).toMatch(/\.\.\.[\w.]+\.map\($/);
      }
    }
    expect((await fetch(`${base()}/../package.json`)).status).toBe(404);
    expect((await fetch(`${base()}/state.ts`)).status).toBe(404);
  });
});

describe("vswarm ui: what leaves the server", () => {
  test("credentials are masked, home paths are ~, finding ids stay on the server", async () => {
    const text = await (await fetch(`${base()}/api/state`, { headers: auth() })).text();
    expect(text).not.toContain(TOKEN_LIKE);
    expect(text).not.toContain("hunter2secret");
    expect(text).not.toContain(m.home);
    expect(text).not.toContain(root);
    expect(text).toContain("~/.config/tool/token");
    for (const f of planted) expect(text).not.toContain(JSON.stringify(f.id));
    const d = JSON.parse(text);
    expect(d.status.level).toBe("stop");
    expect(d.cards.find((c: any) => c.rule === "malicious").canAccept).toBe(false);
    // Each card carries its number in the last check and the one command for it, as the terminal shows them.
    const launch = d.cards.find((c: any) => c.rule === "launch-new");
    expect(launch.n).toBe(3);
    expect(launch.cmd.run).toMatch(/^vswarm (why|fix) 3$/);
    expect(d.cards.find((c: any) => c.rule === "malicious").cmd.run).toBe("vswarm respond");
    expect(Array.isArray(d.held)).toBe(true);
  });

  test("scrub masks again whatever slipped through", () => {
    expect(scrub(`x ${TOKEN_LIKE} y`, "/h/u")).not.toContain(TOKEN_LIKE);
    expect(scrub("/h/u/.ssh/id_ed25519", "/h/u")).toBe("~/.ssh/id_ed25519");
    expect(scrub("--api-key=s3cr3tv4lue", "/h/u")).not.toContain("s3cr3tv4lue");
    expect(scrub(`AKIA${"ABCDEFGHIJKLMNOP"}`, "/h/u")).not.toContain("AKIAABCD");
  });

  test("severities and rules map to the three groups", () => {
    expect(groupOf({ rule: "launch-new", severity: "high" })).toBe("action");
    expect(groupOf({ rule: "vswarm-state", severity: "medium" })).toBe("action");
    expect(groupOf({ rule: "agent-mcp-new", severity: "medium" })).toBe("yours");
    expect(groupOf({ rule: "new-package", severity: "low" })).toBe("info");
  });
});

describe("vswarm ui: the few actions", () => {
  test("This is mine accepts one finding, the same as vswarm accept, and is echoed in the terminal", async () => {
    const f = planted[2];
    const r = await post("/api/accept", { ref: refOf(f.id) });
    expect(r.status).toBe(200);
    expect((await loadAccepted())[f.id]?.title).toBe(f.title);
    expect(logged.some((l) => l.includes("marked as yours") && l.includes(f.title))).toBe(true);
    const d = await r.json();
    expect(d.cards.some((c: any) => c.ref === refOf(f.id))).toBe(false);
    expect(d.status.acceptedSince).toBe(1);
  });

  test("a known-malicious package cannot be marked as yours; an unknown reference finds nothing", async () => {
    expect((await post("/api/accept", { ref: refOf(planted[1].id) })).status).toBe(403);
    expect((await loadAccepted())[planted[1].id]).toBeUndefined();
    expect((await post("/api/accept", { ref: "nope" })).status).toBe(404);
    expect((await post("/api/accept", { ref: planted[2].id })).status).toBe(404);
  });

  test("Run a check now checks the machine it was given and is echoed", async () => {
    const r = await post("/api/check", {});
    expect(r.status).toBe(200);
    const d = await r.json();
    expect(d.status.checkedAt).toBeGreaterThan(Date.now() - 60_000);
    expect(logged.some((l) => l.includes("the page asked for a check"))).toBe(true);
  });

  test("the language is saved beside vswarm's state; VSWARM_LANG wins, then the saved choice, then LANG", async () => {
    expect(langNow({ LANG: "th_TH.UTF-8" })).toBe("th");
    expect((await post("/api/lang", { lang: "xx" })).status).toBe(400);
    expect((await post("/api/lang", { lang: "th" })).status).toBe(200);
    expect(JSON.parse(readFileSync(join(m.sec, "ui.json"), "utf8")).lang).toBe("th");
    expect(langNow({ LANG: "en_US.UTF-8" })).toBe("th");
    expect(langNow({ LANG: "th_TH.UTF-8", VSWARM_LANG: "en" })).toBe("en");
    await post("/api/lang", { lang: "en" });
    expect(langNow({ LANG: "th_TH.UTF-8" })).toBe("en");
  });

  test("it stops on its own when nobody uses it", async () => {
    const short = startUi({ ctx: () => m.ctx, home: m.home, idleMs: 150, log: () => {} });
    const t0 = Date.now();
    expect(await short.done).toBe("idle");
    expect(Date.now() - t0).toBeLessThan(5000);
    const r = await fetch(`http://127.0.0.1:${short.port}/`).then((x) => x.status, () => "refused");
    expect(r).toBe("refused");
  });
});

describe("vswarm ui: words and the report", () => {
  const en = JSON.parse(readFileSync(join(import.meta.dir, "../src/i18n/en.json"), "utf8"));
  const th = JSON.parse(readFileSync(join(import.meta.dir, "../src/i18n/th.json"), "utf8"));

  test("English and Thai have the same strings, with the same placeholders", () => {
    expect(Object.keys(th).sort()).toEqual(Object.keys(en).sort());
    const ph = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((x) => x[1]).sort().join(",");
    for (const k of Object.keys(en)) expect(`${k}: ${ph(th[k])}`).toBe(`${k}: ${ph(en[k])}`);
  });

  test("every sentence the dashboard asks for exists", async () => {
    const d = await dashboard({ home: m.home });
    const keys = [d.status.why, ...d.status.extra, ...d.tiles.flatMap((t) => [t.say, ...t.lines]), ...d.timeline.map((e) => e.say)].map((s) => s.key);
    for (const k of keys) expect(en[k] === undefined ? k : "ok").toBe("ok");
    for (const t of d.tiles) expect(en[`tile.${t.key}.title`]).toBeString();
  });

  test("the HTML report is self-contained, masked, and lets only its own script run", async () => {
    const d = await dashboard({ home: m.home, mode: "report" });
    d.cards[0].title = "</script><script>alert(1)</script>";
    const html = reportHtml(d);
    expect(html).not.toContain(m.home);
    expect(html).not.toContain(TOKEN_LIKE);
    expect(html).not.toContain("<script>alert(1)");
    expect(html).not.toMatch(/src="app\.js"|href="app\.css"|https?:\/\/(?!www\.w3\.org)/);
    const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] ?? "";
    expect(csp).toContain("default-src 'none'");
    const js = readFileSync(join(import.meta.dir, "../src/ui/app.js"), "utf8");
    const hash = new Bun.CryptoHasher("sha256").update(js).digest("base64");
    expect(csp).toContain(`'sha256-${hash}'`);
    expect(html).toContain(`<script>${js}</script>`);
    const json = /<script id="vswarm-data" type="application\/json">([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
    expect(JSON.parse(json).dash.cards[0].title).toBe("</script><script>alert(1)</script>");
    expect(scriptJson("a</script>b")).not.toContain("</");
  });
});
