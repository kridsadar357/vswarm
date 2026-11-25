// vswarm notify (src/sec/notify.ts): vswarm's alerts as a summary card in Thak. Off until a token is given, never
// names or paths, at most a few seconds, and quiet about repeats. Thak is played by a function in memory: no network.
import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { askEvent, card, digestEvent, ENDPOINT, lockedEvent, notifyCommand, notifyOn, refusedEvent, send, validToken, verdictEvent, type Poster } from "../src/sec/notify";
import { writePrivate } from "../src/sec/store";

const saved = process.env.VSWARM_SEC_DIR;
const root = mkdtempSync(join(tmpdir(), "vs-notify-"));
const TOKEN = "thak_test_0123456789abcdef";
let sent: { url: string; init: RequestInit; body: any }[] = [];
const ok: Poster = async (url, init) => (sent.push({ url, init, body: JSON.parse(String(init.body)) }), new Response("{}"));

const turnOn = () => {
  writePrivate(join(root, "notify-token"), `${TOKEN}\n`);
  writePrivate(join(root, "notify.json"), { service: "thak", since: 1 });
};

beforeEach(() => {
  process.env.VSWARM_SEC_DIR = root;
  for (const f of ["notify.json", "notify-token"]) rmSync(join(root, f), { force: true });
  sent = [];
});
afterAll(() => {
  if (saved === undefined) delete process.env.VSWARM_SEC_DIR;
  else process.env.VSWARM_SEC_DIR = saved;
  rmSync(root, { recursive: true, force: true });
});

describe("off until a token is given", () => {
  test("nothing is sent and nothing is written while it is off", async () => {
    expect(notifyOn()).toBe(false);
    expect(await send(verdictEvent("block", [{ severity: "high" }], "vswarm diff"), { post: ok })).toBe("off");
    expect(sent).toEqual([]);
    expect(existsSync(join(root, "notify.json"))).toBe(false);
  });

  test("on: one POST to Thak with the token as a bearer, no redirects, JSON", async () => {
    turnOn();
    expect(await send(refusedEvent("block"), { post: ok })).toBe("sent");
    expect(sent.length).toBe(1);
    expect(sent[0].url).toBe(ENDPOINT);
    expect((sent[0].init.headers as any).authorization).toBe(`Bearer ${TOKEN}`);
    expect(sent[0].init.redirect).toBe("error");
    expect(sent[0].body.card.alt).toContain("refused production access");
  });

  test("the token file is readable by its owner only", () => {
    turnOn();
    if (process.platform !== "win32") expect(statSync(join(root, "notify-token")).mode & 0o077).toBe(0);
  });
});

describe("what goes out", () => {
  test("a card Thak accepts: alt, accent, text and kv rows, a footer with the machine's name", () => {
    const c = card(verdictEvent("block", [{ severity: "medium" }, { severity: "critical" }], "vswarm diff"), "laptop");
    expect(c.text).toBe(c.card.alt);
    expect(c.card.accent).toMatch(/^#[0-9a-f]{6}$/);
    expect(c.card.body[0]).toMatchObject({ type: "text", weight: "bold", tone: "danger" });
    expect(c.card.body.filter((b: any) => b.type === "kv")).toEqual([
      { type: "kv", label: "Verdict", value: "STOP" },
      { type: "kv", label: "New findings", value: "2" },
      { type: "kv", label: "Most serious", value: "CRITICAL" },
    ]);
    expect(c.card.footer[0].text).toContain("laptop");
  });

  test("a question sends the command and its first words, not the hosts or numbers after them", () => {
    const rows = askEvent("vswarm gate ssh prod-db-1 billing-*").rows!;
    expect(rows).toEqual([["Command", "vswarm gate ssh"]]);
    expect(JSON.stringify(card(askEvent("vswarm gate ssh prod-db-1")))).not.toContain("prod-db-1");
  });

  test("the daily check counts findings by severity; a lock names the incident", () => {
    expect(digestEvent("warn", { high: 1, low: 3 }).rows).toEqual([["Verdict", "CHECK"], ["High", "1"], ["Low", "3"]]);
    expect(digestEvent("pass", {}).level).toBe("success");
    expect(lockedEvent("20261125-0102").rows).toEqual([["Incident", "20261125-0102"]]);
  });
});

describe("it never gets in the way", () => {
  test("repeats are quiet: one refusal per five minutes; a test is always sent", async () => {
    turnOn();
    expect(await send(refusedEvent("warn"), { post: ok, now: 1_000_000 })).toBe("sent");
    expect(await send(refusedEvent("warn"), { post: ok, now: 1_000_000 + 60_000 })).toBe("quiet");
    expect(await send(refusedEvent("warn"), { post: ok, now: 1_000_000 + 6 * 60_000 })).toBe("sent");
    expect(await send({ kind: "test", level: "info", title: "t" }, { post: ok, force: true })).toBe("sent");
    expect(sent.length).toBe(3);
  });

  test("a wrong token, a slow server, no network: said in status, never thrown, the token never in the error", async () => {
    turnOn();
    expect(await send(lockedEvent("x"), { post: async () => new Response("no", { status: 401 }) })).toContain("token is wrong or was revoked");
    expect(await send(lockedEvent("x"), { post: (_u, init) => new Promise((_r, no) => init.signal!.addEventListener("abort", () => no(new Error("aborted")))), timeoutMs: 50 })).toBe("Thak did not answer in time");
    const r = await send(lockedEvent("x"), { post: async () => { throw new Error(`connect failed for ${TOKEN}`); } });
    expect(r).toContain("could not reach Thak");
    expect(r).not.toContain(TOKEN);
    expect(readFileSync(join(root, "notify.json"), "utf8")).not.toContain(TOKEN);
  });

  test("tokens: one word of printable characters", () => {
    expect(validToken(TOKEN)).toBe(true);
    expect(validToken("short")).toBe(false);
    expect(validToken("has space inside it")).toBe(false);
  });
});

describe("the command", () => {
  test("thak keeps the token and says so; off asks a person (the test answers yes) and deletes it", async () => {
    // The first message after turning on goes through fetch: it is stubbed for this test.
    const real = globalThis.fetch;
    globalThis.fetch = ((url: string, init: RequestInit) => ok(url, init)) as any;
    try {
      await notifyCommand("thak", { ask: async () => TOKEN });
      expect(notifyOn()).toBe(true);
      expect(readFileSync(join(root, "notify-token"), "utf8").trim()).toBe(TOKEN);
      expect(sent.at(-1)!.body.card.alt).toContain("vswarm is connected");
      await notifyCommand("off", { ask: async () => "" });
      expect(notifyOn()).toBe(false);
      expect(existsSync(join(root, "notify-token"))).toBe(false);
    } finally {
      globalThis.fetch = real;
    }
  });

  test("an empty or malformed token is refused with how to get one", async () => {
    await expect(notifyCommand("thak", { ask: async () => "" })).rejects.toThrow("สร้างโทเคน");
    await expect(notifyCommand("thak", { ask: async () => "two words" })).rejects.toThrow("does not look like a token");
    expect(notifyOn()).toBe(false);
  });
});
