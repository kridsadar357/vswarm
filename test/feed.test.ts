// vswarm feed (src/sec/feed.ts): a signed list of dangerous things, pinned on first use, never taken older, compared
// on this machine. The feed is served from memory (no network) and signed with throwaway keys in a temp folder.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkUrl, expired, FEEDS, feedAdd, feedFindings, feedRemove, feedUpdate, keptLists, loadFeeds, NAMESPACE, parseFeed, slugOf, type Feed, type Fetcher } from "../src/sec/feed";
import { check } from "../src/sec/engine";
import { useKeyStore } from "../src/sec/store";
import type { Item } from "../src/sec/types";
import { fakeMachine, type FakeMachine } from "./ui-fixture";

const WIN = process.platform === "win32";
const tools = !WIN && !!Bun.which("ssh-keygen");
const saved = { sec: process.env.VSWARM_SEC_DIR, agent: process.env.VSWARM_AGENT_DIR };
const root = mkdtempSync(join(tmpdir(), "vs-feed-"));
const URL_ = "https://feeds.example.com/vswarm/pro";
let m: FakeMachine;

// The feed's files as its server would hand them out, and what each request carried.
const served = new Map<string, Buffer>();
const asked: { url: string; headers: Record<string, string> }[] = [];
const get: Fetcher = async (url, headers) => {
  asked.push({ url, headers });
  const name = url.slice(URL_.length + 1);
  const b = served.get(name);
  return b ? new Response(new Uint8Array(b)) : new Response("not found", { status: 404 });
};

const keyOf = (name: string) => {
  const k = join(root, "keys", name);
  if (!existsSync(k)) {
    mkdirSync(join(root, "keys"), { recursive: true });
    Bun.spawnSync(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", `${name}@feed`, "-f", k]);
  }
  return k;
};
const signersOf = (...names: string[]) => names.map((n) => `${n}@feed namespaces="${NAMESPACE}" ${readFileSync(`${keyOf(n)}.pub`, "utf8").trim()}`).join("\n") + "\n";

/** Puts a feed on the fake server: the list signed by `by`, allowed_signers listing `signers`. */
function publish(feed: Feed, by = "owner", signers = ["owner"]) {
  const dir = join(root, "pub");
  mkdirSync(dir, { recursive: true });
  const file = join(dir, "vswarm-feed.json");
  writeFileSync(file, JSON.stringify(feed));
  rmSync(`${file}.sig`, { force: true });
  expect(Bun.spawnSync(["ssh-keygen", "-q", "-Y", "sign", "-f", keyOf(by), "-n", NAMESPACE, file]).exitCode).toBe(0);
  served.set("vswarm-feed.json", readFileSync(file));
  served.set("vswarm-feed.json.sig", readFileSync(`${file}.sig`));
  served.set("allowed_signers", Buffer.from(signersOf(...signers)));
}

const feed = (serial: number, entries: Feed["entries"] = [], extra: Partial<Feed> = {}): Feed => ({ "vswarm-feed": 1, name: "Example Pro", serial, entries, ...extra });
const yes = async () => true;

beforeAll(async () => {
  m = await fakeMachine(root);
});

afterAll(() => {
  for (const [k, v] of [["VSWARM_SEC_DIR", saved.sec], ["VSWARM_AGENT_DIR", saved.agent]] as const) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  useKeyStore(undefined);
  rmSync(root, { recursive: true, force: true });
});

describe("the feed file and its address", () => {
  test("a list of the right shape is taken; anything else is refused with what is wrong", () => {
    expect(parseFeed(JSON.stringify(feed(3, [{ id: "X-1", kind: "npm", name: "evil", versions: ["1.0.0"] }]))).serial).toBe(3);
    expect(() => parseFeed("{")).toThrow("not valid JSON");
    expect(() => parseFeed(JSON.stringify({ ...feed(1), "vswarm-feed": 2 }))).toThrow("version 1");
    expect(() => parseFeed(JSON.stringify(feed(1, [{ id: "a", kind: "shell" as any, name: "x" }])))).toThrow("kind must be");
    // A feed cannot make anything critical: critical findings cannot be marked as yours.
    expect(() => parseFeed(JSON.stringify(feed(1, [{ id: "a", kind: "npm", name: "x", severity: "critical" as any }])))).toThrow("medium or high");
    expect(() => parseFeed(JSON.stringify(feed(-1)))).toThrow("serial");
  });

  test("https only (http to this machine), no token in the URL, no query", () => {
    expect(checkUrl(`${URL_}/`)).toBe(URL_);
    expect(checkUrl("http://127.0.0.1:8080/f")).toBe("http://127.0.0.1:8080/f");
    expect(() => checkUrl("http://feeds.example.com/f")).toThrow("https");
    expect(() => checkUrl("https://user:tok@feeds.example.com/f")).toThrow("--token-env");
    expect(() => checkUrl("https://feeds.example.com/f?token=x")).toThrow("query");
    expect(slugOf(URL_)).toBe("feeds.example.com-vswarm-pro");
  });
});

describe("what a feed names on this machine", () => {
  const items: Item[] = [
    { kind: "npm", id: "evil", name: "evil", version: "1.0.0", path: "/x/node_modules/evil" },
    { kind: "npm", id: "fine", name: "fine", version: "2.0.0" },
    { kind: "pip", id: "Bad_Pkg", name: "Bad_Pkg", version: "0.1" },
    { kind: "mcp", id: "claude:helper", name: "helper", source: "claude-code", meta: { argv: JSON.stringify(["npx", "-y", "shady-mcp@1.2.3"]) } },
    { kind: "conn", id: "/usr/bin/x", name: "x", meta: { remotes: "203.0.113.7:443 198.51.100.1:22" } },
  ];
  const lists = [{ kept: { slug: "s", url: URL_, name: "Example Pro", serial: 1, sha: "", at: 0 }, feed: feed(1, [
    { id: "N-1", kind: "npm", name: "evil", versions: ["1.0.0"], title: "steals tokens" },
    { id: "N-2", kind: "npm", name: "fine", versions: ["9.9.9"] },
    { id: "P-1", kind: "pip", name: "bad-pkg", severity: "medium" },
    { id: "M-1", kind: "mcp", name: "shady-mcp" },
    { id: "I-1", kind: "ip", name: "203.0.113.7" },
  ]) }];

  test("packages by name and version (pip names normalised), MCP servers by the package they run, connections by address", () => {
    const fs = feedFindings(items, lists);
    expect(fs.map((f) => f.detail[0])).toEqual(["Example Pro N-1", "Example Pro P-1", "Example Pro M-1", "Example Pro I-1"]);
    expect(fs.every((f) => f.rule === "feed")).toBe(true);
    expect(fs[0].severity).toBe("high");
    expect(fs[0].title).toContain("evil@1.0.0");
    expect(fs[0].title).toContain("steals tokens");
    expect(fs[1].severity).toBe("medium");
    expect(fs[3].title).toContain("203.0.113.7");
  });

  test("a list past its date is named, so the check can say so", () => {
    const old = { kept: { ...lists[0].kept, expires: "2020-01-01" }, feed: lists[0].feed };
    expect(expired([old])).toEqual(["Example Pro"]);
    expect(expired(lists)).toEqual([]);
  });
});

describe.skipIf(!tools)("following a feed", () => {
  test("add: the signing keys are shown first; not confirmed, nothing is kept", async () => {
    publish(feed(1, [{ id: "N-1", kind: "npm", name: "evil" }]));
    let shown: string[] = [];
    await expect(feedAdd(URL_, { get, confirm: async (keys) => ((shown = keys.map((k) => k.who)), false) })).rejects.toThrow("not confirmed");
    expect(shown).toEqual(["owner@feed"]);
    expect((await loadFeeds()).feeds).toEqual([]);
  });

  test("add with a token from a variable: sent as a header, never kept; no variable, no request", async () => {
    await expect(feedAdd(URL_, { get, confirm: yes, tokenEnv: "FEED_TOKEN", env: {} })).rejects.toThrow("$FEED_TOKEN");
    asked.length = 0;
    const r = await feedAdd(URL_, { get, confirm: yes, tokenEnv: "FEED_TOKEN", env: { FEED_TOKEN: "s3cret-token" } });
    expect(r.signer).toBe("owner@feed");
    expect(asked.every((a) => a.headers.Authorization === "Bearer s3cret-token")).toBe(true);
    expect(asked.map((a) => a.url.slice(URL_.length))).toEqual(["/vswarm-feed.json", "/vswarm-feed.json.sig", "/allowed_signers"]);
    const kept = (await loadFeeds()).feeds;
    expect(kept.map((k) => [k.name, k.serial, k.tokenEnv])).toEqual([["Example Pro", 1, "FEED_TOKEN"]]);
    expect(JSON.stringify(kept)).not.toContain("s3cret-token");
    await expect(feedAdd(URL_, { get, confirm: yes })).rejects.toThrow("already follows");
  });

  test("update: newer is taken; older, the same serial with other contents, other signers or a bad signature are not", async () => {
    const env = { FEED_TOKEN: "s3cret-token" };
    publish(feed(2, [{ id: "N-1", kind: "npm", name: "evil" }, { id: "N-2", kind: "npm", name: "worse" }]));
    expect((await feedUpdate({ get, env }))[0]).toMatchObject({ serial: 2, previous: 1 });
    publish(feed(1));
    expect((await feedUpdate({ get, env }))[0].error).toContain("older");
    publish(feed(2, [{ id: "N-9", kind: "npm", name: "other" }]));
    expect((await feedUpdate({ get, env }))[0].error).toContain("without raising the serial");
    publish(feed(3), "intruder", ["intruder"]);
    expect((await feedUpdate({ get, env }))[0].error).toContain("different signers");
    // Signed by a key the feed does not list: allowed_signers as pinned, signature by someone else.
    publish(feed(3), "intruder", ["owner"]);
    expect((await feedUpdate({ get, env }))[0].error).toContain("not signed by a key");
    // Nothing of those was taken.
    const { lists } = await keptLists();
    expect(lists[0].feed.serial).toBe(2);
    expect(lists[0].feed.entries).toHaveLength(2);
  });

  test("a kept list changed by hand is not used, and the check says so", async () => {
    const { feeds } = await loadFeeds();
    const file = join(FEEDS(), feeds[0].slug, "vswarm-feed.json");
    const good = readFileSync(file);
    writeFileSync(file, JSON.stringify(feed(2)));
    const k = await keptLists();
    expect(k.lists).toEqual([]);
    expect(k.problems[0]).toContain("changed or removed outside vswarm");
    const r = await check(m.ctx, { offline: true });
    expect(r.findings.some((f) => f.rule === "vswarm-state" && f.title.includes("feed"))).toBe(true);
    writeFileSync(file, good);
  });

  test("the check finds what the list names, and a finding from a feed can be marked as yours", async () => {
    const before = await check(m.ctx, { offline: true });
    const pkg = before.scan.items.find((i) => ["npm", "pip", "brew"].includes(i.kind));
    expect(pkg).toBeDefined();
    publish(feed(4, [{ id: "T-1", kind: pkg!.kind as "npm", name: pkg!.name, severity: "medium" }]));
    expect((await feedUpdate({ get, env: { FEED_TOKEN: "s3cret-token" } }))[0].serial).toBe(4);
    const r = await check(m.ctx, { offline: true });
    const f = r.findings.find((x) => x.rule === "feed");
    expect(f?.detail[0]).toBe("Example Pro T-1");
    const { acceptable } = await import("../src/ui/state");
    expect(acceptable(f!)).toBe(true);
  });

  test("remove: the feed's folder and record go", async () => {
    const gone = await feedRemove("Example Pro");
    expect(gone.map((k) => k.name)).toEqual(["Example Pro"]);
    expect((await loadFeeds()).feeds).toEqual([]);
    expect((await keptLists()).lists).toEqual([]);
    await expect(feedRemove("Example Pro")).rejects.toThrow("no feed");
  });
});
