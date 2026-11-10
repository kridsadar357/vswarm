// `vswarm feed`: lists of dangerous things (packages, MCP servers, editor and browser extensions, attacker
// addresses) that someone keeps up to date, signed with an SSH key. vswarm downloads the whole list and compares it
// on this machine: nothing about this machine is sent, only the request for the file (and a token, when the feed
// asks for one).
//
//   <url>/vswarm-feed.json       the list (below)
//   <url>/vswarm-feed.json.sig   ssh-keygen -Y sign -n vswarm-feed over it
//   <url>/allowed_signers        who may sign it: <principal> namespaces="vswarm-feed" <ssh public key>
//
// `feed add` pins allowed_signers on first use, after you confirm its fingerprints (or name one with --fingerprint).
// `feed update` then takes a list only when it is signed by a pinned key, its signers did not change, and its serial
// did not go back (a replayed old list). What a feed can do is limited on purpose: it adds findings, at most HIGH,
// and each can be marked as yours like any other. It cannot run anything, accept anything or switch anything off, so
// the worst a stolen feed key does is false alarms.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { exec } from "./ctx";
import { normName } from "./intel";
import { readSealed, SEC, writeSealed } from "./store";
import type { Finding, Item, Severity } from "./types";
import { fingerprints } from "./update";

export const NAMESPACE = "vswarm-feed";
const FILE = "vswarm-feed.json";
const MAX = 20_000_000;

export const FEEDS = () => join(SEC(), "feeds");
const dirOf = (slug: string) => join(FEEDS(), slug);
const index = () => join(FEEDS(), "feeds.json");

const KINDS = ["npm", "pip", "cargo", "brew", "editor-ext", "browser-ext", "mcp", "ip"] as const;
type Kind = (typeof KINDS)[number];

export interface Entry {
  /** The feed's own id for it, shown in the finding. */
  id: string;
  kind: Kind;
  /** Package, extension or server name (npm/pip the registry name; mcp the package it runs or its name in the agent's config); for ip an address. */
  name: string;
  /** Only these versions (packages); every version when left out. */
  versions?: string[];
  severity?: "medium" | "high";
  title?: string;
  /** Where to read more. */
  ref?: string;
}

export interface Feed {
  "vswarm-feed": 1;
  name: string;
  /** Goes up with every change; a machine never moves to a lower one. */
  serial: number;
  /** After this (an ISO date), the list is said to be old until it is updated. */
  expires?: string;
  entries: Entry[];
}

/** What this machine keeps about each feed, sealed. The token itself is never kept: only the variable it is read from. */
export interface Kept {
  slug: string;
  url: string;
  name: string;
  serial: number;
  expires?: string;
  /** sha256 of the verified vswarm-feed.json kept beside it. */
  sha: string;
  at: number;
  tokenEnv?: string;
}

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const signerSet = (text: string) => text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => l.replace(/\s+/g, " ")).sort().join("\n");

/** The feed's shape, checked before anything of it is used. Throws with what is wrong. */
export function parseFeed(text: string): Feed {
  let f: any;
  try {
    f = JSON.parse(text);
  } catch {
    throw new Error(`${FILE} is not valid JSON`);
  }
  if (!f || f["vswarm-feed"] !== 1) throw new Error(`${FILE} is not a vswarm feed (version 1)`);
  if (typeof f.name !== "string" || !/^[\w .:@/-]{1,80}$/.test(f.name)) throw new Error(`${FILE}: name must be 1 to 80 plain characters`);
  if (!Number.isInteger(f.serial) || f.serial < 0) throw new Error(`${FILE}: serial must be a whole number`);
  if (f.expires !== undefined && (typeof f.expires !== "string" || Number.isNaN(Date.parse(f.expires)))) throw new Error(`${FILE}: expires must be a date`);
  if (!Array.isArray(f.entries)) throw new Error(`${FILE}: entries must be a list`);
  if (f.entries.length > 200_000) throw new Error(`${FILE}: too many entries`);
  f.entries.forEach((e: any, i: number) => {
    const bad = (what: string) => {
      throw new Error(`${FILE}: entry ${i + 1}: ${what}`);
    };
    if (!e || typeof e !== "object") bad("not an object");
    if (typeof e.id !== "string" || !e.id || e.id.length > 80) bad("id must be a short text");
    if (!KINDS.includes(e.kind)) bad(`kind must be one of ${KINDS.join(", ")}`);
    if (typeof e.name !== "string" || !e.name || e.name.length > 300) bad("name must be a short text");
    if (e.versions !== undefined && (!Array.isArray(e.versions) || !e.versions.every((v: unknown) => typeof v === "string"))) bad("versions must be a list of texts");
    if (e.severity !== undefined && e.severity !== "medium" && e.severity !== "high") bad("severity must be medium or high");
    for (const k of ["title", "ref"]) if (e[k] !== undefined && (typeof e[k] !== "string" || e[k].length > 300)) bad(`${k} must be a short text`);
  });
  return f as Feed;
}

/** A feed's folder name: its host and path, plain characters only. */
export function slugOf(url: string): string {
  const u = new URL(url);
  return `${u.hostname}${u.pathname}`.replace(/[^\w.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "feed";
}

/** https anywhere; http only to this machine (a feed you serve yourself, tests). */
export function checkUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`not a URL: ${url}`);
  }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname))) throw new Error("a feed URL must be https:// (http:// only to this machine)");
  if (u.username || u.password) throw new Error("put the feed's token in a variable (--token-env), not in the URL");
  if (u.search || u.hash) throw new Error("a feed URL has no ?query or #fragment: it is the folder that holds vswarm-feed.json");
  return url.replace(/\/+$/, "");
}

export type Fetcher = (url: string, headers: Record<string, string>) => Promise<Response>;
const realFetch: Fetcher = (url, headers) => fetch(url, { headers, redirect: "error", signal: AbortSignal.timeout(30_000) });

async function download(base: string, name: string, tokenEnv: string | undefined, get: Fetcher, env: Record<string, string | undefined>): Promise<Buffer> {
  const headers: Record<string, string> = { "User-Agent": "vswarm" };
  if (tokenEnv) {
    const tok = env[tokenEnv];
    if (!tok) throw new Error(`the feed needs a token in $${tokenEnv}, which is not set`);
    headers.Authorization = `Bearer ${tok}`;
  }
  const r = await get(`${base}/${name}`, headers);
  if (!r.ok) throw new Error(`${name}: the feed answered ${r.status}${r.status === 401 || r.status === 403 ? " (token missing, wrong or expired)" : ""}`);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > MAX) throw new Error(`${name} is larger than ${MAX / 1_000_000} MB`);
  return buf;
}

/** Verifies dir/vswarm-feed.json against its .sig with the signers in `signers`. Returns who signed it. */
export async function verifyFeed(dir: string, signers: string): Promise<string> {
  const file = join(dir, FILE), sig = `${file}.sig`;
  if (!existsSync(sig)) throw new Error(`${FILE} is not signed; vswarm uses only a signed feed`);
  const who = await exec(["ssh-keygen", "-Y", "find-principals", "-s", sig, "-f", signers]);
  const principal = who.out.trim().split("\n")[0];
  if (who.code !== 0 || !principal) throw new Error(`${FILE} is not signed by a key in the feed's pinned allowed_signers`);
  const p = Bun.spawn(["ssh-keygen", "-Y", "verify", "-f", signers, "-I", principal, "-n", NAMESPACE, "-s", sig], { stdin: Bun.file(file), stdout: "pipe", stderr: "pipe" });
  const [err, code] = await Promise.all([new Response(p.stderr).text(), p.exited]);
  if (code !== 0) throw new Error(`the signature on ${FILE} does not verify: ${err.trim().split("\n")[0] || `exit ${code}`}`);
  return principal;
}

/** The feeds this machine follows, and whether the record of them can be trusted. */
export async function loadFeeds(): Promise<{ feeds: Kept[]; untrusted?: string }> {
  if (!existsSync(index())) return { feeds: [] };
  const s = await readSealed<Kept[]>(index());
  // A sealing key that cannot be read right now is said by the check itself (engine.ts nokey), not as a change.
  if (s.untrusted) return { feeds: [], untrusted: s.nokey ? undefined : s.untrusted };
  return { feeds: s.value ?? [] };
}
const saveFeeds = (k: Kept[]) => writeSealed(index(), k);

interface Fetched {
  dir: string;
  feed: Feed;
  signers: string;
}

/** Downloads the three files into a fresh folder beside the kept one. */
async function fetchInto(url: string, slug: string, tokenEnv: string | undefined, get: Fetcher, env: Record<string, string | undefined>): Promise<Fetched> {
  const dir = join(FEEDS(), `${slug}.incoming`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const [list, sig, signers] = await Promise.all([FILE, `${FILE}.sig`, "allowed_signers"].map((n) => download(url, n, tokenEnv, get, env)));
  writeFileSync(join(dir, FILE), list, { mode: 0o600 });
  writeFileSync(join(dir, `${FILE}.sig`), sig, { mode: 0o600 });
  writeFileSync(join(dir, "allowed_signers"), signers, { mode: 0o600 });
  if (!signerSet(signers.toString("utf8"))) throw new Error("the feed lists no signers (allowed_signers)");
  return { dir, feed: parseFeed(list.toString("utf8")), signers: signers.toString("utf8") };
}

function settle(f: Fetched, slug: string) {
  const dir = dirOf(slug);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const n of [FILE, `${FILE}.sig`, "allowed_signers"]) writeFileSync(join(dir, n), readFileSync(join(f.dir, n)), { mode: 0o600 });
  rmSync(f.dir, { recursive: true, force: true });
}

export interface AddOpt {
  tokenEnv?: string;
  confirm: (keys: { who: string; fp: string }[], feed: Feed) => Promise<boolean>;
  get?: Fetcher;
  env?: Record<string, string | undefined>;
}

/** First contact: download, show the signers, pin them only after `confirm`, keep the list only if it verifies. */
export async function feedAdd(rawUrl: string, opt: AddOpt): Promise<{ kept: Kept; signer: string }> {
  const url = checkUrl(rawUrl);
  if (opt.tokenEnv !== undefined && !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(opt.tokenEnv)) throw new Error("--token-env takes the name of a variable, like VSWARM_FEED_TOKEN");
  const { feeds, untrusted } = await loadFeeds();
  if (untrusted) throw new Error(`vswarm's list of feeds was changed outside vswarm (${untrusted}); remove ${index()} and add your feeds again`);
  const slug = slugOf(url);
  if (feeds.some((k) => k.slug === slug)) throw new Error(`this machine already follows ${url}; vswarm feed update`);
  const f = await fetchInto(url, slug, opt.tokenEnv, opt.get ?? realFetch, opt.env ?? process.env);
  try {
    const keys = await fingerprints(join(f.dir, "allowed_signers"));
    if (!keys.length) throw new Error("allowed_signers of the feed holds no usable key");
    if (!(await opt.confirm(keys, f.feed))) throw new Error("not added: the signing keys were not confirmed");
    const signer = await verifyFeed(f.dir, join(f.dir, "allowed_signers"));
    const kept: Kept = { slug, url, name: f.feed.name, serial: f.feed.serial, expires: f.feed.expires, sha: sha(readFileSync(join(f.dir, FILE))), at: Date.now(), tokenEnv: opt.tokenEnv };
    settle(f, slug);
    await saveFeeds([...feeds, kept]);
    return { kept, signer };
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
}

export interface Updated {
  slug: string;
  name: string;
  serial?: number;
  previous?: number;
  error?: string;
}

/** Each feed again: taken only when signed by a pinned key, with the same signers and a serial that did not go back. */
export async function feedUpdate(opt: { get?: Fetcher; env?: Record<string, string | undefined> } = {}): Promise<Updated[]> {
  const { feeds, untrusted } = await loadFeeds();
  if (untrusted) throw new Error(`vswarm's list of feeds was changed outside vswarm (${untrusted}); remove ${index()} and add your feeds again`);
  const out: Updated[] = [];
  const next: Kept[] = [];
  for (const k of feeds) {
    try {
      const f = await fetchInto(k.url, k.slug, k.tokenEnv, opt.get ?? realFetch, opt.env ?? process.env);
      try {
        const pinned = readFileSync(join(dirOf(k.slug), "allowed_signers"), "utf8");
        // A new signer is a decision for a person, like a changed release key: remove the feed and add it again.
        if (sha(signerSet(f.signers)) !== sha(signerSet(pinned)))
          throw new Error(`the feed now lists different signers than the ones pinned here; if that is expected: vswarm feed remove ${k.slug} && vswarm feed add ${k.url}`);
        await verifyFeed(f.dir, join(dirOf(k.slug), "allowed_signers"));
        const now = sha(readFileSync(join(f.dir, FILE)));
        if (f.feed.serial < k.serial) throw new Error(`the feed's list (serial ${f.feed.serial}) is older than the one here (${k.serial}); refusing to go back`);
        if (f.feed.serial === k.serial && now !== k.sha) throw new Error(`the feed changed its list without raising the serial (${k.serial}); refusing it`);
        settle(f, k.slug);
        next.push({ ...k, name: f.feed.name, serial: f.feed.serial, expires: f.feed.expires, sha: now, at: Date.now() });
        out.push({ slug: k.slug, name: f.feed.name, serial: f.feed.serial, previous: k.serial });
      } finally {
        rmSync(f.dir, { recursive: true, force: true });
      }
    } catch (e: any) {
      next.push(k);
      out.push({ slug: k.slug, name: k.name, error: String(e?.message ?? e) });
    }
  }
  await saveFeeds(next);
  return out;
}

/** Stops following a feed (by its folder name, URL or name): its folder and its record go. `--all`: every feed. */
export async function feedRemove(which: string): Promise<Kept[]> {
  const { feeds, untrusted } = await loadFeeds();
  if (which === "--all") {
    rmSync(FEEDS(), { recursive: true, force: true });
    return feeds;
  }
  if (untrusted) throw new Error("vswarm's list of feeds was changed outside vswarm; vswarm feed remove --all, then add the ones you want again");
  const k = feeds.find((x) => x.slug === which || x.url === which.replace(/\/+$/, "") || x.name === which);
  if (!k) throw new Error(`no feed ${which}; vswarm feed list`);
  rmSync(dirOf(k.slug), { recursive: true, force: true });
  await saveFeeds(feeds.filter((x) => x !== k));
  return [k];
}

/** The kept lists whose files still match their record; any other is reported, not used. */
export async function keptLists(): Promise<{ lists: { kept: Kept; feed: Feed }[]; problems: string[] }> {
  const { feeds, untrusted } = await loadFeeds();
  const problems = untrusted ? [`the list of feeds ${untrusted}`] : [];
  const lists: { kept: Kept; feed: Feed }[] = [];
  for (const k of feeds) {
    const file = join(dirOf(k.slug), FILE);
    const buf = existsSync(file) ? readFileSync(file) : undefined;
    if (!buf || sha(buf) !== k.sha) {
      problems.push(`feed ${k.name}: its list was changed or removed outside vswarm`);
      continue;
    }
    try {
      lists.push({ kept: k, feed: parseFeed(buf.toString("utf8")) });
    } catch (e: any) {
      problems.push(`feed ${k.name}: ${e.message}`);
    }
  }
  return { lists, problems };
}

/** The package an MCP server runs (npx some-server, uvx some-server), or its name in the agent's config. */
function mcpNames(i: Item): string[] {
  const out = [i.name];
  try {
    const argv = JSON.parse(String(i.meta?.argv ?? "[]")) as string[];
    const at = argv.findIndex((a) => /(^|[\\/])(npx|bunx|pnpx|uvx|pipx)(\.cmd|\.exe)?$/.test(a));
    const pkg = at >= 0 ? argv.slice(at + 1).find((a) => !a.startsWith("-")) : undefined;
    if (pkg) out.push(pkg.replace(/(.)@[^@/]+$/, "$1"));
  } catch {}
  return out;
}

const PKG_KINDS = new Set(["npm", "pip", "cargo", "brew", "editor-ext", "browser-ext"]);

/** Findings for what the lists name on this machine. Pure: the lists and the scan in, findings out. */
export function feedFindings(items: Item[], lists: { kept: Kept; feed: Feed }[]): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const { feed } of lists) {
    const by = new Map<string, Entry[]>();
    for (const e of feed.entries) {
      const k = `${e.kind}:${e.kind === "ip" ? e.name : normName(e.kind === "mcp" ? "npm" : e.kind, e.name)}`;
      by.set(k, [...(by.get(k) ?? []), e]);
    }
    const hit = (e: Entry, i: Item, what: string) => {
      const id = `feed:${feed.name}:${e.id}:${i.kind}:${i.id}`;
      if (seen.has(id)) return;
      seen.add(id);
      out.push({
        id, rule: "feed", severity: e.severity ?? "high",
        title: `${what} is on the list "${feed.name}"${e.title ? `: ${e.title}` : ""}`,
        detail: [`${feed.name} ${e.id}`, e.ref ?? "", i.path ?? ""].filter(Boolean),
        fix: "Remove it unless you know why it is here; if it ran, vswarm respond. If the list is wrong about it: vswarm ok",
        item: i,
      });
    };
    for (const i of items) {
      if (PKG_KINDS.has(i.kind)) {
        for (const e of by.get(`${i.kind}:${normName(i.kind, i.name)}`) ?? [])
          if (!e.versions || (i.version && e.versions.includes(i.version))) hit(e, i, `${i.name}${i.version ? `@${i.version}` : ""} (${i.kind})`);
      } else if (i.kind === "mcp") {
        for (const n of mcpNames(i)) for (const e of by.get(`mcp:${normName("npm", n)}`) ?? []) hit(e, i, `MCP server ${i.name} (${i.source})`);
      } else if (i.kind === "conn") {
        for (const r of String(i.meta?.remotes ?? "").split(" ").filter(Boolean)) {
          const ip = r.replace(/^\[?([^\]]+?)\]?:\d+$/, "$1");
          for (const e of by.get(`ip:${ip}`) ?? []) hit(e, i, `${i.name} is connected to ${ip}, which`);
        }
      }
    }
  }
  return out;
}

/** Feeds whose list is past its date, for a note in the check. */
export const expired = (lists: { kept: Kept }[], now = Date.now()) => lists.filter(({ kept }) => kept.expires && Date.parse(kept.expires) < now).map(({ kept }) => kept.name);

// ── vswarm feed add | update | list | remove | sign

/** Signs a feed file (whoever keeps the feed): checks its shape first, then ssh-keygen -Y sign. */
export async function signFeed(file: string, key: string): Promise<string> {
  parseFeed(readFileSync(file, "utf8"));
  // On the terminal: a key with a passphrase asks for it there.
  const r = await exec(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", NAMESPACE, file], { tty: true });
  if (r.code !== 0 || !existsSync(`${file}.sig`)) throw new Error(`could not sign ${file} with ${key}`);
  return `${file}.sig`;
}

const USAGE = "usage: vswarm feed add <https url> [--fingerprint SHA256:…] [--token-env VAR] [--yes] | update | list | remove <name|url|--all> | sign <file> --key <key>";

export async function feedCommand(action: string, args: string[], opt: { fingerprint?: string; tokenEnv?: string; yes?: boolean; key?: string; ask: (q: string, def?: boolean) => Promise<boolean> }) {
  const { c, line } = await import("./print");
  if (action === "add") {
    const url = args[0];
    if (!url || args.length > 1) throw new Error(USAGE);
    const r = await feedAdd(url, {
      tokenEnv: opt.tokenEnv,
      confirm: async (keys, feed) => {
        line(`${c.violet("▼ vswarm feed add")} ${c.dim(url)}`);
        line(`  ${c.bold(feed.name)} ${c.dim(`· ${feed.entries.length} entries · serial ${feed.serial}`)}`);
        for (const k of keys) line(`  signing key ${c.bold(k.fp)} ${c.dim(k.who)}`);
        if (opt.fingerprint) {
          const hit = keys.some((k) => k.fp === opt.fingerprint);
          if (!hit) line(c.red(`  none of these is ${opt.fingerprint}`));
          return hit;
        }
        if (opt.yes) return true;
        line(c.dim("  Compare these with what the feed's owner published somewhere else (their site, a README, in person)."));
        return opt.ask("Trust these keys for this feed from now on?", false);
      },
    });
    line(`${c.green("✔")} following ${r.kept.name} (serial ${r.kept.serial}), signed by ${r.signer}`);
    line(c.dim("  The next check compares this machine with it, on this machine. vswarm feed update fetches a newer list."));
    return;
  }
  if (action === "update") {
    if (args.length) throw new Error(USAGE);
    const rs = await feedUpdate();
    if (!rs.length) return line(`  ${c.dim("·")} no feeds · vswarm feed add <https url>`);
    for (const r of rs)
      line(r.error ? `${c.red("✖")} ${r.name}: ${r.error}` : `${c.green("✔")} ${r.name} serial ${r.serial}${r.previous === r.serial ? " (no change)" : ` (was ${r.previous})`}`);
    if (rs.some((r) => r.error)) process.exitCode = 1;
    return;
  }
  if (action === "list") {
    if (args.length) throw new Error(USAGE);
    const { feeds, untrusted } = await loadFeeds();
    if (untrusted) line(c.red(`  vswarm's list of feeds ${untrusted}; none is used · vswarm feed remove --all, then add them again`));
    if (!feeds.length && !untrusted) return line(`  ${c.dim("·")} no feeds · vswarm feed add <https url>`);
    const { lists, problems } = await keptLists();
    const old = new Set(expired(lists));
    for (const k of feeds) {
      const n = lists.find((l) => l.kept.slug === k.slug)?.feed.entries.length;
      line(`  ${c.bold(k.name)} ${c.dim(`· ${k.url} · serial ${k.serial} · ${n ?? "?"} entries · updated ${new Date(k.at).toLocaleString()}${k.tokenEnv ? ` · token from $${k.tokenEnv}` : ""}`)}${old.has(k.name) ? c.amber(" · past its date, vswarm feed update") : ""}`);
      for (const f of await fingerprints(join(dirOf(k.slug), "allowed_signers"))) line(`    ${c.dim(`signing key ${f.fp} ${f.who}`)}`);
    }
    for (const p of problems) line(c.red(`  ${p}`));
    return;
  }
  if (action === "remove") {
    const which = args[0];
    if (!which || args.length > 1) throw new Error(USAGE);
    await (await import("./human")).weaken("feed", ["remove", which]);
    const gone = await feedRemove(which);
    line(`${c.green("✔")} ${gone.length ? `no longer following ${gone.map((k) => k.name).join(", ")}` : "no feeds were kept"}`);
    return;
  }
  if (action === "sign") {
    if (!args[0] || !opt.key) throw new Error("usage: vswarm feed sign vswarm-feed.json --key ~/.ssh/feed_signing_key");
    line(`${c.green("✔")} ${await signFeed(args[0], opt.key)}`);
    return;
  }
  throw new Error(USAGE);
}
