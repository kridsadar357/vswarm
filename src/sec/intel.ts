// Outside knowledge about packages: the OSV database (which carries OpenSSF's malicious-packages list as MAL-*
// records), look-alike names of popular packages, and code signatures of new executables.

import { closeSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { exec, readJson } from "./ctx";
import type { Item } from "./types";

function firstBytes(path: string, n: number): string {
  try {
    const fd = openSync(path, "r");
    const buf = Buffer.alloc(n);
    readSync(fd, buf, 0, n, 0);
    closeSync(fd);
    return buf.toString("latin1");
  } catch {
    return "";
  }
}

const ECOSYSTEM: Record<string, string> = { npm: "npm", pip: "PyPI", cargo: "crates.io" };

export interface Malicious {
  item: Item;
  ids: string[];
  summary?: string;
}

/**
 * Asks OSV which of these exact package versions are known-malicious. Only names and versions are sent.
 * Answers are cached for a day so preflight does not wait on the network.
 */
export async function osvMalicious(items: Item[], cacheFile: string, opt: { offline?: boolean; onlyNew?: boolean; timeoutMs?: number } = {}): Promise<{ hits: Malicious[]; checked: number; error?: string; unchecked?: number }> {
  const cache: Record<string, { at: number; mal: string[]; summary?: string }> = readJson(cacheFile) ?? {};
  const fresh = (k: string) => cache[k] && Date.now() - cache[k].at < 86_400_000;
  const pkgs = items.filter((i) => ECOSYSTEM[i.kind] && i.version);
  const key = (i: Item) => `${ECOSYSTEM[i.kind]}:${i.name}@${i.version}`;
  // onlyNew: what was asked about before keeps its cached answer, however old; only versions never asked about are looked up.
  const todo = pkgs.filter((i) => (opt.onlyNew ? !cache[key(i)] : !fresh(key(i))));
  let error: string | undefined;
  if (todo.length && !opt.offline) {
    try {
      for (let i = 0; i < todo.length; i += 500) {
        const batch = todo.slice(i, i + 500);
        const res = await fetch("https://api.osv.dev/v1/querybatch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: ECOSYSTEM[p.kind] }, version: p.version })) }),
          signal: AbortSignal.timeout(opt.timeoutMs ?? 20_000),
        });
        if (!res.ok) throw new Error(`OSV ${res.status}`);
        const body: any = await res.json();
        batch.forEach((p, j) => {
          const ids: string[] = (body.results?.[j]?.vulns ?? []).map((v: any) => v.id).filter((id: string) => id.startsWith("MAL-"));
          cache[key(p)] = { at: Date.now(), mal: ids };
        });
      }
      // Which packages a machine has is nobody else's business: owner-only, like everything under ~/.vswarm/sec.
      mkdirSync(dirname(cacheFile), { recursive: true, mode: 0o700 });
      writeFileSync(cacheFile, JSON.stringify(cache), { mode: 0o600 });
    } catch (e: any) {
      error = opt.onlyNew
        ? `could not reach OSV (${e.message ?? e}): ${todo.length} package version${todo.length === 1 ? "" : "s"} new since the last full check ${todo.length === 1 ? "was" : "were"} not checked against known-malicious records`
        : `could not reach OSV (${e.message ?? e}); known-malicious check used the cache only`;
    }
  }
  const hits = pkgs.filter((p) => cache[key(p)]?.mal.length).map((p) => ({ item: p, ids: cache[key(p)].mal }));
  const checked = pkgs.filter((p) => cache[key(p)]).length;
  return { hits, checked, error, unchecked: pkgs.length - checked };
}

// ── look-alike names
// The most-downloaded npm and PyPI names (src/sec/data/popular.json, made by scripts/popular.ts from public download
// rankings), plus names attackers are known to imitate that a download ranking may rank low or miss: frameworks, MCP
// servers, wallets, AI SDKs, packages hijacked before. These count as most-used.
const EXTRA: Record<string, string[]> = {
  npm: ["react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "dotenv", "typescript", "webpack", "vite", "eslint", "prettier", "jest", "mocha",
    "moment", "dayjs", "uuid", "yargs", "inquirer", "request", "node-fetch", "cross-env", "nodemon", "next", "angular", "@angular/core", "svelte", "three", "socket.io",
    "mongoose", "sequelize", "prisma", "mysql", "mysql2", "redis", "ioredis", "jsonwebtoken", "bcrypt", "bcryptjs", "colors", "electron", "tailwindcss", "postcss",
    "babel-cli", "core-js", "rimraf", "minimist", "body-parser", "cors", "helmet", "zod", "pnpm", "yarn", "ts-node", "esbuild", "rollup", "turbo", "lerna", "firebase",
    "aws-sdk", "stripe", "jquery", "nodemailer", "event-stream", "ua-parser-js", "eslint-scope", "node-ipc", "faker",
    "ethers", "web3", "solana", "@solana/web3.js", "bitcoinjs-lib", "tronweb", "discord.js", "telegraf", "openai", "@anthropic-ai/sdk", "puppeteer", "playwright",
    // MCP servers people start through npx; a near miss here runs with the agent's access.
    "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/sdk", "@playwright/mcp", "mcp-remote",
    "@upstash/context7-mcp", "@notionhq/notion-mcp-server", "figma-developer-mcp", "@supabase/mcp-server-supabase", "@stripe/mcp", "chrome-devtools-mcp"],
  pip: ["requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "django", "flask", "fastapi", "pydantic", "boto3", "botocore", "setuptools", "wheel",
    "pyyaml", "cryptography", "pycryptodome", "paramiko", "selenium", "beautifulsoup4", "lxml", "pillow", "opencv-python", "torch", "tensorflow", "transformers",
    "colorama", "termcolor", "click", "rich", "httpx", "aiohttp", "jinja2", "sqlalchemy", "psycopg2", "pymongo", "redis", "celery", "pytest", "black", "ruff",
    "python-dotenv", "python-dateutil", "jellyfish", "scikit-learn",
    "web3", "solana", "discord-py", "telethon", "ccxt", "openai", "anthropic", "langchain", "mcp", "fastmcp", "mcp-server-fetch", "mcp-server-git", "mcp-server-time"],
};

let popular: Record<string, { list: string[]; set: Set<string>; rank: Map<string, number> }> | undefined;

/** The ranked names per ecosystem, most popular first, read once. */
function lists() {
  if (!popular) {
    const data = readJson<{ npm: string[]; pip: string[] }>(join(import.meta.dir, "data", "popular.json"), 5_000_000) ?? { npm: [], pip: [] };
    popular = {};
    for (const kind of ["npm", "pip"] as const) {
      const list = [...new Set([...(data[kind] ?? []), ...EXTRA[kind]].map((n) => normName(kind, n)))];
      const extra = new Set(EXTRA[kind].map((n) => normName(kind, n)));
      popular[kind] = { list, set: new Set(list), rank: new Map(list.map((name, i) => [name, extra.has(name) ? 0 : i])) };
    }
  }
  return popular;
}

/** How a registry compares names: npm by lower case, PyPI after PEP 503 (lower case, - _ . all the same). */
export function normName(kind: string, name: string): string {
  const n = name.trim().toLowerCase();
  return kind === "pip" ? n.replace(/[-_.]+/g, "-") : n;
}

/** Names your team says are fine (internal packages that happen to resemble popular ones); see team.ts. */
let allowed: (kind: string, name: string) => boolean = () => false;
export function allowNames(fn: (kind: string, name: string) => boolean) {
  allowed = fn;
}

/**
 * Optimal-string-alignment Damerau–Levenshtein distance (insert, delete, substitute, swap two neighbours), giving up
 * as soon as it must exceed `max`.
 */
export function distance(a: string, b: string, max = 2): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (a.length > 214 || b.length > 214) return max + 1;
  let prev2: number[] = [];
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2] + 1);
      cur.push(v);
      best = Math.min(best, v);
    }
    if (best > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[b.length];
}

const flat = (s: string) => s.replace(/[-_.]/g, "");

/**
 * The popular package this name imitates, if any: the most popular one within one edit (two for names of 8 characters
 * or more), the same name with other separators (cross_env, cross.env), a scope folded into the name
 * (solana-web3.js for @solana/web3.js), or a popular name with a typical suffix (lodashjs, requests2). A popular name
 * is never a look-alike of another popular name, and neither is a name your team allows.
 */
export function lookAlike(kind: string, name: string): string | undefined {
  const l = lists()[kind];
  if (!l) return;
  const n = normName(kind, name);
  // Three letters or fewer: too many real packages sit one edit from each other (ms, ws, ip, npm).
  if (n.length < 4 || l.set.has(n) || allowed(kind, n)) return;
  for (const p of l.list) {
    if (p.length < 4) continue;
    if (flat(p) === flat(n)) return p;
    // @scope/name written without the scope's slash: solana-web3.js, solanaweb3.js.
    const scoped = /^@([^/]+)\/(.+)$/.exec(p);
    if (scoped && !n.startsWith("@") && flat(n) === flat(scoped[1] + scoped[2])) return p;
    // Short names have many real neighbours (color, colord; util, utila): only the most-used ones are matched there.
    const long = Math.min(p.length, n.length) >= 8;
    if (long || l.rank.get(p)! < (kind === "pip" ? 500 : 1000)) {
      const max = long ? 2 : 1;
      const d = distance(p, n, max);
      if (d >= 1 && d <= max && !family(p, n, l.rank.get(p)!)) return p;
    }
    if (n === `${p}js` || n === `${p}-js` || n === `${p}.js` || n === `py${p}` || n === `${p}-py`) return p;
  }
}

/**
 * Near names that are a package family, not a typo: another major version (eventemitter2 / eventemitter3, cu12 /
 * cu13), a scope added or dropped with a second edit, a word added in front or behind (estraverse / traverse), a
 * plural (cookie / cookies) unless the name is among the 200 most used, or one whole word swapped among the same
 * words around it (css-loader / sass-loader, client-sso / client-sts, @sentry/core / @sentry/node). One slip inside
 * a word (react-domm) is still a typo.
 */
function family(p: string, n: string, rank: number): boolean {
  if (/\d/.test(p) && /\d/.test(n) && p.replace(/\d+/g, "") === n.replace(/\d+/g, "")) return true;
  const d = distance(p, n, 2);
  if (p.startsWith("@") !== n.startsWith("@") && d === 2) return true;
  if (d === 2 && (n.startsWith(p) || n.endsWith(p) || p.startsWith(n) || p.endsWith(n))) return true;
  if (rank >= 200 && (n === `${p}s` || p === `${n}s`)) return true;
  const ps = p.split(/[-/.]/), ns = n.split(/[-/.]/);
  if (ps.length < 2 || ps.length !== ns.length) return false;
  const diff = ps.map((s, i) => [s, ns[i]]).filter(([a, b]) => a !== b);
  return diff.length === 1 && distance(diff[0][0], diff[0][1], 2) >= 2;
}

export interface Signature {
  kind: "script" | "developer-id" | "apple" | "adhoc" | "unsigned" | "other" | "unknown";
  who?: string;
}

/** Get-AuthenticodeSignature's answer ("Status|Subject") in the terms the rules use. */
export function authenticode(out: string, script: boolean): Signature {
  const [status = "", subject = ""] = out.trim().split("|");
  // Subject is "CN=Name, O=Org, …"; the CN is who signed it.
  const who = /(?:^|,\s*)CN=("[^"]*"|[^,]*)/.exec(subject)?.[1]?.replace(/"/g, "") || subject || undefined;
  if (status === "Valid") return { kind: "developer-id", who };
  if (status === "NotSigned") return { kind: script ? "script" : "unsigned" };
  if (status === "HashMismatch" || status === "NotTrusted" || status === "UnknownError") return { kind: "other", who: who ? `${who} (${status})` : status };
  return { kind: "unknown" };
}

/** Authenticode on Windows. The path goes in through the environment, so nothing in it is read as PowerShell. */
async function windowsSignature(path: string): Promise<Signature> {
  if (/\.(cmd|bat|vbs|js)$/i.test(path)) return { kind: "script" };
  try {
    const ps = `${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
    const { out, code } = await exec([ps, "-NoProfile", "-NonInteractive", "-Command", "$s = Get-AuthenticodeSignature -LiteralPath $env:VSWARM_SIGN_PATH; [string]$s.Status + '|' + [string]$s.SignerCertificate.Subject"], {
      env: { ...process.env, VSWARM_SIGN_PATH: path }, timeoutMs: 15_000,
    });
    return code === 0 ? authenticode(out, /\.ps1$/i.test(path)) : { kind: "unknown" };
  } catch {
    return { kind: "unknown" };
  }
}

/** How a file is signed (macOS codesign, Windows Authenticode). Scripts carry no signature by nature. */
export async function signature(path: string): Promise<Signature> {
  if (firstBytes(path, 2) === "#!") return { kind: "script" };
  if (process.platform === "win32") return windowsSignature(path);
  if (process.platform !== "darwin") return { kind: "unknown" };
  try {
    const { err, code } = await exec(["codesign", "-dv", "--verbose=2", path]);
    if (/not signed at all/.test(err)) return { kind: "unsigned" };
    if (code !== 0) return { kind: "unknown" };
    if (/Signature=adhoc/.test(err)) return { kind: "adhoc" };
    const auth = /Authority=(.+)/.exec(err)?.[1];
    if (auth?.startsWith("Developer ID Application")) return { kind: "developer-id", who: auth.replace("Developer ID Application: ", "") };
    if (auth?.startsWith("Software Signing") || auth?.startsWith("Apple")) return { kind: "apple", who: auth };
    return { kind: "other", who: auth };
  } catch {
    return { kind: "unknown" };
  }
}

