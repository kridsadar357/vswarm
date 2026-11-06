// Outside knowledge about packages: the OSV database (which carries OpenSSF's malicious-packages list as MAL-*
// records), look-alike names of popular packages, and code signatures of new executables.

import { closeSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
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
export async function osvMalicious(items: Item[], cacheFile: string, opt: { offline?: boolean } = {}): Promise<{ hits: Malicious[]; checked: number; error?: string }> {
  const cache: Record<string, { at: number; mal: string[]; summary?: string }> = readJson(cacheFile) ?? {};
  const fresh = (k: string) => cache[k] && Date.now() - cache[k].at < 86_400_000;
  const pkgs = items.filter((i) => ECOSYSTEM[i.kind] && i.version);
  const key = (i: Item) => `${ECOSYSTEM[i.kind]}:${i.name}@${i.version}`;
  const todo = pkgs.filter((i) => !fresh(key(i)));
  let error: string | undefined;
  if (todo.length && !opt.offline) {
    try {
      for (let i = 0; i < todo.length; i += 500) {
        const batch = todo.slice(i, i + 500);
        const res = await fetch("https://api.osv.dev/v1/querybatch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: ECOSYSTEM[p.kind] }, version: p.version })) }),
          signal: AbortSignal.timeout(20_000),
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
      error = `could not reach OSV (${e.message ?? e}); known-malicious check used the cache only`;
    }
  }
  const hits = pkgs.filter((p) => cache[key(p)]?.mal.length).map((p) => ({ item: p, ids: cache[key(p)].mal }));
  return { hits, checked: pkgs.filter((p) => cache[key(p)]).length, error };
}

/** Popular names that attackers imitate. A short list on purpose: the point is to catch near misses. */
const POPULAR: Record<string, string[]> = {
  npm: ["react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "dotenv", "typescript", "webpack", "vite", "eslint", "prettier", "jest", "mocha", "moment", "dayjs", "uuid", "yargs", "inquirer", "request", "node-fetch", "cross-env", "nodemon", "next", "vue", "angular", "svelte", "three", "socket.io", "mongoose", "sequelize", "prisma", "pg", "mysql", "mysql2", "redis", "ioredis", "jsonwebtoken", "bcrypt", "bcryptjs", "colors", "ethers", "web3", "electron", "puppeteer", "playwright", "tailwindcss", "postcss", "babel-cli", "core-js", "rimraf", "glob", "minimist", "semver", "ws", "body-parser", "cors", "helmet", "zod", "openai", "@anthropic-ai/sdk", "pnpm", "yarn", "npm", "bun", "tsx", "ts-node", "esbuild", "rollup", "turbo", "nx", "lerna", "firebase", "aws-sdk", "stripe", "discord.js", "telegraf", "solana", "@solana/web3.js", "bitcoinjs-lib", "tronweb",
    // MCP servers people start through npx; a near miss here runs with the agent's access.
    "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/sdk", "@playwright/mcp", "mcp-remote",
    "@upstash/context7-mcp", "@notionhq/notion-mcp-server", "figma-developer-mcp", "@supabase/mcp-server-supabase", "@stripe/mcp", "chrome-devtools-mcp"],
  pip: ["requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "django", "flask", "fastapi", "pydantic", "boto3", "botocore", "setuptools", "pip", "wheel", "six", "pyyaml", "cryptography", "pycryptodome", "paramiko", "selenium", "beautifulsoup4", "lxml", "pillow", "opencv-python", "torch", "tensorflow", "transformers", "openai", "anthropic", "langchain", "colorama", "termcolor", "click", "rich", "httpx", "aiohttp", "jinja2", "sqlalchemy", "psycopg2", "pymongo", "redis", "celery", "pytest", "black", "ruff", "web3", "solana", "python-dotenv", "discord.py", "telethon", "ccxt", "mcp", "fastmcp", "mcp-server-fetch", "mcp-server-git", "mcp-server-time"],
};

function distance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  if (a.length > 64 || b.length > 64) return 3;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
        i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1] ? dp[i - 2][j - 2] + 1 : 99);
  return dp[a.length][b.length];
}

/** The popular package this name imitates, if it is one edit away (or the same name with a separator trick). */
export function lookAlike(kind: string, name: string): string | undefined {
  const list = POPULAR[kind];
  if (!list) return;
  const n = name.toLowerCase();
  if (list.includes(n)) return;
  const norm = (s: string) => s.replace(/[-_.]/g, "");
  for (const p of list) {
    if (p.length < 4) continue;
    if (norm(p) === norm(n)) return p;
    if (distance(p, n) === 1) return p;
    if (n === `${p}js` || n === `${p}-js` || n === `py${p}` || n === `${p}-py` || n === `${p}2` || n === `${p}s`) return p;
  }
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

