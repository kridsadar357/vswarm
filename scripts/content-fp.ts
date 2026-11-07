// False alarms of package content analysis, measured: reads the most-downloaded npm and PyPI packages, and the big
// ones known for install scripts and native builds, the way the install guard would (this version and the one
// before it), and lists every package that would warn or stop.
//   VSWARM_SEC_DIR=<a scratch folder> bun scripts/content-fp.ts [npm count] [pypi count] [--json]
// It downloads archives from registry.npmjs.org and files.pythonhosted.org and reads them; nothing in them runs.

import { join } from "node:path";
import { contentCheck } from "../src/sec/content";
import { npmFacts, npmManifest, pipFacts, pypiProject } from "../src/sec/pkg";
import { RANK } from "../src/sec/types";

if (!process.env.VSWARM_SEC_DIR) throw new Error("set VSWARM_SEC_DIR to a scratch folder: results are cached there");
const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const [npmCount = 200, pypiCount = 100] = args.map(Number);
const popular = await Bun.file(join(import.meta.dir, "../src/sec/data/popular.json")).json();

/** Packages with install scripts, native builds or binaries that a content check must not stop. */
const KNOWN_HEAVY = {
  npm: ["esbuild", "sharp", "puppeteer", "bcrypt", "prisma", "@prisma/engines", "@prisma/client", "playwright", "playwright-core", "cypress", "electron", "node-gyp",
    "better-sqlite3", "sqlite3", "canvas", "node-sass", "@swc/core", "core-js", "protobufjs", "husky", "nodemon", "fsevents", "@sentry/cli", "node-pty", "re2",
    "bufferutil", "utf-8-validate", "msgpackr-extract", "@parcel/watcher", "lmdb", "@vscode/ripgrep", "es5-ext", "turbo", "@biomejs/biome", "@tailwindcss/oxide",
    "deasync", "grpc-tools", "@grpc/grpc-js", "argon2", "keytar", "ssh2", "cpu-features", "aws-sdk", "@aws-sdk/credential-providers", "dotenv", "discord.js"],
  pip: ["numpy", "cryptography", "grpcio", "grpcio-tools", "pandas", "torch", "tensorflow", "psycopg2", "psycopg2-binary", "pywin32", "setuptools", "protobuf",
    "pillow", "lxml", "pyyaml", "matplotlib", "scipy", "bcrypt", "pynacl", "cffi", "uvloop", "orjson", "pydantic-core", "mysqlclient", "pycryptodome", "playwright",
    "paramiko", "boto3", "google-cloud-storage", "coverage"],
};

const get = (url: string, init: any = {}) => fetch(url, { method: init.method, body: init.body, headers: { accept: init.accept ?? "application/json", "user-agent": "vswarm scripts/content-fp.ts", ...(init.body ? { "content-type": "application/json" } : {}) }, signal: AbortSignal.timeout(init.timeoutMs ?? 30_000) });
const opt = { get, manifest: (n: string, v: string) => npmManifest(n, v, get), pypi: (n: string) => pypiProject(n, get), budgetMs: 3_600_000, perPackageMs: 300_000, maxBytes: 100_000_000 };

const list = [
  ...[...new Set([...popular.npm.slice(0, npmCount), ...KNOWN_HEAVY.npm])].map((name) => ({ eco: "npm" as const, name })),
  ...[...new Set([...popular.pip.slice(0, pypiCount), ...KNOWN_HEAVY.pip])].map((name) => ({ eco: "pip" as const, name })),
];

const rows: { eco: string; name: string; version?: string; top?: string; findings: string[]; error?: string; ms: number }[] = [];
let i = 0;
await Promise.all(Array.from({ length: 8 }, async () => {
  while (i < list.length) {
    const p = list[i++];
    const t0 = Date.now();
    try {
      const f = await (p.eco === "npm" ? npmFacts : pipFacts)(p.name, undefined, get);
      if (!f.exists || !f.version) throw new Error("not found");
      const r = await contentCheck([{ eco: p.eco, name: p.name, version: f.version, facts: f }], { ...opt, verbose: true });
      const worst = r.findings.reduce((w, x) => Math.max(w, RANK[x.severity]), -1);
      rows.push({ eco: p.eco, name: p.name, version: f.version, top: ["", "low", "medium", "high", "critical"][worst] || undefined,
        findings: r.findings.map((x) => `${x.severity}: ${x.title}`), error: r.notes.join("; ") || undefined, ms: Date.now() - t0 });
    } catch (e: any) {
      rows.push({ eco: p.eco, name: p.name, findings: [], error: String(e?.message ?? e), ms: Date.now() - t0 });
    }
  }
}));

rows.sort((a, b) => a.eco.localeCompare(b.eco) || a.name.localeCompare(b.name));
if (process.argv.includes("--json")) console.log(JSON.stringify(rows, null, 1));
for (const eco of ["npm", "pip"]) {
  const mine = rows.filter((r) => r.eco === eco && !r.error?.startsWith("not found"));
  const read = mine.filter((r) => r.version);
  const by = (s: string) => read.filter((r) => r.top === s);
  console.log(`\n${eco}: ${read.length} read · stop (high+) ${by("high").length + by("critical").length} · warn (medium) ${by("medium").length} · low only ${by("low").length} · clean ${read.filter((r) => !r.top).length}`);
  for (const r of read.filter((r) => r.top && RANK[r.top as "low"] >= RANK.medium)) console.log(`  ${r.top!.toUpperCase().padEnd(8)} ${r.name}@${r.version}\n${r.findings.filter((x) => !x.startsWith("low")).map((x) => `           ${x}`).join("\n")}`);
  for (const r of mine.filter((r) => r.error)) console.log(`  note     ${r.name}: ${r.error}`);
}
