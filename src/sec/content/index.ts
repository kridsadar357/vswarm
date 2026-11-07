// Package contents before an install: the guard downloads the archive the package manager would install (the npm
// tarball, the wheel or sdist pip would pick), checks it against the registry's checksum, unpacks it in memory
// (archive.ts), reads it (scan.ts), compares it with the version before (grade.ts) and, when asked, runs only its
// install scripts in the try sandbox. Nothing in a package is ever run outside the sandbox.
//
// Which packages: the ones named on the command line, and every dependency that has install scripts or was published
// in the last 7 days; --deep reads the whole tree. Popular packages whose version is weeks old and runs no install
// script are not downloaded at all, so the usual install gets no slower. Results are kept per name, version and
// checksum in ~/.vswarm/sec/pkg-content, so each version is read once.
//
// What leaves the machine: the same package names and versions as before, plus downloads of the archives themselves
// from registry.npmjs.org and files.pythonhosted.org. A registry that does not answer is a notice, not a block.

import { createHash } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readJson, sha256 } from "../ctx";
import { SEC } from "../store";
import { RANK, type Finding } from "../types";
import type { Facts, Fetcher, Manifest, PyFile } from "../pkg";
import { LIMITS, readTgz, readZip, stripTop, writeTree, type Archive } from "./archive";
import { grade, type Analysis, type Meta } from "./grade";
import { keepFor, scanPackage, type Kind } from "./scan";

/** Bumped when the scanner changes, so results read by an older one are read again. */
export const SCANNER = 2;
export const CONTENT_DIR = () => join(SEC(), "pkg-content");

const DAY = 86_400_000;
/** Archives larger than this are not downloaded (the registry's own limit for npm is about this size). */
const MAX_DOWNLOAD = 100_000_000;
const ARCHIVE_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com", "files.pythonhosted.org"]);

export interface Target {
  eco: "npm" | "pip";
  name: string;
  version: string;
  /** What the registry said, for packages named on the command line (saves asking again). */
  facts?: Facts;
  /** For a dependency: the package that brings it in. */
  via?: string;
}

export interface ContentOpt {
  get: Fetcher;
  /** npm manifest of one version (pkg.ts npmManifest), and PyPI's project JSON. */
  manifest: (name: string, version: string) => Promise<Manifest | undefined>;
  pypi: (name: string) => Promise<any | undefined>;
  offline?: boolean;
  /** Where results are kept (default ~/.vswarm/sec/pkg-content). */
  dir?: string;
  /** Time for everything, and for one package (download, unpack, read, the version before). */
  budgetMs?: number;
  perPackageMs?: number;
  /** Archives the registry says are bigger than this are not read (default 40 MB; vswarm pkg check reads up to 100 MB). */
  maxBytes?: number;
  /** Compare with the version before (default on). */
  diff?: boolean;
  /** Run install scripts in the try sandbox: for every package that has them, or only where reading found something. */
  sandbox?: "always" | "suspicious";
  /** Keep low findings (vswarm pkg check); the install guard leaves them out. */
  verbose?: boolean;
  now?: number;
}

export interface ContentResult {
  findings: Finding[];
  notes: string[];
  unverified: string[];
  /** name@version of every package whose contents were read. */
  read: string[];
  /** Files and bytes read, for the summary line. */
  files: number;
  bytes: number;
  ms: number;
}

// ── the cache

interface Cached {
  v: number;
  at: number;
  integrity?: string;
  analysis: Analysis;
}

const cachePath = (dir: string, eco: string, name: string, version: string, file: string) => join(dir, `${sha256(`${eco}:${name}@${version}:${file}`).slice(0, 32)}.json`);

function cached(dir: string, eco: string, name: string, version: string, file: string, integrity?: string): Analysis | undefined {
  const c = readJson<Cached>(cachePath(dir, eco, name, version, file), 20_000_000);
  if (!c || c.v !== SCANNER || !c.analysis?.scanned) return;
  // The same name and version with another checksum is another archive: read it again (and integrity decides).
  if (integrity && c.integrity && c.integrity !== integrity) return;
  // Never a read that stopped part way or met a damaged archive, whoever wrote it.
  if (!readClean(c.analysis.scanned)) return;
  return c.analysis;
}

/** Whether an archive was read whole and undamaged: only such a read may stand for the archive later. */
export const readClean = (a: { partial?: string; problems?: Archive["problems"] }) => !a.partial && !(a.problems ?? []).some((p) => p.kind === "damaged" || p.kind === "limit");

function keep(dir: string, a: Analysis, integrity?: string) {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(cachePath(dir, a.meta.eco, a.meta.name, a.meta.version, a.meta.file ?? ""), JSON.stringify({ v: SCANNER, at: Date.now(), integrity, analysis: a } satisfies Cached), { mode: 0o600 });
  } catch {}
}

/** What vswarm learned about dependency versions: install scripts, publish time. Never changes for a version, so kept for good. */
interface DepFacts {
  [key: string]: { s?: 0 | 1; at?: number };
}
const depsFile = (dir: string) => join(dir, "deps.json");
const dirFor = (opt: { dir?: string }) => opt.dir ?? CONTENT_DIR();

// ── checksums

/** Whether bytes match the registry's integrity string (sha512-…, several allowed) or a sha1/sha256 hex digest. */
export function integrityOk(buf: Buffer, want: { integrity?: string; shasum?: string; sha256?: string }): boolean | undefined {
  const sri = (want.integrity ?? "").split(/\s+/).map((x) => /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/=]+)$/.exec(x)).filter(Boolean) as RegExpExecArray[];
  // The strongest one given decides, as npm does.
  const best = ["sha512", "sha384", "sha256", "sha1"].map((alg) => sri.find((m) => m[1] === alg)).find(Boolean);
  if (best) return createHash(best[1]).update(buf).digest("base64") === best[2];
  if (want.sha256) return createHash("sha256").update(buf).digest("hex") === want.sha256.toLowerCase();
  if (want.shasum) return createHash("sha1").update(buf).digest("hex") === want.shasum.toLowerCase();
}

/** A download that stops at `cap` bytes and at the deadline. */
async function download(get: Fetcher, url: string, cap: number, timeoutMs: number): Promise<Buffer> {
  const host = new URL(url).hostname;
  const r = await get(url, { accept: "*/*", timeoutMs });
  if (r.status !== 200) throw new Error(`${host} ${r.status}`);
  const body = (r as any).body as ReadableStream<Uint8Array> | null | undefined;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const parts: Uint8Array[] = [];
    let n = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.length;
      if (n > cap) {
        await reader.cancel().catch(() => {});
        throw new Error(`larger than ${Math.round(cap / 1e6)} MB`);
      }
      parts.push(value);
    }
    return Buffer.concat(parts);
  }
  if (typeof r.arrayBuffer !== "function") throw new Error(`${host}: no archive in the answer`);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > cap) throw new Error(`larger than ${Math.round(cap / 1e6)} MB`);
  return buf;
}

// ── which archive

export interface Artifact {
  url: string;
  file: string;
  kind: Kind;
  integrity?: string;
  shasum?: string;
  sha256?: string;
  /** What the registry says it weighs (npm: unpacked, PyPI: the file). */
  size?: number;
}

/**
 * The file pip would install here: a wheel for this system (pure-Python first, then abi3, then the newest CPython
 * build), else the sdist, else any wheel. Close enough: builds of one version for different systems carry the same
 * Python code.
 */
export function pickPyFile(files: PyFile[], plat: string = process.platform, arch: string = process.arch, prefer?: Kind): PyFile | undefined {
  const wheels = files.filter((f) => f.packagetype === "bdist_wheel" && f.filename.endsWith(".whl"));
  const sdist = files.find((f) => f.packagetype === "sdist" && /\.(tar\.gz|zip)$/.test(f.filename));
  if (prefer === "sdist" && sdist) return sdist;
  const tags = (f: PyFile) => f.filename.replace(/\.whl$/, "").split("-").slice(-3);
  const cpu = arch === "arm64" ? (plat === "darwin" ? "arm64" : "aarch64") : "x86_64";
  const fits = (p: string) =>
    p === "any" ||
    (plat === "darwin" ? /macosx/.test(p) && (p.includes("universal2") || p.includes(cpu)) :
      plat === "linux" ? /manylinux|(^|\.)linux_/.test(p) && p.includes(cpu) :
        plat === "win32" ? p.split(".").includes(arch === "arm64" ? "win_arm64" : "win_amd64") : false);
  const score = (f: PyFile) => {
    const [py, abi, p] = tags(f);
    if (p === "any") return 1000;
    if (abi === "abi3") return 900;
    return Number(/cp3(\d+)/.exec(py)?.[1] ?? 0);
  };
  const fit = wheels.filter((w) => fits(tags(w)[2])).sort((a, b) => score(b) - score(a));
  return fit[0] ?? sdist ?? wheels[0];
}

/** The archive of one version and what the registry says about it. */
async function artifact(t: Target, opt: ContentOpt, prefer?: Kind): Promise<{ art?: Artifact; meta: Meta; versions: { v: string; at?: number }[] }> {
  const meta: Meta = { eco: t.eco, name: t.name, version: t.version };
  if (t.eco === "npm") {
    const m = t.facts?.manifest && t.facts.version === t.version ? t.facts.manifest : await opt.manifest(t.name, t.version);
    if (!m?.dist?.url) return { meta, versions: t.facts?.versionList ?? [] };
    Object.assign(meta, { file: m.dist.url.split("/").pop(), integrity: m.dist.integrity ?? m.dist.shasum, publisher: m.publisher, maintainers: m.maintainers, provenance: m.provenance });
    let versions = t.facts?.versionList;
    if (!versions) {
      const r = await opt.get(`https://api.deps.dev/v3/systems/npm/packages/${encodeURIComponent(t.name)}`).catch(() => undefined);
      const d = r?.status === 200 ? await r.json().catch(() => undefined) : undefined;
      versions = Array.isArray(d?.versions) ? d.versions.map((x: any) => ({ v: String(x?.versionKey?.version), at: x?.publishedAt ? Date.parse(x.publishedAt) : undefined })) : [];
    }
    meta.publishedAt = versions!.find((x) => x.v === t.version)?.at;
    return { art: { url: m.dist.url, file: meta.file!, kind: "npm", integrity: m.dist.integrity, shasum: m.dist.shasum, size: m.dist.size }, meta, versions: versions! };
  }
  const d = t.facts?.pypi ?? (await opt.pypi(t.name));
  const releases: Record<string, PyFile[]> = d?.releases && typeof d.releases === "object" ? d.releases : {};
  const at = (fs: PyFile[]) => Math.min(...fs.map((f) => Date.parse(f.upload_time_iso_8601 ?? f.upload_time ?? "")).filter(Number.isFinite));
  const versions = Object.entries(releases).filter(([, fs]) => Array.isArray(fs) && fs.length).map(([v, fs]) => ({ v, at: at(fs) }));
  const files = releases[t.version] ?? [];
  const f = pickPyFile(files, process.platform, process.arch, prefer);
  meta.publishedAt = versions.find((x) => x.v === t.version)?.at;
  meta.maintainers = Array.isArray(d?.ownership?.roles) ? d.ownership.roles.map((r: any) => String(r?.user)).filter(Boolean) : undefined;
  if (!f?.url) return { meta, versions };
  meta.file = f.filename;
  meta.integrity = f.digests?.sha256;
  return { art: { url: f.url, file: f.filename, kind: f.packagetype === "sdist" ? "sdist" : "wheel", sha256: f.digests?.sha256, size: f.size }, meta, versions };
}

const isPre = (v: string) => /[a-z]/i.test(v.replace(/^v/, "").split("+")[0]);

/** Version order for npm and PyPI alike: numbers as numbers, a pre-release before its release. */
export function compareLoose(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^v/, "").split("+")[0].split(/[.\-_]|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)/i).filter(Boolean);
  const pa = parts(a), pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i], y = pb[i];
    if (x === y) continue;
    if (x === undefined) return /^\d/.test(y) ? -1 : 1;
    if (y === undefined) return /^\d/.test(x) ? 1 : -1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) return Number(x) - Number(y);
    if (nx !== ny) return nx ? 1 : -1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/** The release before this one: the highest lower version, skipping pre-releases unless this is one. */
export function previousVersion(versions: string[], cur: string): string | undefined {
  const pre = isPre(cur);
  return versions.filter((v) => v !== cur && (pre || !isPre(v)) && compareLoose(v, cur) < 0).sort(compareLoose).at(-1);
}

// ── reading one archive

interface Read {
  analysis?: Analysis;
  archive?: Archive;
  findings: Finding[];
  notes: string[];
}

async function readArtifact(meta: Meta, art: Artifact, opt: ContentOpt, deadline: number, keepAll = false): Promise<Read> {
  const lbl = `${meta.eco === "pip" ? "PyPI" : "npm"} ${meta.name}@${meta.version}`;
  const hit = !keepAll ? cached(dirFor(opt), meta.eco, meta.name, meta.version, art.file, art.integrity ?? art.sha256 ?? art.shasum) : undefined;
  if (hit) return { analysis: hit, findings: [], notes: [] };
  if (opt.offline) return { findings: [], notes: [] };
  let host = "";
  try {
    host = new URL(art.url).hostname;
  } catch {}
  if (!ARCHIVE_HOSTS.has(host)) return { findings: [], notes: [`${lbl}: its archive is at ${host || art.url.slice(0, 80)}, not the registry; its contents were not read`] };
  const buf = await download(opt.get, art.url, MAX_DOWNLOAD, Math.max(1000, deadline - Date.now()));
  const ok = integrityOk(buf, art);
  if (ok === false)
    return {
      findings: [{ id: `pkg:integrity:${meta.eco}:${meta.name}@${meta.version}`, rule: "pkg-integrity", severity: "critical", title: `${lbl}: the archive does not match the registry's checksum`,
        detail: [`${art.file} from ${host}`, "why: what you would install is not what the registry published: a tampered mirror or proxy, or a man in the middle"], fix: "do not install; check your registry and proxy settings (npm config get registry), then try again" }],
      notes: [],
    };
  const lim = { ...LIMITS, keep: keepAll ? () => true : keepFor(art.kind), deadline };
  let a = /\.(whl|zip)$/i.test(art.file) ? readZip(buf, lim) : /\.(tgz|tar\.gz)$/i.test(art.file) ? readTgz(buf, lim) : undefined;
  if (!a) return { findings: [], notes: [`${lbl}: ${art.file} is an archive type vswarm does not read`] };
  if (art.kind !== "wheel") a = stripTop(a);
  const analysis: Analysis = { meta, scanned: scanPackage(a, art.kind) };
  // Integrity unknown (no checksum given) or a partial read: not kept, so the next look reads it again.
  if (ok && readClean(a)) keep(dirFor(opt), analysis, art.integrity ?? art.sha256 ?? art.shasum);
  return { analysis, archive: a, findings: [], notes: a.partial ? [`${lbl}: only part of it was read (${a.partial})`] : [] };
}

// ── the install scripts, run in the sandbox

/** The command that runs only this package's install-time code: npm hooks, setup.py, or Python start-up for a .pth. */
export function hookCommand(kind: Kind, hooks: { name: string; cmd: string }[]): string[] | undefined {
  if (kind === "npm") {
    // node-gyp rebuild builds native code; without node-gyp installed it would only fail.
    const run = hooks.filter((h) => !/^node-gyp rebuild/.test(h.cmd)).map((h) => `${h.cmd}`);
    return run.length ? ["/bin/sh", "-c", run.map((c) => `( ${c} )`).join("; ")] : undefined;
  }
  if (kind === "sdist") return hooks.some((h) => h.name === "setup.py") ? ["python3", "setup.py", "--name"] : undefined;
  if (kind === "wheel") return hooks.some((h) => h.name === ".pth") ? ["python3", "-c", "import site, sys; site.addsitedir(sys.argv[1])", "."] : undefined;
}

/** The sandbox runs on macOS and Linux; Windows reads the contents only. */
export const sandboxHere = (plat: string = process.platform) => plat === "darwin" || plat === "linux";

async function sandboxed(a: Analysis, archive: Archive, timeoutMs: number): Promise<{ findings: Finding[]; note?: string }> {
  const lbl = `${a.meta.eco === "pip" ? "PyPI" : "npm"} ${a.meta.name}@${a.meta.version}`;
  const cmd = hookCommand(a.scanned.kind, a.scanned.hooks);
  if (!cmd) return { findings: [], note: `${lbl}: nothing to run in the sandbox (only node-gyp rebuild)` };
  if (!sandboxHere()) return { findings: [], note: `${lbl}: the sandbox check runs on macOS and Linux; on Windows its contents are read, not run` };
  const { makeBox, observe } = await import("../try");
  const { canSandbox } = await import("../try/spawn");
  if (!canSandbox()) return { findings: [], note: `${lbl}: the sandbox is not available here (Linux needs bubblewrap)` };
  const box = makeBox("pkg-");
  try {
    writeTree(archive, box.work);
    const env: Record<string, string> = a.meta.eco === "npm"
      ? { npm_lifecycle_event: "postinstall", npm_package_name: a.meta.name, npm_package_version: a.meta.version, INIT_CWD: box.work, npm_config_user_agent: "npm/10 node/v22 vswarm-sandbox" }
      : {};
    const o = await observe(box, cmd, { net: "none", decoys: true, timeoutMs, env });
    const findings = o.runFindings
      .filter((f) => f.severity !== "info" && f.id !== "try:exit")
      .map((f): Finding => ({ ...f, id: `pkg:sandbox:${f.id}:${a.meta.eco}:${a.meta.name}@${a.meta.version}`, rule: "pkg-sandbox", title: `${lbl}, its install script in the sandbox: ${f.title[0].toLowerCase()}${f.title.slice(1)}`,
        fix: RANK[f.severity] >= RANK.high ? `do not install it; report it: ${a.meta.eco === "npm" ? "https://www.npmjs.com/support" : "https://pypi.org/security/"}` : "read what it tried before installing" }));
    const note = !o.logRead ? `${lbl}: ran its install script in the sandbox, but could not read the ${process.platform === "linux" ? "strace" : "sandbox"} log, so file reads are missing` :
      o.exit !== 0 ? `${lbl}: its install script ${o.timedOut ? "was stopped after the time limit" : `exited with ${o.exit}`} in the sandbox (no network there); what it would do later may be missing` : undefined;
    return { findings, note };
  } finally {
    rmSync(box.dir, { recursive: true, force: true });
  }
}

// ── which dependencies

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      out[k] = await fn(items[k]);
    }
  }));
  return out;
}

/**
 * The dependencies worth reading: those with install scripts or published in the last 7 days (or all, deep). Publish
 * times come in one batch from deps.dev; install scripts from each version's manifest, kept for good once known.
 */
export async function pickDeps(deps: { eco: "npm" | "pip"; name: string; version: string; via?: string }[], opt: ContentOpt & { deep?: boolean }): Promise<{ targets: Target[]; notes: string[] }> {
  const now = opt.now ?? Date.now();
  const notes: string[] = [];
  if (opt.deep) return { targets: deps.slice(0, 400), notes: deps.length > 400 ? [`--deep reads at most 400 packages; ${deps.length - 400} more were not read`] : [] };
  const known: DepFacts = readJson<DepFacts>(depsFile(dirFor(opt)), 50_000_000) ?? {};
  const before = JSON.stringify(known).length;
  const key = (d: { eco: string; name: string; version: string }) => `${d.eco}:${d.name}@${d.version}`;
  const list = deps.slice(0, 2000);
  if (deps.length > 2000) notes.push(`${deps.length - 2000} dependencies past the first 2,000 were not checked for install scripts`);
  // Publish times, in batches of 1,000.
  const noTime = list.filter((d) => known[key(d)]?.at === undefined);
  for (let i = 0; i < noTime.length && !opt.offline; i += 1000) {
    const batch = noTime.slice(i, i + 1000);
    try {
      const r = await opt.get("https://api.deps.dev/v3alpha/versionbatch", {
        method: "POST", timeoutMs: 10_000,
        body: JSON.stringify({ requests: batch.map((d) => ({ versionKey: { system: d.eco === "npm" ? "NPM" : "PYPI", name: d.name, version: d.version } })) }),
      });
      const body = r.status === 200 ? await r.json() : undefined;
      for (const x of Array.isArray(body?.responses) ? body.responses : []) {
        const vk = x?.version?.versionKey;
        if (!vk || !x.version.publishedAt) continue;
        const k = `${vk.system === "NPM" ? "npm" : "pip"}:${vk.name}@${vk.version}`;
        known[k] = { ...known[k], at: Date.parse(x.version.publishedAt) };
      }
    } catch {}
  }
  // Install scripts, from each version's manifest.
  const noScripts = list.filter((d) => known[key(d)]?.s === undefined);
  let failed = 0;
  if (!opt.offline) await pool(noScripts, 24, async (d) => {
    try {
      if (d.eco === "npm") {
        const m = await opt.manifest(d.name, d.version);
        if (m) known[key(d)] = { ...known[key(d)], s: m.scripts.length ? 1 : 0 };
      } else {
        const r = await opt.get(`https://pypi.org/pypi/${encodeURIComponent(d.name)}/${encodeURIComponent(d.version)}/json`);
        const j = r.status === 200 ? await r.json() : undefined;
        const f = Array.isArray(j?.urls) ? pickPyFile(j.urls) : undefined;
        if (f) known[key(d)] = { ...known[key(d)], s: f.packagetype === "sdist" || f.filename.endsWith(".zip") ? 1 : 0 };
      }
    } catch {
      failed++;
    }
  });
  if (failed) notes.push(`could not ask the registry about ${failed} dependenc${failed === 1 ? "y" : "ies"}; ${failed === 1 ? "it was" : "they were"} not checked for install scripts`);
  // Written only when something was learned.
  if (JSON.stringify(known).length !== before) try {
    mkdirSync(dirFor(opt), { recursive: true, mode: 0o700 });
    writeFileSync(depsFile(dirFor(opt)), JSON.stringify(known), { mode: 0o600 });
  } catch {}
  const targets = list.filter((d) => {
    const k = known[key(d)];
    return k?.s === 1 || (k?.at !== undefined && now - k.at < 7 * DAY);
  });
  return { targets: targets.slice(0, 150), notes: targets.length > 150 ? [...notes, `${targets.length - 150} dependencies with install scripts or new versions were not read (limit 150)`] : notes };
}

/** Whether a package named on the command line is worth downloading: not when it is popular, its version weeks old and script-free. */
export function worthReading(eco: "npm" | "pip", f: Facts, now = Date.now()): boolean {
  const hooks = (f.scripts?.length ?? 0) > 0 || !!f.sdistOnly;
  const recent = f.versionAt === undefined || now - f.versionAt < 14 * DAY;
  const known = eco === "npm" ? (f.weeklyDownloads ?? 0) >= 50_000 : f.createdAt !== undefined && now - f.createdAt > 2 * 365 * DAY;
  return hooks || recent || !known;
}

// ── everything together

export async function contentCheck(targets: Target[], opt: ContentOpt): Promise<ContentResult> {
  const t0 = Date.now();
  const now = opt.now ?? t0;
  const deadline = t0 + (opt.budgetMs ?? 20_000);
  const per = opt.perPackageMs ?? 10_000;
  const res: ContentResult = { findings: [], notes: [], unverified: [], read: [], files: 0, bytes: 0, ms: 0 };
  let late = 0;
  const failures: string[] = [];
  await pool(targets, 6, async (t) => {
    if (Date.now() > deadline) return void late++;
    const end = Math.min(deadline, Date.now() + per);
    const lbl = `${t.name}@${t.version}`;
    try {
      const { art, meta, versions } = await artifact(t, opt);
      if (!art) return;
      const max = opt.maxBytes ?? 40_000_000;
      if (art.size !== undefined && art.size > max) {
        res.notes.push(`${lbl}: ${Math.round(art.size / 1e6)} MB, too large to read during an install; read it with: vswarm pkg check ${t.eco} ${t.name}@${t.version}`);
        return;
      }
      const sandbox = opt.sandbox && !opt.offline;
      const cur = await readArtifact(meta, art, opt, end, false);
      res.findings.push(...cur.findings);
      res.notes.push(...cur.notes);
      if (!cur.analysis) return;
      res.read.push(lbl);
      res.files += cur.analysis.scanned.files;
      res.bytes += cur.analysis.scanned.size;
      let prev: Analysis | undefined;
      const pv = opt.diff === false ? undefined : previousVersion(versions.map((x) => x.v), t.version);
      if (pv && Date.now() < end) {
        try {
          const p = await artifact({ eco: t.eco, name: t.name, version: pv, facts: t.facts && { ...t.facts, manifest: undefined } }, opt, art.kind);
          if (p.art && p.art.kind === art.kind && !(p.art.size !== undefined && p.art.size > max)) prev = (await readArtifact(p.meta, p.art, opt, end)).analysis;
        } catch (e: any) {
          res.notes.push(`${lbl}: could not read ${pv} to compare (${e?.message ?? e})`);
        }
      }
      // How old the dependencies it adds are: a brand-new one is how event-stream was poisoned.
      const added = prev ? cur.analysis.scanned.deps.filter((d) => !prev!.scanned.deps.includes(d)).slice(0, 5) : [];
      const newDeps = opt.offline || t.eco !== "npm" ? [] : await Promise.all(added.map(async (name) => {
        try {
          const r = await opt.get(`https://api.deps.dev/v3/systems/npm/packages/${encodeURIComponent(name)}`);
          const d = r.status === 200 ? await r.json() : undefined;
          const times = (Array.isArray(d?.versions) ? d.versions : []).map((x: any) => Date.parse(x?.publishedAt)).filter(Number.isFinite);
          return { name, createdAt: times.length ? Math.min(...times) : undefined };
        } catch {
          return { name };
        }
      }));
      let found = grade(cur.analysis, prev, { now, newDeps });
      if (t.via) for (const f of found) f.detail.push(`pulled in by ${t.via}`);
      const worry = found.some((f) => RANK[f.severity] >= RANK.medium);
      if (sandbox && cur.analysis.scanned.hooks.length && (opt.sandbox === "always" || worry)) {
        // Every file this time, not only the code: the scripts may need their data files.
        const full = await readArtifact(meta, art, opt, Date.now() + 60_000, true);
        if (full.archive) {
          const s = await sandboxed(cur.analysis, full.archive, 60_000);
          found.push(...s.findings);
          if (s.note) res.notes.push(s.note);
        }
      }
      if (!opt.verbose) found = found.filter((f) => RANK[f.severity] >= RANK.medium);
      res.findings.push(...found);
    } catch (e: any) {
      failures.push(`${lbl} (${e?.message ?? e})`);
    }
  });
  if (failures.length) {
    res.notes.push(`could not read the contents of ${failures.slice(0, 3).join(", ")}${failures.length > 3 ? ` and ${failures.length - 3} more` : ""}; judged by registry facts only`);
    res.unverified.push(`the contents of ${failures.length} package${failures.length === 1 ? "" : "s"} could not be read`);
  }
  if (late) {
    res.notes.push(`ran out of time: the contents of ${late} package${late === 1 ? " was" : "s were"} not read (vswarm pkg check reads them without a time limit)`);
    res.unverified.push(`${late} package${late === 1 ? "" : "s"} not read in time`);
  }
  res.ms = Date.now() - t0;
  return res;
}

/** For tests and `pkg check --json`: one archive read from bytes, as the guard would (no network). */
export function analyseBytes(buf: Buffer, meta: Meta, kind: Kind): Analysis {
  const lim = { ...LIMITS, keep: keepFor(kind) };
  let a = kind === "npm" || kind === "sdist" ? (meta.file?.endsWith(".zip") ? readZip(buf, lim) : readTgz(buf, lim)) : readZip(buf, lim);
  if (kind !== "wheel") a = stripTop(a);
  return { meta, scanned: scanPackage(a, kind) };
}
