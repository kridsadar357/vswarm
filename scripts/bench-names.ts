// How well the install guard's offline name checks catch real malicious packages, and how often they flag real ones.
//   bun scripts/bench-names.ts [--cache dir] [--refresh] [--only npm|pip] [--fixture] [--json]
//
// Data (all public, all metadata; no package code is ever downloaded):
//   malicious   OSV's per-ecosystem exports (https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip), of which
//               only the MAL-* records are read: OpenSSF malicious-packages reports, one JSON file per package
//   legitimate  the same rankings scripts/popular.ts builds popular.json from: npm-high-impact (npm, by weekly
//               downloads) and hugovk's top-pypi-packages (PyPI, 30 days of downloads); the ranks popular.json does not
//               contain are the false-positive sample
//
// What is measured is lookAlike() and nameSignals() from src/sec/intel.ts, the checks `vswarm pkg` makes without a
// network. The OSV lookup is left out on purpose: it would find every one of these names by definition.
// Downloads are cached (default: <tmp>/vswarm-bench, about 260 MB); nothing big is ever committed. --fixture writes a
// small sample to test/fixtures/bench/names.json, which the test suite measures offline.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateRawSync } from "node:zlib";
import { lookAlike, nameSignals, normName } from "../src/sec/intel";

const NPM_HIGH_IMPACT = "1.13.0";
const SOURCES = {
  npmMal: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
  pipMal: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
  npmTop: `https://unpkg.com/npm-high-impact@${NPM_HIGH_IMPACT}/lib/top.js`,
  pipTop: "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
};

// ── reading a zip without unpacking it (OSV's exports have 200 000+ entries, so the zip64 end record is read too)

export function* zipEntries(buf: Buffer): Generator<{ name: string; data: () => Buffer }> {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) if (buf.readUInt32LE(i) === 0x06054b50) (eocd = i), (i = -1);
  if (eocd < 0) throw new Error("not a zip file");
  let count = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  if ((count === 0xffff || offset === 0xffffffff) && buf.readUInt32LE(eocd - 20) === 0x07064b50) {
    const z64 = Number(buf.readBigUInt64LE(eocd - 20 + 8));
    count = Number(buf.readBigUInt64LE(z64 + 32));
    offset = Number(buf.readBigUInt64LE(z64 + 48));
  }
  let p = offset;
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error(`bad central directory entry ${n}`);
    const method = buf.readUInt16LE(p + 10);
    let size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28), extraLen = buf.readUInt16LE(p + 30), commentLen = buf.readUInt16LE(p + 32);
    let local = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    // zip64 extra field: the 64-bit values, in order, for each 32-bit one that is 0xffffffff.
    for (let e = p + 46 + nameLen; e < p + 46 + nameLen + extraLen; ) {
      const id = buf.readUInt16LE(e), len = buf.readUInt16LE(e + 2);
      if (id === 1) {
        let q = e + 4;
        if (buf.readUInt32LE(p + 24) === 0xffffffff) q += 8;
        if (size === 0xffffffff) (size = Number(buf.readBigUInt64LE(q))), (q += 8);
        if (local === 0xffffffff) local = Number(buf.readBigUInt64LE(q));
      }
      e += 4 + len;
    }
    p += 46 + nameLen + extraLen + commentLen;
    const at = local, csize = size;
    yield {
      name,
      data: () => {
        const start = at + 30 + buf.readUInt16LE(at + 26) + buf.readUInt16LE(at + 28);
        const raw = buf.subarray(start, start + csize);
        return method === 0 ? raw : inflateRawSync(raw);
      },
    };
  }
}

// ── techniques, as the advisories describe them

const SPAM = "spam (tea.xyz farming)";

/**
 * What an advisory says the package is, when it says so; most say only "Malicious code in X". The package's own name
 * is taken out first (typography is no typo), and so is the sentence GitHub's advisories end with ("should be
 * considered fully compromised"), which says nothing about how the package got there.
 */
export function technique(text: string, name = ""): string {
  let t = (name ? text.split(name).join("<name>") : text).toLowerCase();
  t = t.replace(/any computer that has this package installed or running should be considered fully compromised[^.]*\./g, "");
  // tea.xyz token farming: over half of npm's MAL- records, published to inflate a reward score, not to attack installers.
  if (/tea\.xyz|tea protocol|tea\.yaml|token[- ]farming|\bspam packages?\b/.test(t)) return SPAM;
  // "exfiltrates basic information about the host, and the package has no other purpose" is how one reporter
  // describes the recon beacons of dependency-confusion probing.
  if (/dependency[- ]confusion|namespace confusion|exfiltrates basic information about the host/.test(t)) return "dependency confusion";
  if (/starjack/.test(t)) return "starjacking";
  if (/typo-?squat|misspel|typo of|similar(ly)? name|look-?alike|mimics? (the )?(popular|legitimate)/.test(t)) return "typosquat";
  if (/impersonat|brandjack|masquerad|pretend(s|ing) to be/.test(t)) return "impersonation";
  if (/compromised (maintainer|account|npm account|version|release)|account takeover|hijacked (version|release|account)/.test(t)) return "compromised release";
  return "unspecified";
}

export interface MalName {
  name: string;
  technique: string;
}

/** Unique malicious names per ecosystem from an OSV export, with the most specific technique any of its records names. */
export function malicious(zip: Buffer, eco: "npm" | "pip"): MalName[] {
  const want = eco === "npm" ? "npm" : "PyPI";
  const byName = new Map<string, string>();
  for (const e of zipEntries(zip)) {
    if (!/^MAL-[\w-]+\.json$/.test(e.name)) continue;
    let rec: any;
    try {
      rec = JSON.parse(e.data().toString("utf8"));
    } catch {
      continue;
    }
    for (const a of rec.affected ?? []) {
      if (a?.package?.ecosystem !== want || typeof a.package.name !== "string") continue;
      const tech = technique(`${rec.summary ?? ""}\n${rec.details ?? ""}`, a.package.name);
      const n = normName(eco, a.package.name);
      const prev = byName.get(n);
      if (!prev || prev === "unspecified") byName.set(n, tech);
    }
  }
  return [...byName].map(([name, technique]) => ({ name, technique }));
}

// ── the measurement

/** Whether the offline name checks would stop this name, and why. */
export function flagged(eco: "npm" | "pip", name: string): string | undefined {
  const like = lookAlike(eco, name);
  if (like) return `looks like ${like}`;
  return nameSignals(eco, name)[0];
}

export interface Rates {
  total: number;
  hit: number;
  rate: number;
}
const rate = (hit: number, total: number): Rates => ({ total, hit, rate: total ? hit / total : 0 });

export function measure(eco: "npm" | "pip", mal: MalName[], legit: string[]) {
  const legitSet = new Set(legit);
  // A name that is also on the download ranking was a real package whose release was poisoned (or reclaimed): no name
  // check can see that, and it is reported apart instead of counted as a miss.
  const ranked = mal.filter((m) => legitSet.has(m.name));
  const named = mal.filter((m) => !legitSet.has(m.name));
  const byTech: Record<string, Rates> = {};
  let hit = 0;
  for (const m of named) {
    const f = flagged(eco, m.name) ? 1 : 0;
    hit += f;
    const r = (byTech[m.technique] ??= { total: 0, hit: 0, rate: 0 });
    r.total++;
    r.hit += f;
  }
  for (const r of Object.values(byTech)) r.rate = r.total ? r.hit / r.total : 0;
  const fpHits = legit.filter((n) => flagged(eco, n));
  // tea.xyz farming packages are malicious by the registry's rules but attack nobody; the rate without them is the one
  // that says something about attacks.
  const spam = byTech[SPAM] ?? { total: 0, hit: 0, rate: 0 };
  return {
    detection: rate(hit, named.length), withoutSpam: rate(hit - spam.hit, named.length - spam.total), byTechnique: byTech, rankedMalicious: ranked.length,
    falsePositives: rate(fpHits.length, legit.length), fpExamples: fpHits.slice(0, 30),
  };
}

// ── the data

async function cached(dir: string, file: string, url: string, refresh: boolean): Promise<Buffer> {
  const path = join(dir, file);
  if (!refresh && existsSync(path)) return readFileSync(path);
  process.stderr.write(`downloading ${url} …\n`);
  const r = await fetch(url, { headers: { "user-agent": "vswarm scripts/bench-names.ts" } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  writeFileSync(path, buf);
  return buf;
}

/** The download rankings, most used first, as registry names. */
export function rankings(npmTop: string, pipTop: string): { npm: string[]; pip: string[] } {
  // `export const top = ['semver', …]`, read as data (never imported or run).
  const npm = [...new Set([...npmTop.matchAll(/^\s*'((?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+)',?$/gm)].map((m) => normName("npm", m[1])))];
  const pip = [...new Set((JSON.parse(pipTop).rows as { project: string }[]).map((r) => normName("pip", r.project)))];
  return { npm, pip };
}

/** A stable pseudo-random order: the same sample every time from the same data. */
const shuffle = <T>(xs: T[], key: (x: T) => string) => [...xs].sort((a, b) => (createHash("sha1").update(key(a)).digest("hex") < createHash("sha1").update(key(b)).digest("hex") ? -1 : 1));

export interface Fixture {
  generated: string;
  sources: Record<string, string>;
  npm: { malicious: MalName[]; legit: string[] };
  pip: { malicious: MalName[]; legit: string[] };
  /** What the full data measured when the fixture was written, for the record. */
  full: unknown;
  /** What this sample measured then: the test suite fails if detection drops below it or false positives rise above it. */
  sample: Record<"npm" | "pip", { detection: number; falsePositives: number }>;
}

if (import.meta.main) {
  const args = process.argv.slice(2);
  const opt = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
  const dir = opt("--cache") ?? process.env.VSWARM_BENCH_CACHE ?? join(tmpdir(), "vswarm-bench");
  const refresh = args.includes("--refresh");
  mkdirSync(dir, { recursive: true });
  const [npmZip, pipZip, npmTop, pipTop] = await Promise.all([
    cached(dir, "osv-npm.zip", SOURCES.npmMal, refresh),
    cached(dir, "osv-pypi.zip", SOURCES.pipMal, refresh),
    cached(dir, "npm-top.js", SOURCES.npmTop, refresh),
    cached(dir, "pypi-top.json", SOURCES.pipTop, refresh),
  ]);
  const top = rankings(npmTop.toString("utf8"), pipTop.toString("utf8"));
  const popular = JSON.parse(readFileSync(join(import.meta.dir, "../src/sec/data/popular.json"), "utf8"));
  const inPopular = { npm: popular.npm.length as number, pip: popular.pip.length as number };
  // Reading 230 000 zip entries takes a while; the names and techniques are kept beside the zip they came from.
  const parsed = (eco: "npm" | "pip", zip: Buffer): MalName[] => {
    const file = join(dir, `mal-${eco}.json`);
    const key = createHash("sha256").update(zip).digest("hex");
    const prev = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : undefined;
    // The classifier's own source is part of the key, so a changed classifier reads the records again.
    const v = createHash("sha256").update(technique.toString()).digest("hex").slice(0, 12);
    if (prev?.key === key && prev.v === v) return prev.names;
    const names = malicious(zip, eco);
    writeFileSync(file, JSON.stringify({ key, v, names }));
    return names;
  };
  const mal = { npm: parsed("npm", npmZip), pip: parsed("pip", pipZip) };
  const pipLast = JSON.parse(pipTop.toString("utf8")).last_update;
  const result: Record<string, any> = { date: new Date().toISOString().slice(0, 10), pypiRankingDate: pipLast };
  const ecos = (opt("--only") ? [opt("--only")] : ["npm", "pip"]) as ("npm" | "pip")[];
  for (const eco of ecos) {
    // Everything ranked below what popular.json holds: names the look-alike list does not contain.
    const legit = top[eco].slice(inPopular[eco]);
    result[eco] = { legitRanks: `${inPopular[eco] + 1}-${top[eco].length}`, maliciousNames: mal[eco].length, ...measure(eco, mal[eco], legit) };
    // One fixed band for both, ranks 5,001 and below, so lists of different lengths compare on the same names.
    result[eco].falsePositives5k = measure(eco, [], top[eco].slice(5000)).falsePositives;
  }
  if (args.includes("--json")) console.log(JSON.stringify(result, null, 1));
  else {
    const pct = (r: Rates) => `${(r.rate * 100).toFixed(1)}% (${r.hit}/${r.total})`;
    for (const eco of ecos) {
      const r = result[eco];
      console.log(`\n${eco === "pip" ? "PyPI" : "npm"}: ${r.maliciousNames} malicious names in OSV MAL- records, ${r.rankedMalicious} of them also on the download ranking (poisoned releases, left out)`);
      console.log(`  caught by name alone   ${pct(r.detection)} · without tea.xyz spam ${pct(r.withoutSpam)}`);
      for (const [t, x] of Object.entries<Rates>(r.byTechnique).sort((a, b) => b[1].total - a[1].total)) console.log(`    ${t.padEnd(22)} ${pct(x)}`);
      console.log(`  false positives        ${pct(r.falsePositives)} of ranks ${r.legitRanks} · of ranks 5001-${top[eco].length}: ${pct(r.falsePositives5k)}`);
      console.log(`    e.g. ${r.fpExamples.slice(0, 12).join(", ")}`);
    }
  }
  writeFileSync(join(dir, "result.json"), JSON.stringify(result, null, 1));
  if (args.includes("--fixture")) {
    if (ecos.length < 2) throw new Error("--fixture needs both ecosystems (no --only)");
    // Up to 60 names of each technique an advisory names, 300 of the rest; legitimate names sampled likewise.
    const sample = (eco: "npm" | "pip") => {
      const legitSet = new Set(top[eco]);
      const named = mal[eco].filter((m) => !legitSet.has(m.name));
      const techs = [...new Set(named.map((m) => m.technique))];
      const picked = techs.flatMap((t) => shuffle(named.filter((m) => m.technique === t), (m) => m.name).slice(0, t === "unspecified" ? 300 : 60));
      return { malicious: picked.sort((a, b) => a.name.localeCompare(b.name)), legit: shuffle(top[eco].slice(inPopular[eco]), (n) => n).slice(0, 1000).sort() };
    };
    const s = { npm: sample("npm"), pip: sample("pip") };
    const onSample = (eco: "npm" | "pip") => {
      const m = measure(eco, s[eco].malicious, s[eco].legit);
      return { detection: m.detection.rate, falsePositives: m.falsePositives.rate };
    };
    const fixture: Fixture = {
      generated: result.date,
      sources: { ...SOURCES, pypiRanking: pipLast },
      npm: s.npm,
      pip: s.pip,
      full: { npm: { detection: result.npm.detection, withoutSpam: result.npm.withoutSpam, falsePositives: result.npm.falsePositives }, pip: { detection: result.pip.detection, falsePositives: result.pip.falsePositives } },
      sample: { npm: onSample("npm"), pip: onSample("pip") },
    };
    const out = join(import.meta.dir, "../test/fixtures/bench/names.json");
    mkdirSync(join(out, ".."), { recursive: true });
    writeFileSync(out, JSON.stringify(fixture, null, 0).replace(/\},\{/g, "},\n{") + "\n");
    console.log(`\nwrote ${out}`);
  }
}
