// Package archives, read without running anything in them: npm tarballs (.tgz), PyPI source distributions (.tar.gz,
// .zip) and wheels (.whl). vswarm reads them itself, in memory, instead of handing them to tar or unzip, so a crafted
// archive meets limits it cannot talk its way past:
//   size     what it unpacks to is capped before it is unpacked (gzip and deflate stop at the cap: a zip bomb stops there)
//   count    so many entries and no more
//   paths    absolute names, drive letters and `..` are refused and reported; nothing is ever written outside its folder
//   links    symbolic and hard links, devices and FIFOs are never created, only reported
//   time     a deadline, checked as it goes
// Only the files a check needs are kept in memory (`keep`); the rest are counted.

import { mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { gunzipSync, inflateRawSync } from "node:zlib";

export interface Entry {
  /** Forward slashes, no leading folder (npm's package/, an sdist's name-version/), never `..`. */
  path: string;
  size: number;
  /** Unix permission bits when the archive has them. */
  mode: number;
  /** The first bytes, for telling programs from text. */
  head: Buffer;
  /** The contents, when `keep` asked for them; cut at `maxKeep` (then `cut` is set). */
  data?: Buffer;
  cut?: boolean;
}

export interface Problem {
  kind: "traversal" | "link" | "special" | "limit" | "damaged" | "encrypted";
  path: string;
  detail?: string;
}

export interface Archive {
  entries: Entry[];
  problems: Problem[];
  /** Bytes it unpacks to (files only). */
  total: number;
  /** Why only part of it was read (a limit, a deadline, a damaged archive). */
  partial?: string;
}

export interface Limits {
  /** Most bytes the archive may unpack to. */
  maxUnpacked: number;
  maxFiles: number;
  /** Most bytes kept of one file. */
  maxKeep: number;
  /** Whether a file's contents are kept (the rest are only counted). */
  keep: (path: string, size: number) => boolean;
  /** Date.now() past which reading stops. */
  deadline: number;
}

export const LIMITS: Limits = { maxUnpacked: 256_000_000, maxFiles: 30_000, maxKeep: 12_000_000, keep: () => true, deadline: Infinity };

/**
 * A name from an archive as a safe relative path, or undefined when it points outside (absolute, a drive letter,
 * `..`). Backslashes count as separators: on Windows they are, and a name that means one thing on each system is not
 * worth keeping apart.
 */
export function safePath(name: string): string | undefined {
  const p = name.replace(/\\/g, "/");
  if (p.startsWith("/") || /^[A-Za-z]:/.test(p) || p.includes("\0")) return;
  const parts = p.split("/").filter((s) => s && s !== ".");
  if (!parts.length || parts.includes("..")) return;
  return parts.join("/");
}

/** Where a link points, read against the folder it sits in: inside the package or not. */
function linkLeaves(path: string, target: string): boolean {
  if (target.startsWith("/") || target.startsWith("\\") || /^[A-Za-z]:/.test(target)) return true;
  let depth = path.split("/").length - 1;
  for (const s of target.replace(/\\/g, "/").split("/")) {
    if (s === "..") depth--;
    else if (s && s !== ".") depth++;
    if (depth < 0) return true;
  }
  return false;
}

class Reader {
  entries = new Map<string, Entry>();
  problems: Problem[] = [];
  total = 0;
  partial?: string;
  count = 0;
  constructor(readonly lim: Limits) {}

  /** False when reading must stop. */
  file(rawName: string, size: number, mode: number, body: (keep: boolean) => Buffer): boolean {
    if (++this.count > this.lim.maxFiles) return this.stop(`more than ${this.lim.maxFiles} files`);
    if (this.count % 256 === 0 && Date.now() > this.lim.deadline) return this.stop("ran out of time");
    const path = safePath(rawName);
    if (!path) {
      this.problems.push({ kind: "traversal", path: rawName.slice(0, 200) });
      return true;
    }
    this.total += size;
    if (this.total > this.lim.maxUnpacked) return this.stop(`unpacks to more than ${Math.round(this.lim.maxUnpacked / 1e6)} MB`);
    const keep = this.lim.keep(path, size);
    const data = body(keep);
    // The last entry of a name wins, as it does when tar unpacks it.
    this.entries.set(path, {
      path, size, mode, head: Buffer.from(data.subarray(0, 8)),
      ...(keep ? { data: Buffer.from(data.subarray(0, this.lim.maxKeep)), cut: data.length > this.lim.maxKeep } : {}),
    });
    return true;
  }

  link(rawName: string, target: string, hard: boolean) {
    const path = safePath(rawName) ?? rawName.slice(0, 200);
    this.problems.push({ kind: "link", path, detail: `${hard ? "hard link" : "symlink"} to ${target.slice(0, 200)}${linkLeaves(path, target) ? " (outside the package)" : ""}` });
  }

  stop(why: string): false {
    this.partial ??= why;
    this.problems.push({ kind: "limit", path: "", detail: why });
    return false;
  }

  done(): Archive {
    return { entries: [...this.entries.values()], problems: this.problems, total: this.total, partial: this.partial };
  }
}

const str = (b: Buffer, at: number, len: number) => {
  const s = b.subarray(at, at + len);
  const nul = s.indexOf(0);
  return s.subarray(0, nul < 0 ? s.length : nul).toString("utf8");
};

/** A tar number: octal text, or base-256 when the top bit is set (GNU, for sizes past 8 GB). */
function tarNum(b: Buffer, at: number, len: number): number {
  if (b[at] & 0x80) {
    let n = b[at] & 0x7f;
    for (let i = 1; i < len; i++) n = n * 256 + b[at + i];
    return n;
  }
  const t = str(b, at, len).trim();
  return t ? parseInt(t, 8) : 0;
}

/** pax extended header records: "<len> key=value\n". */
function pax(data: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let i = 0;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    if (sp < 0) break;
    const len = Number(data.subarray(i, sp).toString());
    if (!Number.isInteger(len) || len <= 0 || i + len > data.length) break;
    const rec = data.subarray(sp + 1, i + len - 1).toString("utf8");
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

export function readTar(buf: Buffer, lim: Limits = LIMITS): Archive {
  const r = new Reader(lim);
  let off = 0;
  let next: { path?: string; link?: string } = {};
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h[0] === 0 && h.every((x) => x === 0)) break;
    // The checksum counts its own field as spaces; anything else is not a tar header.
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
    if (sum !== tarNum(h, 148, 8)) {
      r.problems.push({ kind: "damaged", path: "", detail: `bad header at byte ${off}` });
      r.partial ??= "the archive is damaged";
      break;
    }
    const size = tarNum(h, 124, 12);
    const type = h[156] === 0 ? "0" : String.fromCharCode(h[156]);
    const ustar = h.subarray(257, 262).toString("latin1") === "ustar";
    const prefix = ustar ? str(h, 345, 155) : "";
    const name = (prefix ? `${prefix}/` : "") + str(h, 0, 100);
    const start = off + 512;
    if (start + size > buf.length) {
      r.problems.push({ kind: "damaged", path: name.slice(0, 200), detail: "cut short" });
      r.partial ??= "the archive is cut short";
      break;
    }
    const data = buf.subarray(start, start + size);
    off = start + Math.ceil(size / 512) * 512;
    if (type === "x") {
      const p = pax(data);
      next = { path: p.path ?? next.path, link: p.linkpath ?? next.link };
      continue;
    }
    if (type === "g") continue;
    if (type === "L") {
      next.path = str(data, 0, data.length);
      continue;
    }
    if (type === "K") {
      next.link = str(data, 0, data.length);
      continue;
    }
    const path = next.path ?? name;
    const link = next.link ?? str(h, 157, 100);
    next = {};
    if (type === "5") continue;
    if (type === "1" || type === "2") {
      r.link(path, link, type === "1");
      continue;
    }
    if (type !== "0" && type !== "7") {
      r.problems.push({ kind: "special", path: safePath(path) ?? path.slice(0, 200), detail: `entry of type ${JSON.stringify(type)}` });
      continue;
    }
    if (!r.file(path, size, tarNum(h, 100, 8) & 0o7777, () => data)) break;
  }
  return r.done();
}

export function readTgz(buf: Buffer, lim: Limits = LIMITS): Archive {
  let tar: Buffer;
  try {
    // A tar is a little larger than what it holds (512-byte headers and padding).
    tar = gunzipSync(buf, { maxOutputLength: lim.maxUnpacked + Math.min(lim.maxFiles, 30_000) * 1024 + 1_048_576 });
  } catch (e: any) {
    const why = e?.code === "ERR_BUFFER_TOO_LARGE" ? `unpacks to more than ${Math.round(lim.maxUnpacked / 1e6)} MB` : "not a gzip file";
    return { entries: [], problems: [{ kind: e?.code === "ERR_BUFFER_TOO_LARGE" ? "limit" : "damaged", path: "", detail: why }], total: 0, partial: why };
  }
  return readTar(tar, lim);
}

export function readZip(buf: Buffer, lim: Limits = LIMITS): Archive {
  const r = new Reader(lim);
  const damaged = (detail: string) => {
    r.problems.push({ kind: "damaged", path: "", detail });
    r.partial ??= "the archive is damaged";
    return r.done();
  };
  // The end-of-central-directory record: 22 bytes, plus a comment of up to 64 KB.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return damaged("not a zip file");
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  if (p === 0xffffffff || count === 0xffff) {
    r.stop("a ZIP64 archive (over 4 GB or 65,535 files), which vswarm does not read");
    return r.done();
  }
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) return damaged("bad central directory");
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const ext = buf.readUInt32LE(p + 38);
    const lho = buf.readUInt32LE(p + 42);
    if (p + 46 + nlen > buf.length) return damaged("bad central directory");
    const name = buf.toString("utf8", p + 46, p + 46 + nlen);
    p += 46 + nlen + xlen + clen;
    const mode = ext >>> 16;
    if (name.endsWith("/") || (mode & 0o170000) === 0o040000) continue;
    if ((mode & 0o170000) === 0o120000) {
      r.link(name, readLocal(buf, lho, csize)?.toString("utf8").slice(0, 300) ?? "?", false);
      continue;
    }
    if (flags & 1) {
      r.problems.push({ kind: "encrypted", path: safePath(name) ?? name.slice(0, 200) });
      continue;
    }
    let bad: string | undefined;
    const ok = r.file(name, usize, mode & 0o7777, (keep) => {
      const raw = readLocal(buf, lho, csize);
      // A file nobody reads is counted, not inflated.
      if (!keep && raw && method !== 0) return Buffer.alloc(0);
      if (!raw) return ((bad = "bad local header"), Buffer.alloc(0));
      if (method === 0) return raw;
      if (method !== 8) return ((bad = `compression method ${method}`), Buffer.alloc(0));
      try {
        // Inflating past the size the directory declares is a bomb or a lie; either way it stops at that size.
        return inflateRawSync(raw, { maxOutputLength: Math.max(usize, 1) });
      } catch {
        bad = "inflates past its declared size, or is damaged";
        return Buffer.alloc(0);
      }
    });
    if (bad) r.problems.push({ kind: "damaged", path: safePath(name) ?? name.slice(0, 200), detail: bad });
    if (!ok) break;
  }
  return r.done();
}

function readLocal(buf: Buffer, at: number, csize: number): Buffer | undefined {
  if (at + 30 > buf.length || buf.readUInt32LE(at) !== 0x04034b50) return;
  const start = at + 30 + buf.readUInt16LE(at + 26) + buf.readUInt16LE(at + 28);
  if (start + csize > buf.length) return;
  return buf.subarray(start, start + csize);
}

/** Drops the one folder every entry sits in (npm's package/, an sdist's name-1.0/), as npm and pip do. */
export function stripTop(a: Archive): Archive {
  const tops = new Set(a.entries.map((e) => e.path.split("/")[0]));
  if (tops.size !== 1 || a.entries.some((e) => !e.path.includes("/"))) return a;
  return { ...a, entries: a.entries.map((e) => ({ ...e, path: e.path.slice(e.path.indexOf("/") + 1) })) };
}

/**
 * Writes the kept files under `root`, for the sandbox to run. Only regular files, never over an existing one (a
 * second entry of the same name, or one that differs only by case on macOS, is skipped), and each path is checked to
 * stay inside `root` after its folders are made.
 */
export function writeTree(a: Archive, root: string): string[] {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const top = realpathSync(root);
  const skipped: string[] = [];
  for (const e of a.entries) {
    if (!e.data || e.cut) {
      skipped.push(e.path);
      continue;
    }
    const dest = resolve(top, ...e.path.split("/"));
    if (!dest.startsWith(top + sep)) {
      skipped.push(e.path);
      continue;
    }
    try {
      mkdirSync(dirname(dest), { recursive: true, mode: 0o700 });
      const parent = realpathSync(dirname(dest));
      if (parent !== top && !parent.startsWith(top + sep)) throw new Error("outside");
      writeFileSync(dest, e.data, { flag: "wx", mode: e.mode & 0o111 ? 0o700 : 0o600 });
    } catch {
      skipped.push(e.path);
    }
  }
  return skipped;
}
