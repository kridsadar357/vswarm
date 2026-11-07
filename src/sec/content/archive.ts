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

/**
 * A tar number: octal text (ended by NUL or space, as node-tar and Python's tarfile read it), or base-256 when the top
 * bit is set (GNU, for sizes past 8 GB; 0xff first is a negative number). NaN for anything else: not octal, negative,
 * or past what a double holds exactly. parseInt would read "12zz" as 10, and the next header from the wrong place.
 */
export function tarNum(b: Buffer, at: number, len: number): number {
  if (b[at] === 0xff) return NaN;
  if (b[at] & 0x80) {
    let n = b[at] & 0x7f;
    for (let i = 1; i < len; i++) n = n * 256 + b[at + i];
    return Number.isSafeInteger(n) ? n : NaN;
  }
  const t = str(b, at, len).trim();
  if (!t) return 0;
  return /^[0-7]+$/.test(t) ? parseInt(t, 8) : NaN;
}

/** A pax size: decimal digits, or NaN for anything else; undefined when the record is not there. */
const paxSize = (v: string | undefined) => (v === undefined ? undefined : /^\d{1,15}$/.test(v) ? Number(v) : NaN);

/** pax extended header records: "<len> key=value\n". Undefined when a record is malformed, as tarfile refuses it. */
function pax(data: Buffer): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  let i = 0;
  // Padding after the last record is NULs.
  while (i < data.length && data[i] !== 0) {
    const sp = data.indexOf(0x20, i);
    if (sp < 0) return;
    const lenText = data.subarray(i, sp).toString("latin1");
    const len = /^\d{1,9}$/.test(lenText) ? Number(lenText) : NaN;
    if (!(len > sp - i + 1) || i + len > data.length || data[i + len - 1] !== 0x0a) return;
    const rec = data.subarray(sp + 1, i + len - 1).toString("utf8");
    const eq = rec.indexOf("=");
    if (eq <= 0) return;
    out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/**
 * Reads a tar the way node-tar (npm) and Python's tarfile (pip) do, so the files checked are the files installed: pax
 * `path`, `linkpath` and `size` records apply to the entry after them, GNU long names too, sizes may be base-256. A
 * header whose checksum or size is not what a tar header holds, a malformed pax record, or a global pax header that
 * would move paths or sizes (node-tar applies it to every entry, tarfile does not) ends the read as damaged: what
 * follows could be read differently by the installer, so nothing after it is guessed at.
 */
export function readTar(buf: Buffer, lim: Limits = LIMITS): Archive {
  const r = new Reader(lim);
  const damaged = (path: string, detail: string) => {
    r.problems.push({ kind: "damaged", path: path.slice(0, 200), detail });
    r.partial ??= "the archive is damaged";
  };
  let off = 0;
  let next: { path?: string; link?: string; size?: number } = {};
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h[0] === 0 && h.every((x) => x === 0)) break;
    // The checksum counts its own field as spaces; tarfile also takes the sum of the bytes read as signed.
    let sum = 0, signed = 0;
    for (let i = 0; i < 512; i++) {
      const x = i >= 148 && i < 156 ? 32 : h[i];
      sum += x;
      signed += x > 127 ? x - 256 : x;
    }
    const want = tarNum(h, 148, 8);
    if (want !== sum && want !== signed) {
      damaged("", `bad header checksum at byte ${off}`);
      break;
    }
    const type = h[156] === 0 ? "0" : String.fromCharCode(h[156]);
    const ustar = h.subarray(257, 262).toString("latin1") === "ustar";
    const prefix = ustar ? str(h, 345, 155) : "";
    const name = (prefix ? `${prefix}/` : "") + str(h, 0, 100);
    const own = tarNum(h, 124, 12);
    if (Number.isNaN(own)) {
      damaged(name, `the size field of the header at byte ${off} is not a number`);
      break;
    }
    // A pax size describes the entry after it, never another pax or long-name header.
    const meta = type === "x" || type === "g" || type === "L" || type === "K";
    const size = meta ? own : (next.size ?? own);
    const start = off + 512;
    if (start + size > buf.length) {
      r.problems.push({ kind: "damaged", path: name.slice(0, 200), detail: "cut short" });
      r.partial ??= "the archive is cut short";
      break;
    }
    const data = buf.subarray(start, start + size);
    off = start + Math.ceil(size / 512) * 512;
    if (type === "x" || type === "g") {
      const p = pax(data);
      if (!p) {
        damaged(name, `a malformed pax header at byte ${start - 512}`);
        break;
      }
      const ps = paxSize(p.size);
      if (Number.isNaN(ps)) {
        damaged(name, `a pax size that is not a number (${String(p.size).slice(0, 40)})`);
        break;
      }
      if (type === "g") {
        const moves = ["path", "linkpath", "size"].filter((k) => k in p);
        if (moves.length) {
          damaged(name, `a global pax header sets ${moves.join(", ")} for every entry, which npm and pip apply differently`);
          break;
        }
        continue;
      }
      next = { path: p.path ?? next.path, link: p.linkpath ?? next.link, size: ps ?? next.size };
      continue;
    }
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

/**
 * Reads a zip from its central directory, as Python's zipfile (pip) does. Where pip would read a file differently or
 * refuse it, the archive counts as damaged and is read again next time: a local header whose name is not the
 * directory's (zipfile refuses that entry; other unzippers take the local name), two entries that land on the same
 * path, and a name with non-ASCII bytes not marked UTF-8 (zipfile reads that as code page 437).
 */
export function readZip(buf: Buffer, lim: Limits = LIMITS): Archive {
  const r = new Reader(lim);
  const damaged = (detail: string) => {
    r.problems.push({ kind: "damaged", path: "", detail });
    r.partial ??= "the archive is damaged";
    return r.done();
  };
  const odd = (name: string, detail: string) => {
    r.problems.push({ kind: "damaged", path: safePath(name) ?? name.slice(0, 200), detail });
    r.partial ??= "the archive is damaged";
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
  const names = new Set<string>();
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
    const rawName = buf.subarray(p + 46, p + 46 + nlen);
    const name = rawName.toString("utf8");
    p += 46 + nlen + xlen + clen;
    if (!(flags & 0x800) && rawName.some((b) => b > 0x7f)) odd(name, "a name with non-ASCII bytes not marked UTF-8: pip reads it as code page 437, so it names another file there");
    const local = readLocal(buf, lho, csize);
    if (local && !local.name.equals(rawName)) odd(name, `its local header names ${JSON.stringify(local.name.toString("utf8").slice(0, 120))}: pip refuses the entry, other unzippers unpack that name`);
    const mode = ext >>> 16;
    if (name.endsWith("/") || (mode & 0o170000) === 0o040000) continue;
    const key = safePath(name);
    if (key !== undefined) {
      if (names.has(key)) odd(name, "a second entry for the same path: which one counts depends on the tool that unpacks it");
      names.add(key);
    }
    if ((mode & 0o170000) === 0o120000) {
      r.link(name, local?.data.toString("utf8").slice(0, 300) ?? "?", false);
      continue;
    }
    if (flags & 1) {
      r.problems.push({ kind: "encrypted", path: safePath(name) ?? name.slice(0, 200) });
      continue;
    }
    let bad: string | undefined;
    const ok = r.file(name, usize, mode & 0o7777, (keep) => {
      const raw = local?.data;
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
    if (bad) odd(name, bad);
    if (!ok) break;
  }
  return r.done();
}

function readLocal(buf: Buffer, at: number, csize: number): { name: Buffer; data: Buffer } | undefined {
  if (at + 30 > buf.length || buf.readUInt32LE(at) !== 0x04034b50) return;
  const nlen = buf.readUInt16LE(at + 26);
  const start = at + 30 + nlen + buf.readUInt16LE(at + 28);
  if (start + csize > buf.length) return;
  return { name: buf.subarray(at + 30, at + 30 + nlen), data: buf.subarray(start, start + csize) };
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
