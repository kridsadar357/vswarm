// SSH keys and signatures on the wire, as OpenSSH writes them (RFC 4251 types, RFC 8709 ed25519, RFC 8332
// rsa-sha2, RFC 5656 ecdsa, and draft-miller-ssh-agent for the private-key messages). Signing is node:crypto's;
// this file only moves bytes between OpenSSH's encodings and key objects.
//
//   public key blob   string type, then:  ed25519 string A · rsa mpint e, mpint n · ecdsa string curve, string Q
//   private (agent)   string type, then:  ed25519 string A, string k||A · rsa mpint n e d iqmp p q · ecdsa string curve, string Q, mpint d
//   signature         string alg, string sig  (ecdsa: sig is mpint r, mpint s)
//
// Certificates, security keys (-sk) and DSA are not taken: those stay with ssh-agent or the hardware.

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, type KeyObject } from "node:crypto";

export class Reader {
  constructor(public b: Buffer, public o = 0) {}
  private need(n: number) {
    if (n < 0 || this.o + n > this.b.length) throw new Error("message too short");
  }
  u8(): number {
    this.need(1);
    return this.b[this.o++];
  }
  u32(): number {
    this.need(4);
    const v = this.b.readUInt32BE(this.o);
    this.o += 4;
    return v;
  }
  bytes(n: number): Buffer {
    this.need(n);
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }
  str(): Buffer {
    return this.bytes(this.u32());
  }
  text(): string {
    return this.str().toString("utf8");
  }
  /** An unsigned mpint as plain big-endian bytes; a negative one is refused (no key field is negative). */
  mpint(): Buffer {
    const v = this.str();
    if (v.length && v[0] & 0x80) throw new Error("negative mpint");
    let i = 0;
    while (i < v.length && v[i] === 0) i++;
    return v.subarray(i);
  }
  get left(): number {
    return this.b.length - this.o;
  }
}

export class Writer {
  private parts: Buffer[] = [];
  u8(v: number) {
    this.parts.push(Buffer.from([v]));
    return this;
  }
  u32(v: number) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v >>> 0);
    this.parts.push(b);
    return this;
  }
  raw(b: Buffer) {
    this.parts.push(b);
    return this;
  }
  str(v: Buffer | string) {
    const b = typeof v === "string" ? Buffer.from(v, "utf8") : v;
    return this.u32(b.length).raw(b);
  }
  /** A non-negative integer from big-endian bytes: leading zeros dropped, one put back when the top bit is set. */
  mpint(v: Buffer) {
    let i = 0;
    while (i < v.length && v[i] === 0) i++;
    const m = v.subarray(i);
    return this.str(m.length && m[0] & 0x80 ? Buffer.concat([Buffer.from([0]), m]) : m);
  }
  out(): Buffer {
    return Buffer.concat(this.parts);
  }
}

const CURVES: Record<string, { crv: string; len: number; hash: string }> = {
  nistp256: { crv: "P-256", len: 32, hash: "sha256" },
  nistp384: { crv: "P-384", len: 48, hash: "sha384" },
  nistp521: { crv: "P-521", len: 66, hash: "sha512" },
};

export interface SshKey {
  /** ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256 … */
  type: string;
  /** The public key blob, as servers and agents compare keys. */
  blob: Buffer;
  comment: string;
  priv: KeyObject;
  /** The private-key message body this key came from (type … comment), kept so the vault can hand it back unchanged. */
  wire: Buffer;
}

const b64u = (b: Buffer) => b.toString("base64url");
const pad = (b: Buffer, n: number) => (b.length >= n ? b.subarray(b.length - n) : Buffer.concat([Buffer.alloc(n - b.length), b]));
const big = (b: Buffer) => (b.length ? BigInt(`0x${b.toString("hex")}`) : 0n);
const bytesOf = (v: bigint) => {
  const h = v.toString(16);
  return Buffer.from(h.length % 2 ? `0${h}` : h, "hex");
};

/** Whether a key type is one this agent can hold. */
export const supported = (type: string) => type === "ssh-ed25519" || type === "ssh-rsa" || /^ecdsa-sha2-nistp(256|384|521)$/.test(type);

/**
 * A private key as SSH_AGENTC_ADD_IDENTITY carries it (and as ssh-add sends it, whatever the file format was).
 * Reads from the reader's position up to and including the comment. The public half is checked against the private.
 */
export function readPrivate(r: Reader): SshKey {
  const start = r.o;
  const type = r.text();
  let blob: Buffer, priv: KeyObject;
  if (type === "ssh-ed25519") {
    const a = r.str(), ka = r.str();
    if (a.length !== 32 || ka.length !== 64 || !ka.subarray(32).equals(a)) throw new Error("malformed ed25519 key");
    priv = createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", d: b64u(ka.subarray(0, 32)), x: b64u(a) }, format: "jwk" });
    blob = new Writer().str(type).str(a).out();
  } else if (type === "ssh-rsa") {
    const [n, e, d, iqmp, p, q] = [r.mpint(), r.mpint(), r.mpint(), r.mpint(), r.mpint(), r.mpint()];
    const [D, P, Q] = [big(d), big(p), big(q)];
    // OpenSSH refuses RSA keys under 1024 bits; so does this agent.
    if (big(n).toString(2).length < 1024) throw new Error("RSA key shorter than 1024 bits");
    if (P * Q !== big(n)) throw new Error("malformed RSA key");
    priv = createPrivateKey({
      key: { kty: "RSA", n: b64u(n), e: b64u(e), d: b64u(d), p: b64u(p), q: b64u(q), dp: b64u(bytesOf(D % (P - 1n))), dq: b64u(bytesOf(D % (Q - 1n))), qi: b64u(iqmp) },
      format: "jwk",
    });
    blob = new Writer().str(type).mpint(e).mpint(n).out();
  } else if (supported(type)) {
    const curve = r.text();
    const cv = CURVES[curve];
    if (!cv || type !== `ecdsa-sha2-${curve}`) throw new Error("malformed ecdsa key");
    const point = r.str(), d = r.mpint();
    if (point.length !== 1 + 2 * cv.len || point[0] !== 4) throw new Error("malformed ecdsa key");
    const x = point.subarray(1, 1 + cv.len), y = point.subarray(1 + cv.len);
    priv = createPrivateKey({ key: { kty: "EC", crv: cv.crv, x: b64u(x), y: b64u(y), d: b64u(pad(d, cv.len)) }, format: "jwk" });
    // The public point must be the private scalar's: a mismatched pair would sign with a key nobody trusts.
    const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string; y: string };
    if (jwk.x !== b64u(x) || jwk.y !== b64u(y)) throw new Error("malformed ecdsa key");
    blob = new Writer().str(type).str(curve).str(point).out();
  } else {
    throw new Error(`key type ${type.slice(0, 60)} is not supported here (certificates, -sk and DSA keys stay with ssh-agent)`);
  }
  if (type === "ssh-ed25519") {
    const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string };
    if (jwk.x !== b64u(blob.subarray(blob.length - 32))) throw new Error("malformed ed25519 key");
  }
  const comment = r.text();
  return { type, blob, comment, priv, wire: Buffer.from(r.b.subarray(start, r.o)) };
}

/** Back from the vault: the private-key body exactly as it was added. */
export const keyFromWire = (wire: Buffer) => readPrivate(new Reader(wire));

/** SSH_AGENT_RSA_SHA2_256 and _512 in a sign request's flags. */
export const RSA_SHA2_256 = 2;
export const RSA_SHA2_512 = 4;

/** A signature blob for `data`, in the algorithm the flags ask for. */
export function signWith(k: SshKey, data: Buffer, flags = 0): Buffer {
  if (k.type === "ssh-ed25519") return new Writer().str("ssh-ed25519").str(nodeSign(null, data, k.priv)).out();
  if (k.type === "ssh-rsa") {
    // rsa-sha2 when the client asks for it (every OpenSSH since 7.2 does); plain ssh-rsa (SHA-1) only otherwise.
    const [alg, hash] = flags & RSA_SHA2_512 ? ["rsa-sha2-512", "sha512"] : flags & RSA_SHA2_256 ? ["rsa-sha2-256", "sha256"] : ["ssh-rsa", "sha1"];
    return new Writer().str(alg).str(nodeSign(hash, data, k.priv)).out();
  }
  const cv = CURVES[k.type.slice("ecdsa-sha2-".length)];
  const rs = nodeSign(cv.hash, data, { key: k.priv, dsaEncoding: "ieee-p1363" });
  const inner = new Writer().mpint(rs.subarray(0, cv.len)).mpint(rs.subarray(cv.len)).out();
  return new Writer().str(k.type).str(inner).out();
}

/** SHA256:… as ssh-keygen -l prints it. */
export function fingerprint(blob: Buffer): string {
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`;
}

/** The key type named inside a blob. */
export function blobType(blob: Buffer): string {
  try {
    return new Reader(blob).text();
  } catch {
    return "unknown";
  }
}

/** One line of a .pub file. */
export const publicLine = (k: { blob: Buffer; comment: string }) => `${blobType(k.blob)} ${k.blob.toString("base64")}${k.comment ? ` ${k.comment}` : ""}`;

/** The blob of a .pub line (or authorized_keys line without options), or undefined. */
export function parsePublicLine(text: string): Buffer | undefined {
  const m = /^\s*(\S+)\s+([A-Za-z0-9+/=]+)/.exec(text);
  if (!m) return;
  const blob = Buffer.from(m[2], "base64");
  return blobType(blob) === m[1] ? blob : undefined;
}

export interface SignedFor {
  kind: "userauth" | "sshsig" | "other";
  /** userauth: the account on the server, the signature algorithm, and the server's host key when the client says. */
  user?: string;
  alg?: string;
  hostKey?: string;
  /** ssh-keygen -Y sign: the namespace (git, file, …). */
  namespace?: string;
}

/**
 * What a signature is for, read from the data to be signed: an ssh login (RFC 4252 §7, and OpenSSH's
 * publickey-hostbound-v00 that also carries the server's host key), an SSHSIG (ssh-keygen -Y sign, git), or other.
 * Only for the audit log; nothing here decides whether to sign.
 */
export function signedFor(data: Buffer): SignedFor {
  try {
    if (data.subarray(0, 6).toString("latin1") === "SSHSIG") {
      const r = new Reader(data, 6);
      return { kind: "sshsig", namespace: r.text().slice(0, 64) };
    }
    const r = new Reader(data);
    const sid = r.str();
    if (sid.length < 16 || sid.length > 64 || r.u8() !== 50) return { kind: "other" };
    const user = r.text(), service = r.text(), method = r.text();
    if (service !== "ssh-connection" || !method.startsWith("publickey") || r.u8() !== 1) return { kind: "other" };
    const alg = r.text();
    r.str();
    const hostKey = method === "publickey-hostbound-v00@openssh.com" ? fingerprint(r.str()) : undefined;
    return { kind: "userauth", user: user.slice(0, 64), alg: alg.slice(0, 64), hostKey };
  } catch {
    return { kind: "other" };
  }
}
