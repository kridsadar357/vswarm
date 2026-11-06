// Short-lived SSH certificates, issued only to a machine that passes preflight.
//
// Servers trust a CA instead of individual keys. `vswarm cert` makes a fresh session key and asks the CA to sign it
// for a few minutes (15 by default). A stolen key file is then worthless: it is trusted nowhere on its own, and its
// certificate expires before it can be used for long. The CA key never signs silently: it is protected by a
// passphrase you type, or lives on a hardware key (ed25519-sk) that needs a touch.

import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "../home";
import { whoami } from "./ctx";

export const CA_DIR = () => process.env.VSWARM_CA_DIR ?? join(HOME, "ca");

export const caFiles = {
  key: () => join(CA_DIR(), "ca_key"),
  pub: () => join(CA_DIR(), "ca_key.pub"),
  config: () => join(CA_DIR(), "config.json"),
  session: () => join(CA_DIR(), "session"),
  cert: () => join(CA_DIR(), "session-cert.pub"),
};

export interface CaConfig {
  /** Names the certificate is valid for; servers map them to accounts (AuthorizedPrincipalsFile). */
  principals: string[];
  /** Lifetime of each certificate, ssh-keygen -V syntax: 15m, 1h. */
  ttl: string;
}

export function loadCaConfig(): CaConfig {
  try {
    return { principals: [whoami()], ttl: "15m", ...JSON.parse(readFileSync(caFiles.config(), "utf8")) };
  } catch {
    return { principals: [whoami()], ttl: "15m" };
  }
}

async function sh(cmd: string[], opt: { tty?: boolean } = {}): Promise<{ code: number; out: string; err: string }> {
  const p = Bun.spawn(cmd, {
    stdin: opt.tty ? "inherit" : "ignore",
    stdout: "pipe",
    stderr: opt.tty ? "inherit" : "pipe",
  });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), opt.tty ? Promise.resolve("") : new Response(p.stderr as ReadableStream).text(), p.exited]);
  return { code, out, err };
}

/** Creates the CA. Interactive: ssh-keygen asks for the passphrase (or a touch, for --sk). */
export async function caInit(opt: { sk?: boolean; noPassphrase?: boolean; principals?: string[]; ttl?: string }) {
  if (existsSync(caFiles.key())) throw new Error(`a CA already exists: ${caFiles.key()}`);
  mkdirSync(CA_DIR(), { recursive: true, mode: 0o700 });
  const cmd = ["ssh-keygen", "-t", opt.sk ? "ed25519-sk" : "ed25519", "-f", caFiles.key(), "-C", `vswarm CA ${whoami()} ${new Date().toISOString().slice(0, 10)}`];
  // Without a passphrase anyone who can read the file can sign; only for tests and throwaway setups.
  if (opt.noPassphrase) cmd.push("-N", "");
  if (opt.sk) cmd.push("-O", "application=ssh:vswarm-ca");
  const r = await sh(cmd, { tty: true });
  if (r.code !== 0) throw new Error("ssh-keygen could not create the CA key");
  chmodSync(caFiles.key(), 0o600);
  const cfg: CaConfig = { principals: opt.principals?.length ? opt.principals : [whoami()], ttl: opt.ttl ?? "15m" };
  writeFileSync(caFiles.config(), JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  return cfg;
}

export interface CertInfo {
  valid: boolean;
  /** Seconds left, when valid. */
  left?: number;
  principals: string[];
  id?: string;
}

/** Reads a certificate with ssh-keygen -L. */
export async function certInfo(path = caFiles.cert()): Promise<CertInfo> {
  if (!existsSync(path)) return { valid: false, principals: [] };
  const r = await sh(["ssh-keygen", "-L", "-f", path]);
  if (r.code !== 0) return { valid: false, principals: [] };
  const to = /Valid: from (\S+) to (\S+)/.exec(r.out)?.[2];
  const id = /Key ID: "([^"]*)"/.exec(r.out)?.[1];
  const principals = [...(/Principals:\s*\n((?:\s{16,}\S+\n?)+)/.exec(r.out)?.[1] ?? "").matchAll(/\S+/g)].map((m) => m[0]);
  const end = to ? Date.parse(to) : NaN;
  const left = Number.isFinite(end) ? Math.round((end - Date.now()) / 1000) : undefined;
  return { valid: left !== undefined && left > 0, left, principals, id };
}

/**
 * Makes sure a certificate with at least `minLeft` seconds is in place. Signing needs the CA passphrase (typed on the
 * terminal) or a touch on the hardware key. Returns what happened.
 */
export async function issue(opt: { host?: string; minLeft?: number; quiet?: boolean } = {}): Promise<{ reused: boolean; info: CertInfo }> {
  if (!existsSync(caFiles.key())) throw new Error("no CA yet: vswarm ca init");
  const cur = await certInfo();
  if (cur.valid && (cur.left ?? 0) > (opt.minLeft ?? 120)) return { reused: true, info: cur };
  const cfg = loadCaConfig();
  // A fresh key for every certificate: nothing long-lived to steal.
  rmSync(caFiles.session(), { force: true });
  rmSync(caFiles.session() + ".pub", { force: true });
  rmSync(caFiles.cert(), { force: true });
  const gen = await sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", `vswarm session ${new Date().toISOString()}`, "-f", caFiles.session()]);
  if (gen.code !== 0) throw new Error(`could not make a session key: ${gen.err.trim()}`);
  const id = `vswarm:${whoami()}@${opt.host ?? "any"}:${new Date().toISOString()}`;
  const sign = await sh([
    "ssh-keygen", "-q", "-s", caFiles.key(), "-I", id, "-n", cfg.principals.join(","), "-V", `-1m:+${cfg.ttl}`,
    "-O", "no-x11-forwarding", "-O", "no-agent-forwarding",
    caFiles.session() + ".pub",
  ], { tty: true });
  if (sign.code !== 0 || !existsSync(caFiles.cert())) throw new Error("the CA did not sign (wrong passphrase, or no touch on the hardware key)");
  return { reused: false, info: await certInfo() };
}

/** Commands to run on a server, as root, to trust this CA. Printed for you to review and run; vswarm never logs in. */
export function serverSetup(account: string, cfg: CaConfig): string {
  const pub = readFileSync(caFiles.pub(), "utf8").trim();
  return `# 1. trust the vswarm CA for user logins
install -d -m 755 /etc/ssh/auth_principals
cat > /etc/ssh/vswarm_user_ca.pub <<'PUB'
${pub}
PUB
# 2. which certificate names may log in as ${account}
printf '%s\\n' ${cfg.principals.map((p) => `'${p}'`).join(" ")} > /etc/ssh/auth_principals/${account}
# 3. sshd settings (a drop-in file, easy to remove)
cat > /etc/ssh/sshd_config.d/50-vswarm-ca.conf <<'CONF'
TrustedUserCAKeys /etc/ssh/vswarm_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
CONF
sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd
# 4. keep this session open, log in again from another terminal with a certificate, and only then remove the old
#    keys from ~${account}/.ssh/authorized_keys, so a stolen key file stops working.`;
}
