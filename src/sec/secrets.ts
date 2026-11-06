// Long-lived credentials sitting on this machine: what anyone who gets a copy of the disk, or code running as
// this user, could take and use from anywhere. Values are never printed or stored; only where, what kind, how old.

import { join } from "node:path";
import { isDir, ls, mtime, readJson, readText, type Ctx } from "./ctx";
import type { Finding, Severity } from "./types";
import { canaryKeyIds, canaryWhere } from "./canary";

const day = 86_400_000;
const age = (path: string) => {
  const t = mtime(path);
  return t ? `${Math.max(0, Math.round((Date.now() - t) / day))} days old` : "";
};

function finding(id: string, severity: Severity, title: string, detail: string[], fix: string): Finding {
  return { id: `secret:${id}`, rule: "secret", severity, title, detail: detail.filter(Boolean), fix };
}

/** Whether an OpenSSH or PEM private key is protected by a passphrase, read from its header only. */
export function keyEncrypted(text: string): boolean | undefined {
  if (/ENCRYPTED/.test(text.slice(0, 200))) return true;
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END/.exec(text);
  if (m) {
    const buf = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
    const magic = "openssh-key-v1\0";
    if (buf.subarray(0, magic.length).toString("latin1") !== magic) return;
    const len = buf.readUInt32BE(magic.length);
    const cipher = buf.subarray(magic.length + 4, magic.length + 4 + len).toString("latin1");
    return cipher !== "none";
  }
  if (/-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/.test(text)) return false;
}

/** The `exp` of a JWT, if the token is one; read locally, never sent anywhere. */
function jwtExpiry(token: string): number | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return;
  try {
    const p = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return typeof p.exp === "number" ? p.exp * 1000 : undefined;
  } catch {
    return;
  }
}

/** Users in a kubeconfig and how each one authenticates. A small reader for the one shape kubeconfigs have. */
export function kubeUsers(yaml: string): { name: string; how: string; expires?: number }[] {
  const out: { name: string; how: string; expires?: number }[] = [];
  // Files written on Windows end lines with \r\n; the value regexes expect bare \n.
  yaml = yaml.replace(/\r/g, "");
  const start = yaml.search(/^users:\s*$/m);
  if (start < 0) return out;
  const block = yaml.slice(start).split("\n").slice(1);
  let cur: { name: string; how: string; expires?: number } | undefined;
  for (const line of block) {
    if (/^[A-Za-z]/.test(line)) break; // next top-level key; list items may start at column 0
    const name = /^- name:\s*(.+)$/.exec(line.trim());
    if (name && /^\s{0,2}- /.test(line)) {
      cur = { name: name[1].replace(/["']/g, ""), how: "unknown" };
      out.push(cur);
      continue;
    }
    if (!cur) continue;
    const kv = /^\s+(token|client-key-data|client-key|password|exec|auth-provider|tokenFile):\s*(.*)$/.exec(line);
    if (!kv) continue;
    const [, key, val] = kv;
    if (key === "exec" || key === "auth-provider") cur.how = key;
    else if (cur.how !== "exec") {
      cur.how = key === "client-key-data" || key === "client-key" ? "client certificate" : key === "password" ? "password" : "token";
      if (key === "token") cur.expires = jwtExpiry(val.trim().replace(/["']/g, ""));
    }
  }
  return out;
}

// AUTH only as a word of its own (BASIC_AUTH, OAUTH_…), not inside AUTHOR or NEXTAUTH_URL.
const SECRET_NAME = /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|(^|_|O)AUTH(_|$)|CREDENTIAL)/i;
const SECRET_SHAPE = /\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|xox[abp]-[A-Za-z0-9-]{20,})/;

/** Names of variables in an env-style file that look like secrets with values set. Values are dropped here. */
export function secretNames(text: string): string[] {
  const names = new Set<string>();
  for (const line of text.split("\n")) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\s#]+)/.exec(line);
    if (!m) continue;
    const [, name, value] = m;
    if (value.length < 8 || /^\$|^(true|false|null|none|changeme|xxx+|your[_-])/i.test(value)) continue;
    if (SECRET_NAME.test(name) || SECRET_SHAPE.test(value)) names.add(name);
  }
  return [...names];
}

const CODE_DIRS = ["develop", "code", "projects", "src", "work", "dev", "git", "repos"];

export async function secrets(ctx: Ctx): Promise<Finding[]> {
  const out: Finding[] = [];
  const h = ctx.home;

  // SSH private keys without a passphrase (one finding for all of them; a new key changes its id and warns again)
  const bare: string[] = [];
  for (const f of ls(join(h, ".ssh"))) {
    if (f.endsWith(".pub") || /^(config|known_hosts|authorized_keys)/.test(f)) continue;
    const p = join(h, ".ssh", f);
    const t = readText(p, 64_000);
    if (t && /PRIVATE KEY-----/.test(t) && keyEncrypted(t) === false) bare.push(f);
  }
  if (bare.length) {
    bare.sort();
    out.push(finding(`ssh:${bare.join(",")}`, "medium", `${bare.length} SSH private key${bare.length > 1 ? "s" : ""} without a passphrase`,
      [...bare.map((f) => `~/.ssh/${f} · ${age(join(h, ".ssh", f))}`), "Anyone who copies these files can log in wherever they are trusted."],
      `Add a passphrase (ssh-keygen -p -f ~/.ssh/<key>), or move production access to a hardware key or short-lived SSH certificates.`));
  }

  // AWS long-term access keys
  const awsCred = join(h, ".aws/credentials");
  const aws = readText(awsCred);
  if (aws) {
    let profile = "default";
    const longTerm: string[] = [];
    // Your own canary keys are decoys, not exposure.
    const decoys = canaryKeyIds();
    for (const line of aws.split("\n")) {
      const sec = /^\s*\[([^\]]+)\]/.exec(line);
      if (sec) profile = sec[1];
      const id = /^\s*aws_access_key_id\s*=\s*(AKIA\w+)/.exec(line)?.[1];
      if (id && !decoys.has(id)) longTerm.push(profile);
    }
    if (longTerm.length) {
      out.push(finding("aws", "medium", `AWS long-term access keys in ~/.aws/credentials (${longTerm.length} profile${longTerm.length > 1 ? "s" : ""})`,
        [`profiles: ${longTerm.join(", ")}`, age(awsCred), "AKIA keys never expire on their own."],
        "Use AWS SSO / IAM Identity Center (aws configure sso) and delete the static keys after rotating them."));
    }
  }

  // kubeconfig users with static tokens or client keys
  for (const kc of [join(h, ".kube/config"), ...(process.env.KUBECONFIG ?? "").split(":").filter((p) => p && ctx.system)]) {
    const y = readText(kc);
    if (!y) continue;
    for (const u of kubeUsers(y)) {
      if (u.how === "exec" || u.how === "auth-provider" || u.how === "unknown") continue;
      if (u.how === "token" && u.expires && u.expires - Date.now() < 2 * day) continue;
      out.push(finding(`kube:${u.name}`, "medium", `Kubernetes user "${u.name}" uses a stored ${u.how}`,
        [kc.replace(h, "~"), u.how === "token" ? (u.expires ? `expires ${new Date(u.expires).toISOString().slice(0, 10)}` : "no expiry in the token") : "", age(kc)],
        "Switch this user to an exec plugin that issues short-lived tokens (cloud CLI or kubelogin), then revoke the stored one."));
    }
  }

  // Docker registry passwords stored in the config instead of a credential helper
  const dc = readJson(join(h, ".docker/config.json"));
  const plain = Object.entries<any>(dc?.auths ?? {}).filter(([, v]) => v && typeof v.auth === "string" && v.auth.length > 0).map(([k]) => k);
  if (plain.length) {
    out.push(finding("docker", "medium", `Docker registry passwords stored in plain config (${plain.length})`, [`registries: ${plain.join(", ")}`],
      "Set \"credsStore\": \"osxkeychain\" in ~/.docker/config.json and docker login again."));
  }

  // Tokens in plain files of common CLIs
  const plainFiles: [string, RegExp, string, Severity][] = [
    [".config/gh/hosts.yml", /oauth_token:\s*\S+/, "GitHub CLI token stored in a plain file", "medium"],
    [".git-credentials", /:\/\/[^\s:]+:[^\s@]+@/, "Git passwords/tokens stored in ~/.git-credentials", "medium"],
    // ${NPM_TOKEN} is a reference to the environment, the recommended way; only a literal token counts.
    [".npmrc", /_authToken\s*=\s*(?!\$\{)\S+/, "npm publish token in ~/.npmrc", "medium"],
    [".pypirc", /password\s*[:=]\s*\S+/, "PyPI password/token in ~/.pypirc", "medium"],
    [".netrc", /password\s+\S+/, "Passwords in ~/.netrc", "medium"],
  ];
  for (const [rel, re, title, sev] of plainFiles) {
    const p = join(h, rel);
    const t = readText(p);
    if (t && re.test(t)) {
      out.push(finding(rel, sev, title, [`~/${rel}`, age(p)], rel === ".config/gh/hosts.yml"
        ? "gh auth logout && gh auth login (it stores the token in the keychain when it can)."
        : "Move it to the keychain or a credential helper, and rotate the token."));
    }
  }

  // Cloud service-account keys
  const gcp = readJson(join(h, ".config/gcloud/application_default_credentials.json"));
  if (gcp?.type === "service_account") {
    out.push(finding("gcp-sa", "medium", "Google Cloud service-account key file as application default credentials",
      ["~/.config/gcloud/application_default_credentials.json", "Service-account keys do not expire."], "Use gcloud auth application-default login or workload identity, and delete the key."));
  }

  // Secrets exported from shell startup files
  for (const rc of [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"]) {
    const t = readText(join(h, rc));
    const names = t ? secretNames(t) : [];
    if (names.length) {
      out.push(finding(`rc:${rc}`, "low", `Secrets set in ~/${rc}: ${names.slice(0, 6).join(", ")}${names.length > 6 ? " …" : ""}`,
        ["Every program you start can read these."], "Keep them in the keychain or a secrets manager and load them only where needed."));
    }
  }

  // .env files in code folders (one level deep)
  const envHits: string[] = [];
  const decoyFiles = canaryWhere();
  for (const base of CODE_DIRS) {
    const root = join(h, base);
    if (!isDir(root)) continue;
    for (const proj of ls(root)) {
      for (const f of ls(join(root, proj))) {
        if (!/^\.env(\.|$)/.test(f) || /\.(example|sample|template)$/.test(f)) continue;
        if (decoyFiles.has(join(root, proj, f))) continue;
        const t = readText(join(root, proj, f), 200_000);
        const names = t ? secretNames(t) : [];
        if (names.length) envHits.push(`~/${base}/${proj}/${f} (${names.length})`);
      }
    }
  }
  if (envHits.length) {
    out.push(finding("env-files", "low", `${envHits.length} .env file${envHits.length > 1 ? "s" : ""} with secrets in code folders`, envHits.slice(0, 8).concat(envHits.length > 8 ? [`… ${envHits.length - 8} more`] : []),
      "Fine for local dev keys; production keys do not belong on a laptop."));
  }
  return out;
}
