// Configuration of the tools a developer runs all day, where one line changes what they install or what they run:
//   tool-config  package manager settings (pip, uv, yarn, bun, conda, gem, cargo) and systemd's environment.d, read
//                as text so an added line shows up in a diff, like a shell rc file
//   tool-exec    programs other tools start for you: kubeconfig exec plugins, AWS credential_process, Docker
//                credential helpers and contexts, editor tasks that run when a folder opens, and Python start-up hooks
//                (.pth import lines, sitecustomize / usercustomize)
// Secrets in these files are never kept: a line that holds one is stored with its value replaced by a fingerprint.

import { join, resolve } from "node:path";
import { HOME } from "../../home";
import { ls, readJson, readText, sha256, type Ctx } from "../ctx";
import type { Item } from "../types";

/** Package manager and session config files, relative to the home folder. */
export const TOOL_CONFIGS = [
  ".config/pip/pip.conf", ".pip/pip.conf", "Library/Application Support/pip/pip.conf", "AppData/Roaming/pip/pip.ini",
  ".config/uv/uv.toml", ".yarnrc.yml", ".yarnrc", ".bunfig.toml", ".condarc", ".gemrc", ".cargo/config.toml", ".cargo/config",
];

/** Lines that carry a credential: kept as the key and a fingerprint of the value, never the value. */
// The key may carry a registry in front of it (//registry.npmjs.org/:_authToken=…).
const SECRET_LINE = /^(\s*[^=#\s]*?(?:_authToken|_auth|_password|password|passwd|token|secret|apikey|api_key|npmAuthToken|npmAuthIdent)[^=:\s]*\s*[=:]\s*)(.+)$/i;

export function maskSecrets(text: string): string {
  return text.split("\n").map((line) => {
    // A password in a URL (index-url = https://user:pass@host/simple) too.
    const l = line.replace(/(\w[\w+.-]*:\/\/[^\s/@:]+:)([^\s/@]+)@/g, (_, a, pw) => `${a}<secret ${sha256(pw).slice(0, 8)}>@`);
    const m = SECRET_LINE.exec(l);
    // ${NPM_TOKEN} is a reference, not a secret; it may stay as it is.
    return m && !/^["']?\$\{?[A-Za-z_]/.test(m[2].trim()) ? `${m[1]}<secret ${sha256(m[2].trim()).slice(0, 8)}>` : l;
  }).join("\n");
}

export async function toolConfigs(ctx: Ctx): Promise<{ items: Item[]; texts: Record<string, string> }> {
  const items: Item[] = [];
  const texts: Record<string, string> = {};
  const add = (rel: string, path: string) => {
    const raw = readText(path, 1_000_000);
    if (raw === undefined) return;
    const t = maskSecrets(raw);
    items.push({ kind: "tool-config", id: rel, name: rel, path, hash: sha256(t), meta: { lines: t.split("\n").length } });
    texts[rel] = t;
  };
  for (const rel of TOOL_CONFIGS) add(rel, join(ctx.home, rel));
  // systemd's user manager reads these into the environment of every user service and the graphical session.
  for (const f of ls(join(ctx.home, ".config/environment.d"))) if (f.endsWith(".conf")) add(`.config/environment.d/${f}`, join(ctx.home, ".config/environment.d", f));
  return { items, texts };
}

// ── programs other tools run (kept as written: ~ and $HOME are expanded only where the rules judge the path)

const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "");
const indentOf = (l: string) => l.length - l.trimStart().length;
/** ["eks", "get-token"] as a YAML flow list. */
const flowList = (s: string) => [...s.replace(/^\s*\[|\]\s*$/g, "").matchAll(/"([^"]*)"|'([^']*)'|([^,\s][^,]*)/g)].map((m) => (m[1] ?? m[2] ?? m[3]).trim());

/** The exec plugins of a kubeconfig's users: name, and command with its arguments. A small reader for the one shape they take. */
export function kubeExecs(yaml: string): { user: string; command: string }[] {
  const out: { user: string; command: string }[] = [];
  const lines = yaml.replace(/\r/g, "").split("\n");
  let user = "";
  for (let i = 0; i < lines.length; i++) {
    const name = /^\s*- name:\s*(.+)$/.exec(lines[i]);
    if (name) user = unquote(name[1]);
    if (!/^\s*exec:\s*$/.test(lines[i])) continue;
    const at = indentOf(lines[i]);
    let cmd = "";
    const args: string[] = [];
    let inArgs = false;
    // Everything indented under exec: belongs to it (its env list too, whose "- name:" entries are not users).
    for (i++; i < lines.length; i++) {
      const l = lines[i];
      if (!l.trim()) continue;
      if (indentOf(l) <= at) {
        i--;
        break;
      }
      const c = /^\s*command:\s*(.+)$/.exec(l);
      const a = /^\s*args:\s*(.*)$/.exec(l);
      const item = /^\s*-\s+(.*)$/.exec(l);
      if (c) (cmd = unquote(c[1])), (inArgs = false);
      else if (a) (inArgs = !a[1].trim()), a[1].trim().startsWith("[") && args.push(...flowList(a[1]));
      else if (item && inArgs) args.push(unquote(item[1]));
      else inArgs = false;
    }
    if (cmd) out.push({ user, command: [cmd, ...args].join(" ") });
  }
  return out;
}

/**
 * The command behind vswarm's own gate, `<this vswarm> preflight --quiet --then <command>` (what vswarm gate aws and
 * gate kube write), or undefined. Only this vswarm's launcher counts, in the quoting those gates write: another program
 * named vswarm in front of a command is not vswarm's gate.
 */
export function behindGate(program: string, launchers = ownLaunchers()): string | undefined {
  const sq = (s: string) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'"'"'`)}'`);
  const dq = (s: string) => (/^[A-Za-z0-9_@%+=:,./\\-]+$/.test(s) ? s : `"${s}"`);
  for (const l of launchers)
    for (const form of new Set([l.join(" "), l.map(sq).join(" "), l.map(dq).join(" ")])) {
      const head = `${form} preflight --quiet --then `;
      if (program.startsWith(head) && program.length > head.length) return program.slice(head.length);
    }
}

/** How this vswarm is started from other tools: its launcher, or bun and the CLI. */
export const ownLaunchers = (): string[][] => [
  [join(HOME, "bin", process.platform === "win32" ? "vswarm.cmd" : "vswarm")],
  [process.execPath, resolve(import.meta.dir, "../../cli.ts")],
];

/** credential_process lines of ~/.aws/config, per profile. */
export function awsProcesses(ini: string): { profile: string; command: string }[] {
  const out: { profile: string; command: string }[] = [];
  let profile = "default";
  for (const l of ini.replace(/\r/g, "").split("\n")) {
    const sec = /^\s*\[\s*(?:profile\s+)?([^\]]+?)\s*\]/.exec(l);
    if (sec) profile = sec[1];
    const cp = /^\s*credential_process\s*=\s*(.+)$/.exec(l);
    if (cp) out.push({ profile, command: cp[1].trim() });
  }
  return out;
}

/**
 * Import lines that setuptools, virtualenv, editable installs and coverage tools write into .pth files: ordinary, and
 * many. pytest-cov's runs its code through exec(), which would otherwise look like a loader.
 */
export const STOCK_PTH = /^import (os; var = 'SETUPTOOLS_USE_DISTUTILS'|_virtualenv|__editable___[\w]+_finder; __editable___[\w]+_finder\.install\(\)|_distutils_hack|coverage; coverage\.process_startup\(\)|os, sys;exec\('if \\'COV_CORE_SOURCE\\' in os\.environ:)/;

/** User site-packages folders: macOS's ~/Library/Python and the XDG ~/.local/lib/pythonX.Y. */
function userSites(h: string): string[] {
  const out: string[] = [];
  for (const v of ls(join(h, "Library/Python"))) out.push(join(h, "Library/Python", v, "lib/python/site-packages"));
  for (const v of ls(join(h, ".local/lib")).filter((d) => /^python\d/.test(d))) out.push(join(h, ".local/lib", v, "site-packages"));
  return out;
}

const EDITOR_USER: [string, string][] = [
  ["vscode", "Library/Application Support/Code/User"], ["vscode", ".config/Code/User"], ["vscode", "AppData/Roaming/Code/User"],
  ["cursor", "Library/Application Support/Cursor/User"], ["cursor", ".config/Cursor/User"], ["cursor", "AppData/Roaming/Cursor/User"],
  ["windsurf", "Library/Application Support/Windsurf/User"], ["windsurf", ".config/Windsurf/User"],
];

/** Docker's own credential helpers, which ship with Docker Desktop or the distribution. */
export const STOCK_DOCKER_HELPERS = new Set(["desktop", "osxkeychain", "wincred", "pass", "secretservice", "ecr-login", "gcloud", "gcr", "acr-env"]);

export async function toolHelpers(ctx: Ctx): Promise<Item[]> {
  const h = ctx.home;
  const out: Item[] = [];
  const add = (id: string, name: string, what: string, path: string, program: string, extra: Record<string, string | boolean | undefined> = {}) =>
    out.push({ kind: "tool-exec", id, name, path, source: what, hash: sha256(program + JSON.stringify(extra)), meta: { what, program: program.slice(0, 300), ...extra } });

  // A command vswarm's own gate runs is judged and fingerprinted as that command: gating it is not a change to it.
  const gated = (id: string, name: string, what: string, path: string, program: string) => {
    const inner = behindGate(program);
    if (!inner) return add(id, name, what, path, program);
    out.push({ kind: "tool-exec", id, name, path, source: what, hash: sha256(inner + "{}"), meta: { what, program: program.slice(0, 300), gated: inner.slice(0, 300) } });
  };

  const kube = join(h, ".kube/config");
  for (const e of kubeExecs(readText(kube) ?? "")) gated(`kube:${kube}:${e.user}`, e.user, "kubectl exec plugin", kube, e.command);

  const awsCfg = join(h, ".aws/config");
  for (const p of awsProcesses(readText(awsCfg) ?? "")) gated(`aws:${p.profile}`, p.profile, "AWS credential_process", awsCfg, p.command);

  const dockerCfg = join(h, ".docker/config.json");
  const dc = readJson(dockerCfg);
  if (dc && typeof dc === "object") {
    if (typeof dc.credsStore === "string") add("docker-cred:*", "all registries", "Docker credential helper", dockerCfg, `docker-credential-${dc.credsStore}`, { stock: STOCK_DOCKER_HELPERS.has(dc.credsStore) });
    for (const [reg, helper] of Object.entries<any>(dc.credHelpers ?? {}))
      if (typeof helper === "string") add(`docker-cred:${reg}`, reg, "Docker credential helper", dockerCfg, `docker-credential-${helper}`, { stock: STOCK_DOCKER_HELPERS.has(helper) });
  }
  const current = typeof dc?.currentContext === "string" ? dc.currentContext : undefined;
  const metas = join(h, ".docker/contexts/meta");
  for (const d of ls(metas)) {
    const m = readJson(join(metas, d, "meta.json"));
    const host = m?.Endpoints?.docker?.Host;
    if (typeof m?.Name !== "string" || typeof host !== "string") continue;
    add(`docker-context:${m.Name}`, m.Name, "Docker context", join(metas, d, "meta.json"), host, { current: m.Name === current, skipTls: m.Endpoints.docker.SkipTLSVerify === true });
  }

  for (const [ed, rel] of EDITOR_USER) {
    const f = join(h, rel, "tasks.json");
    // tasks.json allows comments and trailing commas; whole-line comments are dropped before reading it.
    const text = readText(f);
    if (!text) continue;
    let j: any;
    try {
      j = JSON.parse(text.replace(/^\s*\/\/.*$/gm, "").replace(/,(\s*[}\]])/g, "$1"));
    } catch {
      continue;
    }
    for (const t of Array.isArray(j?.tasks) ? j.tasks : []) {
      if (t?.runOptions?.runOn !== "folderOpen") continue;
      const label = String(t.label ?? t.command ?? "task");
      const cmd = [t.command, ...(Array.isArray(t.args) ? t.args : [])].filter((x) => typeof x === "string").join(" ");
      add(`task:${f}:${label}`, label, `${ed} task run when a folder opens`, f, cmd);
    }
  }

  for (const site of userSites(h)) {
    for (const f of ls(site)) {
      const path = join(site, f);
      if (f.endsWith(".pth")) {
        // Only import lines run; the rest of a .pth file is folders added to sys.path.
        const imports = (readText(path, 200_000) ?? "").split("\n").map((l) => l.trim()).filter((l) => /^import[\s\t]/.test(l));
        if (!imports.length) continue;
        const stock = f.endsWith("-nspkg.pth") || imports.every((l) => STOCK_PTH.test(l));
        add(`python:${path}`, f, "Python start-up hook", path, imports.join(" ; "), { stock });
      } else if (f === "sitecustomize.py" || f === "usercustomize.py") {
        add(`python:${path}`, f, "Python start-up hook", path, (readText(path, 200_000) ?? "").replace(/\s+/g, " "), { stock: false });
      }
    }
  }
  return out;
}
