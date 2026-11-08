// Reading ~/.ssh/config the way ssh does, without running it: which blocks apply to a host name, and what they say.
//
// `ssh -G` is the authority, but it runs every `Match exec` (vswarm's own gates among them) and costs a process per
// host. Scans, the agent's check before a login and doctor only need the plain parts: Host and Match originalhost/host
// patterns, IdentityFile, HostName and Port. A Match with any other criterion is skipped (said in `skipped`), Include is
// not followed. `agent protect` asks `ssh -G` itself, once per host, because it is about to rely on the answer.

import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { readText } from "./ctx";
import { AGENT_END, AGENT_START, GATE_END, GATE_START } from "./sshblocks";
import { removeBlock } from "./store";

export interface Block {
  /** "host" for Host, "match" for Match; "top" for lines before the first of either. */
  kind: "top" | "host" | "match";
  /** Host patterns, or Match originalhost/host patterns. */
  patterns: string[];
  /** Match criteria this reader does not evaluate (exec, user, localuser, canonical, final, tagged …). */
  other: string[];
  /** Match all. */
  all?: boolean;
  options: { key: string; value: string }[];
}

/** Splits a config line into words, as ssh does: whitespace or one `=`, double quotes group. */
export function words(line: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|([^\s="]+)/g;
  const l = line.trim().replace(/^(\S+?)\s*=\s*/, "$1 ");
  for (let m = re.exec(l); m; m = re.exec(l)) out.push(m[1] ?? m[2]);
  return out;
}

export function blocks(text: string): Block[] {
  const out: Block[] = [{ kind: "top", patterns: [], other: [], options: [] }];
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.trim();
    if (!l || l.startsWith("#")) continue;
    const w = words(l);
    if (!w.length) continue;
    const key = w[0].toLowerCase();
    if (key === "host") {
      out.push({ kind: "host", patterns: w.slice(1).flatMap((p) => p.split(",")).filter(Boolean), other: [], options: [] });
      continue;
    }
    if (key === "match") {
      const b: Block = { kind: "match", patterns: [], other: [], options: [] };
      for (let i = 1; i < w.length; i++) {
        const c = w[i].toLowerCase();
        if (c === "all") b.all = true;
        else if ((c === "originalhost" || c === "host" || c === "!originalhost" || c === "!host") && w[i + 1] !== undefined) {
          const pats = w[++i].split(",").filter(Boolean);
          b.patterns.push(...(c.startsWith("!") ? pats.map((p) => (p.startsWith("!") ? p.slice(1) : `!${p}`)) : pats));
        } else if (c === "canonical" || c === "final") b.other.push(c);
        else {
          b.other.push(`${c} ${w[i + 1] ?? ""}`.trim());
          i++;
        }
      }
      out.push(b);
      continue;
    }
    out.at(-1)!.options.push({ key, value: w.slice(1).join(" ") });
  }
  return out;
}

/** One ssh pattern against a name: `*` any run, `?` one character, case-insensitive. */
export function globMatch(pattern: string, name: string): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`, "i");
  return re.test(name);
}

/** A pattern list as ssh reads it: a negated pattern that matches wins over everything, otherwise any positive match. */
export function listMatch(patterns: string[], name: string): boolean {
  let hit = false;
  for (const p of patterns) {
    if (p.startsWith("!")) {
      if (globMatch(p.slice(1), name)) return false;
    } else if (globMatch(p, name)) hit = true;
  }
  return hit;
}

/** Patterns that name one host (no wildcard, no negation): what can be resolved and reached. */
export const literal = (p: string) => !/[*?!\[\]]/.test(p);

export interface HostView {
  identityFiles: string[];
  hostname?: string;
  port?: number;
  user?: string;
  /** Match blocks with criteria not evaluated here, which might also apply. */
  skipped: number;
}

/** ~ and %d (the home), as ssh expands them in IdentityFile. */
export function expandPath(p: string, home = homedir()): string {
  const x = p.replace(/^~(?=[\\/]|$)/, home).replace(/%d/g, home).replace(/%%/g, "%");
  // resolve() also gives one kind of separator on Windows (~/.ssh/x with a C:\Users\… home).
  return isAbsolute(x) ? resolve(x) : resolve(join(home, ".ssh"), x);
}

/**
 * What the config says for `host` (the name you type). First value wins, as in ssh, except IdentityFile, which adds
 * up. `skipBlocks` leaves vswarm's own blocks out (the agent block lists every protected key for its hosts).
 */
export function hostView(text: string, host: string, opt: { home?: string; withoutOwn?: boolean } = {}): HostView {
  const home = opt.home ?? homedir();
  const src = opt.withoutOwn ? removeBlock(removeBlock(text, AGENT_START, AGENT_END), GATE_START, GATE_END) : text;
  const v: HostView = { identityFiles: [], skipped: 0 };
  for (const b of blocks(src)) {
    if (b.kind === "host" && !listMatch(b.patterns, host)) continue;
    if (b.kind === "match") {
      if (b.other.length) {
        v.skipped++;
        continue;
      }
      if (!b.all && !listMatch(b.patterns, host)) continue;
    }
    for (const o of b.options) {
      if (o.key === "identityfile" && o.value && o.value.toLowerCase() !== "none") v.identityFiles.push(expandPath(o.value, home));
      else if (o.key === "hostname" && v.hostname === undefined) v.hostname = o.value.replace(/%h/g, host);
      else if (o.key === "port" && v.port === undefined && /^\d+$/.test(o.value)) v.port = Number(o.value);
      else if (o.key === "user" && v.user === undefined) v.user = o.value;
    }
  }
  return v;
}

/** Host names written out in Host lines (no wildcards): the hosts a config knows by name. */
export function namedHosts(text: string): string[] {
  const out = new Set<string>();
  for (const b of blocks(text)) if (b.kind === "host") for (const p of b.patterns) if (literal(p)) out.add(p);
  return [...out];
}

/** The host patterns of vswarm's ssh gate block and of its agent block, as written. */
export function ownHosts(text: string): { gate: string[]; agent: string[] } {
  const inBlock = (start: string, end: string) => {
    const i = text.indexOf(start);
    const j = i < 0 ? -1 : text.indexOf(end, i);
    return i < 0 || j < 0 ? "" : text.slice(i, j);
  };
  const first = (b: string) => /Match originalhost (\S+)/.exec(b)?.[1].split(",") ?? [];
  return { gate: first(inBlock(GATE_START, GATE_END)), agent: first(inBlock(AGENT_START, AGENT_END)) };
}

/**
 * Hosts that count as production: the patterns of vswarm's gate and agent blocks. A key counts as a production key when
 * a Host the config names, or a pattern itself, matches them and uses that key; a production host with no IdentityFile
 * of its own uses ssh's default keys.
 */
export function productionKeys(text: string, home = homedir()): Set<string> {
  const { gate, agent } = ownHosts(text);
  const pats = [...new Set([...gate, ...agent])];
  const keys = new Set<string>();
  if (!pats.length) return keys;
  const hosts = new Set<string>([...namedHosts(text).filter((h) => listMatch(pats, h)), ...pats.filter(literal)]);
  // A pattern with no named host behind it (prod-*): its hosts take ssh's defaults unless a Host block says more.
  const bare = pats.filter((p) => !p.startsWith("!") && !literal(p) && ![...hosts].some((h) => globMatch(p, h)));
  for (const h of [...hosts, ...bare.map((p) => p.replace(/[*?]/g, "x"))]) {
    const v = hostView(text, h, { home, withoutOwn: true });
    if (v.identityFiles.length) for (const f of v.identityFiles) keys.add(f.replace(/\.pub$/, ""));
    else for (const d of DEFAULT_KEYS) keys.add(expandPath(join("~", ".ssh", d), home));
  }
  return keys;
}

/** The key files ssh tries when a host names none. */
export const DEFAULT_KEYS = ["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss", "id_dsa"];

/** The user's ssh config, or "" (VSWARM_HOME scoping: `home` is the home whose config this is). */
export const sshConfigText = (home = homedir()) => readText(join(home, ".ssh", "config")) ?? "";
