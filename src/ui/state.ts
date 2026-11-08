// What `vswarm ui` and `vswarm report --html` show: the machine's state, read from vswarm's own files and put in
// plain terms. Everything here only reads (the one write is the language choice, in setLang). Every string that
// leaves this module passes through scrub(): credentials masked again, the home folder shortened to ~. Finding ids
// never leave at all: a card carries a short reference that only this process can map back (refOf).

import { createHash } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { VERSION } from "../home";
import { lang, saveLang, type Lang } from "../i18n";
import { AGENT_NAMES, groupOf as termGroup, paramsOf, UI_GROUP } from "../i18n/findings";
import { readJson, readText, redact } from "../sec/ctx";
import { STATE_RULE } from "../sec/engine";
import { files, loadAccepted, readAudit, readBaseline, readLast, readLog, lockState, stateKey, type LogEntry } from "../sec/store";
import { RANK, verdictOf, type Finding, type Severity, type Verdict } from "../sec/types";

export type { Lang };
export type Level = "safe" | "check" | "stop";
export type Group = "action" | "yours" | "info";
type Tone = "good" | "warn" | "bad" | "off" | "info";

/** A sentence the page puts together from the language files: a key and the values that go into it. */
export interface Say {
  key: string;
  p?: Record<string, string | number>;
}

export interface Card {
  /** Short reference for "This is mine"; the finding id itself stays on the server. */
  ref: string;
  group: Group;
  rule: string;
  severity: Severity;
  /** vswarm's own technical title and details, shown small under the plain words. */
  title: string;
  detail: string[];
  fix?: string;
  p: Record<string, string>;
  canAccept: boolean;
}

export interface Event {
  at: number;
  tone: Tone;
  say: Say;
}

export interface Tile {
  key: "watch" | "guard" | "keys" | "doors" | "ai" | "seal";
  tone: Tone;
  say: Say;
  lines: Say[];
  /** The terminal command that changes this, to copy. */
  cmd?: string;
}

export interface Dash {
  v: 1;
  mode: "live" | "report";
  at: number;
  host: string;
  user: string;
  version: string;
  lang: Lang;
  platform: string;
  status: {
    level: Level;
    why: Say;
    checkedAt?: number;
    baselineAt?: number;
    items?: number;
    /** Findings marked as yours since that check, taken out of the cards and the headline. */
    acceptedSince: number;
    extra: Say[];
  };
  cards: Card[];
  /** vswarm's notes from the last check (English, technical), shown in a details box. */
  notes: string[];
  timeline: Event[];
  tiles: Tile[];
}

// ── safety of what leaves

/** Credentials masked (again: finding details already are), and the home folder as ~. */
export function scrub(s: unknown, home: string): string {
  let t = redact(String(s ?? "")).slice(0, 600);
  for (const h of new Set([home, homedir()].filter((x) => x && x.length > 1))) {
    t = t.split(h).join("~");
    if (process.platform === "win32") t = t.replace(new RegExp(h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), "~");
  }
  return t;
}

/** Every string in a value through scrub(), keys left as they are. */
export function scrubAll<T>(v: T, home: string): T {
  if (typeof v === "string") return scrub(v, home) as T;
  if (Array.isArray(v)) return v.map((x) => scrubAll(x, home)) as T;
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubAll(x, home)])) as T;
  return v;
}

// A per-process salt: a reference means nothing to anyone outside this run.
const SALT = crypto.getRandomValues(new Uint8Array(16));
export const refOf = (id: string) => createHash("sha256").update(SALT).update(id).digest("base64url").slice(0, 16);

// ── language: one setting for the terminal and this page (src/i18n)

/** VSWARM_LANG, then the choice saved here or with `vswarm lang`, then the system's language; English otherwise. */
export const langNow = (env: Record<string, string | undefined> = process.env): Lang => lang(env);

export const setLang = (l: Lang) => saveLang(l);

// ── findings as cards

/** The terminal's groups (src/i18n/findings.ts), under the dashboard's names. */
export const groupOf = (f: Pick<Finding, "rule" | "severity">): Group => UI_GROUP[termGroup(f)];

/** What `vswarm accept` takes: never a known-malicious package, vswarm's own files or a team requirement; a critical one neither, from the page. */
export const acceptable = (f: Finding) => !["malicious", "pkg-malicious", STATE_RULE, "team-require"].includes(f.rule) && f.severity !== "critical";

function cardOf(f: Finding): Card {
  return { ref: refOf(f.id), group: groupOf(f), rule: f.rule, severity: f.severity, title: f.title, detail: f.detail.filter(Boolean).slice(0, 6), fix: f.fix, p: paramsOf(f), canAccept: acceptable(f) };
}

// ── the timeline

/** Host names of known_hosts lines in the clear (hashed lines name nothing), by key fingerprint. */
export function knownHosts(home: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const l of (readText(join(home, ".ssh", "known_hosts")) ?? "").split("\n")) {
    const [hosts, , b64] = l.trim().split(/\s+/);
    if (!hosts || !b64 || hosts.startsWith("|") || hosts.startsWith("#") || hosts.startsWith("@")) continue;
    const fp = `SHA256:${createHash("sha256").update(Buffer.from(b64, "base64")).digest("base64").replace(/=+$/, "")}`;
    if (!out.has(fp)) out.set(fp, hosts.split(",")[0].replace(/^\[([^\]]+)\](?::\d+)?$/, "$1"));
  }
  return out;
}

/** One line of the agent's audit log, in parts: "PASS · ssh login as deploy · alg … · host key SHA256:…". */
export function auditParts(reason = "") {
  const user = /ssh login as (\S+)/.exec(reason)?.[1];
  const hostKey = /host key (SHA256:[A-Za-z0-9+/]+)/.exec(reason)?.[1];
  const head = reason.split(" · ")[0];
  return { user, hostKey, head, sshsig: /ssh-keygen -Y sign/.test(reason) };
}

/** The agent's reasons for a refusal (agent.ts), as a key the page can put in plain words; "" for any other. */
export function refusal(head: string): string {
  if (/^incident .* is open$/.test(head)) return "incident";
  return ({ "this machine does not pass preflight": "block", "preflight warns and this key is strict": "strict", "not confirmed": "unconfirmed", "the agent is locked (ssh-add -x)": "locked" } as Record<string, string>)[head] ?? "";
}

function logEvents(entries: LogEntry[]): Event[] {
  return entries.map((e): Event => {
    if (e.event === "lock") return { at: e.at, tone: "bad", say: { key: "ev.lock", p: { incident: e.incident ?? "?" } } };
    if (e.event === "unlock") return { at: e.at, tone: "good", say: { key: "ev.unlock", p: { incident: e.incident ?? "?" } } };
    return { at: e.at, tone: "info", say: { key: "ev.reset" } };
  });
}

// ── reading it all

export interface StateOpt {
  home?: string;
  mode?: "live" | "report";
  lang?: Lang;
  /** Notes of a check this process ran (the stored last check does not keep them). */
  notes?: string[];
}

export async function dashboard(opt: StateOpt = {}): Promise<Dash> {
  const home = opt.home ?? homedir();
  const now = Date.now();
  const last = await readLast();
  const base = await readBaseline();
  const accepted = await loadAccepted();
  const { lock, why: lockWhy } = await lockState();
  const trusted = last.value && !last.untrusted ? last.value : undefined;

  // The last check, without what was marked as yours since.
  const all = trusted?.findings ?? [];
  const live = all.filter((f) => !accepted[f.id] || !acceptable(f));
  const acceptedSince = all.length - live.length;
  const cards = live.map(cardOf).sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  let verdict: Verdict | undefined = trusted ? (acceptedSince ? verdictOf(live) : trusted.verdict) : undefined;
  if (lock) verdict = "block";

  const extra: Say[] = [];
  let why: Say;
  let level: Level;
  if (lock) {
    level = "stop";
    why = { key: "why.locked", p: { incident: lock.incident } };
    if (lockWhy) extra.push({ key: "why.lockDetail", p: { why: lockWhy } });
  } else if (last.untrusted && !last.nokey) {
    level = "check";
    why = { key: "why.untrusted" };
  } else if (!trusted) {
    level = "check";
    why = { key: "why.never" };
  } else {
    const n = (g: Group) => cards.filter((c) => c.group === g).length;
    level = verdict === "block" ? "stop" : verdict === "warn" ? "check" : "safe";
    why = level === "stop" ? { key: "why.block", p: { n: n("action") } } : level === "check" ? { key: "why.warn", p: { n: n("yours") + n("action") } } : { key: base.value ? "why.pass" : "why.passNoBase" };
  }
  if (trusted && now - trusted.at > 2 * 86_400_000) extra.push({ key: "why.stale" });
  if (base.untrusted && !base.nokey) extra.push({ key: "why.baseUntrusted" });
  else if (!base.value) extra.push({ key: "why.noBase" });
  if (acceptedSince) extra.push({ key: "why.acceptedSince", p: { n: acceptedSince } });

  const tiles: Tile[] = [];
  const timeline: Event[] = [];

  // Checks: the last full one, the background watch, the real-time one.
  const { watchInstalled, realtimeInstalled, watchState } = await import("../sec/schedule");
  const ws = watchState().state;
  const watchOn = watchInstalled(home);
  const realtime = realtimeInstalled(home);
  if (trusted) timeline.push({ at: trusted.at, tone: trusted.verdict === "pass" ? "good" : trusted.verdict === "warn" ? "warn" : "bad", say: { key: `ev.check.${trusted.verdict}`, p: { n: trusted.findings.filter((f) => RANK[f.severity] >= RANK.medium).length } } });
  for (const f of live.filter((f) => RANK[f.severity] >= RANK.medium).slice(0, 3))
    timeline.push({ at: trusted!.at - 1, tone: groupOf(f) === "action" ? "bad" : "warn", say: { key: "ev.found", p: { rule: f.rule, ...cardOf(f).p, title: f.title } } });
  if (ws?.at && ws.at !== trusted?.at) timeline.push({ at: ws.at, tone: ws.verdict === "block" ? "bad" : ws.verdict === "warn" ? "warn" : "good", say: { key: "ev.watch", p: { verdict: ws.verdict || "pass" } } });
  if (ws?.quick?.at) timeline.push({ at: ws.quick.at, tone: "info", say: { key: "ev.quick", p: { parts: ws.quick.parts.length } } });
  if (ws?.last && ws.at) timeline.push({ at: ws.at + 1, tone: "warn", say: { key: "ev.notified", p: { title: ws.last } } });
  if (base.value) timeline.push({ at: base.value.at, tone: "info", say: { key: "ev.baseline" } });
  for (const a of Object.values(accepted)) timeline.push({ at: a.at, tone: "info", say: { key: "ev.accepted", p: { title: a.title } } });

  tiles.push(
    watchOn
      ? { key: "watch", tone: "good", say: { key: realtime ? "tile.watch.realtime" : process.platform === "win32" ? "tile.watch.schedule" : "tile.watch.hourly" }, lines: [ws?.at ? { key: "tile.watch.last", p: { at: ws.at } } : { key: "tile.watch.none" }, ...(ws?.quick ? [{ key: "tile.watch.quick", p: { at: ws.quick.at } }] : [])], cmd: realtime || process.platform === "win32" ? "vswarm watch status" : "vswarm watch on" }
      : { key: "watch", tone: "off", say: { key: "tile.watch.off" }, lines: [{ key: "tile.watch.offWhy" }], cmd: "vswarm watch on" },
  );

  // The install guard.
  const { rcFiles, readKept, guardOn } = await import("../setup");
  const { GUARD_START, loadGuardConfig } = await import("../sec/pkg");
  const guard = process.platform === "win32" ? await guardOn().catch(() => false) : rcFiles(home).filter((r) => /\.(zsh|bash)rc$/.test(r.file)).some((r) => (readKept(r.file)?.text ?? "").includes(GUARD_START));
  const g = loadGuardConfig();
  tiles.push(guard
    ? { key: "guard", tone: "good", say: { key: "tile.guard.on" }, lines: [{ key: "tile.guard.what" }, ...(g.ignoreScripts ? [{ key: "tile.guard.scripts" }] : []), ...(g.sandbox ? [{ key: "tile.guard.sandbox" }] : []), ...(g.strict ? [{ key: "tile.guard.strict" }] : [])], cmd: "vswarm guard status" }
    : { key: "guard", tone: "off", say: { key: "tile.guard.off" }, lines: [{ key: "tile.guard.offWhy" }], cmd: "vswarm guard on" });

  // Production keys in vswarm agent, and their audit log.
  const agent = await import("../sec/agent");
  const vaults = process.platform === "win32" ? [] : agent.listVaults();
  const audit = await readAudit();
  const hosts = knownHosts(home);
  const keyName = (fp?: string) => {
    const v = vaults.find((x) => x.v.fp === fp)?.v;
    return v ? basename(v.path) : "";
  };
  for (const e of audit.entries.slice(-40)) {
    if (e.event !== "sign" && e.event !== "refuse") continue;
    const a = auditParts(e.reason);
    const host = a.hostKey ? hosts.get(a.hostKey) : undefined;
    const p = { key: keyName(e.incident), host: host ?? "", user: a.user ?? "", why: e.event === "refuse" ? a.head : "", whyKey: e.event === "refuse" ? refusal(a.head) : "" };
    timeline.push({ at: e.at, tone: e.event === "sign" ? "info" : "warn", say: { key: `ev.${e.event}${host ? ".host" : a.user ? ".user" : ""}`, p } });
  }
  if (audit.why) timeline.push({ at: now, tone: "bad", say: { key: "ev.auditBroken", p: { why: audit.why } } });
  if (process.platform === "win32") tiles.push({ key: "keys", tone: "off", say: { key: "tile.keys.notHere" }, lines: [], cmd: undefined });
  else if (!vaults.length) tiles.push({ key: "keys", tone: "off", say: { key: "tile.keys.none" }, lines: [{ key: "tile.keys.noneWhy" }], cmd: "vswarm agent protect ~/.ssh/<production key>" });
  else {
    const running = existsSync(agent.agentPaths.sock()) ? !!(await agent.listIdentities(agent.agentPaths.sock(), 1500).catch(() => undefined)) : false;
    const pol = await agent.keyPolicies().catch(() => ({}) as Record<string, { allowWarn: boolean; confirm: boolean }>);
    const lastSign = audit.entries.filter((e) => e.event === "sign").at(-1);
    const lines: Say[] = vaults.map(({ v }) => {
      const x = (pol as Record<string, { allowWarn: boolean; confirm: boolean }>)[v.fp];
      return { key: x ? (x.allowWarn ? "tile.keys.allowWarn" : "tile.keys.passOnly") : "tile.keys.unknown", p: { name: basename(v.path), confirm: x?.confirm ? 1 : 0 } };
    });
    lines.push(lastSign ? { key: "tile.keys.lastUse", p: { at: lastSign.at, name: keyName(lastSign.incident) } } : { key: "tile.keys.neverUsed" });
    tiles.push({ key: "keys", tone: running ? "good" : "bad", say: { key: running ? "tile.keys.held" : "tile.keys.down", p: { n: vaults.length } }, lines, cmd: running ? "vswarm agent status" : "vswarm agent on" });
  }

  // Production doors: the gates in front of ssh, aws, kubectl, gcloud and other commands.
  const sshCfg = readText(join(home, ".ssh", "config")) ?? "";
  const ssh = agent.gatedHosts(sshCfg);
  const { loadCloudGates, gcloudHookStatus } = await import("../sec/cloudgate");
  const { awsStatus } = await import("../sec/awsgate");
  const { kubeStatus } = await import("../sec/kubegate");
  const { loadCmdGates } = await import("../sec/cmdgate");
  const cloud = loadCloudGates();
  const statusOf = (f: () => { name: string; ok: boolean }[]) => {
    try {
      return f();
    } catch {
      return [];
    }
  };
  const aws = statusOf(() => awsStatus({ env: process.env, home, launcher: [] }));
  const kube = statusOf(kubeStatus);
  const gcloud = statusOf(gcloudHookStatus);
  const cmd = Object.keys(loadCmdGates().tools);
  const doors: Say[] = [];
  if (ssh.length) doors.push({ key: "tile.doors.ssh", p: { list: ssh.join(", ") } });
  if (aws.length) doors.push({ key: "tile.doors.aws", p: { list: aws.map((x) => x.name).join(", ") } });
  if (kube.length) doors.push({ key: "tile.doors.kube", p: { list: Object.values(cloud.kube).flatMap((h) => h.for).join(", ") || kube.map((x) => x.name).join(", ") } });
  if (gcloud.length) doors.push({ key: "tile.doors.gcloud", p: { list: gcloud.map((x) => x.name).join(", ") } });
  if (cmd.length) doors.push({ key: "tile.doors.cmd", p: { list: cmd.join(", ") } });
  const broken = [...aws, ...kube, ...gcloud].filter((x) => !x.ok).map((x) => x.name);
  if (broken.length) doors.push({ key: "tile.doors.broken", p: { list: broken.join(", ") } });
  const nDoors = ssh.length + aws.length + kube.length + gcloud.length + cmd.length;
  if (nDoors) doors.push({ key: "tile.doors.reach" });
  tiles.push(nDoors
    ? { key: "doors", tone: broken.length ? "warn" : "good", say: { key: "tile.doors.on", p: { n: nDoors } }, lines: doors, cmd: "vswarm gate status" }
    : { key: "doors", tone: "off", say: { key: "tile.doors.off" }, lines: [{ key: "tile.doors.offWhy" }], cmd: 'vswarm gate ssh "prod-*"' });

  // AI tools: MCP servers in the last check, and which of them `agents --inspect` has read.
  const { loadPins, mcpDrift } = await import("../sec/mcp");
  const pins = await loadPins();
  const servers = (trusted?.scan.items ?? []).filter((i) => i.kind === "mcp" && !i.meta?.disabled);
  const never = mcpDrift(servers, pins.pins).never;
  const apps = [...new Set(servers.map((i) => AGENT_NAMES[String(i.source)] ?? String(i.source)))];
  tiles.push(!trusted
    ? { key: "ai", tone: "off", say: { key: "tile.ai.unknown" }, lines: [], cmd: "vswarm agents" }
    : !servers.length
      ? { key: "ai", tone: "good", say: { key: "tile.ai.none" }, lines: [], cmd: "vswarm agents" }
      : { key: "ai", tone: never.length ? "warn" : "good", say: { key: never.length ? "tile.ai.some" : "tile.ai.all", p: { n: servers.length, done: servers.length - never.length } }, lines: [{ key: "tile.ai.apps", p: { list: apps.join(", ") } }, ...(never.length ? [{ key: "tile.ai.never", p: { list: [...new Set(never.map((i) => i.name))].slice(0, 4).join(", ") } }] : [])], cmd: "vswarm agents --inspect" });

  // The seal on vswarm's own files.
  const k = await stateKey();
  const kind = k.store.kind;
  const sealTone: Tone = k.tampered || !k.key ? "bad" : kind === "file" && !process.env.VSWARM_SEC_DIR && !process.env.VSWARM_KEYSTORE ? "warn" : "good";
  tiles.push({ key: "seal", tone: sealTone, say: { key: k.tampered ? "tile.seal.tampered" : !k.key ? "tile.seal.nokey" : "tile.seal.on", p: { store: kind } }, lines: [{ key: `tile.seal.store.${kind}` }, ...(sealTone === "warn" ? [{ key: "tile.seal.fileWhy" }] : [])], cmd: "vswarm doctor" });

  // Incidents: the sealed log of locks and unlocks.
  const log = await readLog();
  timeline.push(...logEvents(log.entries));
  if (log.why) timeline.push({ at: now, tone: "bad", say: { key: "ev.logBroken", p: { why: log.why } } });
  const incDir = files.incidents();
  if (existsSync(incDir))
    for (const id of readdirSync(incDir).sort().slice(-10)) {
      const inc = readJson<{ at?: number; findings?: unknown[] }>(join(incDir, id, "incident.json"));
      if (inc?.at) timeline.push({ at: inc.at, tone: "bad", say: { key: "ev.incident", p: { incident: id, n: inc.findings?.length ?? 0 } } });
    }

  timeline.sort((a, b) => b.at - a.at);
  const dash: Dash = {
    v: 1,
    mode: opt.mode ?? "live",
    at: now,
    host: trusted?.scan.host ?? "",
    user: trusted?.scan.user ?? "",
    version: VERSION,
    lang: opt.lang ?? langNow(),
    platform: process.platform,
    status: { level, why, checkedAt: trusted?.at, baselineAt: base.value?.at, items: trusted?.scan.items.length, acceptedSince, extra },
    cards,
    notes: opt.notes ?? [],
    timeline: timeline.slice(0, 60),
    tiles,
  };
  return scrubAll(dash, home);
}

/** The finding behind a card's reference, from the sealed last check. */
export async function findingOf(ref: string): Promise<Finding | undefined> {
  const last = await readLast();
  if (!last.value || last.untrusted) return;
  return last.value.findings.find((f) => refOf(f.id) === ref);
}
