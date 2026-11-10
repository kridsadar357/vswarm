// `vswarm setup`: one guided path instead of seven commands. It says what it will do, checks the machine and explains
// each finding (fix it, or say it is yours), takes a starting point (baseline), offers the background watch, the
// install guard and an inspection of AI tool servers, puts doors (gates) in front of the production hosts in
// ~/.ssh/config and offers the key safe (vault) for their keys, asks the WARN policy question, and ends with what is on.
//
// Every step reuses the command that does it (baseline, ok, fix, watch on, guard on, agents --inspect, gate ssh,
// agent protect, policy), so setup can do nothing they would not. Each step can be skipped, and setup can be run again:
// what is on already is said, and only what is missing is offered. Without a terminal it prints the plan and changes
// nothing; --yes takes the recommended answers (no new production hosts and no keys moved: those need a person).
// No passphrase is ever typed into vswarm: key operations prompt through ssh's own tools, as agent protect does.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { t } from "./i18n";
import { acceptFindings, baselineCommand, cannotAccept, fixable, selfCommand } from "./commands";
import { readText } from "./sec/ctx";
import type { Check } from "./sec/engine";
import { c, card, checkedAt, dateOf, headline, line, para, sentenceOf } from "./sec/print";
import { DEFAULT_KEYS, expandPath, hostView, listMatch, literal, namedHosts, ownHosts } from "./sec/sshconfig";
import { readBaseline } from "./sec/store";
import { RANK, type Finding, type Item } from "./sec/types";
import type { PolicyState, WarnPolicy } from "./sec/policy";

export interface SetupDeps {
  /** The home whose ~/.ssh/config lists the hosts. */
  home: string;
  platform: NodeJS.Platform;
  /** A person at a terminal to answer. */
  interactive: boolean;
  /** --yes: the recommended answers, without asking. */
  auto: boolean;
  /** A free answer ("" when nothing was typed). */
  ask: (q: string) => Promise<string>;
  yes: (q: string, def?: boolean) => Promise<boolean>;
  check: () => Promise<Check>;
  watch: { on: () => boolean; enable: () => Promise<void> };
  guard: { on: () => Promise<boolean>; enable: () => Promise<void> };
  /** AI tool servers never inspected in this check, and the inspection (agents --inspect). */
  uninspected: (r: Check) => Promise<Item[]>;
  inspect: (servers: Item[]) => Promise<void>;
  /** vswarm gate ssh with these patterns (all of them: the block is written anew). */
  gate: (patterns: string[]) => Promise<void>;
  /** vswarm agent protect; true when the key is in the vault. */
  protect: (key: string) => Promise<boolean>;
  vaulted: () => string[];
  fix: (f: Finding, n: number) => Promise<void>;
  policy: { read: () => Promise<PolicyState>; save: (w: WarnPolicy) => Promise<void> };
}

const step = (n: number, of: number, title: string) => line(`\n${c.violet(`[${n}/${of}]`)} ${c.bold(title)}`);
const done = (s: string) => line(`  ${c.green("✔")} ${s}`);
const off = (s: string) => line(`  ${c.dim("·")} ${s}`);

/** What setup can already see as on, for the opening and for setup run again. */
interface Status {
  baselineAt?: number;
  watch: boolean;
  guard: boolean;
  gated: string[];
  vaulted: string[];
  policy: PolicyState;
}

async function status(d: SetupDeps): Promise<Status> {
  const b = await readBaseline();
  const cfg = readText(join(d.home, ".ssh", "config")) ?? "";
  return {
    baselineAt: b.value && !b.untrusted ? b.value.at : undefined,
    watch: d.watch.on(),
    guard: await d.guard.on(),
    gated: ownHosts(cfg).gate,
    vaulted: d.platform === "win32" ? [] : d.vaulted(),
    policy: await d.policy.read(),
  };
}

const bgNote = (platform: NodeJS.Platform) => t(platform === "darwin" ? "cli.setup.bgMac" : platform === "win32" ? "cli.setup.bgWin" : "cli.setup.bgLinux");

/** The lines for what is on, used at the start (setup again) and at the end. */
function statusLines(s: Status, platform: NodeJS.Platform): [boolean, string][] {
  return [
    [!!s.baselineAt, s.baselineAt ? t("cli.setup.st.baseline", { at: dateOf(s.baselineAt) }) : t("cli.setup.st.noBaseline")],
    [s.watch, t(s.watch ? "cli.setup.st.watch" : "cli.setup.st.noWatch")],
    [s.guard, t(s.guard ? "cli.setup.st.guard" : "cli.setup.st.noGuard")],
    [s.gated.length > 0, s.gated.length ? t("cli.setup.st.gated", { list: s.gated.join(", ") }) : t("cli.setup.st.noGate")],
    ...(platform === "win32" ? [] : [[s.vaulted.length > 0, s.vaulted.length ? t("cli.setup.st.vault", { n: s.vaulted.length }) : t("cli.setup.st.noVault")] as [boolean, string]]),
    [s.policy.set, t(s.policy.warn === "allow" ? "cli.setup.st.policyAllow" : "cli.setup.st.policyRefuse") + (s.policy.set ? "" : t("cli.policy.default"))],
  ];
}

/** The hosts ~/.ssh/config names, with what each one connects to. */
function hostsOf(home: string): { host: string; to: string }[] {
  const cfg = readText(join(home, ".ssh", "config")) ?? "";
  return namedHosts(cfg).map((host) => {
    const v = hostView(cfg, host, { home, withoutOwn: true });
    return { host, to: `${v.user ? `${v.user}@` : ""}${v.hostname ?? host}${v.port && v.port !== 22 ? `:${v.port}` : ""}` };
  });
}

/** The key files these hosts log in with, as ssh would pick them: their IdentityFile, or ssh's default keys. */
export function keysOf(home: string, hosts: string[]): Map<string, string[]> {
  const cfg = readText(join(home, ".ssh", "config")) ?? "";
  const out = new Map<string, string[]>();
  for (const h of hosts.filter(literal)) {
    const v = hostView(cfg, h, { home, withoutOwn: true });
    const files = v.identityFiles.length ? v.identityFiles.map((f) => f.replace(/\.pub$/, "")) : DEFAULT_KEYS.map((k) => expandPath(join("~", ".ssh", k), home));
    for (const f of files.filter((f) => existsSync(f))) out.set(f, [...(out.get(f) ?? []), h]);
  }
  return out;
}

/** Numbers and names typed for a list, as the entries they mean; what matches nothing comes back as `unknown`. */
export function pickHosts(answer: string, hosts: string[]): { picked: string[]; unknown: string[] } {
  const picked: string[] = [];
  const unknown: string[] = [];
  for (const w of answer.split(/[\s,]+/).filter(Boolean)) {
    const n = /^\d+$/.test(w) ? hosts[Number(w) - 1] : hosts.find((h) => h === w);
    if (n) picked.includes(n) || picked.push(n);
    else unknown.push(w);
  }
  return { picked, unknown };
}

export async function runSetup(d: SetupDeps): Promise<number> {
  const short = (p: string) => p.replace(d.home, "~");
  const before = await status(d);
  const again = !!before.baselineAt || before.watch || before.guard || before.gated.length > 0 || before.vaulted.length > 0 || before.policy.set;

  line(`${c.violet("▼ vswarm setup")} ${c.dim(`· ${t("cli.setup.sub")}`)}`);
  para(t("cli.setup.intro"), 2, (s) => s, "\n  ");
  para(bgNote(d.platform), 2, c.dim, "  ");
  if (again) {
    line(`\n  ${c.bold(t("cli.setup.already"))}`);
    for (const [on, s] of statusLines(before, d.platform)) (on ? done : off)(s);
  }

  // No one to ask and no --yes: the plan, and nothing changed.
  if (!d.interactive && !d.auto) {
    line(`\n  ${c.bold(t("cli.setup.plan"))}`);
    const plan: [boolean, string][] = [
      [false, t("cli.setup.plan.check")],
      [!!before.baselineAt, t("cli.setup.plan.baseline")],
      [before.watch, t("cli.setup.plan.watch")],
      [before.guard, t("cli.setup.plan.guard")],
      [false, t("cli.setup.plan.inspect")],
      [before.gated.length > 0, t("cli.setup.plan.gate")],
      ...(d.platform === "win32" ? [] : [[false, t("cli.setup.plan.vault")] as [boolean, string]]),
      [before.policy.set, t("cli.setup.plan.policy")],
    ];
    plan.forEach(([on, s], i) => line(`  ${c.dim(`${i + 1}.`)} ${s}${on ? c.dim(` · ${t("cli.setup.isOn")}`) : ""}`));
    para(t("cli.setup.noTerminal"), 2, c.amber, "\n  ");
    return 0;
  }

  // In --yes the default answer is taken and said; otherwise the person is asked.
  const confirm = async (q: string, def = false) => {
    if (!d.auto) return d.yes(q, def);
    line(`  ${c.cyan("?")} ${q} ${c.dim(`${def ? t("cli.setup.yes") : t("cli.setup.no")} (--yes)`)}`);
    return def;
  };
  const N = 5;

  // 1 · check, and each finding in one sentence, with fix / it's mine.
  step(1, N, t("cli.setup.s.check"));
  off(t("cli.setup.checking"));
  let r = await d.check();
  headline(r.verdict, sentenceOf(r), checkedAt(Date.now()));
  const canFix = await fixable();
  const shown = r.findings.map((f, i) => ({ f, n: i + 1 })).filter(({ f }) => RANK[f.severity] >= RANK.medium);
  let changed = false;
  const MAX = 12;
  for (const { f, n } of shown.slice(0, MAX)) {
    line("");
    const fix = canFix(f, n);
    // The question below is the way on; the card's own command would only repeat it.
    card(f, n, { fixable: fix, action: d.auto });
    if (d.auto) continue;
    const no = cannotAccept(f) ?? (f.rule === "team-require" ? t("cli.why.teamOnly") : undefined);
    if (!fix && no) {
      para(no, 7, c.dim, "       ");
      continue;
    }
    const a = (await d.ask(t(fix && !no ? "cli.setup.askFixOk" : fix ? "cli.setup.askFix" : "cli.setup.askOk", { n }))).trim().toLowerCase();
    if (fix && /^f/.test(a)) {
      await d.fix(f, n);
      changed = true;
    // Only the letter the question offers: a stray "y" is not "this is mine".
    } else if (!no && /^o/.test(a)) {
      if (await acceptFindings([f])) changed = true;
    } else off(t("cli.setup.skipped"));
  }
  if (shown.length > MAX) para(t("cli.setup.more", { n: shown.length - MAX }), 2, c.dim, "\n  ");
  if (d.auto && shown.length) para(t("cli.setup.reviewLater"), 2, c.dim, "\n  ");
  if (!shown.length) done(t("cli.setup.nothingToReview"));

  // 2 · the starting point. Over HIGH or CRIT findings nobody marked as theirs, baseline refuses as it always does.
  step(2, N, t("cli.setup.s.baseline"));
  if (before.baselineAt) {
    done(t("cli.setup.baselineHave", { at: dateOf(before.baselineAt) }));
    off(t("cli.setup.baselineRefresh"));
  } else {
    para(t("cli.setup.baselineWhat"), 2, c.dim, "  ");
    if (changed) r = await d.check();
    const b = await baselineCommand({ r, quiet: true, auto: d.auto, yes: confirm });
    if (b === "refused") para(t("cli.setup.baselineLater"), 2, c.amber, "  ");
  }

  // 3 · what runs on its own from now on.
  step(3, N, t("cli.setup.s.protect"));
  if (before.watch) done(t("cli.setup.watchHave"));
  else if (await confirm(t(d.platform === "win32" ? "cli.setup.askWatchWin" : "cli.setup.askWatch"), true)) await d.watch.enable();
  else off(t("cli.setup.later", { cmd: "vswarm watch on" }));
  if (before.guard) done(t("cli.setup.guardHave"));
  else if (await confirm(t("cli.setup.askGuard"), true)) await d.guard.enable();
  else off(t("cli.setup.later", { cmd: "vswarm guard on" }));
  const servers = await d.uninspected(r);
  if (!servers.length) done(t("cli.setup.inspectNone"));
  else if (d.platform === "win32") off(t("cli.setup.inspectWin"));
  else if (await confirm(t("cli.setup.askInspect", { n: servers.length }), true)) await d.inspect(servers);
  else off(t("cli.setup.later", { cmd: "vswarm agents --inspect" }));

  // 4 · production: which hosts, a door (gate) in front of them, and the key safe (vault) for their keys.
  step(4, N, t("cli.setup.s.production"));
  const hosts = hostsOf(d.home);
  let gated = before.gated;
  if (!hosts.length && !gated.length) off(t("cli.setup.noHosts"));
  else {
    para(t("cli.setup.gateWhat"), 2, c.dim, "  ");
    const names = hosts.map((h) => h.host);
    hosts.forEach((h, i) => line(`  ${c.bold(String(i + 1).padStart(3))}  ${h.host.padEnd(24)} ${c.dim(h.to)}${listMatch(gated, h.host) ? c.green(`  ${t("cli.setup.isGated")}`) : ""}`));
    let picked: string[] = [];
    if (d.auto) off(t("cli.setup.hostsAuto"));
    else if (hosts.length) {
      const res = pickHosts(await d.ask(t(gated.length ? "cli.setup.askHostsKeep" : "cli.setup.askHosts", { list: gated.join(", ") })), names);
      if (res.unknown.length) off(t("cli.setup.notInList", { list: res.unknown.join(", ") }));
      picked = res.picked.filter((h) => !listMatch(gated, h));
    }
    if (picked.length) {
      await d.gate([...gated, ...picked]);
      gated = [...gated, ...picked];
    } else if (gated.length) done(t("cli.setup.gateKept", { list: gated.join(", ") }));
    else off(t("cli.setup.later", { cmd: 'vswarm gate ssh "prod-*"' }));

    // The keys those hosts use, as ssh picks them; each one offered for the vault.
    if (gated.length) {
      const vaulted = new Set(d.vaulted());
      const keys = [...keysOf(d.home, [...new Set([...gated.filter(literal), ...names.filter((h) => listMatch(gated, h))])])].filter(([k]) => !vaulted.has(k));
      if (!keys.length) done(t(vaulted.size ? "cli.setup.keysHave" : "cli.setup.keysNone"));
      else {
        para(t("cli.setup.vaultWhat"), 2, (s) => s, "\n  ");
        para(t("cli.setup.vaultCode"), 2, c.amber, "  ");
        for (const [key, users] of keys) {
          if (d.auto) {
            off(t("cli.setup.later", { cmd: `vswarm agent protect ${short(key)}` }));
            continue;
          }
          if (!(await confirm(t("cli.setup.askVault", { key: short(key), hosts: users.join(", ") }), false))) {
            off(t("cli.setup.later", { cmd: `vswarm agent protect ${short(key)}` }));
            continue;
          }
          line("");
          if (!(await d.protect(key))) para(t("cli.setup.vaultNot", { key: short(key) }), 2, c.amber, "  ");
        }
      }
    }
  }

  // 5 · the WARN policy, in plain words.
  step(5, N, t("cli.setup.s.policy"));
  if (before.policy.set) done(t(before.policy.warn === "allow" ? "cli.setup.st.policyAllow" : "cli.setup.st.policyRefuse"));
  else {
    para(t("cli.setup.policyWhat"), 2, c.dim, "  ");
    if (d.auto) done(t("cli.setup.policyDefault"));
    else {
      const allow = await d.yes(t("cli.setup.askPolicy"), true);
      await d.policy.save(allow ? "allow" : "refuse");
      done(t(allow ? "cli.setup.st.policyAllow" : "cli.setup.st.policyRefuse"));
    }
  }

  // What is on now, and the two ways on from here.
  const after = await status(d);
  line(`\n${c.violet("▼")} ${c.bold(t("cli.setup.summary"))}`);
  for (const [on, s] of statusLines(after, d.platform)) (on ? done : off)(s);
  line("");
  line(`  ${t("cli.setup.ui")} ${c.cyan(c.bold("vswarm ui"))}`);
  line(`  ${t("cli.setup.undo")} ${c.cyan(c.bold("vswarm uninstall"))}`);
  line(`  ${c.dim(t("cli.setup.again"))}`);
  return 0;
}

/** `vswarm setup [--yes]` on this machine: the real commands behind every step. */
export async function setupCommand(opt: { auto: boolean; offline?: boolean }): Promise<number> {
  // Setup can take a starting point and change gates: asked about like any command that could weaken protection.
  await (await import("./sec/human")).weaken("setup", opt.auto ? ["--yes"] : []);
  const { ask, canAsk, gate, guard, guardOn, yes } = await import("./setup");
  const { realCtx } = await import("./sec/ctx");
  const { check } = await import("./sec/engine");
  const schedule = await import("./sec/schedule");
  const policy = await import("./sec/policy");
  const self = await selfCommand();
  const platform = process.platform;
  const agent = await import("./sec/agent");
  return runSetup({
    home: homedir(), platform, interactive: canAsk(), auto: opt.auto, ask, yes,
    check: () => check(realCtx(), { offline: opt.offline }),
    watch: { on: () => schedule.watchInstalled(), enable: () => schedule.watchCommand("on", { every: 60 }) },
    guard: { on: () => guardOn(), enable: () => guard(["on"]) },
    uninspected: async (r) => {
      const { loadPins, mcpDrift } = await import("./sec/mcp");
      const servers = r.scan.items.filter((i) => i.kind === "mcp" && !i.meta?.disabled);
      return mcpDrift(servers, (await loadPins()).pins).never;
    },
    inspect: async (servers) => void (await (await import("./sec/mcp")).inspectAll(servers, { sandbox: true, show: false, timeoutMs: 90_000 })),
    gate: (patterns) => gate(["ssh", ...patterns]),
    protect: async (key) => !!agent && agent.protectKey(key, {}, { yes }),
    vaulted: () => agent?.listVaults().map((x) => x.v.path) ?? [],
    fix: async (f, n) => void (await (await import("./sec/fix")).fixCommand(f, n, { self, yes })),
    policy: { read: policy.readPolicy, save: async (w) => void (await policy.savePolicy(w)) },
  });
}
