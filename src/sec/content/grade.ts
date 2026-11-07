// How much the signals in a package matter, and what changed since the version before it.
//
// Where code runs decides most of it. Code in an install hook (npm preinstall/install/postinstall, setup.py, a wheel's
// .pth file, binding.gyp commands) runs the moment you install, with everything you can reach; code that only runs
// when the package is used weighs less. Combinations weigh more than parts: reading where keys are kept is a finding,
// reading them in code that also talks to the network is a stealer's shape.
//
//   critical   reads credentials or the environment AND sends to a drop box, or decodes and runs hidden code that does
//   high       at install: decode-and-run, download-and-run, drop-box or raw-IP hosts, persistence, secrets + network,
//              obfuscated code that reaches out; when used: decode-and-run, obfuscation with secrets, secrets sent out;
//              a new release that suddenly carries obfuscated or decode-and-run code
//   medium     at install: secrets or the environment read, an IP lookup, a background process, packed or encoded
//              code; when used: obfuscation, secrets next to network code; a new release that adds an install script
//   low        at install: network or a downloaded program from ordinary hosts (prebuilt binaries); anything else
//              worth knowing, shown by `vswarm pkg check` and not by the install guard
//
// A release whose publisher changed or that lost its provenance gets its findings raised a level: that is how the
// account-takeover releases looked (event-stream 3.3.6, ua-parser-js 0.7.29, chalk/debug in September 2025).

import { RANK, type Finding, type Severity } from "../types";
import type { Cat, Kind, Scanned, Signal } from "./scan";

export interface Meta {
  eco: "npm" | "pip";
  name: string;
  version: string;
  /** The file read: the npm tarball, the wheel or sdist chosen. */
  file?: string;
  integrity?: string;
  /** npm: the account that published this version. */
  publisher?: string;
  maintainers?: string[];
  /** npm: the version carries a provenance attestation (built and published by CI). */
  provenance?: boolean;
  publishedAt?: number;
}

export interface Analysis {
  meta: Meta;
  scanned: Scanned;
}

const LEVELS: Severity[] = ["info", "low", "medium", "high", "critical"];
const up = (s: Severity): Severity => LEVELS[Math.min(LEVELS.indexOf(s) + 1, 4)];

const label = (m: Meta) => `${m.eco === "pip" ? "PyPI" : "npm"} ${m.name}@${m.version}`;

/** When install-time code runs, in words. */
function during(kind: Kind): string {
  return kind === "npm" ? "during npm install" : kind === "sdist" ? "during pip install (setup.py)" : "when installed (a .pth file runs at every Python start)";
}

const evidence = (list: Signal[], n = 4) => {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const s of list) {
    const k = `${s.file}:${s.line}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(`${k}  ${s.text}`);
    if (out.length >= n) break;
  }
  return out;
};

const hostsIn = (list: Signal[]) => [...new Set(list.filter((s) => s.cat === "host" && s.hostKind !== "benign").map((s) => s.host!))];

/** Each risk once: a stable id per package, version and kind of risk. */
function builder(m: Meta, out: Finding[]) {
  return (key: string, severity: Severity, title: string, ev: Signal[], why: string, fix: string, more: string[] = []) =>
    out.push({ id: `pkg:content:${key}:${m.eco}:${m.name}@${m.version}`, rule: "pkg-content", severity, title: `${label(m)}: ${title}`, detail: [...evidence(ev), ...more, `why: ${why}`], fix });
}

export function reportUrl(eco: "npm" | "pip") {
  return eco === "npm" ? "https://www.npmjs.com/support" : "https://pypi.org/security/";
}

export function grade(a: Analysis, prev?: Analysis, opt: { now?: number; newDeps?: { name: string; createdAt?: number }[] } = {}): Finding[] {
  const out: Finding[] = [];
  const m = a.meta;
  const s = a.scanned;
  const add = builder(m, out);
  const check = `vswarm pkg check ${m.eco} ${m.name}@${m.version} --sandbox`;
  const stop = `do not install it${prev ? `; pin ${m.name}@${prev.meta.version} if you need the package` : ""}; report it: ${reportUrl(m.eco)}`;
  const careful = `${m.eco === "npm" ? "install with --ignore-scripts" : "prefer a wheel (pip install --only-binary :all:)"}, or watch what it does first: ${check}`;
  const at = during(s.kind);

  const I = s.signals.filter((x) => x.where === "install");
  // Bundled or minified files hold a whole program in one line: what sits next to what in them means little.
  const packed = new Set(s.dense ?? []);
  const M = s.signals.filter((x) => x.where === "import");
  const Mx = M.filter((x) => !packed.has(x.file));
  const pick = (list: Signal[], ...cats: Cat[]) => list.filter((x) => cats.includes(x.cat));
  const hosts = (list: Signal[], ...kinds: string[]) => list.filter((x) => x.cat === "host" && kinds.includes(x.hostKind!));
  const sameFile = (a1: Signal[], a2: Signal[]) => a1.filter((x) => a2.some((y) => y.file === x.file));

  // ── code that runs at install
  const iSec = pick(I, "secrets"), iEnv = pick(I, "env-dump"), iWeak = pick(I, "secrets-weak"), iTok = pick(I, "token-env");
  const iExfil = [...hosts(I, "exfil"), ...pick(I, "dns-exfil")], iIp = hosts(I, "ip"), iRecon = hosts(I, "recon"), iPlain = hosts(I, "plain");
  const iNetApi = pick(I, "network");
  const iNet = [...iNetApi, ...iExfil, ...iIp, ...iRecon, ...iPlain];
  const iExec = pick(I, "exec-decoded"), iPipe = pick(I, "pipe-shell"), iPers = pick(I, "persistence"), iObf = pick(I, "obfuscated", "hidden");
  const what = (sec: Signal[], env: Signal[]) => [sec.length ? "where your keys and credentials are kept" : "", env.length ? "all your environment variables (tokens included)" : ""].filter(Boolean).join(" and ");

  if ((iSec.length || iEnv.length) && iNet.length)
    add("steal", iExfil.length || iExec.length ? "critical" : "high", `reads ${what(iSec, iEnv)} and reaches the network ${at}`, [...iSec, ...iEnv, ...iExfil, ...iIp, ...iNetApi, ...iPlain],
      "code that runs at install can read everything you can; reading credentials in code that also sends data out is how npm and PyPI stealers work", stop);
  else if (iSec.length || iEnv.length)
    add("secrets", "medium", `looks for ${what(iSec, iEnv)} ${at}`, [...iSec, ...iEnv], "an install script has no reason to open your keys or dump your environment; the sending part may be hidden or come later", careful);
  if (iWeak.length && [...iExfil, ...iIp].length)
    add("tokens", "high", `reads token files (.npmrc, .env) and contacts ${hostsIn([...iExfil, ...iIp]).join(", ")} ${at}`, [...iWeak, ...iExfil, ...iIp], "npm and registry tokens are what worms like Shai-Hulud (2025) steal to publish themselves into your packages", stop);
  else if (iWeak.length && iNet.length && !iSec.length)
    add("tokens", "medium", `reads token files (.npmrc, .env) in code that reaches the network ${at}`, [...iWeak, ...iNet], "a registry token sent elsewhere lets someone publish as you", careful);
  if (iTok.length && [...iExfil, ...iIp].length)
    add("token-env", "high", `reads tokens from the environment (NPM_TOKEN, GITHUB_TOKEN …) and contacts ${hostsIn([...iExfil, ...iIp]).join(", ")} ${at}`, [...iTok, ...iExfil, ...iIp], "CI tokens in the environment are the first thing install-time malware sends out", stop);
  if (iExec.length)
    add("exec", iSec.length || iEnv.length || iNet.length ? "critical" : "high", `decodes hidden code and runs it ${at}`, iExec,
      "legitimate install scripts are readable; code that is decoded at run time is written to stay unread until it runs", stop);
  if (iPipe.length) add("pipe", "high", `downloads code and runs it straight away ${at}`, iPipe, "whatever the server sends runs with your access, and can change between one install and the next", stop);
  if (iExfil.length && !iSec.length && !iEnv.length)
    add("exfil", "high", `sends data to ${hostsIn(iExfil).join(", ") || "a host it builds at run time"} ${at}`, iExfil, "webhooks, paste sites, tunnels and DNS lookups built from data are where stolen data goes; installers have no use for them", stop);
  const ipWithNet = sameFile(iIp, iNetApi);
  if (iIp.length)
    add("ip", ipWithNet.length ? "high" : "medium", `contacts the raw address ${hostsIn(iIp).join(", ")} ${at}`, [...iIp, ...ipWithNet.length ? sameFile(iNetApi, iIp) : []],
      "real download servers have names; a bare IP address is a sign of a throwaway server", ipWithNet.length ? stop : careful);
  if (iPers.length) add("persist", "high", `sets itself up to start again later (login item, shell file, cron, systemd) ${at}`, iPers, "a package has no business adding things that run at every login or every new terminal", stop);
  if (iObf.length)
    add("obfuscated", iNet.length || iSec.length || pick(I, "proc").length ? "high" : "medium", `runs obfuscated code ${at}`, iObf, "obfuscation in an install script hides what it does from exactly this kind of review", iNet.length ? stop : careful);
  if (iRecon.length) add("recon", "medium", `looks up this machine's public IP address (${hostsIn(iRecon).join(", ")}) ${at}`, iRecon, "stealers report where they landed; an installer does not need to know", careful);
  const iDet = pick(I, "detached");
  if (iDet.length) add("detached", "medium", `starts a background process that keeps running after the install`, iDet, "an install that leaves something running can keep working after you think it is done", careful);
  const iMaybe = pick(I, "exec-maybe");
  if (iMaybe.length && !iExec.length) add("exec-maybe", "medium", `decodes text and runs code it builds at run time ${at}`, iMaybe, "decode-then-eval is how hidden payloads are started", careful);
  const iBlob = pick(I, "blob");
  if (iBlob.length) add("blob", "medium", `carries a long encoded string in code that runs ${at}`, iBlob, "an install script with an encoded payload is hiding what it does", careful);
  const iDense = pick(I, "dense");
  const packedRoot = iDense.filter((x) => !/(^|\/)(dist|build|lib|out)\//.test(x.file));
  if (packedRoot.length) add("packed", "medium", `runs packed or minified code ${at}, so what it does cannot be read`, packedRoot, "install scripts are usually a few readable lines; a packed one is hard to review", careful);
  else if (iDense.length) add("packed", "low", `runs bundled code ${at}`, iDense, "a bundled install script is common in big tools, but cannot be read at a glance", `see what it does: ${check}`);
  const iChmod = pick(I, "chmod"), iProc = pick(I, "proc");
  if (iChmod.length && iProc.length && iNet.length && !out.some((f) => RANK[f.severity] >= RANK.high))
    add("download-run", "low", `downloads a program and runs it ${at}${hostsIn(iNet).length ? ` (${hostsIn(iNet).slice(0, 4).join(", ")})` : ""}`, [...iChmod, ...iNet], "usual for packages that fetch a prebuilt binary (esbuild, prisma, sentry-cli); unusual for anything else", `see what it does: ${check}`);
  else if (iNet.length && !out.some((f) => RANK[f.severity] >= RANK.medium))
    add("network", "low", `reaches the network ${at}${hostsIn(iNet).length ? ` (${hostsIn(iNet).slice(0, 4).join(", ")})` : ""}`, iNet, "usual for packages that download a prebuilt binary; the version diff below says if this is new", `see what it does: ${check}`);
  const gyp = pick(I, "gyp").filter((g) => !I.some((x) => x !== g && x.cat !== "gyp" && x.file === "binding.gyp" && x.line === g.line));
  if (gyp.length) add("gyp", "low", `binding.gyp runs ${gyp.length === 1 ? "a command" : `${gyp.length} commands`} while the native module builds`, gyp, "node-gyp runs the <!(…) commands of binding.gyp during npm install; usually pkg-config or a path lookup", `see what it does: ${check}`);
  for (const p of pick(I, "pth")) if (!I.some((x) => x !== p && x.file === p.file && x.cat !== "pth"))
    add(`pth:${p.file}`, "low", `adds ${p.file}, whose code runs every time Python starts`, [p], ".pth files are meant for search paths; an import line in one runs code on every Python start, a known way to persist", `read ${p.file} before installing`);

  // ── code that runs when the package is used
  const mSec = pick(M, "secrets"), mEnv = pick(M, "env-dump"), mExfil = [...hosts(M, "exfil"), ...pick(M, "dns-exfil")], mNetApi = pick(M, "network");
  const mExec = pick(M, "exec-decoded"), mObf = pick(M, "obfuscated", "hidden");
  const used = "when the package is loaded or run";
  if ((mSec.length || mEnv.length) && mExfil.length)
    add("m-steal", "critical", `reads ${what(mSec, mEnv)} and names a drop box (${hostsIn(mExfil).join(", ") || "DNS"})`, [...mSec, ...mEnv, ...mExfil],
      "credentials next to a webhook or paste-site address is a stealer, wherever in the package it sits", stop);
  if (mExec.length)
    add("m-exec", mSec.length || mEnv.length || mExfil.length ? "critical" : "high", `decodes hidden code and runs it ${used}`, mExec,
      "ordinary libraries do not decode and run code they ship encoded; malware on PyPI does this from __init__.py", stop);
  const pM = pick(M, "pipe-shell");
  if (pM.length) add("m-pipe", "medium", `downloads code and runs it ${used}`, pM, "whatever the server sends runs with your access", `read ${pM[0].file} before using it`);
  const dM = pick(M, "dns-exfil");
  if (dM.length && !mSec.length && !mEnv.length) add("m-dns", "high", "builds host names from data and looks them up (DNS exfiltration)", dM, "data hidden in DNS lookups gets past most firewalls", stop);
  if (mObf.length) {
    const near = [...sameFile(mSec, mObf), ...sameFile(mExfil, mObf), ...sameFile(mEnv, mObf), ...sameFile(pick(M, "network"), mObf)];
    add("m-obfuscated", near.length ? "high" : "medium", `carries obfuscated code${near.length ? " next to credential or drop-box code" : ""}`, [...mObf, ...near],
      "the 2025 chalk/debug release hid its wallet stealer exactly like this; real libraries publish readable or plainly minified code", near.length ? stop : `read ${mObf[0].file}, or pin the previous version`);
  }
  // An SDK reads its own kind of credential (botocore ~/.aws, paramiko ~/.ssh); a stealer takes several kinds at once,
  // or sends them to a bare IP address.
  const secNet = sameFile(mSec, mNetApi).filter((x) => !mObf.length && !packed.has(x.file));
  const kinds = (f: string) => new Set(mSec.filter((x) => x.file === f).map((x) => x.family)).size;
  const secOut = secNet.filter((x) => kinds(x.file) >= 2 || Mx.some((y) => y.file === x.file && y.cat === "host" && y.hostKind === "ip"));
  if (secOut.length && !mExfil.length)
    add("m-secrets", "high", `reads ${[...new Set(secOut.map((x) => x.family))].join(", ")} credentials in code that sends data out${hostsIn(Mx.filter((y) => secOut.some((x) => x.file === y.file))).length ? ` (${hostsIn(Mx.filter((y) => secOut.some((x) => x.file === y.file))).slice(0, 3).join(", ")})` : ""}`, [...secOut, ...sameFile(mNetApi, secOut)],
      "several kinds of credentials, or a bare IP address, in the code that talks to the network is the shape of a stealer", stop);
  else if (secNet.length && !mExfil.length)
    add("m-secrets", "low", `reads ${what(mSec, [])} in code that uses the network`, [...secNet, ...sameFile(mNetApi, secNet)], "fine for SDKs and CLIs that use your credentials on purpose (cloud SDKs, git tools); odd for anything else", `make sure ${m.name} is meant to use your credentials`);
  else if (mSec.length && !mExfil.length && !mObf.length)
    add("m-secrets", "low", `reads ${what(mSec, [])} when used`, mSec, "fine for tools that work with your keys (ssh, cloud SDKs); odd for anything else", `make sure ${m.name} is meant to use your credentials`);
  const envNet = sameFile(mEnv, mNetApi).filter((x) => !packed.has(x.file));
  if (envNet.length && !mExfil.length) add("m-env", "medium", "collects all environment variables in code that uses the network", [...envNet, ...sameFile(mNetApi, envNet)], "the environment holds API keys and CI tokens", `read ${envNet[0].file} before using it`);
  const mPers = pick(M, "persistence");
  // Browser drivers and CLIs that set up completion write such files on request: said, not stopped. At install it is high.
  if (mPers.length) add("m-persist", "low", `writes start-up files (login items, shell files, cron) ${used}`, mPers, "fine for tools that install shell completion when asked; otherwise a way to persist", `read ${mPers[0].file}`);
  if (mExfil.length && !mSec.length && !mEnv.length) add("m-exfil", "low", `names ${hostsIn(mExfil).join(", ") || "a drop box"}`, mExfil, "webhook and paste-site addresses are normal in chat-bot libraries, and a stealer's mark elsewhere", `make sure ${m.name} is meant to post there`);
  const mBlob = [...pick(M, "blob"), ...pick(M, "dense"), ...pick(M, "exec-maybe")];
  if (mBlob.length) add("m-packed", "low", "carries encoded strings or packed code outside a bundle", mBlob, "usually generated code or embedded data; the version diff says if it is new", `read ${mBlob[0].file}`);

  // ── the archive itself
  const pr = s.problems;
  const trav = pr.filter((p) => p.kind === "traversal");
  const more = (list: typeof pr) => list.slice(0, 4).map((p) => `${p.path}${p.detail ? `  ${p.detail}` : ""}`);
  if (trav.length) out.push({ id: `pkg:content:traversal:${m.eco}:${m.name}@${m.version}`, rule: "pkg-content", severity: "high", title: `${label(m)}: its archive has entries that point outside the package folder`,
    detail: [...more(trav), "why: path traversal in an archive is an attack on whatever unpacks it; registries' own tools refuse it, other tools may not"], fix: stop });
  const away = pr.filter((p) => p.kind === "link" && /outside the package/.test(p.detail ?? ""));
  if (away.length) out.push({ id: `pkg:content:links:${m.eco}:${m.name}@${m.version}`, rule: "pkg-content", severity: "medium", title: `${label(m)}: its archive has links that point outside the package`,
    detail: [...more(away), "why: a link out of the package folder can make an unpacker write or read elsewhere; vswarm skipped them"], fix: `read the package page before installing ${m.name}` });
  const odd = pr.filter((p) => p.kind === "special" || p.kind === "encrypted" || (p.kind === "link" && !away.includes(p)));
  if (odd.length) out.push({ id: `pkg:content:entries:${m.eco}:${m.name}@${m.version}`, rule: "pkg-content", severity: "low", title: `${label(m)}: its archive has ${odd.length} entr${odd.length > 1 ? "ies" : "y"} vswarm did not read (links, devices, encrypted files)`,
    detail: more(odd), fix: "nothing to do unless other findings point here" });
  const dmg = pr.filter((p) => p.kind === "damaged");
  if (dmg.length) out.push({ id: `pkg:content:damaged:${m.eco}:${m.name}@${m.version}`, rule: "pkg-content", severity: "medium", title: `${label(m)}: its archive is damaged; vswarm could not read all of it`,
    detail: [...more(dmg), "why: a damaged archive cannot be checked, and a crafted one may unpack differently in different tools"], fix: "try again later; if it stays damaged, do not install that version" });

  if (prev) diff(a, prev, out, opt);
  // A release from another account, or one that lost its provenance, makes everything it brings weigh more.
  const swapped = prev && takenOver(m, prev.meta);
  if (swapped) for (const f of out) if (RANK[f.severity] >= RANK.medium && f.severity !== "critical" && !f.id.startsWith("pkg:content:diff")) f.severity = up(f.severity);
  return out.sort((x, y) => RANK[y.severity] - RANK[x.severity]);
}

/** Bots that publish for a project (npm trusted publishing): a release by one is not a new person. */
const CI_PUBLISHER = /^(GitHub Actions|GitLab CI|npm-oidc|.*\[bot\])$/i;

/**
 * The shape of an account takeover: published by someone who was not a maintainer of the version before (a CI bot
 * is not someone), or without the provenance the version before had.
 */
export function takenOver(m: Meta, prev: Meta): boolean {
  const stranger = !!m.publisher && !!prev.publisher && m.publisher !== prev.publisher && !CI_PUBLISHER.test(m.publisher) && !(prev.maintainers ?? []).includes(m.publisher);
  return stranger || (!!prev.provenance && !m.provenance);
}

/** Categories whose sudden appearance in a release means something. */
const NEW_INSTALL: Partial<Record<string, string>> = {
  "exec-decoded": "decodes and runs hidden code", "exec-maybe": "decodes text and runs it", "pipe-shell": "downloads and runs code", obfuscated: "runs obfuscated code",
  hidden: "hides code off-screen", blob: "carries an encoded string", secrets: "reads where keys are kept", "secrets-weak": "reads token files", "env-dump": "dumps the environment",
  "token-env": "reads tokens from the environment", network: "reaches the network", proc: "starts programs", persistence: "writes start-up files", detached: "leaves a background process",
  "host:exfil": "names a drop box", "host:ip": "contacts a raw IP address", "host:recon": "looks up your public IP", "dns-exfil": "builds DNS lookups from data",
};
const NEW_IMPORT_HIGH = new Set(["exec-decoded", "obfuscated", "hidden", "pipe-shell", "dns-exfil"]);
const NEW_IMPORT_MED = new Set(["secrets", "env-dump", "host:exfil", "persistence", "exec-maybe"]);

const caps = (s: Scanned, where: string) =>
  new Set(s.signals.filter((x) => x.where === where && !(x.cat === "host" && (x.hostKind === "benign" || x.hostKind === "plain"))).map((x) => (x.cat === "host" ? `host:${x.hostKind}` : x.cat)));

function diff(a: Analysis, prev: Analysis, out: Finding[], opt: { now?: number; newDeps?: { name: string; createdAt?: number }[] }) {
  const m = a.meta, s = a.scanned, p = prev.scanned;
  const items: { sev: Severity; text: string }[] = [];
  const now = opt.now ?? Date.now();
  const hooksBefore = new Map(p.hooks.map((h) => [h.name, h.cmd]));
  const added = s.hooks.filter((h) => !hooksBefore.has(h.name));
  const changed = s.hooks.filter((h) => hooksBefore.has(h.name) && hooksBefore.get(h.name) !== h.cmd);
  const fresh = m.publishedAt !== undefined && now - m.publishedAt < 7 * 86_400_000;
  const swapped = takenOver(m, prev.meta);
  if (added.length) items.push({ sev: fresh && swapped ? "high" : "medium", text: `adds an install script ${prev.meta.version} did not have: ${added.map((h) => `${h.name}: ${h.cmd}`).join("; ").slice(0, 200)}` });
  for (const h of changed) items.push({ sev: "low", text: `changes its ${h.name} script: ${hooksBefore.get(h.name)?.slice(0, 80)} → ${h.cmd.slice(0, 80)}` });
  const ci = caps(s, "install"), pi = caps(p, "install");
  for (const c of ci) if (!pi.has(c) && NEW_INSTALL[c]) items.push({ sev: c === "network" || c === "proc" ? "low" : "medium", text: `its install code now ${NEW_INSTALL[c]}` });
  const cm = caps(s, "import"), pm = caps(p, "import");
  for (const c of cm) {
    if (pm.has(c)) continue;
    if (NEW_IMPORT_HIGH.has(c)) items.push({ sev: "high", text: `its code now ${NEW_INSTALL[c]} (absent in ${prev.meta.version})` });
    else if (NEW_IMPORT_MED.has(c)) items.push({ sev: "medium", text: `its code now ${NEW_INSTALL[c]}` });
  }
  const hostsBefore = new Set(p.signals.filter((x) => x.cat === "host").map((x) => x.host));
  const newHosts = [...new Set(s.signals.filter((x) => x.cat === "host" && x.hostKind !== "benign" && !hostsBefore.has(x.host) && (x.where === "install" || s.signals.some((y) => y.file === x.file && y.cat === "network"))).map((x) => x.host!))];
  if (newHosts.length) items.push({ sev: s.signals.some((x) => x.where === "install" && x.cat === "host" && newHosts.includes(x.host!)) ? "medium" : "low", text: `names new hosts in network code: ${newHosts.slice(0, 6).join(", ")}` });
  if (p.size > 0 && s.size > 2 * p.size && s.size - p.size > 100_000 && s.files <= p.files * 1.2 + 5)
    items.push({ sev: items.some((i) => RANK[i.sev] >= RANK.medium) ? "medium" : "low", text: `grew from ${kb(p.size)} to ${kb(s.size)} with ${s.files - p.files > 0 ? `only ${s.files - p.files} new` : "no new"} files` });
  if (m.publisher && prev.meta.publisher && m.publisher !== prev.meta.publisher) items.push({ sev: "low", text: `published by ${m.publisher}; ${prev.meta.version} was published by ${prev.meta.publisher}` });
  const newMaint = (m.maintainers ?? []).filter((x) => prev.meta.maintainers && !prev.meta.maintainers.includes(x));
  if (newMaint.length) items.push({ sev: "low", text: `new maintainer${newMaint.length > 1 ? "s" : ""}: ${newMaint.slice(0, 4).join(", ")}` });
  if (prev.meta.provenance && !m.provenance) items.push({ sev: fresh ? "medium" : "low", text: `${prev.meta.version} was built and published by CI with provenance; this version has none (published by hand)` });
  const depsBefore = new Set(p.deps);
  const newDeps = s.deps.filter((d) => !depsBefore.has(d));
  for (const d of newDeps.slice(0, 6)) {
    const info = opt.newDeps?.find((x) => x.name === d);
    const young = info?.createdAt !== undefined && now - info.createdAt < 30 * 86_400_000;
    items.push({ sev: young ? "medium" : "low", text: `adds the dependency ${d}${young ? `, a package created ${Math.round((now - info!.createdAt!) / 86_400_000)} days ago` : ""}` });
  }
  if (!items.length) return;
  let sev = items.reduce<Severity>((x, i) => (RANK[i.sev] > RANK[x] ? i.sev : x), "info");
  // Something new and risky, from another account or without the provenance it used to have.
  if (swapped && RANK[sev] >= RANK.medium) sev = up(sev);
  // An install script that arrives in the same release as new install-time behaviour weighs more.
  if (added.length) for (const f of out) if (f.id.startsWith("pkg:content:") && f.severity === "medium" && !/^pkg:content:(m-|traversal|links|entries|damaged)/.test(f.id)) f.severity = "high";
  items.sort((x, y) => RANK[y.sev] - RANK[x.sev]);
  out.push({
    id: `pkg:content:diff:${m.eco}:${m.name}@${m.version}`, rule: "pkg-content", severity: sev,
    title: `${label(m)}: new since ${prev.meta.version}: ${items[0].text}`,
    detail: [...items.slice(1, 8).map((i) => i.text), "why: releases from a taken-over account look like this: event-stream 3.3.6, ua-parser-js 0.7.29, chalk and debug (September 2025)"],
    fix: RANK[sev] >= RANK.medium ? `pin the version before (${m.eco === "npm" ? `${m.name}@${prev.meta.version}` : `${m.name}==${prev.meta.version}`}) until this release is explained` : "nothing to do unless other findings point here",
  });
}

const kb = (n: number) => (n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)} MB` : `${Math.round(n / 1000)} KB`);
