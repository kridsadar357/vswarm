// Before an install: what is this package, and is it safe to let its install scripts run?
//
// `vswarm guard on` wraps npm, npx, pnpm, yarn, bun, bunx, pip, pip3, uv, pipx and brew in your shell. When you type an
// install, vswarm reads the package names from the command line (or the lockfile, for a bare `npm install`) and asks
// the registries before the package manager runs anything:
//
//   known-malicious   OSV MAL- records (OpenSSF malicious-packages)                      critical
//   look-alike        close to a popular name (axois, reqeusts, solana-web3.js)           high, low when established
//   does not exist    a name nobody published yet: a typo, or a name an AI made up        high when it looks like a popular one
//   brand new         the version was published in the last 48 hours (hijacked releases)   medium
//   new and unknown   package created in the last 30 days with few downloads              medium, high with an install script
//   install script    preinstall / install / postinstall, or a Python sdist (setup.py)     low, raised by the signals above
//   outside registry  git URLs, tarballs, third-party Homebrew taps                       medium
//   contents          what the archive holds and what is new since the version before     graded (content/)
//
// Only package names and versions leave the machine (registry.npmjs.org, api.npmjs.org, api.deps.dev, pypi.org,
// api.osv.dev); archives are downloaded from registry.npmjs.org and files.pythonhosted.org to be read, never run.
// If a registry cannot be reached the install goes ahead with a notice: a broken network is not an attack.

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { exec, readJson, shq } from "./ctx";
import { lookAlike, nameSignals, osvMalicious } from "./intel";
import { c, finding as printFinding, line, VERDICT } from "./print";
import { files, SEC, writePrivate } from "./store";
import { RANK, verdictOf, type Finding, type Item, type Severity, type Verdict } from "./types";

export type Eco = "npm" | "pip" | "brew";

export interface Want {
  eco: Eco;
  name: string;
  /** Exact version when the command or lockfile pins one. */
  version?: string;
  /** git URL, tarball, path: installs code the registry never saw. */
  outside?: string;
  /** Homebrew tap, for user/tap/formula. */
  tap?: string;
  /** Code already on this machine (link:, portal:, workspace:, ./folder): nothing to download, nothing to ask a registry. */
  local?: boolean;
}

export interface Plan {
  wants: Want[];
  /** True when this command installs nothing (npm run, pip list): vswarm stays out of the way. */
  skip: boolean;
  /** Where the names came from, for the summary line. */
  from: string;
}

const NPM_INSTALL = new Set(["install", "i", "add", "a", "isntall", "in", "ins", "inst", "insta", "instal", "update", "up", "upgrade"]);
const NPM_RUN_PKG = new Set(["exec", "x", "dlx"]);
// Options that take a value, so the value is not mistaken for a package name.
const VALUE_OPTS = new Set(["--registry", "--prefix", "-C", "--cwd", "--tag", "--filter", "-F", "--workspace", "-w", "--cache", "--userconfig",
  "-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target", "--python", "-p", "--package", "--with", "--root", "--platform"]);

function names(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (VALUE_OPTS.has(a)) {
      i++;
      continue;
    }
    if (a.startsWith("-") || !a) continue;
    out.push(a);
  }
  return out;
}

/** npx / npm exec / bunx / uvx: the package is what -p, --package or --from names, else the first plain word; `--` only separates it from its own arguments. */
function execSpecs(args: string[]): string[] {
  const dash = args.indexOf("--");
  const opts = dash < 0 ? args : args.slice(0, dash);
  const pkgs: string[] = [];
  for (let i = 0; i < opts.length; i++) {
    if (opts[i] === "-p" || opts[i] === "--package" || opts[i] === "--from") pkgs.push(opts[++i] ?? "");
    else if (opts[i].startsWith("--package=") || opts[i].startsWith("--from=")) pkgs.push(opts[i].slice(opts[i].indexOf("=") + 1));
  }
  if (pkgs.some(Boolean)) return pkgs.filter(Boolean);
  const first = names(opts)[0] ?? (dash >= 0 ? args[dash + 1] : undefined);
  return first ? [first] : [];
}

/** npm name[@version] → Want. Scoped names keep their leading @; local folders come back marked `local`, and npmWants drops them. */
export function npmSpec(spec: string): Want {
  if (/\.(tgz|tar\.gz)$/.test(spec)) return { eco: "npm", name: spec, outside: spec };
  // A folder of the user's own code: nothing is downloaded, and there is no registry to ask about it.
  if (/^(link:|portal:|workspace:)/.test(spec) || /^\.\.?(\/|$)/.test(spec)) return { eco: "npm", name: spec, local: true };
  if (/^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|\/|~\/)/.test(spec) || /^[\w-]+\/[\w.-]+(#.*)?$/.test(spec))
    return { eco: "npm", name: spec, outside: spec };
  // An alias (name@npm:real-name@1) installs the real name.
  const alias = /^@?[^@]+@npm:(.+)$/.exec(spec);
  if (alias) return npmSpec(alias[1]);
  const at = spec.lastIndexOf("@");
  const [name, range] = at > 0 ? [spec.slice(0, at), spec.slice(at + 1)] : [spec, ""];
  return { eco: "npm", name, version: /^\d+\.\d+\.\d+(-[\w.-]+)?(\+[\w.-]+)?$/.test(range) ? range : undefined };
}

const npmWants = (specs: string[]): Want[] => specs.map(npmSpec).filter((w) => !w.local);

/** pip requirement → Want, or nothing for local paths and editable installs of the project itself. */
export function pipSpec(spec: string): Want | undefined {
  const s = spec.trim().replace(/\s*[;#].*$/, "");
  if (!s) return;
  // PEP 508 direct references need no space around the @.
  if (/^(git\+|https?:|hg\+|svn\+)/.test(s) || /\s*@\s*(git\+|https?:|file:)/.test(s)) return { eco: "pip", name: s, outside: s };
  if (/^(\.|\/|~)/.test(s) || /\.(whl|tar\.gz|zip)$/.test(s)) return;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==\s*([\w.+!-]+))?/.exec(s);
  if (!m) return;
  return { eco: "pip", name: m[1].toLowerCase().replace(/[._]+/g, "-"), version: m[4] };
}

function requirements(path: string, depth = 0): Want[] {
  let text: string;
  try {
    // A folder or an unreadable file is pip's problem to report, not a reason to stop the check.
    if (depth > 3 || !statSync(path).isFile()) return [];
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const out: Want[] = [];
  for (const raw of text.split("\n")) {
    const l = raw.trim();
    if (!l || l.startsWith("#")) continue;
    const inc = /^(?:-r|--requirement)(?:\s+|=)(\S+)/.exec(l);
    if (inc) {
      out.push(...requirements(resolve(dirname(path), inc[1]), depth + 1));
      continue;
    }
    // -e git+https://… installs code from outside the registry, like the same spec on the command line.
    const spec = l.replace(/^(?:-e|--editable)(?:\s+|=)/, "");
    if (spec.startsWith("-")) continue;
    const w = pipSpec(spec);
    if (w) out.push(w);
  }
  return out;
}

/** What a bare `npm install` would bring in: the lockfile when there is one, else the direct dependencies. */
export function npmProject(dir: string): Want[] {
  for (const lock of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const p = join(dir, lock);
    if (!existsSync(p)) continue;
    try {
      const j = JSON.parse(readFileSync(p, "utf8"));
      const outside = (v: any) => (typeof v.resolved === "string" && !/^https:\/\/registry\.npmjs\.org\//.test(v.resolved) ? { outside: v.resolved } : {});
      const pkgs: Record<string, any> = j.packages ?? {};
      const out = Object.entries(pkgs)
        .filter(([k, v]) => k && v && !v.link)
        .map(([k, v]) => ({ eco: "npm" as const, name: v.name ?? k.split("node_modules/").at(-1)!, version: v.version, ...outside(v) }));
      // Lockfile v1 (npm 6) nests `dependencies` instead of listing `packages`.
      const walk = (deps: unknown) => {
        for (const [name, v] of Object.entries<any>(deps && typeof deps === "object" ? deps : {})) {
          if (!v || typeof v !== "object") continue;
          out.push({ eco: "npm", name, version: v.version, ...outside(v) });
          walk(v.dependencies);
        }
      };
      if (!out.length) walk(j.dependencies);
      if (out.length) return out;
    } catch {}
  }
  try {
    const pj = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    return Object.entries({ ...pj.dependencies, ...pj.devDependencies, ...pj.optionalDependencies }).flatMap(([n, r]): Want[] => {
      const v = String(r);
      // Workspace and linked packages are folders of this project, not downloads.
      if (/^(link:|portal:|workspace:|\.\.?\/)/.test(v)) return [];
      if (v.startsWith("npm:")) return npmWants([v.slice(4)]);
      return [/^(git|github:|https?:|file:)/.test(v) ? { eco: "npm", name: n, outside: v } : { eco: "npm", name: n }];
    });
  } catch {
    return [];
  }
}

/** Reads a package-manager command line. `tool` is what was typed: npm, pnpm, yarn, bun, npx, bunx, pip, pip3, uv, pipx, brew. */
export function plan(tool: string, args: string[], cwd = process.cwd()): Plan {
  const none: Plan = { wants: [], skip: true, from: "" };
  const sub = args[0];
  if (tool === "npx" || tool === "bunx" || tool === "uvx") {
    const specs = execSpecs(args);
    const wants = tool === "uvx" ? specs.map(pipSpec).filter((w): w is Want => !!w) : npmWants(specs);
    return wants.length ? { wants, skip: false, from: `${tool} ${specs.join(" ")}` } : none;
  }
  if (["npm", "pnpm", "yarn", "bun"].includes(tool)) {
    // yarn with options before the command (or only options): the first plain word is the command; none is an
    // install, except yarn --version and --help.
    if (tool === "yarn" && sub?.startsWith("-")) {
      if (args.some((a) => /^(--version|-v|--help|-h)$/.test(a))) return none;
      const at = args.findIndex((a, k) => !a.startsWith("-") && !(k > 0 && VALUE_OPTS.has(args[k - 1])));
      if (at < 0) {
        const wants = npmProject(cwd);
        return { wants, skip: !wants.length, from: `${wants.length} packages in this project` };
      }
      return plan(tool, [args[at], ...args.slice(0, at), ...args.slice(at + 1)], cwd);
    }
    if (sub && NPM_RUN_PKG.has(sub)) {
      const specs = execSpecs(args.slice(1));
      const wants = npmWants(specs);
      return wants.length ? { wants, skip: false, from: `${tool} ${sub} ${specs.join(" ")}` } : none;
    }
    // yarn global add|upgrade <names>: the names are what gets installed; a bare `yarn global upgrade` has no project to read.
    if (tool === "yarn" && sub === "global") {
      const specs = NPM_INSTALL.has(args[1] ?? "") ? names(args.slice(2)) : [];
      const wants = npmWants(specs);
      return wants.length ? { wants, skip: false, from: specs.join(" ") } : none;
    }
    // yarn with no arguments installs; `yarn <script>` runs a script.
    const installs = (sub && NPM_INSTALL.has(sub)) || sub === "ci" || (tool === "yarn" && !sub);
    if (!installs) return none;
    const specs = names(args.slice(1));
    // `npm update` without names, `npm ci` and bare installs read the project.
    if (!specs.length || sub === "ci") {
      const wants = npmProject(cwd);
      return { wants, skip: !wants.length, from: `${wants.length} packages in this project` };
    }
    const wants = npmWants(specs);
    return { wants, skip: !wants.length, from: specs.join(" ") };
  }
  if (["pip", "pip3", "uv", "pipx"].includes(tool)) {
    let rest = args;
    if (tool === "uv") {
      if (sub === "pip") rest = args.slice(1);
      else if (sub === "add" || sub === "tool") rest = sub === "tool" ? args.slice(1) : ["install", ...args.slice(1)];
      else return none;
    }
    if (tool === "pipx" && !["install", "inject", "run"].includes(rest[0] ?? "")) return none;
    if (tool !== "pipx" && rest[0] !== "install" && !(tool === "uv" && sub === "tool" && (rest[0] === "install" || rest[0] === "run"))) return none;
    const wants: Want[] = [];
    for (let i = 1; i < rest.length; i++) {
      if (rest[i] === "-r" || rest[i] === "--requirement") wants.push(...requirements(resolve(cwd, rest[++i] ?? "")));
      else if (rest[i].startsWith("--requirement=")) wants.push(...requirements(resolve(cwd, rest[i].slice("--requirement=".length))));
    }
    const specs = names(rest.slice(1));
    // pipx inject <venv> <pkgs…>: the first name is the existing app.
    for (const s of tool === "pipx" && rest[0] === "inject" ? specs.slice(1) : specs) {
      const w = pipSpec(s);
      if (w) wants.push(w);
    }
    return { wants, skip: !wants.length, from: wants.length > 3 ? `${wants.length} Python packages` : wants.map((w) => w.name).join(" ") };
  }
  if (tool === "brew") {
    if (sub === "tap") {
      const t = names(args.slice(1))[0];
      return t ? { wants: [{ eco: "brew", name: t, tap: t }], skip: false, from: `brew tap ${t}` } : none;
    }
    if (!["install", "reinstall", "upgrade"].includes(sub ?? "")) return none;
    const specs = names(args.slice(1));
    const wants = specs.map((s): Want => {
      // A formula file (./x.rb, /abs/x.rb, https://…/x.rb) comes from outside any tap.
      if (/^(\.{0,2}\/|~\/|https?:\/\/)/.test(s) || s.endsWith(".rb")) return { eco: "brew", name: s, outside: s };
      const parts = s.split("/");
      return parts.length === 3 ? { eco: "brew", name: s, tap: `${parts[0]}/${parts[1]}` } : { eco: "brew", name: s };
    });
    return { wants, skip: !wants.length, from: specs.join(" ") };
  }
  return none;
}

// ── What the registries say

export interface Facts {
  exists: boolean;
  /** The version that would be installed. */
  version?: string;
  /** Install hooks of that version, when the registry tells. */
  scripts?: string[];
  /** Python: only a source distribution, so setup.py runs at install. */
  sdistOnly?: boolean;
  versionAt?: number;
  createdAt?: number;
  weeklyDownloads?: number;
  /** npm: the version's manifest (archive, publisher, provenance), so reading its contents asks nothing again. */
  manifest?: Manifest;
  /** Every published version and when, for finding the one before. */
  versionList?: { v: string; at?: number }[];
  /** PyPI: the project's JSON (its releases and their files). */
  pypi?: any;
}

/** What one npm version's manifest says about running and publishing it. */
export interface Manifest {
  version: string;
  /** Install hooks, as "name: command". */
  scripts: string[];
  dist?: { url: string; integrity?: string; shasum?: string; size?: number };
  /** The account that published it. */
  publisher?: string;
  maintainers?: string[];
  /** Published with a provenance attestation (built in CI). */
  provenance?: boolean;
}

/** One file of a PyPI release, as the JSON API lists it. */
export interface PyFile {
  filename: string;
  url: string;
  packagetype: string;
  digests?: { sha256?: string };
  size?: number;
  upload_time?: string;
  upload_time_iso_8601?: string;
}

export interface FetchInit {
  method?: string;
  body?: string;
  accept?: string;
  timeoutMs?: number;
}

export type Fetcher = (url: string, init?: FetchInit) => Promise<{ status: number; json(): Promise<any>; arrayBuffer?(): Promise<ArrayBuffer> }>;

const realFetch: Fetcher = (url, init = {}) =>
  fetch(url, {
    method: init.method, body: init.body,
    headers: { accept: init.accept ?? "application/json", "user-agent": "vswarm", ...(init.body ? { "content-type": "application/json" } : {}) },
    signal: AbortSignal.timeout(init.timeoutMs ?? 6000),
  });

const enc = (n: string) => n.replace("/", "%2F");

/** One version's manifest; undefined when npm has no such package or version. */
export async function npmManifest(name: string, version: string | undefined, get: Fetcher = realFetch): Promise<Manifest | undefined> {
  const man = await get(`https://registry.npmjs.org/${enc(name)}/${version ?? "latest"}`);
  if (man.status === 404) return;
  if (man.status !== 200) throw new Error(`registry.npmjs.org ${man.status}`);
  const m = await man.json();
  const str = (x: unknown) => (typeof x === "string" ? x : undefined);
  return {
    version: m.version as string,
    scripts: ["preinstall", "install", "postinstall", "prepare"].filter((s) => m.scripts?.[s]).map((s) => `${s}: ${m.scripts[s]}`),
    dist: str(m.dist?.tarball) ? { url: m.dist.tarball, integrity: str(m.dist.integrity), shasum: str(m.dist.shasum), size: typeof m.dist.unpackedSize === "number" ? m.dist.unpackedSize : undefined } : undefined,
    publisher: str(m._npmUser?.name),
    maintainers: Array.isArray(m.maintainers) ? m.maintainers.map((x: any) => str(x?.name)).filter((x: any): x is string => !!x) : undefined,
    provenance: !!m.dist?.attestations,
  };
}

export async function npmFacts(name: string, version: string | undefined, get: Fetcher = realFetch): Promise<Facts> {
  const m = await npmManifest(name, version, get);
  if (!m) return { exists: false };
  const { scripts, version: v } = m;
  const [dl, dep] = await Promise.all([
    get(`https://api.npmjs.org/downloads/point/last-week/${name}`).then((r) => (r.status === 200 ? r.json() : undefined)).catch(() => undefined),
    get(`https://api.deps.dev/v3/systems/npm/packages/${encodeURIComponent(name)}`).then((r) => (r.status === 200 ? r.json() : undefined)).catch(() => undefined),
  ]);
  const times: Record<string, number> = {};
  for (const x of dep?.versions ?? []) if (x.publishedAt) times[x.versionKey?.version] = Date.parse(x.publishedAt);
  const all = Object.values(times);
  return {
    exists: true, version: v, scripts, versionAt: times[v], createdAt: all.length ? Math.min(...all) : undefined, weeklyDownloads: dl?.downloads,
    manifest: m, versionList: all.length ? Object.entries(times).map(([x, at]) => ({ v: x, at })) : undefined,
  };
}

/** PyPI's JSON for a project (every release and its files); undefined when there is no such project. */
export async function pypiProject(name: string, get: Fetcher = realFetch): Promise<any> {
  const r = await get(`https://pypi.org/pypi/${name}/json`);
  if (r.status === 404) return;
  if (r.status !== 200) throw new Error(`pypi.org ${r.status}`);
  return r.json();
}

export async function pipFacts(name: string, version: string | undefined, get: Fetcher = realFetch): Promise<Facts> {
  const d = await pypiProject(name, get);
  if (!d) return { exists: false };
  const v: string = version ?? d.info?.version;
  const rel: any[] = d.releases?.[v] ?? d.urls ?? [];
  const at = (x: any) => Date.parse(x.upload_time_iso_8601 ?? x.upload_time);
  const first = Object.values(d.releases ?? {}).flat().map(at).filter(Number.isFinite) as number[];
  const mine = rel.map(at).filter(Number.isFinite);
  return {
    exists: true,
    version: v,
    sdistOnly: rel.length > 0 && rel.every((x) => x.packagetype === "sdist"),
    versionAt: mine.length ? Math.min(...mine) : undefined,
    createdAt: first.length ? Math.min(...first) : undefined,
    pypi: d,
  };
}

const DAY = 86_400_000;
const ago = (t: number) => {
  const h = Math.round((Date.now() - t) / 3_600_000);
  return h < 48 ? `${h} hours ago` : `${Math.round(h / 24)} days ago`;
};

const label = (w: Want) => `${w.eco === "pip" ? "PyPI" : w.eco} ${w.name}`;

/** Findings for one wanted package, from what the registry said. */
export function judge(w: Want, f: Facts | undefined, now = Date.now()): Finding[] {
  const out: Finding[] = [];
  const add = (rule: string, severity: Severity, title: string, detail: string[], fix?: string) =>
    out.push({ id: `pkg:${rule}:${w.eco}:${w.name}`, rule: `pkg-${rule}`, severity, title, detail, fix });
  if (w.outside) {
    add("outside", "medium", `${w.name}: installs code from outside the registry`, [`source: ${w.outside}`, "Nothing here was checked by the registry or by vswarm; it can run install scripts."],
      "read it first, or try it in the sandbox: vswarm try <url>");
    return out;
  }
  if (w.eco === "brew") {
    if (w.tap && !/^homebrew\//i.test(w.tap))
      add("tap", "medium", `${w.name}: from the third-party tap ${w.tap}`, ["A tap is someone's git repository; its formulae run their own install code, outside Homebrew's review."],
        `check who owns github.com/${w.tap.split("/")[0]}/homebrew-${w.tap.split("/")[1]} before trusting it`);
    return out;
  }
  const near = lookAlike(w.eco, w.name);
  // What the name says of itself (a proof-of-concept, a dependency-confusion probe), whatever the registry answers.
  for (const s of nameSignals(w.eco, w.name)) add("name", "high", `${label(w)}: ${s.split(":")[0]}`, [s], `do not install it unless it is your own test package`);
  if (!f) {
    if (near) add("lookalike", "high", `${label(w)}: looks like ${near}`, ["Close to a popular package name: the classic typo-squat, which runs its install script as soon as it lands."], `did you mean ${near}? If ${w.name} is really what you want, check its page on the registry first`);
    return out;
  }
  if (!f.exists) {
    add("missing", near ? "high" : "low", `${label(w)}: no such package`, [
      near ? `It looks like ${near}. Someone can register this name at any time and wait for the typo.` : "A typo, or a name an AI assistant made up. Attackers register such names once they see them suggested.",
    ], near ? `did you mean ${near}?` : "check the name on the registry website");
    return out;
  }
  // A name that resembles a popular one but is itself widely used and years old is a real package of its own
  // (lodash.set, babel-core): said in one line, not stopped. Typo-squats are new and little used; they get taken down.
  // PyPI publishes no download counts; there, years on the registry stand in for them.
  const established = (f.weeklyDownloads ?? 0) >= 50_000 || (w.eco === "pip" && f.weeklyDownloads === undefined && f.createdAt !== undefined && now - f.createdAt > 3 * 365 * DAY);
  if (near && established)
    add("lookalike", "low", `${label(w)}: resembles ${near}, but is an established package of its own`,
      [f.weeklyDownloads !== undefined ? `${f.weeklyDownloads} downloads last week` : `first published ${ago(f.createdAt!)}`], `make sure you meant ${w.name}, not ${near}`);
  else if (near)
    add("lookalike", "high", `${label(w)}: looks like ${near}`, ["Close to a popular package name and not established itself: the classic typo-squat, which runs its install script as soon as it lands."],
      `did you mean ${near}? If ${w.name} is really what you want, check its page on the registry first`);
  const fresh = f.versionAt !== undefined && now - f.versionAt < 2 * DAY;
  const young = f.createdAt !== undefined && now - f.createdAt < 30 * DAY;
  const unknown = f.weeklyDownloads !== undefined ? f.weeklyDownloads < 500 : young;
  const hooks = (f.scripts?.length ?? 0) > 0 || !!f.sdistOnly;
  const hookText = f.scripts?.length ? f.scripts : f.sdistOnly ? ["only a source distribution: its setup.py runs during the install"] : [];
  if (young && unknown)
    add("new", hooks ? "high" : "medium", `${label(w)}: created ${ago(f.createdAt!)}${f.weeklyDownloads !== undefined ? `, ${f.weeklyDownloads} downloads last week` : ""}`,
      [...(hooks ? ["and it runs code when installed:", ...hookText] : ["New and little used. Fine if you know the author; a common shape for fake packages."])],
      hooks ? "read the install script first, or install with --ignore-scripts" : undefined);
  else if (fresh)
    add("fresh", "medium", `${label(w)}@${f.version}: published ${ago(f.versionAt!)}`, [
      "Hijacked maintainer accounts publish poisoned versions that are pulled within hours or days.",
      ...(hooks ? ["This version runs code when installed:", ...hookText] : []),
    ], `pin the previous version unless you need this one${w.eco === "npm" ? ` (npm view ${w.name} versions)` : ""}`);
  else if (hooks && w.eco === "npm")
    add("scripts", "low", `${label(w)}@${f.version}: runs an install script`, hookText);
  return out;
}

export interface PkgCheck {
  plan: Plan;
  findings: Finding[];
  verdict: Verdict;
  notes: string[];
  ms: number;
  /** Dependencies checked beyond the named packages (the whole tree, from deps.dev). */
  deps: number;
  /** What could not be checked (a registry or OSV did not answer); --strict stops on these. */
  unverified: string[];
  /** Named packages whose chosen version runs install scripts. */
  scripted: string[];
  /** Packages whose contents were read, and how much of them (content/). */
  read: string[];
  readFiles: number;
  readBytes: number;
}

export interface CheckOpt {
  get?: Fetcher;
  offline?: boolean;
  osvCache?: string;
  /** Read package contents (default on; never offline). */
  content?: boolean;
  /** Read every package in the tree, not only named ones and those with install scripts or new versions. */
  deep?: boolean;
  /** Read named packages even when popular, old and script-free (vswarm pkg check). */
  readAll?: boolean;
  /** Run install scripts in the try sandbox (content/index.ts). */
  sandbox?: "always" | "suspicious";
  /** Keep low content findings (vswarm pkg check). */
  verbose?: boolean;
  budgetMs?: number;
  /** Largest archive read, by what the registry says it weighs. */
  maxBytes?: number;
}

/** Every package a version pulls in, resolved the way the registry would (api.deps.dev), with the one that brings it. */
export async function depTree(eco: "npm" | "pip", name: string, version: string, get: Fetcher = realFetch): Promise<{ name: string; version: string; via: string }[]> {
  const sys = eco === "npm" ? "npm" : "pypi";
  const r = await get(`https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}:dependencies`);
  if (r.status !== 200) return [];
  const g = await r.json();
  const nodes: { versionKey: { name: string; version: string } }[] = g.nodes ?? [];
  const parent = new Map<number, number>();
  for (const e of g.edges ?? []) if (!parent.has(e.toNode)) parent.set(e.toNode, e.fromNode);
  return nodes.slice(1).map((n, i) => {
    // The direct dependency this one hangs under, so a finding can say which package brought it in.
    // Dependency graphs have cycles; a chain that loops never reaches the root.
    let at = i + 1;
    const seen = new Set<number>();
    while (parent.has(at) && parent.get(at) !== 0 && !seen.has(at)) (seen.add(at), (at = parent.get(at)!));
    return { name: n.versionKey.name, version: n.versionKey.version, via: nodes[at]?.versionKey.name ?? name };
  });
}

/** Checks everything a command would install. Lockfiles are checked against OSV only; named packages also against the registry. */
export async function checkInstall(p: Plan, opt: CheckOpt = {}): Promise<PkgCheck> {
  const t0 = Date.now();
  const get = opt.get ?? realFetch;
  const notes: string[] = [];
  const unverified: string[] = [];
  const findings: Finding[] = [];
  // Named on the command line: ask the registry about each (a lockfile can list a thousand; those get OSV only).
  const named = p.wants.length <= 25 ? p.wants : p.wants.filter((w) => w.outside);
  const facts = new Map<Want, Facts>();
  if (!opt.offline) {
    let failed = "";
    await Promise.all(named.filter((w) => w.eco !== "brew" && !w.outside).map(async (w) => {
      try {
        facts.set(w, await (w.eco === "npm" ? npmFacts : pipFacts)(w.name, w.version, get));
      } catch (e: any) {
        failed = e.message ?? String(e);
      }
    }));
    if (failed) {
      notes.push(`could not ask the registry (${failed}); checked names offline only`);
      unverified.push(`the registry did not answer (${failed})`);
    }
  }
  for (const w of p.wants.length <= 25 ? p.wants : p.wants.filter((x) => x.outside || lookAlike(x.eco, x.name) || nameSignals(x.eco, x.name).length)) findings.push(...judge(w, facts.get(w)));
  // Known-malicious: every exact version we know, from the command line, the registry answer, or the lockfile.
  const items: Item[] = p.wants
    .filter((w) => w.eco !== "brew" && !w.outside)
    .map((w) => ({ kind: w.eco, id: w.name, name: w.name, version: w.version ?? facts.get(w)?.version }))
    .filter((i) => i.version);
  // And everything those named packages pull in: most malware arrives as a dependency of something harmless.
  const via = new Map<string, string>();
  const inTree: { eco: "npm" | "pip"; name: string; version: string; via?: string }[] = [];
  if (!opt.offline && named.length === p.wants.length) {
    const trees = await Promise.all(items.map((i) => depTree(i.kind as "npm" | "pip", i.name, i.version!, get).catch(() => [])));
    const seen = new Set(items.map((i) => `${i.kind}:${i.name}@${i.version}`));
    trees.forEach((tree, k) => {
      for (const d of tree) {
        const key = `${items[k].kind}:${d.name}@${d.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        via.set(key, d.via === d.name ? items[k].name : `${items[k].name} → ${d.via}`);
        items.push({ kind: items[k].kind, id: d.name, name: d.name, version: d.version, meta: { dep: true } });
        inTree.push({ eco: items[k].kind as "npm" | "pip", name: d.name, version: d.version, via: via.get(key) });
        const like = lookAlike(items[k].kind, d.name);
        if (like)
          findings.push({ id: `pkg:dep-lookalike:${items[k].kind}:${d.name}`, rule: "pkg-lookalike", severity: "medium", title: `${items[k].name} pulls in ${d.name}, which looks like ${like}`,
            detail: [`via ${via.get(key)}`], fix: `check why ${items[k].name} depends on it; a typo-squat in the tree runs its install scripts too` });
      }
    });
  }
  const deps = items.filter((i) => i.meta?.dep).length;
  // What is inside: read while OSV answers, so the usual install waits no longer than before.
  const reading = opt.content === false || opt.offline ? undefined : readContents(p, facts, inTree, get, opt).catch((e: any) => ({ error: String(e?.message ?? e) }));
  if (items.length) {
    const osv = await osvMalicious(items, opt.osvCache ?? files.osv(), { offline: opt.offline });
    if (osv.error) {
      notes.push(osv.error);
      unverified.push("the known-malicious database (OSV) did not answer");
    }
    for (const h of osv.hits) {
      const path = via.get(`${h.item.kind}:${h.item.name}@${h.item.version}`);
      findings.push({ id: `pkg:malicious:${h.item.kind}:${h.item.name}@${h.item.version}`, rule: "pkg-malicious", severity: "critical",
        title: path ? `${h.item.name}@${h.item.version} (a dependency): known malicious` : `${h.item.name}@${h.item.version}: known malicious`,
        detail: [`OSV ${h.ids.join(", ")}`, ...(path ? [`pulled in by ${path}`] : [])], fix: "do not install it; if it was installed before on this machine: vswarm respond" });
    }
  }
  const content = await reading;
  if (content && "error" in content) {
    notes.push(`could not read package contents (${content.error}); judged by registry facts only`);
    unverified.push("package contents could not be read");
  } else if (content) {
    findings.push(...content.findings);
    notes.push(...content.notes);
    unverified.push(...content.unverified);
  }
  findings.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  const scripted = [...facts].filter(([, f]) => (f.scripts?.length ?? 0) > 0 || f.sdistOnly).map(([w]) => w.name);
  const r = content && !("error" in content) ? content : undefined;
  return { plan: p, findings, verdict: verdictOf(findings), notes, ms: Date.now() - t0, deps, unverified, scripted, read: r?.read ?? [], readFiles: r?.files ?? 0, readBytes: r?.bytes ?? 0 };
}

/**
 * Package contents (content/): the named packages, unless popular, weeks old and script-free; and the dependencies
 * (from the tree, or the lockfile) that run install scripts or were published in the last 7 days.
 */
async function readContents(p: Plan, facts: Map<Want, Facts>, tree: { eco: "npm" | "pip"; name: string; version: string; via?: string }[], get: Fetcher, opt: CheckOpt) {
  const c = await import("./content");
  const copt = {
    get, manifest: (n: string, v: string) => npmManifest(n, v, get), pypi: (n: string) => pypiProject(n, get),
    sandbox: opt.sandbox, verbose: opt.verbose, budgetMs: opt.budgetMs, maxBytes: opt.maxBytes, perPackageMs: opt.budgetMs ? Math.max(10_000, opt.budgetMs / 2) : undefined,
    // Next to the OSV cache it is given (tests), else ~/.vswarm/sec/pkg-content.
    dir: opt.osvCache ? join(dirname(opt.osvCache), "pkg-content") : undefined,
  };
  const named: import("./content").Target[] = [];
  for (const [w, f] of facts) {
    if (!f.exists || !f.version || (w.eco !== "npm" && w.eco !== "pip")) continue;
    if (opt.readAll || opt.deep || c.worthReading(w.eco, f)) named.push({ eco: w.eco, name: w.name, version: f.version, facts: f });
  }
  const seen = new Set(named.map((t) => `${t.eco}:${t.name}@${t.version}`));
  // A lockfile (more than 25 packages) has no named ones: all of it is dependencies.
  const lock = p.wants.length > 25 ? p.wants.filter((w): w is Want & { eco: "npm" | "pip"; version: string } => (w.eco === "npm" || w.eco === "pip") && !!w.version && !w.outside) : [];
  const deps = [...tree, ...lock.map((w) => ({ eco: w.eco, name: w.name, version: w.version }))].filter((d) => !seen.has(`${d.eco}:${d.name}@${d.version}`));
  const picked = deps.length ? await c.pickDeps(deps, { ...copt, deep: opt.deep }) : { targets: [], notes: [] };
  const r = await c.contentCheck([...named, ...picked.targets], copt);
  r.notes.push(...picked.notes);
  return r;
}

/** How to run a tool once without the guard: `command npm` in sh; in PowerShell the program itself, npm.cmd or uv.exe. */
const skipOnce = (tool: string) => (process.platform === "win32" ? `${tool}.cmd … (or ${tool}.exe …)` : `command ${tool} …`);

// ── Guard settings (vswarm guard on [--ignore-scripts] [--sandbox] [--strict])

export interface GuardConfig {
  /** npm, pnpm, yarn and bun installs run with their lifecycle scripts off. */
  ignoreScripts?: boolean;
  /** Those installs run in the try sandbox (macOS, Linux): your project folder writable, the rest of home hidden, registries only. */
  sandbox?: boolean;
  /** A registry or OSV that does not answer stops the install instead of letting it through. */
  strict?: boolean;
}

const guardFile = () => join(SEC(), "guard.json");
export const loadGuardConfig = (): GuardConfig => readJson<GuardConfig>(guardFile()) ?? {};
export const saveGuardConfig = (g: GuardConfig) => writePrivate(guardFile(), g);

/** Tools whose installs vswarm runs itself when scripts are off or the sandbox is on. */
export const RUN_TOOLS = ["npm", "pnpm", "yarn", "bun"];

const isGlobal = (tool: string, args: string[]) => args.includes("-g") || args.includes("--global") || (tool === "yarn" && args[0] === "global");

/**
 * The same install with lifecycle scripts off: --ignore-scripts right after the subcommand for npm, pnpm, bun and
 * yarn 1; yarn 2 and later have no such flag and read YARN_ENABLE_SCRIPTS instead. Commands that run a package
 * (npm exec, dlx) are left as they are.
 */
export function withoutScripts(tool: string, args: string[], yarnMajor = 1): { args: string[]; env: Record<string, string> } {
  const sub = args[0];
  const installs = (sub !== undefined && NPM_INSTALL.has(sub)) || sub === "ci" || (tool === "yarn" && (sub === undefined || sub === "global"));
  if (!installs || args.includes("--ignore-scripts")) return { args, env: {} };
  if (tool === "yarn" && yarnMajor >= 2) return { args, env: { YARN_ENABLE_SCRIPTS: "false" } };
  // yarn global add <names>: the flag belongs after "add".
  const at = tool === "yarn" && sub === "global" ? 2 : sub === undefined ? 0 : 1;
  return { args: [...args.slice(0, at), "--ignore-scripts", ...args.slice(at)], env: {} };
}

/** How to run the scripts that were skipped, deliberately: in the sandbox first, for real once you trust them. */
export function scriptsHint(tool: string, names: string[]): string {
  const which = names.length ? names.slice(0, 4).join(" ") : "<package>";
  const rebuild = tool === "pnpm" ? `pnpm rebuild ${which}` : tool === "bun" ? `bun pm trust ${which}` : `npm rebuild ${which}`;
  return `install scripts were skipped${names.length ? ` (${names.slice(0, 4).join(", ")}${names.length > 4 ? " …" : ""} has them)` : ""}. Native modules (sharp, bcrypt, esbuild, puppeteer …) may need them: ` +
    `see what they do with: vswarm try . -- ${rebuild} · then run them for real: command ${rebuild}`;
}

/**
 * `vswarm pkg [--run] <tool> <arguments>`: the check the shell wrapper runs before every install. Prints only when
 * there is something to say (one dim line on a terminal otherwise) and returns the exit code: 3 stops the install.
 * With --run (guard on --ignore-scripts or --sandbox), vswarm then runs the install itself, the way those settings say.
 */
export async function pkgCommand(tool: string, args: string[], opt: { offline: boolean; strict?: boolean; run?: boolean; deep?: boolean; get?: Fetcher; ask: (q: string, def?: boolean) => Promise<boolean>; canSandbox?: () => boolean }): Promise<number> {
  // guard on --sandbox promised the install a sandbox: where there is none (no bubblewrap, Windows), it does not run
  // at all, rather than run outside one without a word.
  const missing = sandboxMissing(tool, args, loadGuardConfig(), opt.canSandbox ?? (await import("./try/spawn")).canSandbox);
  if (missing) {
    line(`${c.red("✖")} vswarm: the install guard runs ${tool} installs in the sandbox, and ${missing}. Nothing was installed.`);
    line(c.dim(`  ${process.platform === "linux" ? "install bubblewrap (sudo apt install bubblewrap), or " : ""}turn the sandbox off: vswarm guard on${loadGuardConfig().ignoreScripts ? " --ignore-scripts" : ""} · skip vswarm once: ${skipOnce(tool)}`));
    return 3;
  }
  let checked: { code: number; scripted: string[] };
  try {
    checked = await pkgCheck(tool, args, opt);
  } catch (e: any) {
    // Fail closed: the shell wrapper installs only on exit 0. Say so, or the user sees an error and wonders what happened.
    line(`${c.red("✖")} ${e?.message ?? e}`);
    line(c.dim(`  vswarm could not check this install; nothing was installed · skip vswarm once with: ${skipOnce(tool)}`));
    return 4;
  }
  if (!opt.run || checked.code !== 0) return checked.code;
  // yarn --version and --help (a bare yarn with options reaches here too): nothing to install, run as it is.
  if (tool === "yarn" && args.some((a) => /^(--version|-v|--help|-h)$/.test(a))) {
    const real = Bun.which(tool);
    if (!real) return 127;
    return Bun.spawn([real, ...args], { stdin: "inherit", stdout: "inherit", stderr: "inherit" }).exited;
  }
  return runInstall(tool, args, checked.scripted);
}

/** Why an install the guard would sandbox cannot be (the sandbox is not there), or undefined. */
export function sandboxMissing(tool: string, args: string[], g: GuardConfig, canSandbox: () => boolean, platform = process.platform): string | undefined {
  if (!g.sandbox || !RUN_TOOLS.includes(tool) || isGlobal(tool, args) || EXEC_SUBS.includes(args[0] ?? "") || plan(tool, args).skip) return;
  if (platform === "win32") return "there is no sandbox on Windows yet";
  if (!canSandbox()) return platform === "linux" ? "bubblewrap (bwrap) is not installed" : "sandbox-exec is not available";
}

/** Hosts Socket Firewall itself asks about each download, let through the sandbox when sfw runs inside it. */
export const SFW_HOSTS = ["socket.dev"];

/** The install itself, as the guard settings say: scripts off, in the sandbox, through Socket Firewall when it is there. */
async function runInstall(tool: string, args: string[], scripted: string[]): Promise<number> {
  const g = loadGuardConfig();
  const real = Bun.which(tool);
  if (!real) {
    line(`${c.red("✖")} ${tool}: not found on PATH`);
    return 127;
  }
  const yarnMajor = tool === "yarn" ? Number((await exec([real, "--version"]).catch(() => ({ out: "1" }))).out.trim().split(".")[0]) || 1 : 1;
  const plain = { args, env: {} as Record<string, string> };
  const cmd = g.ignoreScripts && RUN_TOOLS.includes(tool) ? withoutScripts(tool, args, yarnMajor) : plain;
  const skipped = cmd.args !== args || Object.keys(cmd.env).length > 0;
  const sfw = process.env.VSWARM_SFW !== "off" && SFW.has(tool) ? Bun.which("sfw") : null;
  const argv = sfw ? [sfw, tool, ...cmd.args] : [real, ...cmd.args];
  let code: number;
  const { canSandbox, sandboxRun } = await import("./try/spawn");
  if (g.sandbox && RUN_TOOLS.includes(tool) && !isGlobal(tool, args)) {
    // pkgCommand refused already when there is no sandbox; this is the same promise kept at the last step.
    if (!canSandbox()) throw new Error("the sandbox is not available; not installed");
    line(c.dim(`vswarm: ${tool} runs in the sandbox (this folder writable, the rest of your home hidden, package registries only${sfw ? ", through Socket Firewall" : ""})`));
    // Socket Firewall goes inside the sandbox with the install, so every download is still checked by it.
    const r = await sandboxRun(sfw ? [sfw, tool, ...cmd.args] : [tool, ...cmd.args], { cwd: process.cwd(), env: cmd.env, ...(sfw ? { extraRead: [dirname(sfw)], extraHosts: SFW_HOSTS } : {}) });
    code = r.code;
    if (r.refused.length) line(c.amber(`vswarm: the install tried to reach ${r.refused.slice(0, 5).join(", ")}, which the sandbox refused (only package registries are open). A private registry: install with ${skipOnce(tool)}`));
  } else {
    if (g.sandbox && isGlobal(tool, args)) line(c.dim("vswarm: a global install changes files outside this folder, so it does not run in the sandbox"));
    const p = Bun.spawn(argv, { env: { ...process.env, ...cmd.env }, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
    code = await p.exited;
  }
  if (skipped && code === 0) line(c.dim(`vswarm: ${scriptsHint(tool, scripted)}`));
  return code;
}

async function pkgCheck(tool: string, args: string[], opt: { offline: boolean; strict?: boolean; deep?: boolean; get?: Fetcher; ask: (q: string, def?: boolean) => Promise<boolean> }): Promise<{ code: number; scripted: string[] }> {
  const p = plan(tool, args);
  if (p.skip) return { code: 0, scripted: [] };
  // Your team's own package names are not look-alikes here either.
  const { applyAllow, loadPolicy } = await import("./team");
  applyAllow((await loadPolicy()).policy);
  const g = loadGuardConfig();
  // guard on --sandbox: a package whose contents look suspicious has its install scripts run in the sandbox first.
  const r = await checkInstall(p, { offline: opt.offline, get: opt.get, deep: opt.deep, sandbox: g.sandbox && !opt.offline ? "suspicious" : undefined });
  const done = (code: number) => ({ code, scripted: r.scripted });
  // Strict: what could not be checked is a reason to stop, not a notice. Offline on purpose (--offline) is not.
  const strictOn = (opt.strict || g.strict) && !opt.offline;
  const strict = strictOn && r.unverified.length > 0;
  // Contents that are suspicious but not damning: asked about on a terminal, stopped under --strict.
  const suspicious = r.verdict === "warn" && r.findings.some((f) => (f.rule === "pkg-content" || f.rule === "pkg-sandbox") && f.severity === "medium");
  const read = r.read.length ? ` · contents of ${r.read.length} read` : "";
  const quietPass = !r.findings.some((f) => f.severity !== "info") && !r.notes.length;
  if (quietPass) {
    if (process.stderr.isTTY) line(c.dim(`vswarm ✔ ${p.wants.length > 1 ? `${p.wants.length} packages` : p.from}${r.deps ? ` and ${r.deps} dependencies` : ""} checked${read} · ${r.ms} ms`));
    return done(0);
  }
  line(`${c.violet("▼ vswarm")} checked ${p.from.startsWith(tool) ? p.from : `${tool} ${p.from}`} ${c.dim(`${r.deps ? `and ${r.deps} dependencies ` : ""}${read ? `${read.slice(3)} ` : ""}· ${r.ms} ms`)}`);
  for (const f of r.findings.filter((x) => x.severity !== "info")) printFinding({ ...f, id: "" }, f.severity !== "low");
  for (const n of r.notes) line(c.dim(`  · ${n}`));
  const stopSuspicious = suspicious && strictOn;
  if (r.verdict !== "block" && !strict && !stopSuspicious) {
    if (suspicious) {
      // No by default, and no without a terminal to ask on: suspicious contents are a reason to stop, not to shrug.
      if (await opt.ask(`${c.amber("Suspicious contents above.")} Install anyway?`, false)) {
        line(c.dim("  going ahead"));
        return done(0);
      }
      line(c.dim(`  not installed · read it without installing: vswarm pkg check ${tool === "pip" || tool === "pip3" || tool === "uv" || tool === "pipx" || tool === "uvx" ? "pip" : "npm"} <name>`));
      return done(3);
    }
    if (r.findings.length) line(c.dim(`  ${VERDICT[r.verdict]} · going ahead`));
    return done(0);
  }
  if (strict && r.verdict !== "block") line(c.amber(`  strict guard: ${r.unverified.join("; ")}, so this install was not fully checked`));
  if (stopSuspicious && r.verdict !== "block") line(c.amber("  strict guard: suspicious package contents stop the install"));
  if (await opt.ask(`${c.red("Stop here.")} Install anyway?`, false)) {
    line(c.dim("  going ahead, as you said"));
    return done(0);
  }
  line(c.dim(`  not installed · ${strict && r.verdict !== "block" ? "try again when online, or " : ""}skip vswarm once with: ${skipOnce(tool)}`));
  return done(3);
}

/**
 * `vswarm pkg check <npm|pip> <name>[@version]`: what the guard checks, with every package's contents read in full
 * (no fast path, low findings too), without installing anything. --deep reads the whole tree, --sandbox runs the
 * install scripts in the try sandbox. Exit 3 on BLOCK (and on WARN with --strict).
 */
export async function pkgCheckCommand(eco: string, spec: string | undefined, opt: { offline?: boolean; deep?: boolean; sandbox?: boolean; json?: boolean; strict?: boolean; get?: Fetcher }): Promise<number> {
  if ((eco !== "npm" && eco !== "pip") || !spec) throw new Error("usage: vswarm pkg check npm|pip <name>[@version] [--deep] [--sandbox] [--json]   e.g. vswarm pkg check npm left-pad@1.3.0");
  // name@1.2.3 for PyPI too, besides pip's own name==1.2.3.
  const w = eco === "npm" ? npmSpec(spec) : pipSpec(spec.replace(/^([A-Za-z0-9][\w.-]*)@(?=\d)/, "$1=="));
  if (!w || w.local || w.outside) throw new Error(`${spec}: name a package on the registry, e.g. vswarm pkg check ${eco} ${eco === "npm" ? "left-pad@1.3.0" : "requests==2.32.3"}`);
  const { applyAllow, loadPolicy } = await import("./team");
  applyAllow((await loadPolicy()).policy);
  const r = await checkInstall({ wants: [w], skip: false, from: spec }, {
    get: opt.get, offline: opt.offline, deep: opt.deep, readAll: true, verbose: true, sandbox: opt.sandbox ? "always" : undefined, budgetMs: 600_000, maxBytes: 100_000_000,
  });
  const code = r.verdict === "block" || (opt.strict && r.verdict === "warn") ? 3 : 0;
  if (opt.json) {
    console.log(JSON.stringify({ package: `${eco}:${w.name}${w.version ? `@${w.version}` : ""}`, verdict: r.verdict, findings: r.findings, notes: r.notes, unverified: r.unverified, read: r.read, files: r.readFiles, bytes: r.readBytes, ms: r.ms }, null, 2));
    return code;
  }
  const size = r.readBytes >= 1e6 ? `${(r.readBytes / 1e6).toFixed(1)} MB` : `${Math.round(r.readBytes / 1000)} KB`;
  line(`${c.violet("▼ vswarm pkg check")} ${eco} ${spec} ${c.dim(`· ${r.read.length ? `read ${r.readFiles} files (${size}) of ${r.read.join(", ")}` : "contents not read"}${r.deps ? ` · ${r.deps} dependencies checked` : ""} · ${r.ms} ms`)}`);
  if (!r.findings.length) line(`  ${c.green("✔")} nothing found: no install-time code that reaches for secrets or the network, nothing hidden, nothing new that changes that`);
  for (const f of r.findings) printFinding({ ...f, id: "" }, true);
  for (const n of r.notes) line(c.dim(`  · ${n}`));
  if (!opt.sandbox && r.findings.some((f) => f.rule === "pkg-content" && RANK[f.severity] >= RANK.medium) && process.platform !== "win32")
    line(c.dim(`  · see what its install scripts do, in the sandbox: vswarm pkg check ${eco} ${spec} --sandbox`));
  line(`\n${VERDICT[r.verdict]} ${c.dim(r.verdict === "block" ? "· do not install it" : r.verdict === "warn" ? "· read the findings before installing" : "· what was read looks ordinary; it is not a guarantee")}`);
  return code;
}

// ── The shell wrapper

export const GUARD_START = "# >>> vswarm guard >>>";
export const GUARD_END = "# <<< vswarm guard <<<";

/** Subcommands that install, per tool, so other commands (npm run, pip list) do not even start vswarm. */
const INSTALLS: Record<string, string> = {
  npm: "install|i|in|ins|inst|insta|instal|isntall|add|ci|update|up|upgrade|exec|x",
  pnpm: "install|i|add|update|up|upgrade|dlx|exec",
  // A bare `yarn`, also with options only (yarn --frozen-lockfile, yarn --immutable), installs the project.
  yarn: '""|-*|install|add|upgrade|up|dlx|global',
  bun: "install|i|add|a|update|x",
  pip: "install", pip3: "install", uv: "pip|add|tool", pipx: "install|inject|run",
  brew: "install|reinstall|upgrade|tap",
};

/** Functions for ~/.zshrc and ~/.bashrc. `function name {` keeps zsh from expanding an alias of the same name. */
/** Package managers Socket Firewall (sfw) can proxy; with sfw installed, approved installs run through it as well. */
const SFW = new Set(["npm", "pnpm", "yarn", "pip", "pip3", "uv"]);

/** Subcommands that run a package rather than install into the project; scripts-off and the sandbox leave them alone. */
const EXEC_SUBS = ["exec", "x", "dlx"];

/**
 * `run`: guard on --ignore-scripts or --sandbox. npm, pnpm, yarn and bun installs then go through `vswarm pkg --run`,
 * which checks and then runs the install itself the way those settings say.
 */
export function guardBlock(launcher: string, opt: { run?: boolean } = {}): string {
  const q = shq(launcher);
  const run = (tool: string) => (SFW.has(tool) ? `__vswarm_run ${tool} "$@"` : `command ${tool} "$@"`);
  const checked = (tool: string, subs: string) => `${subs}) ${q} pkg ${tool} -- "$@" || return $?; ${run(tool)}; return $?;;`;
  const fn = (tool: string, subs?: string) => {
    if (subs === undefined) return `function ${tool} { ${q} pkg ${tool} -- "$@" && command ${tool} "$@"; }`;
    if (!opt.run || !RUN_TOOLS.includes(tool)) return `function ${tool} { case "$1" in ${checked(tool, subs)} esac; command ${tool} "$@"; }`;
    const all = subs.split("|");
    const exec = all.filter((s) => EXEC_SUBS.includes(s));
    const installs = all.filter((s) => !EXEC_SUBS.includes(s)).join("|");
    return `function ${tool} { case "$1" in ${exec.length ? `${checked(tool, exec.join("|"))} ` : ""}${installs}) ${q} pkg --run ${tool} -- "$@"; return $?;; esac; command ${tool} "$@"; }`;
  };
  return [
    GUARD_START,
    "# Package installs are checked by vswarm first. Skip once: command npm …   Turn off: vswarm guard off",
    // Socket Firewall, when present, checks every download of the install too (VSWARM_SFW=off to skip it).
    `function __vswarm_run { if [ "\${VSWARM_SFW:-}" != off ] && command -v sfw >/dev/null 2>&1; then sfw "$@"; else command "$@"; fi; }`,
    ...Object.entries(INSTALLS).map(([t, s]) => fn(t, s)),
    fn("npx"),
    fn("bunx"),
    fn("uvx"),
    GUARD_END,
  ].join("\n");
}

/**
 * The same guard for PowerShell (profile.ps1). Each function calls bun and the CLI by full path, not vswarm.cmd:
 * cmd.exe would read & or | inside a package URL as its own. The real tool is found as an application on PATH, so
 * the function never calls itself.
 */
export function psGuardBlock(bun: string, cli: string, opt: { ignoreScripts?: boolean } = {}): string {
  const q = (s: string) => `'${s.replace(/['\u2018\u2019\u201a\u201b]/g, "$&$&")}'`;
  // guard on --ignore-scripts: npm, pnpm, bun and yarn 1 get --ignore-scripts after the subcommand; yarn 2+ has no such
  // flag and reads YARN_ENABLE_SCRIPTS. (No sandbox on Windows yet.)
  const scriptsOff = opt.ignoreScripts
    ? [
      `  $ys = $null`,
      `  if (@(${RUN_TOOLS.map(q).join(", ")}) -contains $tool -and $first -notmatch '^(${EXEC_SUBS.join("|")})$' -and -not ($a -contains '--ignore-scripts')) {`,
      "    if ($tool -eq 'yarn' -and [int](([string](& $real --version)) -split '\\.')[0] -ge 2) { $ys = [string]$env:YARN_ENABLE_SCRIPTS; $env:YARN_ENABLE_SCRIPTS = 'false' }",
      "    else { $at = if ($tool -eq 'yarn' -and $first -eq 'global') { 2 } elseif ($a.Count) { 1 } else { 0 }; $a = @($a | Select-Object -First $at) + @('--ignore-scripts') + @($a | Select-Object -Skip $at) }",
      `    Write-Host "vswarm: install scripts were skipped; run them deliberately with: npm rebuild <package> (pnpm rebuild, bun pm trust)" -ForegroundColor DarkGray`,
      "  }",
    ]
    : [];
  const fn = (tool: string, subs?: string) =>
    `function ${tool} { __vswarm_go ${tool} ${subs === undefined ? "'.*'" : q(`^(${subs.replace(/""/g, "").replace(/-\*/g, "-.*")})$`)} $args }`;
  return [
    GUARD_START,
    "# Package installs are checked by vswarm first. Skip once: npm.cmd ...   Turn off: vswarm guard off",
    "function __vswarm_go($tool, $installs, $a) {",
    "  $real = Get-Command -Name $tool -CommandType Application -TotalCount 1 -ErrorAction SilentlyContinue",
    "  if (-not $real) { Write-Error \"${tool}: not found on PATH\"; return }",
    "  $first = if ($a.Count) { [string]$a[0] } else { '' }",
    "  if ($first -notmatch $installs) { & $real @a; return }",
    `  & ${q(bun)} ${q(cli)} pkg $tool '--' @a`,
    "  if ($LASTEXITCODE -ne 0) { return }",
    ...scriptsOff,
    // Socket Firewall, when present, checks every download of the install too (VSWARM_SFW=off to skip it).
    `  $sfw = if ($env:VSWARM_SFW -ne 'off' -and @(${[...SFW].map(q).join(", ")}) -contains $tool) { Get-Command -Name sfw -CommandType Application -TotalCount 1 -ErrorAction SilentlyContinue }`,
    "  if ($sfw) { & $sfw $tool @a } else { & $real @a }",
    ...(opt.ignoreScripts ? ["  if ($null -ne $ys) { $env:YARN_ENABLE_SCRIPTS = $(if ($ys) { $ys } else { $null }) }"] : []),
    "}",
    ...Object.entries(INSTALLS).filter(([t]) => t !== "brew").map(([t, subs]) => fn(t, subs)),
    fn("npx"),
    fn("bunx"),
    fn("uvx"),
    GUARD_END,
  ].join("\n");
}
