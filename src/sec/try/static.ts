// Before anything runs: what in this code is built to run on its own, or looks like a hidden loader.
// Patterns come from public write-ups of fake job-interview campaigns ("Contagious Interview"), npm and PyPI malware:
// install scripts, VS Code tasks that run when the folder opens, loaders tucked into config files, obfuscation.

import { closeSync, lstatSync, openSync, readdirSync, readSync } from "node:fs";
import { join, relative } from "node:path";
import { lookAlike } from "../intel";
import type { Finding, Severity } from "../types";

const SKIP_DIRS = new Set([".git", "node_modules", ".next", "dist", "build", "out", ".venv", "venv", "__pycache__", "target", ".turbo", "coverage"]);
const CODE = /\.(c?js|mjs|ts|tsx|jsx|py|sh|bash|zsh|rb|php|ps1|bat|cmd)$/i;
/** Config files that every dev tool loads; a loader here runs on `npm run dev`, `npm test`, a build, or an editor opening the folder. */
const CONFIG = /^(next|vite|webpack|tailwind|postcss|babel|jest|vitest|eslint|prettier|nuxt|svelte|astro|rollup|tsup|playwright)\.config\.(c?js|mjs|ts)$|^\.eslintrc\.c?js$|^gulpfile\.js$|^Gruntfile\.js$/;

const PATTERNS: [RegExp, string, Severity][] = [
  [/\beval\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent)\b/, "decodes text and runs it with eval", "high"],
  [/new\s+Function\s*\(\s*(atob|Buffer\.from)/, "decodes text and runs it with new Function", "high"],
  [/require\(\s*['"]child_process['"]\s*\)[\s\S]{0,400}\b(curl|wget|powershell|bash\s+-c|sh\s+-c)\b/, "starts a shell that downloads something", "high"],
  [/\b(exec|execSync|spawn)\s*\(\s*['"`](curl|wget)\b[^'"`]*\|\s*(ba|z)?sh/, "pipes a download straight into a shell", "high"],
  [/(https?:\/\/)?\b(\d{1,3}\.){3}\d{1,3}(:\d{2,5})?\/[\w/.-]*/, "talks to a raw IP address", "medium"],
  [/\b(atob|Buffer\.from)\s*\(\s*['"][A-Za-z0-9+/=]{200,}['"]/, "carries a long encoded string", "medium"],
  [/(\\x[0-9a-f]{2}){40,}/i, "carries a long hex-escaped string", "medium"],
  [/Library\/Application Support\/(Google\/Chrome|BraveSoftware|Exodus|Electrum|atomic)|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|login\.keychain|\.ssh\/id_|\.aws\/credentials/, "names browser, wallet, keychain or credential locations", "high"],
  [/\bexec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode)/, "decodes text and runs it (Python)", "high"],
  [/__import__\(\s*['"](base64|zlib|marshal)['"]\s*\)/, "imports decoders indirectly (Python)", "medium"],
  [/\b(socket\.create_connection|urllib\.request\.urlopen|requests\.(get|post))\s*\(\s*['"]https?:\/\/\d/, "connects to a raw IP (Python)", "medium"],
];

function head(path: string, n: number): string {
  try {
    const fd = openSync(path, "r");
    const buf = Buffer.alloc(n);
    const got = readSync(fd, buf, 0, n, 0);
    closeSync(fd);
    return buf.subarray(0, got).toString("utf8");
  } catch {
    return "";
  }
}

function walk(root: string, max = 20_000): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length && out.length < max) {
    const dir = stack.pop()!;
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = join(dir, e);
      let st;
      try {
        st = lstatSync(p);
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(e)) stack.push(p);
      } else out.push(p);
    }
  }
  return out;
}

export function staticCheck(root: string): Finding[] {
  const out: Finding[] = [];
  const rel = (p: string) => relative(root, p);
  const add = (id: string, severity: Severity, title: string, detail: string[] = []) => out.push({ id: `try:${id}`, rule: "try-static", severity, title, detail });

  for (const p of walk(root)) {
    const name = p.split("/").pop()!;
    const r = rel(p);

    if (name === "package.json") {
      let pkg: any;
      try {
        pkg = JSON.parse(head(p, 2_000_000));
      } catch {
        continue;
      }
      for (const s of ["preinstall", "install", "postinstall", "prepare", "prepublish"]) {
        if (typeof pkg.scripts?.[s] === "string") add(`script:${r}:${s}`, s === "prepare" ? "medium" : "high", `${r} runs "${s}" on npm install`, [`${s}: ${pkg.scripts[s].slice(0, 200)}`]);
      }
      for (const [k, v] of Object.entries<any>(pkg.scripts ?? {})) {
        if (/\b(curl|wget)\b.*\|\s*(ba|z)?sh|node\s+-e|eval\b|base64\s+(-d|--decode)/.test(String(v))) add(`scriptcmd:${r}:${k}`, "high", `${r} script "${k}" downloads or decodes code`, [String(v).slice(0, 200)]);
      }
      const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies };
      for (const [d, spec] of Object.entries<any>(deps)) {
        const like = lookAlike("npm", d);
        if (like) add(`dep-lookalike:${d}`, "high", `dependency "${d}" looks like "${like}"`, [`in ${r}`]);
        if (/^(https?:|git\+|git:|github:|file:|[\w-]+\/[\w.-]+(#.*)?$)/.test(String(spec))) add(`dep-url:${d}`, "medium", `dependency "${d}" comes from a URL or repo, not the registry`, [`${d}: ${spec}`, `in ${r}`]);
      }
      continue;
    }

    if (r === ".vscode/tasks.json" || r.endsWith("/.vscode/tasks.json")) {
      const t = head(p, 500_000);
      if (/"runOn"\s*:\s*"folderOpen"/.test(t)) add(`vscode:${r}`, "high", `${r} runs a task as soon as the folder is opened in VS Code / Cursor`, ["a known way fake-interview repos start malware without you running anything"]);
      continue;
    }

    if (/^(requirements.*\.txt|setup\.py|pyproject\.toml)$/.test(name)) {
      const t = head(p, 500_000);
      if (name === "setup.py" && /\b(os\.system|subprocess|urllib|requests|exec\()/.test(t)) add(`setup:${r}`, "high", `${r} runs commands or downloads during pip install`);
      for (const m of t.matchAll(/^\s*([A-Za-z0-9_.-]+)\s*[=<>~!]/gm)) {
        const like = lookAlike("pip", m[1]);
        if (like) add(`pydep:${m[1]}`, "high", `Python dependency "${m[1]}" looks like "${like}"`, [`in ${r}`]);
      }
    }

    const h4 = head(p, 4);
    if (h4.startsWith("\x7fELF") || ["\xcf\xfa\xed\xfe", "\xce\xfa\xed\xfe", "\xca\xfe\xba\xbe"].includes(Buffer.from(h4, "utf8").toString("latin1"))) {
      add(`binary:${r}`, "medium", `ships a compiled program: ${r}`);
      continue;
    }

    if (!CODE.test(name)) continue;
    const text = head(p, 3_000_000);
    const isConfig = CONFIG.test(name);
    for (const [re, why, sev] of PATTERNS) {
      if (re.test(text)) add(`pattern:${r}:${why}`, isConfig && sev !== "high" ? "high" : sev, `${r} ${why}${isConfig ? " (inside a config file every dev tool loads)" : ""}`);
    }
    const longest = Math.max(0, ...text.split("\n").map((l) => l.length));
    if (longest > 5_000 && !/\.min\.|vendor|bundle/.test(r)) add(`dense:${r}`, isConfig ? "high" : "low", `${r} has a ${Math.round(longest / 1000)}k-character line (obfuscated or bundled code)`);
  }
  return out;
}
