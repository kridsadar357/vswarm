// What is inside a package, read as text and never run: which of its files run when it installs, and what those files
// and the rest of its code reach for. Each hit is a signal with its file, line and a short masked snippet; grade.ts
// decides how much a set of signals matters. Patterns come from public write-ups of npm and PyPI malware (event-stream,
// ua-parser-js, the 2025 chalk/debug and Shai-Hulud releases, PyPI stealers that run from setup.py, __init__.py or a
// .pth file); the decode-and-run patterns of `vswarm try` (try/static.ts) are used here as well.

import { basename } from "node:path";
import { redact } from "../ctx";
import { DECODE_RUN } from "../try/static";
import type { Archive, Entry } from "./archive";

export type Kind = "npm" | "sdist" | "wheel";

/** Where a file's code runs: during the install (npm hooks, setup.py, .pth, binding.gyp), when the package is used, or never (tests, docs). */
export type Where = "install" | "import" | "never";

export type Cat =
  | "exec-decoded" | "exec-maybe" | "pipe-shell" | "obfuscated" | "hidden" | "blob" | "dense"
  | "secrets" | "secrets-weak" | "env-dump" | "token-env" | "network" | "proc" | "chmod" | "detached" | "persistence"
  | "dns-exfil" | "host" | "pth" | "gyp";

export type HostKind = "exfil" | "recon" | "ip" | "plain" | "benign";

export interface Signal {
  cat: Cat;
  where: Where;
  file: string;
  line: number;
  /** The code around the hit, one line, credentials and long encoded runs masked. */
  text: string;
  host?: string;
  hostKind?: HostKind;
  /** secrets: which kind (ssh, cloud, browser, wallet, keychain …). */
  family?: string;
}

export interface Hook {
  name: string;
  cmd: string;
}

export interface Scanned {
  kind: Kind;
  signals: Signal[];
  hooks: Hook[];
  /** Files whose code runs during the install. */
  installFiles: string[];
  files: number;
  size: number;
  /** Most of its JavaScript is minified or bundled; long lines say nothing then. */
  bundle: boolean;
  /** Files with very long lines (bundled or minified): what sits near what in them says little. */
  dense: string[];
  /** npm: dependencies the package.json names. */
  deps: string[];
  /** Archive problems: path traversal, links, limits. */
  problems: Archive["problems"];
  partial?: string;
}

const CODE = /\.(c?js|mjs|jsx|ts|cts|mts|tsx|py|pyw|pth|sh|bash|zsh|command|ps1|psm1|bat|cmd|vbs|gyp|gypi)$/i;
const ROOT_TEXT = /^(package\.json|setup\.py|setup\.cfg|pyproject\.toml|binding\.gyp)$/;

/** Which files to keep in memory while unpacking: code, and the root files that say what runs. */
export function keepFor(kind: Kind) {
  return (path: string, size: number) => {
    // Paths still carry the folder npm and sdists wrap everything in (package/, name-1.0/).
    const p = kind === "wheel" ? path : path.slice(path.indexOf("/") + 1);
    if (ROOT_TEXT.test(p) || p.endsWith(".pth")) return true;
    if (/\.d\.[cm]?ts$|\.map$/.test(path)) return false;
    if (CODE.test(path)) return true;
    // Scripts without an extension (bin/run, scripts/install) that a hook may call.
    return !/\.[^/]*$/.test(basename(path)) && size < 1_000_000;
  };
}

const NEVER = /(^|\/)(tests?|__tests__|spec|specs|examples?|docs?|benchmarks?|bench|fixtures?|__mocks__|\.github|testing)\//i;
const NEVER_FILE = /\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)test_[^/]*\.py$|_test\.py$|(^|\/)conftest\.py$/;

type Lang = "js" | "py" | "sh" | "ps";

function langOf(path: string, head: string): Lang | undefined {
  if (/\.(c?js|mjs|jsx|ts|cts|mts|tsx)$/i.test(path)) return "js";
  if (/\.(py|pyw|pth)$/i.test(path)) return "py";
  if (/\.(sh|bash|zsh|command)$/i.test(path)) return "sh";
  if (/\.(ps1|psm1|bat|cmd|vbs)$/i.test(path)) return "ps";
  if (/\.(gyp|gypi)$/i.test(path)) return "py";
  if (head.startsWith("#!")) return /node|bun|deno/.test(head.slice(0, 80)) ? "js" : /python/.test(head.slice(0, 80)) ? "py" : "sh";
}

// ── the patterns

interface Rule {
  cat: Cat;
  re: RegExp;
  langs: Lang[];
}

const ALL: Lang[] = ["js", "py", "sh", "ps"];
const R = (cat: Cat, langs: Lang[], re: RegExp): Rule => ({ cat, re: new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"), langs });

/** Where credentials live. Forward or back slashes, so Windows paths count too. */
const SECRET_PATH = new RegExp([
  String.raw`[\\/]\.ssh(?:[\\/'"\x60]|\b)`, String.raw`['"\x60]\.ssh['"\x60]`, String.raw`\bid_(?:rsa|ed25519|ecdsa|dsa)\b`,
  String.raw`\.aws[\\/](?:credentials|config)\b`, String.raw`['"\x60]\.aws['"\x60]`,
  String.raw`\.config[\\/]gcloud`, String.raw`application_default_credentials\.json`, String.raw`[\\/]\.azure[\\/]`, String.raw`\.kube[\\/]config`,
  String.raw`\.docker[\\/]config\.json`, String.raw`\.git-credentials`, String.raw`\.config[\\/]gh[\\/]hosts\.yml`, String.raw`[\\/]\.gnupg\b`, String.raw`\.password-store`,
  String.raw`Login Data\b`, String.raw`Local State['"\x60]`, String.raw`Local Extension Settings`, String.raw`IndexedDB[\\/]chrome-extension`,
  // MetaMask, Phantom, Coinbase Wallet, Ronin, BNB Chain: the extension IDs stealers look for.
  "nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "hnfanknocfeofbddgcijnmhnfnkdnaad", "fnjhmkhhmkbjkkabndcnnogagogbneec", "fhbohimaelbohpjbbldcngcnapndodjp",
  String.raw`(?:Exodus|Electrum|atomic|Ledger Live)[\\/](?:exodus\.wallet|wallets|Local Storage)`, String.raw`[\\/]\.electrum\b`, String.raw`\bwallet\.dat\b`,
  String.raw`\.config[\\/]solana[\\/]id\.json`, String.raw`\.ethereum[\\/]keystore`,
  String.raw`Library[\\/]Keychains`, String.raw`login\.keychain`, String.raw`\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)`,
  String.raw`\bsecret-tool\s+lookup`, String.raw`\.local[\\/]share[\\/]keyrings`, String.raw`\bCryptUnprotectData\b`, String.raw`\bcmdkey(?:\.exe)?\s+\/list`,
  String.raw`\.(?:bash|zsh)_history\b`, String.raw`\/etc\/shadow\b`,
].join("|"), "g");

const RULES: Rule[] = [
  // Decoded text handed to something that runs it.
  ...DECODE_RUN.map(([re, lang]) => R("exec-decoded", [lang], re)),
  R("exec-decoded", ["js"], /\b(?:eval|Function|execScript)\s*\(\s*(?:unescape|decodeURIComponent|String\.fromCharCode|(?:require\(\s*['"](?:node:)?zlib['"]\s*\)|zlib)\.(?:inflate|gunzip|brotliDecompress|unzip)\w*)\s*\(/),
  R("exec-decoded", ["js"], /\bnew\s+Function\s*\([^;]{0,120}?\b(?:atob|Buffer\.from|fromCharCode)\s*\(/),
  R("exec-decoded", ["js"], /\b(?:vm\.)?(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(\s*(?:atob|Buffer\.from)\s*\(|\bnew\s+vm\.Script\s*\(\s*(?:atob|Buffer\.from)\s*\(/),
  R("exec-decoded", ["js"], /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:atob|Buffer\.from)\s*\(/),
  R("exec-decoded", ["py"], /\b(?:exec|eval)\s*\(\s*(?:base64\.\w*decode|b64decode|zlib\.decompress|lzma\.decompress|bz2\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|binascii\.(?:a2b_\w+|unhexlify)|__import__\(\s*['"](?:base64|zlib|marshal|codecs|binascii|lzma|bz2)['"]\s*\))/),
  R("exec-decoded", ["py"], /\bexec\s*\(\s*compile\s*\(\s*(?:base64|zlib|marshal|codecs|__import__)|\b(?:exec|eval)\s*\(\s*Fernet\s*\(|\bexec\s*\(\s*['"]{1,3}['"]{0,2}\s*\.join\s*\(\s*(?:map\s*\(\s*chr|\[?\s*chr\s*\()/),
  R("exec-decoded", ["sh", "ps"], /\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,120}\|\s*(?:ba|z|da)?sh\b|\becho\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64/),
  R("exec-decoded", ["sh", "ps", "js", "py"], /powershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{24,}/i),
  // A download run straight away.
  R("pipe-shell", ALL, /\b(?:curl|wget)\b[^\n|;'"\x60]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n|;]{0,200}\|\s*(?:python[23]?|node|perl|ruby)\b/),
  R("pipe-shell", ALL, /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]{0,200}\b(?:iex|Invoke-Expression)\b|\b(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+(?:System\.)?Net\.WebClient|iwr|irm|Invoke-WebRequest)|\bcertutil(?:\.exe)?\s+-urlcache\b/i),
  R("pipe-shell", ALL, /\/dev\/tcp\/[\w.-]+\/\d+/),
  R("pipe-shell", ["js"], /\.then\(\s*(?:\(?\s*\w+\s*\)?\s*=>\s*)?eval\s*\)|\beval\s*\(\s*await\s+(?:\(\s*await\s+)?fetch\b|\bnew\s+Function\s*\(\s*await\b|\b(?:https?|http2)\.(?:get|request)\s*\([^;]{0,400}?\b(?:eval|new\s+Function|runInThisContext)\s*\(/),
  R("pipe-shell", ["py"], /\b(?:exec|eval)\s*\(\s*(?:urllib\.request\.|urllib2\.)?urlopen\s*\(|\b(?:exec|eval)\s*\(\s*(?:requests|httpx)\.get\s*\(/),
  // Credentials and where they live.
  R("secrets", ALL, SECRET_PATH),
  R("secrets-weak", ALL, /['"\x60\\/]\.(?:npmrc|pypirc|netrc)\b|['"\x60]\.env(?:\.local|\.production)?['"\x60]/),
  R("env-dump", ["js"], /JSON\.stringify\(\s*process\.env\s*[,)]|\b(?:btoa|encodeURIComponent)\(\s*JSON\.stringify\(\s*process\.env|querystring\.stringify\(\s*process\.env|new\s+URLSearchParams\(\s*process\.env\s*\)/),
  R("env-dump", ["py"], /json\.dumps\(\s*(?:dict\(\s*)?os\.environ|\bstr\(\s*os\.environ\s*\)|urlencode\(\s*(?:dict\(\s*)?os\.environ|base64\.\w*encode\([^)\n]*os\.environ/),
  R("env-dump", ["sh", "ps"], /\b(?:printenv|env)\s*\|\s*(?:curl|nc|base64)|\bGet-ChildItem\s+env:[^\n]{0,80}\|\s*(?:ConvertTo-Json|Out-String)/i),
  R("token-env", ["js", "py", "sh"], /(?:process\.env|os\.environ(?:\.get)?|os\.getenv|\$\{?)\s*[\[.(]?\s*['"]?(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|SLACK_TOKEN|DISCORD_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|HEROKU_API_KEY|DOCKER_PASSWORD)\b/),
  // The network.
  R("network", ["js"], /\brequire\(\s*['"](?:node:)?(?:https?|http2|net|dgram|tls|dns)['"]\s*\)|\bfrom\s+['"](?:node:)?(?:https?|http2|net|dgram|tls|dns)['"]|\bimport\s*\(\s*['"](?:node:)?(?:https?|net|dns)['"]\s*\)|\bfetch\s*\(|\bnew\s+(?:XMLHttpRequest|WebSocket)\s*\(/),
  R("network", ["py"], /^\s*(?:import|from)\s+(?:urllib\.request|urllib2|urllib3|http\.client|socket|requests|httpx|aiohttp|ftplib|smtplib)\b|\burlopen\s*\(|\brequests\.(?:get|post|put|request)\s*\(|\bsocket\.(?:socket|create_connection)\s*\(/m),
  R("network", ["sh", "ps"], /\b(?:curl|wget|nc|ncat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|bitsadmin)\b|Net\.WebClient/i),
  R("dns-exfil", ["js"], /(?:\bdns|dns['"]\))\.(?:lookup|resolve\w*)\s*\(\s*(?:[\w$.]+\s*\+|\x60[^\x60]*\$\{)/),
  R("dns-exfil", ["py"], /\bsocket\.gethostbyname\s*\(\s*(?:[\w.]+\s*\+|f['"])/),
  // Running programs, making them runnable, leaving them running.
  R("proc", ["js"], /\brequire\(\s*['"](?:node:)?child_process['"]\s*\)|\bfrom\s+['"](?:node:)?child_process['"]/),
  R("proc", ["py"], /\b(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput))\s*\(/),
  R("chmod", ["js"], /\bchmod(?:Sync)?\s*\([^)\n]*?(?:0o?[75][0-7]{2}\b|\b493\b|['"]\+?x['"]|['"][75][0-7]{2}['"])/),
  R("chmod", ["sh", "ps"], /\bchmod\s+(?:[ugoa]*\+x|[0-7]?[75][0-7]{2})\b/),
  R("chmod", ["py"], /\bos\.chmod\s*\([^)\n]*(?:0o?[75][0-7]{2}|S_IEXEC|S_IXUSR)/),
  R("detached", ["js"], /\bdetached\s*:\s*true\b/),
  R("detached", ["py"], /\bstart_new_session\s*=\s*True|DETACHED_PROCESS/),
  R("detached", ["sh"], /\bnohup\b|\bdisown\b|\bsetsid\b/),
  // Starting again later.
  R("persistence", ALL, /Library[\\/]Launch(?:Agents|Daemons)|\blaunchctl\s+(?:load|bootstrap|submit|enable)\b|\bcrontab\s+(?:-l\b|-e\b|-\s|-$|[\w./-]+\.txt\b)|\/etc\/cron\.|\/var\/spool\/cron|\bsystemctl\s+--user\s+(?:enable|start)\b|\.config[\\/]systemd[\\/]user|\.config[\\/]autostart|CurrentVersion\\{1,2}Run\b|\bschtasks(?:\.exe)?\s+\/create\b|Start Menu\\{1,2}Programs\\{1,2}Startup|\breg(?:\.exe)?\s+add\s+HK|authorized_keys/i),
];

/** Shell start-up files: persistence only where the same file also writes something. */
const RC_FILE = /['"\x60\\/](?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.zshenv|\.profile|config\.fish)\b/g;
const WRITES = /\b(?:appendFileSync|writeFileSync|appendFile|writeFile|createWriteStream)\s*\(|\bopen\s*\([^)\n]*['"]a\+?['"]|>>\s*["'$~\w/]/;

const URL_RE = /\b(?:https?|wss?|ftp):\/\/(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*)(?::\d{1,5})?(\/[^\s'"\x60)<>\\]*)?/g;
const HOST_KEY = /\b(?:host|hostname|HOST)\s*[:=]\s*['"\x60]([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)+)['"\x60]/g;
const BARE_IP = /['"\x60](\d{1,3}(?:\.\d{1,3}){3})(?::\d{2,5})?['"\x60/]/g;

/** Services built to receive what someone sends them: webhooks, paste sites, tunnels, out-of-band test servers. */
const EXFIL_HOST = /(^|\.)(pastebin\.com|paste\.ee|hastebin\.com|rentry\.co|ghostbin\.\w+|ngrok\.io|ngrok-free\.app|ngrok\.app|ngrok\.dev|webhook\.site|pipedream\.net|requestbin\.(?:com|net)|burpcollaborator\.net|oastify\.com|oast\.(?:pro|live|site|online|fun|me)|interact\.sh|interactsh\.com|transfer\.sh|file\.io|gofile\.io|anonfiles\.com|bashupload\.com|temp\.sh|trycloudflare\.com|serveo\.net|loca\.lt|localtunnel\.me|beeceptor\.com|hookbin\.com|requestcatcher\.com|postb\.in|dnslog\.cn|ceye\.io)$/i;
/** Paths on ordinary hosts that do the same: Discord webhooks, Telegram bots. */
const EXFIL_PATH = /^(?:(?:www\.|ptb\.|canary\.)?discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/|api\.telegram\.org\/bot)/i;
/** What-is-my-IP services: how stealers learn where they landed. */
const RECON_HOST = /(^|\.)(ipinfo\.io|ipify\.org|ifconfig\.me|ifconfig\.co|icanhazip\.com|ip-api\.com|checkip\.amazonaws\.com|ipecho\.net|myexternalip\.com|wtfismyip\.com|ident\.me|ipapi\.co|geolocation-db\.com)$/i;
/** Registries, code hosts and vendors that packages download their own builds from. */
const BENIGN_HOST = /(^|\.)(npmjs\.org|npmjs\.com|yarnpkg\.com|npmmirror\.com|pypi\.org|pythonhosted\.org|python\.org|github\.com|githubusercontent\.com|github\.io|gitlab\.com|bitbucket\.org|nodejs\.org|googleapis\.com|gstatic\.com|microsoft\.com|visualstudio\.com|azureedge\.net|electronjs\.org|cypress\.io|playwright\.dev|prisma\.sh|sentry\.io|sentry-cdn\.com|sourceforge\.net|apache\.org|mozilla\.org|w3\.org|unpkg\.com|jsdelivr\.net|cdnjs\.cloudflare\.com|opencollective\.com|nvidia\.com|apple\.com|chromium\.org|example\.(?:com|org|net)|localhost)$/i;
/** Public DNS resolvers, used by is-online checks. */
const DNS_IP = new Set(["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.222.222"]);

/** How a host found in code reads: a drop box, an IP lookup, a raw address, a known vendor, or just a host. */
export function hostKind(hostAndPath: string): HostKind | undefined {
  const host = hostAndPath.split("/")[0].toLowerCase().replace(/:\d+$/, "");
  if (EXFIL_PATH.test(hostAndPath) || EXFIL_HOST.test(host)) return "exfil";
  if (RECON_HOST.test(host)) return "recon";
  const ip = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (ip) {
    const [a, b] = [Number(ip[1]), Number(ip[2])];
    if (ip.slice(1).some((x) => Number(x) > 255)) return;
    // Loopback, private, link-local, multicast and "this network" are not somewhere data goes.
    if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || DNS_IP.has(host)) return;
    return "ip";
  }
  if (host.startsWith("[")) return /^\[(?:::1|fe80:|fc|fd)/i.test(host) ? undefined : "ip";
  if (!host.includes(".")) return;
  return BENIGN_HOST.test(host) ? "benign" : "plain";
}

/** The kind of credential a path is: stealers take many kinds at once, an SDK reads its own. */
export function family(hit: string): string {
  if (/ssh|id_(rsa|ed25519|ecdsa|dsa)/i.test(hit)) return "ssh";
  if (/aws/i.test(hit)) return "aws";
  if (/gcloud|application_default|azure|kube|docker|gh[\\/]hosts|git-credentials/i.test(hit)) return "cloud";
  if (/Login Data|Local State|Extension|IndexedDB|^[a-p]{32}$/i.test(hit)) return "browser";
  if (/Exodus|Electrum|atomic|Ledger|wallet|solana|ethereum/i.test(hit)) return "wallet";
  if (/keychain|security|secret-tool|keyrings|CryptUnprotect|cmdkey/i.test(hit)) return "keychain";
  if (/history/i.test(hit)) return "history";
  return "other";
}

// ── reading one file

class Text {
  private nl?: number[];
  constructor(readonly s: string) {}
  line(i: number): number {
    this.nl ??= [...this.s.matchAll(/\n/g)].map((m) => m.index!);
    let lo = 0, hi = this.nl.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.nl[mid] < i) lo = mid + 1;
      else hi = mid;
    }
    return lo + 1;
  }
  /** Whether the hit sits on a comment line: comments run nothing, and are full of URLs and paths. */
  comment(i: number, lang: Lang): boolean {
    const l = this.s.slice(this.s.lastIndexOf("\n", i - 1) + 1, i).trimStart();
    return lang === "js" ? /^(\/\/|\/\*|\*)/.test(l) : /^#/.test(l);
  }
  /** The hit and a little around it, on one line, masked. */
  snippet(i: number, len: number): string {
    const start = Math.max(this.s.lastIndexOf("\n", i) + 1, i - 40);
    const endLine = this.s.indexOf("\n", i + len);
    const end = Math.min(endLine < 0 ? this.s.length : endLine, i + Math.min(len, 100) + 40);
    const t = this.s.slice(start, end).replace(/\s+/g, " ").trim();
    return mask(t.length > 160 ? t.slice(0, 157) + "…" : t);
  }
}

/** Credentials, and any long encoded run: evidence should say what the code does, not repeat its payload. */
export function mask(t: string): string {
  return redact(t)
    .replace(/[A-Za-z0-9+/=_-]{40,}/g, (m) => `${m.slice(0, 6)}…(${m.length} chars)`)
    .replace(/(?:\\x[0-9a-fA-F]{2}){8,}/g, (m) => `\\x…(${m.length / 4} bytes)`)
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

function scanText(path: string, where: Where, lang: Lang, s: string, out: Signal[]) {
  const t = new Text(s);
  const add = (cat: Cat, i: number, len: number, extra: Partial<Signal> = {}) => out.push({ cat, where, file: path, line: t.line(i), text: t.snippet(i, len), ...extra });
  for (const r of RULES) {
    if (!r.langs.includes(lang)) continue;
    let n = 0;
    r.re.lastIndex = 0;
    for (const m of s.matchAll(r.re)) {
      if (t.comment(m.index!, lang)) continue;
      add(r.cat, m.index!, m[0].length, r.cat === "secrets" ? { family: family(m[0]) } : {});
      if (++n >= 3) break;
    }
  }
  if (lang !== "sh" && lang !== "ps") {
    // A decoder and an eval of a plain variable in the same file: decode first, run later.
    const decodes = lang === "js" ? /\b(?:atob\s*\(|Buffer\.from\s*\([^)]{0,200}['"](?:base64|hex)['"])/ : /\b(?:b64decode|base64\.\w*decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)\s*\(/;
    const runsVar = lang === "js" ? /\b(?:eval|new\s+Function)\s*\(\s*[A-Za-z_$][\w$]*\s*\)/ : /\bexec\s*\(\s*[A-Za-z_]\w*\s*[,)]/;
    const ev = runsVar.exec(s);
    if (ev && decodes.test(s) && !out.some((x) => x.file === path && x.cat === "exec-decoded")) add("exec-maybe", ev.index, ev[0].length);
  }
  // obfuscator.io output: many _0x1a2b names.
  const ox = s.match(/\b_0x[0-9a-f]{4,6}\b/g);
  if (ox && ox.length >= 30) add("obfuscated", s.indexOf(ox[0]), 12);
  const armor = /\b__pyarmor__\s*\(|\bfrom\s+pytransform\s+import\s+pyarmor_runtime|\bpyarmor_runtime\s*\(/.exec(s);
  if (armor) add("obfuscated", armor.index, armor[0].length);
  // Code pushed far to the right, past the edge of the editor.
  const hidden = /\S[ \t]{300,}(?=\S)/.exec(s);
  if (hidden) add("hidden", hidden.index + hidden[0].length, 60);
  // Long encoded strings. Data URIs (images, fonts) and embedded WebAssembly are ordinary.
  for (const m of s.matchAll(/(['"\x60])((?:[A-Za-z0-9+/]{4}){150,}(?:[A-Za-z0-9+/]{2,3}={0,2})?)\1/g)) {
    if (m[2].startsWith("AGFzbQ")) continue;
    add("blob", m.index!, 60);
    break;
  }
  const hex = /(['"\x60])(?:[0-9a-fA-F]{2}){300,}\1|(?:\\x[0-9a-fA-F]{2}){80,}/.exec(s);
  if (hex) add("blob", hex.index, 60);
  for (const m of s.matchAll(RC_FILE)) {
    if (WRITES.test(s)) add("persistence", m.index!, m[0].length);
    break;
  }
  // Hosts named in code: one signal per host and file.
  const seen = new Set<string>();
  const host = (h: string, i: number, len: number) => {
    if (t.comment(i, lang)) return;
    const kind = hostKind(h);
    const name = h.split("/")[0].toLowerCase();
    if (!kind || seen.has(name) || seen.size >= 40) return;
    seen.add(name);
    add("host", i, len, { host: kind === "exfil" && EXFIL_PATH.test(h) ? h.split("/").slice(0, 3).join("/") : name, hostKind: kind });
  };
  for (const m of s.matchAll(URL_RE)) host(m[1] + (m[2] ?? ""), m.index!, m[0].length);
  // { hostname: "collector.example" } in request options, and host = "…" in Python.
  for (const m of s.matchAll(HOST_KEY)) host(m[1], m.index!, m[0].length);
  // A bare dotted quad of small numbers is an OID or a version (2.5.4.3 is X.509's commonName), not a server.
  for (const m of s.matchAll(BARE_IP)) if (m[1].split(".").some((x) => Number(x) >= 10)) host(m[1], m.index!, m[0].length);
}

// ── which files run at install

/** Files a JavaScript file loads by relative path. */
function jsImports(s: string): string[] {
  const out: string[] = [];
  for (const m of s.matchAll(/\brequire\s*\(\s*['"](\.{1,2}\/[^'"]+|\.{1,2})['"]\s*\)|\bimport\s+(?:[^'";]*?\sfrom\s+)?['"](\.{1,2}\/[^'"]+)['"]|\bimport\s*\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g))
    out.push(m[1] ?? m[2] ?? m[3]);
  // require(path.join(__dirname, "lib", "install.js"))
  for (const m of s.matchAll(/\brequire\s*\(\s*(?:path\.)?(?:join|resolve)\s*\(\s*__dirname\s*,\s*((?:['"][^'"]+['"]\s*,?\s*)+)\)\s*\)/g))
    out.push("./" + [...m[1].matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]).join("/"));
  return out;
}

function pyImports(s: string): string[] {
  const out: string[] = [];
  for (const m of s.matchAll(/^\s*(?:from\s+([\w.]+)\s+import\b|import\s+([\w.]+(?:\s*,\s*[\w.]+)*))/gm)) {
    if (m[1]) out.push(m[1]);
    else out.push(...m[2].split(",").map((x) => x.trim()));
  }
  // exec(open("pkg/version.py").read()) and friends
  for (const m of s.matchAll(/\bopen\s*\(\s*['"]([\w./-]+\.py)['"]/g)) out.push("file:" + m[1]);
  return out;
}

const norm = (p: string) => {
  const parts: string[] = [];
  for (const s of p.split("/")) {
    if (s === "..") parts.pop();
    else if (s && s !== ".") parts.push(s);
  }
  return parts.join("/");
};
const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");

/** The scripts a hook command starts (node install.js, sh ./x.sh, python setup_helper.py), and inline code (node -e "…"). */
export function hookTargets(cmd: string): { files: string[]; inline: string[] } {
  const files: string[] = [], inline: string[] = [];
  for (const seg of cmd.split(/&&|\|\||;|\|/)) {
    const words = [...seg.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g)].map((m) => m[1] ?? m[2] ?? m[3]);
    const i = words.findIndex((w) => !/^\w+=/.test(w));
    const prog = (words[i] ?? "").replace(/^.*\//, "");
    const rest = words.slice(i + 1);
    if (/^(node|nodejs|bun|deno|python[\d.]*|py|sh|bash|zsh|dash|pwsh|powershell)$/.test(prog)) {
      for (let j = 0; j < rest.length; j++) {
        if (/^(-e|--eval|-p|--print|-c)$/.test(rest[j])) {
          if (rest[j + 1]) inline.push(rest[++j]);
          continue;
        }
        if (rest[j] === "run" && prog === "deno") continue;
        if (rest[j].startsWith("-")) continue;
        files.push(rest[j]);
        break;
      }
    } else if (words[i] && /^\.{0,2}\//.test(words[i])) files.push(words[i]);
  }
  return { files: files.map(norm).filter(Boolean), inline };
}

/** Everything reachable from the given files by relative imports, inside the package. */
function reach(start: string[], byPath: Map<string, Entry>, py: boolean): Set<string> {
  const found = new Set<string>();
  const queue = [...start];
  const resolveJs = (from: string, spec: string) => {
    const base = norm(`${dirOf(from)}/${spec}`);
    return [base, `${base}.js`, `${base}.cjs`, `${base}.mjs`, `${base}.json`, `${base}/index.js`, `${base}/index.cjs`, `${base}/index.mjs`].find((p) => byPath.has(p));
  };
  const resolvePy = (spec: string) => {
    if (spec.startsWith("file:")) return byPath.has(norm(spec.slice(5))) ? norm(spec.slice(5)) : undefined;
    const base = spec.replace(/\./g, "/");
    return [`${base}.py`, `${base}/__init__.py`, `src/${base}.py`, `src/${base}/__init__.py`].find((p) => byPath.has(p));
  };
  while (queue.length && found.size < 300) {
    const f = queue.shift()!;
    if (found.has(f) || !byPath.has(f)) continue;
    found.add(f);
    const s = byPath.get(f)!.data?.toString("utf8") ?? "";
    if (py || /\.pyw?$/.test(f)) for (const spec of pyImports(s)) {
      const p = resolvePy(spec);
      if (p) queue.push(p);
    }
    else if (/\.(c?js|mjs)$/.test(f) || !/\.\w+$/.test(f)) for (const spec of jsImports(s)) {
      const p = resolveJs(f, spec);
      if (p) queue.push(p);
    }
  }
  return found;
}

const lineOfKey = (text: string, key: string) => {
  const i = text.indexOf(`"${key}"`);
  return i < 0 ? 1 : text.slice(0, i).split("\n").length;
};

/** A `.pth` line that Python runs: one starting with `import`. */
const PTH_EXEC = /^import[\s;]/;
/** .pth files every Python install has: setuptools' distutils switch and namespace-package shims. */
const PTH_KNOWN = /^import os; var = 'SETUPTOOLS_USE_DISTUTILS'|^import sys, types, os;\s*has_mfs = |^import _virtualenv\s*$|^import __editable___[\w]+\s*$/;

export function scanPackage(a: Archive, kind: Kind): Scanned {
  const byPath = new Map(a.entries.map((e) => [e.path, e]));
  const text = (p: string) => byPath.get(p)?.data?.toString("utf8") ?? "";
  const signals: Signal[] = [];
  const hooks: Hook[] = [];
  const entry: string[] = [];
  const inline: { file: string; line: number; code: string }[] = [];
  let deps: string[] = [];

  if (kind === "npm") {
    let pj: any = {};
    try {
      pj = JSON.parse(text("package.json") || "{}");
    } catch {}
    const scripts = pj && typeof pj.scripts === "object" && pj.scripts ? pj.scripts : {};
    for (const name of ["preinstall", "install", "postinstall"]) {
      if (typeof scripts[name] !== "string") continue;
      hooks.push({ name, cmd: scripts[name] });
      const t = hookTargets(scripts[name]);
      entry.push(...t.files);
      const line = lineOfKey(text("package.json"), name);
      inline.push({ file: "package.json", line, code: scripts[name] }, ...t.inline.map((code) => ({ file: "package.json", line, code })));
    }
    // binding.gyp with no install script of its own: npm runs node-gyp rebuild, and the gyp file's <!(…) commands with it.
    if (byPath.has("binding.gyp") && !hooks.some((h) => h.name === "install" || h.name === "preinstall")) hooks.push({ name: "install", cmd: "node-gyp rebuild (binding.gyp)" });
    deps = Object.keys({ ...(pj.dependencies ?? {}), ...(pj.optionalDependencies ?? {}) });
  }
  if (kind === "sdist") {
    if (byPath.has("setup.py")) {
      hooks.push({ name: "setup.py", cmd: "python setup.py (pip runs it to build the package)" });
      entry.push("setup.py");
    }
    // An in-tree build backend (pyproject backend-path) is code of the package that pip runs to build it.
    const pp = text("pyproject.toml");
    const backend = /^\s*backend-path\s*=\s*\[([^\]]*)\]/m.exec(pp);
    const name = /^\s*build-backend\s*=\s*["']([\w.]+)["']/m.exec(pp)?.[1];
    if (backend && name) {
      for (const dir of [...backend[1].matchAll(/["']([^"']+)["']/g)].map((m) => norm(m[1]))) {
        const base = `${dir ? dir + "/" : ""}${name.replace(/\./g, "/")}`;
        const f = [`${base}.py`, `${base}/__init__.py`].find((p) => byPath.has(p));
        if (f) {
          hooks.push({ name: "build-backend", cmd: `${name} (from the package itself)` });
          entry.push(f);
        }
      }
    }
  }
  // .pth files in a wheel: their import lines run every time Python starts, from the moment it is installed.
  for (const e of a.entries) {
    if (kind !== "wheel" || !e.path.endsWith(".pth") || e.path.split("/").length > 3) continue;
    const lines = text(e.path).split("\n");
    lines.forEach((l, i) => {
      if (!PTH_EXEC.test(l.trim())) return;
      if (!PTH_KNOWN.test(l.trim())) signals.push({ cat: "pth", where: "install", file: e.path, line: i + 1, text: mask(l.trim().slice(0, 160)) });
      const mod = /^import\s+([\w.]+)\s*$/.exec(l.trim())?.[1];
      if (mod) entry.push(`${mod.replace(/\./g, "/")}.py`, `${mod.replace(/\./g, "/")}/__init__.py`);
    });
    if (lines.some((l) => PTH_EXEC.test(l.trim()))) {
      hooks.push({ name: ".pth", cmd: `${e.path} (runs at every Python start)` });
      entry.push(e.path);
    }
  }
  // binding.gyp: <!(command) and <!@(command) run while node-gyp configures the build.
  if (byPath.has("binding.gyp")) {
    const g = text("binding.gyp");
    const t = new Text(g);
    for (const m of g.matchAll(/<!@?\(([^)\n]*)\)/g)) {
      const cmd = m[1].trim();
      if (/^node\s+-[pe]\s+["']?\s*require\(/.test(cmd) && !/child_process|https?:|eval/.test(cmd)) continue;
      signals.push({ cat: "gyp", where: "install", file: "binding.gyp", line: t.line(m.index!), text: mask(cmd.slice(0, 160)) });
      inline.push({ file: "binding.gyp", line: t.line(m.index!), code: cmd });
      entry.push(...hookTargets(cmd).files);
    }
  }

  const install = reach([...new Set(entry)].filter((p) => byPath.has(p)), byPath, kind !== "npm");
  // Hook commands and inline code, read as both shell and JavaScript.
  for (const x of inline) {
    const before = signals.length;
    scanText(x.file, "install", "sh", x.code, signals);
    scanText(x.file, "install", "js", x.code, signals);
    for (const s of signals.slice(before)) s.line = x.line;
    for (const spec of jsImports(x.code)) {
      const p = [norm(spec), `${norm(spec)}.js`, `${norm(spec)}/index.js`].find((q) => byPath.has(q));
      if (p) for (const f of reach([p], byPath, false)) install.add(f);
    }
  }

  let jsBytes = 0, denseBytes = 0;
  const denseFiles: string[] = [];
  const dense: Signal[] = [];
  for (const e of a.entries) {
    if (!e.data || e.path === "package.json") continue;
    const s = e.data.toString("utf8");
    const lang = langOf(e.path, s.slice(0, 100));
    if (!lang || e.path === "binding.gyp") continue;
    const where: Where = install.has(e.path) ? "install" : NEVER.test(e.path) || NEVER_FILE.test(e.path) ? "never" : "import";
    if (where === "never") continue;
    scanText(e.path, where, lang, s, signals);
    if (lang === "js") {
      jsBytes += s.length;
      let longest = 0, at = 0, prev = 0;
      for (let i = s.indexOf("\n"); ; i = s.indexOf("\n", i + 1)) {
        const end = i < 0 ? s.length : i;
        if (end - prev > longest) (longest = end - prev), (at = prev);
        if (i < 0) break;
        prev = i + 1;
      }
      if (longest > 4000) {
        denseBytes += s.length;
        denseFiles.push(e.path);
        const t = new Text(s);
        dense.push({ cat: "dense", where, file: e.path, line: t.line(at), text: `a ${Math.round(longest / 1000)}k-character line` });
      }
    }
  }
  const bundle = jsBytes > 0 && denseBytes / jsBytes > 0.5;
  // A packed file says something only where the rest of the package is readable, or where it runs at install.
  for (const d of dense) if (d.where === "install" || (!bundle && !/(^|\/)(dist|build|umd|bundles?|out|vendor|lib\/browser)\/|\.min\.|\.bundle\./.test(d.file))) signals.push(d);

  return {
    kind, signals, hooks, installFiles: [...install].sort(), files: a.entries.length, size: a.total, bundle, dense: denseFiles, deps,
    problems: a.problems, partial: a.partial,
  };
}
