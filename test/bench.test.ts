// The measurements: the planted-technique catalogue (selftest), the name bench on its committed sample of real OSV
// malicious names and real download rankings, and the rules the catalogue added. Offline; nothing touches the real home.
import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { measure, technique, zipEntries, type Fixture } from "../scripts/bench-names";
import { BENIGN, CASES } from "../src/sec/selftest-cases";
import { awsProcesses, kubeExecs, maskSecrets, toolConfigs, toolHelpers } from "../src/sec/collect/tools";
import { galleryInstalled } from "../src/sec/collect/packages";
import { gitValue } from "../src/sec/collect/system";
import { hiddenProgram, lineRisk, urlRisk } from "../src/sec/rules";
import { lookAlike, nameSignals } from "../src/sec/intel";
import { judge } from "../src/sec/pkg";
import type { Ctx } from "../src/sec/ctx";

const tmp = (tag: string) => mkdtempSync(join(tmpdir(), `vs-bench-${tag}-`));
const ctxFor = (home: string): Ctx => ({ home, pathDirs: [], system: false, host: "t", user: "t", run: async () => undefined });

describe("selftest catalogue", () => {
  test("50+ planted techniques with benign look-alikes, every case named after a technique", () => {
    expect(CASES.length).toBeGreaterThanOrEqual(50);
    expect(BENIGN.length).toBeGreaterThanOrEqual(25);
    for (const c of [...CASES, ...BENIGN]) expect(c.technique).toMatch(/\S/);
    // Most techniques that have attacks also have a benign counterpart to measure false alarms on.
    const withBenign = new Set(BENIGN.map((b) => b.technique));
    const techniques = new Set(CASES.map((c) => c.technique));
    expect([...techniques].filter((t) => withBenign.has(t)).length).toBeGreaterThanOrEqual(15);
    expect(new Set(CASES.map((c) => c.name)).size).toBe(CASES.length);
  });
});

describe("name bench", () => {
  const fx: Fixture = JSON.parse(readFileSync(join(import.meta.dir, "fixtures/bench/names.json"), "utf8"));

  test("the committed sample of OSV malicious names and ranked real names: no worse than when it was recorded", () => {
    for (const eco of ["npm", "pip"] as const) {
      const m = measure(eco, fx[eco].malicious, fx[eco].legit);
      expect([eco, m.detection.rate]).toEqual([eco, expect.any(Number)]);
      expect(m.detection.rate).toBeGreaterThanOrEqual(fx.sample[eco].detection - 1e-9);
      expect(m.falsePositives.rate).toBeLessThanOrEqual(fx.sample[eco].falsePositives + 1e-9);
    }
    expect(fx.npm.legit.length + fx.pip.legit.length).toBeGreaterThanOrEqual(1500);
  }, 60_000);

  test("techniques are read from the advisory text, not the package's own name or GitHub's closing sentence", () => {
    expect(technique("Malicious code in typography-kit (npm) Any computer that has this package installed or running should be considered fully compromised.", "typography-kit")).toBe("unspecified");
    expect(technique("This package employs typosquatting to impersonate a legitimate author")).toBe("typosquat");
    expect(technique("consistent with a dependency-confusion payload targeting internal build systems")).toBe("dependency confusion");
    expect(technique("This package appears to be part of the tea.xyz token reward campaign")).toBe("spam (tea.xyz farming)");
    expect(technique("This package is a starjacking attack which bundles a cryptostealing payload.")).toBe("starjacking");
  });

  test("zip reader: stored and deflated entries", () => {
    // A two-entry zip written by hand: one deflated, one stored.
    const entries = [["MAL-1.json", Buffer.from('{"id":"MAL-1"}'), 8], ["README", Buffer.from("x"), 0]] as const;
    const locals: Buffer[] = [], central: Buffer[] = [];
    let off = 0;
    for (const [name, data, method] of entries) {
      const body = method === 8 ? deflateRawSync(data) : data;
      const n = Buffer.from(name);
      const lh = Buffer.alloc(30);
      lh.writeUInt32LE(0x04034b50, 0), lh.writeUInt16LE(method, 8), lh.writeUInt32LE(body.length, 18), lh.writeUInt32LE(data.length, 22), lh.writeUInt16LE(n.length, 26);
      const ch = Buffer.alloc(46);
      ch.writeUInt32LE(0x02014b50, 0), ch.writeUInt16LE(method, 10), ch.writeUInt32LE(body.length, 20), ch.writeUInt32LE(data.length, 24), ch.writeUInt16LE(n.length, 28), ch.writeUInt32LE(off, 42);
      locals.push(lh, n, body);
      central.push(ch, n);
      off += 30 + n.length + body.length;
    }
    const cd = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0), end.writeUInt16LE(2, 8), end.writeUInt16LE(2, 10), end.writeUInt32LE(cd.length, 12), end.writeUInt32LE(off, 16);
    const zip = Buffer.concat([...locals, cd, end]);
    expect([...zipEntries(zip)].map((e) => [e.name, e.data().toString()])).toEqual([["MAL-1.json", '{"id":"MAL-1"}'], ["README", "x"]]);
  });

  test("look-alikes: a doubled version digit is a typo, another version is a family; Babel's old names are Babel's", () => {
    expect(lookAlike("pip", "beautifulsoup44")).toBe("beautifulsoup4");
    expect(lookAlike("pip", "urllib33")).toBe("urllib3");
    expect(lookAlike("npm", "eventemitter2")).toBeUndefined();
    expect(lookAlike("npm", "babel-plugin-transform-runtime")).toBeUndefined();
    expect(lookAlike("npm", "solana-web3.js")).toBe("@solana/web3.js");
    expect(lookAlike("npm", "types-node")).toBe("@types/node");
  });

  test("names that say what they are: proof-of-concept, dependency-confusion probes, stealers", () => {
    for (const n of ["dependency-confusion-poc777", "pip-rce", "do-not-install-this-package-001", "tdata-grabber", "@x/test-poc3", "revshell"]) expect([n, nameSignals("npm", n).length]).toEqual([n, 1]);
    for (const n of ["pocketbase", "process", "rcedit", "pwned-passwords-django", "exploitable", "stealthy", "react", "hackernews"]) expect([n, nameSignals("npm", n)]).toEqual([n, []]);
    // The install guard says so offline, before anything is fetched.
    const f = judge({ eco: "npm", name: "dependency-confusion-poc777" }, undefined);
    expect(f.map((x) => [x.rule, x.severity])).toEqual([["pkg-name", "high"]]);
  });
});

describe("rules the catalogue added", () => {
  const H = "/Users/a";
  test("registry and index URLs: plain http, bare IPs and look-alike hosts; official ones, mirrors and company registries over https are fine", () => {
    expect(urlRisk("http://45.61.0.9:4873/")).toContain("bare IP");
    expect(urlRisk("http://nexus.corp.example.com/repository/npm/")).toContain("without TLS");
    expect(urlRisk("https://registry.npmjss.org/")).toContain("registry.npmjs.org");
    expect(urlRisk("https://pypi-org.simple-mirror.net/simple")).toContain("pypi.org");
    expect(urlRisk("https://registry.yarnpkg.co")).toContain("registry.yarnpkg.com");
    for (const ok of ["https://registry.npmjs.org/", "http://localhost:4873/", "https://registry.npmmirror.com/", "https://mirrors.aliyun.com/pypi/simple/",
      "https://pypi.corp.example.com/simple", "https://gitlab.com/api/v4/packages/npm/", "https://npm.pkg.github.com", "https://acme.jfrog.io/artifactory/api/pypi/pypi/simple"])
      expect([ok, urlRisk(ok)]).toEqual([ok, undefined]);
  });

  test("shell lines: preloads, prompt hooks, sudo wrappers, history off, PATH from odd places; ordinary lines are not", () => {
    const risky = ["export LD_PRELOAD=$HOME/.l/x.so", "export DYLD_INSERT_LIBRARIES=/tmp/x.dylib", `export NODE_OPTIONS="--require $HOME/.n/h.js"`, `PROMPT_COMMAND="$HOME/.config/.h/h.sh"`,
      "trap '~/.x/log' DEBUG", "alias sudo='$HOME/.s/sudo'", "sudo() { read -s p; }", "unset HISTFILE", "export HISTFILE=/dev/null", `export PATH="$HOME/.cache/.bin:$PATH"`,
      "path=(/tmp/.x/bin $path)", "export DOCKER_HOST=tcp://45.61.0.9:2375"];
    for (const l of risky) expect([l, typeof lineRisk(".zshrc", l, H)]).toEqual([l, "string"]);
    const fine = ["alias ll='ls -la'", "alias sudo='sudo '", "alias sudo='nocorrect sudo'", "export NODE_OPTIONS=--max-old-space-size=8192", `export PATH="$HOME/.cargo/bin:$HOME/.yarn/bin:$PATH"`,
      `PROMPT_COMMAND="history -a; $PROMPT_COMMAND"`, `PROMPT_COMMAND='printf "\\033]0;%s\\007" "\${PWD/#$HOME/~}"'`, "export DOCKER_HOST=unix:///var/run/docker.sock", "export HISTSIZE=50000",
      "export DYLD_LIBRARY_PATH=/opt/oracle/instantclient", "fish_add_path ~/.fly/bin"];
    for (const l of fine) expect([l, lineRisk(".zshrc", l, H)]).toEqual([l, undefined]);
  });

  test("git, ssh and package manager settings that start programs", () => {
    expect(lineRisk(".gitconfig", "fsmonitor = /Users/a/.config/.g/fsmon", H)).toContain("every status");
    expect(lineRisk(".gitconfig", "fsmonitor = true", H)).toBeUndefined();
    expect(lineRisk(".gitconfig", "sshCommand = ssh -i ~/.ssh/id_work", H)).toBeUndefined();
    expect(lineRisk(".gitconfig", "helper = !/opt/homebrew/bin/gh auth git-credential", H)).toBeUndefined();
    expect(lineRisk(".ssh/config", "LocalCommand /bin/sh -c id", H)).toContain("LocalCommand");
    expect(lineRisk(".ssh/config", 'Match exec "test -f /tmp/x"', H)).toContain("every connection");
    expect(lineRisk(".ssh/config", "ProxyCommand ssh -W %h:%p bastion", H)).toBeUndefined();
    expect(lineRisk(".ssh/config", "ProxyJump bastion", H)).toBeUndefined();
    expect(lineRisk(".npmrc", "script-shell=/Users/a/.cache/sh", H)).toBeDefined();
    expect(lineRisk(".npmrc", "@acme:registry=https://npm.pkg.github.com", H)).toBeUndefined();
    expect(lineRisk(".cargo/config.toml", 'rustc-wrapper = "sccache"', H)).toBeUndefined();
    expect(lineRisk(".cargo/config.toml", 'runner = "/Users/a/.local/share/.r/run"', H)).toBeDefined();
  });

  test("hiddenProgram: temp, caches and hidden folders inside others; an installer's own top-level folder is not; Windows paths too", () => {
    expect(hiddenProgram("/tmp/x", H)).toBeDefined();
    expect(hiddenProgram("~/.cache/k/auth token", H)).toBeDefined();
    expect(hiddenProgram("$HOME/.config/.x/run", H)).toBeDefined();
    expect(hiddenProgram("/Users/a/.krew/bin/kubectl-oidc_login", H)).toBeUndefined();
    expect(hiddenProgram("aws eks get-token", H)).toBeUndefined();
    expect(hiddenProgram("C:\\Users\\nok\\.cache\\.k\\auth.exe", "C:\\Users\\nok")).toBeDefined();
    expect(hiddenProgram("C:\\Users\\nok/.config/.a/creds", "C:\\Users\\nok")).toBeDefined();
    expect(hiddenProgram("C:\\Users\\nok\\.krew\\bin\\kubectl-oidc_login.exe", "C:\\Users\\nok")).toBeUndefined();
  });

  test("readers: kubeconfig exec plugins, AWS credential_process, git config values, masked npm tokens, marketplace installs", () => {
    const kube = `users:\n- name: eks\n  user:\n    exec:\n      command: aws\n      args: ["eks", "get-token"]\n      env:\n      - name: AWS_PROFILE\n        value: dev\n- name: sh\n  user:\n    exec:\n      command: sh\n      args:\n      - -c\n      - echo hi\n`;
    expect(kubeExecs(kube)).toEqual([{ user: "eks", command: "aws eks get-token" }, { user: "sh", command: "sh -c echo hi" }]);
    expect(awsProcesses("[default]\nregion=x\n[profile prod]\ncredential_process = /bin/creds --p prod\n")).toEqual([{ profile: "prod", command: "/bin/creds --p prod" }]);
    expect(gitValue('[user]\n\tname = x\n[core]\n\thooksPath = ~/.githooks\n[includeIf "gitdir:~/w/"]\n\thooksPath = no\n', "core", "hookspath")).toBe("~/.githooks");
    const masked = maskSecrets("registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_secretsecret\n//x/:_authToken=${NPM_TOKEN}\n");
    expect(masked).not.toContain("npm_secretsecret");
    expect(masked).toContain("_authToken=<secret ");
    expect(masked).toContain("${NPM_TOKEN}");
    const root = tmp("ext");
    writeFileSync(join(root, "extensions.json"), JSON.stringify([{ relativeLocation: "a.b-1.0.0", metadata: { id: "u", publisherId: "p", source: "gallery" } }, { relativeLocation: "c.d-1.0.0", metadata: { source: "vsix" } }]));
    expect([...galleryInstalled(root)!]).toEqual(["a.b-1.0.0"]);
    expect(galleryInstalled(tmp("noext"))).toBeUndefined();
  });

  test("tool collectors read a fake home only, and keep no secret in what they store", async () => {
    const h = tmp("home");
    mkdirSync(join(h, ".config/pip"), { recursive: true });
    writeFileSync(join(h, ".config/pip/pip.conf"), "[global]\nindex-url = https://u:hunter2hunter2@pypi.corp.example.com/simple\npassword = hunter2hunter2\n");
    mkdirSync(join(h, ".docker/contexts/meta/x"), { recursive: true });
    writeFileSync(join(h, ".docker/config.json"), JSON.stringify({ credsStore: "osxkeychain", currentContext: "r" }));
    writeFileSync(join(h, ".docker/contexts/meta/x/meta.json"), JSON.stringify({ Name: "r", Endpoints: { docker: { Host: "tcp://10.0.0.5:2375" } } }));
    const c = await toolConfigs(ctxFor(h));
    expect(c.items.map((i) => i.id)).toEqual([".config/pip/pip.conf"]);
    expect(JSON.stringify(c.texts)).not.toContain("hunter2hunter2");
    expect(c.texts[".config/pip/pip.conf"]).toContain("password = <secret ");
    const helpers = await toolHelpers(ctxFor(h));
    expect(helpers.map((i) => [i.id, i.meta?.program, i.meta?.current ?? i.meta?.stock])).toEqual([["docker-cred:*", "docker-credential-osxkeychain", true], ["docker-context:r", "tcp://10.0.0.5:2375", true]]);
  });
});
