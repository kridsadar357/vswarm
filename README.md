# vswarm

**Don't be the one who carries it in.**

Servers get hardened; they still trust whoever holds valid keys. So attackers go for the developer and the laptop:
a typo-squatted npm package, a "coding assignment" from a fake recruiter, a poisoned MCP server, a tampered Homebrew
tap. The malware runs as you, uses what your laptop remembers, and the server only sees a valid token.

vswarm warns you and pauses at the risky moments, before anything big happens:

- **installing a package**: `guard` checks npm, pip, brew … names before the install runs (look-alikes, known
  malware, brand-new releases, install scripts);
- **running a stranger's code**: `try` runs it in a sandbox and tells you what it tried;
- **adding an AI agent or MCP server**: `agents --inspect` starts it sandboxed and reads what the model will read;
- **reaching production**: `preflight` / `gate` check the machine before ssh, AWS or kubectl get your credentials.

Every warning says why it is risky and what to do instead. Outside those moments it stays out of your way: a tool
that cries wolf gets uninstalled, so false alarms are treated as bugs.

It is one local command: no server, no MDM, no per-seat licence, so a solo developer or a small team can actually use
it. It is **not** an EDR and not a hard access control: malware already running as you can switch it off (see
[what it protects and what not](SECURITY.md#what-vswarm-can-and-cannot-protect-against)). It complements Socket,
osquery, EDR and device trust (Teleport, Kolide); it does not replace them.

[ภาษาไทย](README.th.md)

![vswarm try stopping a fake job-interview repo, and preflight blocking ssh](docs/poc.png)

<sub>Output from the test runs: `test/fixtures/fake-interview` (harmless imitation) and the selftest's planted Homebrew tap.</sub>

**Full guide with screenshots:** [docs/guide.md](docs/guide.md) · [คู่มือภาษาไทย](docs/guide.th.md)

## Install

macOS and Linux. Needs git, and [Bun](https://bun.sh) (the installer uses yours, or installs a pinned Bun release
after checking its SHA-256); on Linux, `vswarm try` also needs bubblewrap and strace
(`sudo apt install bubblewrap strace`). Windows 10/11: a preview that checks the machine (Run keys, tasks, services,
WMI, PowerShell profiles, …) with watch, the ssh gate and the install guard, installed with `install.ps1`; `try` stays
in WSL for now, see [Windows (preview)](docs/guide.md#windows-preview).

```bash
curl -fsSL https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.sh | sh
# or
git clone https://github.com/kridsadar357/vswarm.git && cd vswarm && ./vswarm install
```

## Use

```bash
vswarm scan                 # what is on this machine that deserves attention
vswarm baseline             # on a machine you trust: "this is clean"
vswarm diff                 # later: what changed since then
vswarm secrets              # long-lived credentials (never prints values)
vswarm selftest             # plant fake threats in a sandbox home, measure detection
```

### Gate production access

```bash
vswarm gate ssh "prod-*" "*.wallet.internal"     # adds a Match block to ~/.ssh/config (backup kept)
```

```ini
# ~/.aws/config
[profile prod]
credential_process = vswarm preflight --quiet --then aws configure export-credentials --profile prod-sso --format process
```

```yaml
# kubeconfig
users:
- name: prod-deployer
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: vswarm
      args: [preflight, --quiet, --then, kubelogin, get-token, --server-id, "<id>"]
```

`vswarm preflight` exits **0** on PASS and WARN, **3** on BLOCK (and **2** on WARN with `--strict`). A verdict is
reused for two minutes, so gating every `kubectl` call costs about 20 ms. A fresh check takes about 0.2 s.

### Short-lived SSH certificates

Servers trust a CA instead of keys. vswarm issues a fresh key with a 15-minute certificate, and only when the machine
passes preflight. A stolen key file is trusted nowhere, and a stolen certificate expires before it is worth much.

```bash
vswarm ca init                      # CA key protected by a passphrase you type at each signing (or: --sk, a hardware key touch)
vswarm ca server root               # prints the sshd commands to trust the CA; review them and run them on the server
vswarm gate ssh --cert prod-*       # ssh gets a certificate automatically when it connects
```

Tested end to end against a real `sshd`: the certificate logs in, the bare key is refused, an expired certificate is
refused, and no certificate is issued while preflight says BLOCK.

### Canary tokens

Decoy credentials placed where stealers look. Nobody has a reason to use them, so any use means the machine or a copy
of its files is in someone else's hands. Make the tokens at [canarytokens.org](https://canarytokens.org) (free, by
Thinkst) with your e-mail; vswarm plants and tracks them, and does not report your own decoys as exposure.

```bash
vswarm canary plant aws             # a decoy profile in ~/.aws/credentials
vswarm canary plant dns <token-host> # a decoy host at the top of ~/.ssh/config
vswarm canary plant env ~/develop/old-project
vswarm canary list · vswarm canary remove <id>
```

### AI agents and MCP servers

Coding agents run code with your access, and their settings decide what they may start on their own. `vswarm agents`
lists, and `scan` / `preflight` check, the MCP servers of Claude Code (every profile), Claude Desktop, Cursor,
Windsurf, VS Code, Gemini CLI and Codex, Claude Code hooks and `statusLine` commands, permission modes and plugins.

| Signal | Severity |
| --- | --- |
| MCP server or hook that downloads, decodes or backgrounds something, or runs from a temp/cache/hidden folder | high |
| MCP server started through npx/uvx with a look-alike package name | high |
| new or changed MCP server, new or changed hook, agent given more freedom (bypass, `Bash(*)`) since the baseline | medium |
| remote MCP server over plain http; token pasted into an MCP config | medium |
| a server `agents --inspect` saw change its tools (rug pull), until accepted | high |
| a server defined differently than when it was inspected (checked without starting it) | medium |

A baseline taken before vswarm checked agents does not report every existing server as new; it says the baseline
is older than the check, and `vswarm baseline` brings it up to date.

### Check packages before they install

Most stealers arrive as a package: a look-alike name, a hijacked release, a name an AI assistant made up and an
attacker then registered. `vswarm guard on` puts a thin wrapper around npm, npx, pnpm, yarn, bun, bunx, pip, pip3,
uv, uvx, pipx and brew in your shell. Installs are checked before the package manager runs any install script;
everything else (`npm run dev`, `pip list`) does not even start vswarm.

```
$ npm install axois
▼ vswarm checked npm axois · 412 ms
  CRIT  axois@0.0.1-security: known malicious
        OSV MAL-2025-15245
  HIGH  npm axois: looks like axios
        → did you mean axios?
  ? Stop here. Install anyway? [y/N]
```

| Signal | Severity |
| --- | --- |
| known-malicious version (OSV `MAL-`) | critical, blocks |
| close to one of the top 2,000 npm / 1,000 PyPI names, and not established itself | high, blocks |
| no such package, but it looks like a popular one | high, blocks |
| package created in the last 30 days, few downloads, with an install script | high, blocks |
| version published in the last 48 hours | medium, warns |
| git URL, tarball, third-party Homebrew tap | medium, warns |
| install script on an established package | low, one line |

A bare `npm install` / `npm ci` checks every locked version against OSV. Blocking asks first; skip vswarm once with
`command npm …`, or turn it off with `vswarm guard off`. Check by hand without the wrapper:
`vswarm pkg npm install <name>`. If a registry cannot be reached, the install goes ahead with a notice (`guard on --strict`
stops instead). Opt-in: `guard on --ignore-scripts` runs npm/pnpm/yarn/bun installs with their install scripts off, and
`--sandbox` runs them in the `try` sandbox inside your project folder; see the [guide](docs/guide.md#8-check-packages-before-they-install-guard-and-pkg).

### Run code you do not trust

A "take-home assignment" from a recruiter, a repo a stranger sent, an installer: run it in a sandbox first.

```bash
vswarm try ./assignment -- npm install          # or a git URL, a .zip, a single file
vswarm try https://github.com/someone/repo      # no command: a shell opens inside the sandbox
vswarm try ./repo --net registries -- npm ci    # allow package registries only
```

Before running, it reads the code for things built to run on their own: install scripts, VS Code tasks that run when
the folder opens, loaders hidden in `tailwind.config.js` / `next.config.js`, `eval(atob(…))`, raw IPs, references to
wallets and browser password stores. Then it runs the code on a **copy**, under the macOS sandbox:

- no access to your home folder (only your toolchains, read-only), keychain, clipboard, or other apps;
- a fake `HOME` and a clean environment (your tokens are not passed in);
- no network except localhost and a vswarm proxy that records every host it tries (`--net none` by default).

Afterwards it reports what the code **tried**: reading `~/.ssh`, browser passwords or wallets, planting login jobs or
shell lines, contacting outside hosts, leaving processes behind. Verdicts: DANGEROUS, SUSPICIOUS, NOTHING SEEN, or
INCONCLUSIVE when the command failed early.

```
3  what it tried
  HIGH  Tried to read SSH keys            ~/.ssh/id_ed25519 (node)
  HIGH  Tried to read browser passwords   ~/Library/Application Support/Google/Chrome/Default/Login Data (node)
  HIGH  tried to install a login job      ~/Library/LaunchAgents/com.dev.helper.plist
  HIGH  Tried to contact raw IP addresses 203.0.113.9:1224
DANGEROUS · do not run this outside the sandbox; report it (see report.md)
```

`test/fixtures/fake-interview` is a harmless imitation of a fake-interview repo used to test this.

### When something is wrong

```bash
vswarm respond      # 1 lock  2 evidence  3 credential checklist  4 contain  5 report
vswarm unlock       # after the machine is clean (best: reinstalled) and a new baseline is recorded
```

`respond` locks production access, copies the suspicious files with SHA-256 hashes, snapshots processes and
connections, lists every credential to rotate **from another device**, and asks before each change it would make
(unloading a login job, moving a binary to quarantine, removing added shell lines). It writes `report.md` /
`report.json` for your team, and OSV-format drafts for
[OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) and the package registries. Nothing is sent
anywhere; you review and send.

## What it checks

| Area | What | Why |
|---|---|---|
| Homebrew | taps, formulae, casks; third-party taps | tampered formulae from unofficial taps |
| npm / bun globals, Python, Cargo | new packages, install scripts, look-alike names | install-time malware, typosquats |
| Known-malicious | exact versions against [OSV](https://osv.dev) `MAL-` records | packages already reported |
| Login jobs | LaunchAgents / LaunchDaemons, crontab | persistence |
| Startup files | `.zshrc`, `.bashrc`, `.profile`, `.gitconfig`, `~/.ssh/config`, `authorized_keys`, `/etc/hosts` | persistence, backdoors, redirection |
| Executables | new programs on PATH and their code signature | dropped binaries |
| Right now | programs running from temp/cache/hidden folders; who they talk to | active implants |
| Credentials | SSH keys without a passphrase, AWS `AKIA` keys, static kube tokens, plain docker/gh/npm/pypi tokens, `.env` files | what a thief would take |
| Editors, browsers | VS Code / Cursor extensions; Chrome / Brave / Edge / Arc extensions and their permissions | extension malware |

## Measured, not claimed

`vswarm selftest` builds a fake home, records a clean baseline, plants harmless stand-ins for real attack steps,
and prints what was caught:

```
detected 11/11 (100%) · false alarms on the clean parts: 0
```

That number covers the cases in [`src/sec/selftest.ts`](src/sec/selftest.ts), not every attack. Adding a case for
a technique you have seen is the most useful contribution you can make.

## Updates: signing is built, not switched on yet

The signature check is in the code and enforced as soon as there is a key to check against, but **no release key has
been published yet**: [`trust/allowed_signers`](trust/allowed_signers) lists none and the existing tags are unsigned.
So today the installer installs `main` as it is, and `vswarm update` follows `main` with `git pull`; both say so.
That is as safe as the GitHub account behind this repository, no more.

Once the maintainer publishes a key and signs a release, the installer checks the newest tag's signature,
`vswarm install` pins the key, and `vswarm update` from then on moves only to tags signed by a pinned key, never to an
older version: a takeover of the repository or of the maintainer's account cannot ship code to installed copies
without the signing key. `vswarm trust` shows what is pinned; [SECURITY.md](SECURITY.md) has the steps and, once there
is one, the fingerprint.

The installer itself does not pipe a script from the network into a shell for Bun: it uses the Bun on your PATH, or
downloads one pinned Bun release from GitHub and installs it only if its SHA-256 matches the value in the script.

## How it relates to other tools

| | vswarm | also look at |
| --- | --- | --- |
| scan a developer machine (packages, extensions, MCP, AI agents) | local, no account | StepSecurity Dev Machine Guard (reports to its platform) |
| check installs before scripts run | names, whole dependency tree, brand-new versions; hands off to `sfw` | Socket Firewall (`sfw`) |
| MCP tool poisoning and rug pulls | servers started **in a sandbox**, tools read and pinned | mcp-scan (Snyk) |
| gate production access on the machine's state | ssh, AWS, kubectl from the local verdict; short-lived SSH certificates | 1Password Device Trust (Kolide), Teleport Device Trust |
| run an untrusted repo and see what it tries | Seatbelt / bubblewrap with a behaviour report | a disposable VM |
| persistence and binaries | baseline diff, signatures, background watch | osquery, Objective-See BlockBlock, Santa |

vswarm puts these in one local tool for people and small teams without an endpoint platform, and uses the others
when they are there (`sfw`). Enforcement on the server side (device trust in your identity provider, Teleport) is
stronger than any check on the laptop; short-lived certificates and signed reports (`vswarm report --json --sign`)
are vswarm's steps in that direction, see [docs/server-side.md](docs/server-side.md).

## Privacy

- Everything stays on your machine, under `~/.vswarm/sec` with owner-only permissions. No telemetry.
- One network call: package **names and versions** to `api.osv.dev` for the known-malicious check, cached for a day.
  `--offline` skips it; the quiet gate (`preflight --quiet`) asks only about package versions it has never seen,
  waits at most 3 seconds, and says so when it could not.
- With `vswarm guard on`, the names you install also go to the registry they come from (registry.npmjs.org,
  api.npmjs.org, api.deps.dev, pypi.org): the same names your package manager is about to send anyway.
- Credential checks report where and what kind, never the value.

## Linux

The same commands, with Linux's own places to hide:

| | macOS | Linux |
| --- | --- | --- |
| login jobs | LaunchAgents / LaunchDaemons | systemd units (user and system), XDG autostart |
| system-wide hooks | | `/etc/ld.so.preload` |
| running programs | `ps`, `lsof` | `/proc`, `ss` |
| `vswarm try` walls | Seatbelt (`sandbox-exec`) | bubblewrap: every home hidden, system read-only, `/run` hidden (Docker, D-Bus, keyring and agent sockets), own network and pid namespace |
| `vswarm try` record | the sandbox's deny log | strace: every path it tried and every address it tried to connect to |
| code signatures | `codesign` | not checked; new programs on PATH are reported as unverified |

Things that differ: on Linux the code's background processes end with the sandbox (reported as "detaches from the
terminal"); a hidden home is an empty writable folder, so writes there are recorded and thrown away. Ubuntu 24.04
limits user namespaces: `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`, or give bwrap an AppArmor
profile. Inside Docker, run the container with `--security-opt seccomp=unconfined --security-opt apparmor=unconfined`.

## Limits

- **Malware already running as you can disable vswarm.** It can remove the ssh gate from `~/.ssh/config`, stop the
  watch, or run `vswarm unlock --force` itself. vswarm seals its own files (verdict, lock, baseline, accepted
  findings, an incident log) with a key kept in the Keychain / Secret Service / DPAPI, so a hand-edited "pass" or a
  deleted lock is noticed, but a program running as you can read that key too. What vswarm does well is catch what
  such malware leaves behind before you reach production, and pause the risky moments that let it in; the decision
  that cannot be bypassed from the laptop belongs on the server ([docs/server-side.md](docs/server-side.md)).
- It cannot see malware that hides well (rootkits, firmware) or code that ran once and left nothing behind.
- If a credential was already stolen and is used from the attacker's machine, nothing here sees it. What stops that
  is on the server side: short-lived credentials, hardware keys, device posture checks.
- On macOS, browser extensions need **Full Disk Access** for your terminal; without it vswarm says it could not
  check them instead of looking clean.
- A baseline taken on a machine that is already compromised treats the compromise as normal.

## Development

```bash
bun test            # unit + end-to-end tests (sandbox homes)
bunx tsc --noEmit
bun src/cli.ts selftest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Licensed under Apache-2.0.
