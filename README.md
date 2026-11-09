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
WMI, PowerShell profiles, …) with watch, the ssh gate, the install guard and the ssh agent, installed with
`install.ps1`; `try` runs in an AppContainer there, where Node projects with install scripts are better tried in WSL,
see [Windows (preview)](docs/guide.md#windows-preview).

```bash
curl -fsSL https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.sh | sh
# or
git clone https://github.com/kridsadar357/vswarm.git && cd vswarm && ./vswarm install
```

Then one step, in a new terminal:

```bash
vswarm setup
```

It says what it will do, checks the machine and explains each finding in one sentence (fix it, or say it is yours),
records the starting point (baseline), offers the background watch, the install guard and an inspection of AI tool
servers, asks which hosts in `~/.ssh/config` are production and puts a door (gate) in front of them, offers to move
their keys into the key safe (`agent protect`, which tries each key on its server first), and asks the one policy
question in plain words. Every step can be skipped; run it again and it offers only what is missing. `--yes` takes
the recommended answers (it never picks production hosts or moves keys); without a terminal it prints the plan and
changes nothing. On macOS, turning the watch on makes macOS show *Background Items Added: vswarm*: that is expected.

![vswarm setup](docs/img/setup.png)

## Use

```bash
vswarm scan                 # the state in one line (Safe, Check this or Stop), then numbered findings with one command each
vswarm why [n]              # each finding: why it matters, every way out (fix, or mark it as yours), the details, the policy
vswarm fix 2 · vswarm ok 3  # fix finding 2 (shows what, asks first) · mark finding 3 as yours
vswarm baseline             # on a machine you trust: "this is clean" (refused over HIGH/CRIT findings unless --accept-high)
vswarm diff                 # later: what changed since then
vswarm secrets              # long-lived credentials (never prints values)
vswarm selftest             # plant fake threats in a sandbox home, measure detection
vswarm watch on             # check hourly, and within seconds when a login job, rc or agent config changes
vswarm lang th              # Thai in the terminal and the dashboard (th, en or auto; VSWARM_LANG=… for one run)
```

Every report speaks one vocabulary: **● Safe**, **● Check this** or **● Stop** with a plain sentence first ("Nothing
dangerous, 1 thing worth a look"), then the findings grouped as *Needs action*, *Worth a look* and *FYI*, each with a
plain title, why it matters, one command to run, and vswarm's technical title dimmed under it (`--details` for the
rest). The PASS / WARN / BLOCK tag stays beside the state, and `--json` and exit codes are unchanged, so scripts keep
working. Colour marks the state and the action only; `NO_COLOR` loses nothing, lines wrap at the terminal's width.

![vswarm scan](docs/img/scan.png)

### The dashboard: vswarm ui

```bash
vswarm ui                   # a local page in plain words, Thai or English; Ctrl+C to stop
vswarm report --html        # the same view as one HTML file to share, credentials masked
```

One big answer (**Safe**, **Check this** or **Stop**) with the reason, the findings as cards that say why each
matters and what to do ("Needs action", "Fine if it's yours", "For your information"), recent events (checks, the
watch, key use by `vswarm agent`, incidents) and a tile per protection. It is made for someone who does not read
security output. From the page you can run a check and mark a finding as yours; everything else (respond, unlock,
gates, keys, uninstall) stays in the terminal and the page shows the command to copy. It listens on 127.0.0.1 only,
with a one-time key in the link; see [SECURITY.md](SECURITY.md#the-local-dashboard-vswarm-ui).

![vswarm ui in Thai: Check this, four cards, protection tiles and recent events](docs/img/ui-th-light.png)

<sub>A fake demo machine. English and dark mode: [light](docs/img/ui-en-light.png) · [dark](docs/img/ui-en-dark.png) · [Thai dark](docs/img/ui-th-dark.png) · [narrow screen](docs/img/ui-th-phone.png).</sub>

### Gate production access

```bash
vswarm gate ssh "prod-*" "*.wallet.internal"     # adds a Match block to ~/.ssh/config (backup kept)
vswarm agent protect ~/.ssh/prod_key             # tries the key on its hosts, then moves it into an ssh agent that signs only while the machine passes
vswarm gate aws prod-sso prod-admin               # the profile's credential_process runs preflight first (backup kept)
vswarm gate kube prod                             # the context's exec plugin runs preflight first (backup kept)
```

`gate aws` handles SSO profiles, profiles with a `credential_process`, and roles (`role_arn` + `source_profile`, gated
at their source); `gate kube` handles users with an exec plugin (`aws eks get-token`, `gke-gcloud-auth-plugin`,
kubelogin), in whichever `KUBECONFIG` file defines them. Static AWS keys, static kube tokens and client certificates
are refused, because those are sent without running anything. `--off` puts the files back as they were (backups live
in `~/.vswarm/backups` and go with the gate), and `status` notices a later hand edit, static keys added since, and a
look-alike wrapper ([guide](docs/guide.md#aws-and-kubernetes)). Or by hand:

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

`vswarm gate gcloud <configuration>` puts the same check in front of a workload-identity credential's token command;
`vswarm gate cmd psql "*.prod.internal"` (and `gate az "<subscription>"`, or `gate az --all`) is a shell reminder for tools with no credential hook, one
you can bypass with `command psql` ([guide](docs/guide.md#commands-with-no-credential-hook-gate-cmd)).

The config gate is advice to OpenSSH; `vswarm agent` puts the check on the key itself, so `ssh -F /dev/null`, an IP
address or another client gets no signature from a machine that does not pass ([guide](docs/guide.md#vswarm-agent)).
`agent protect` proves the key first: it checks the machine, finds the hosts in `~/.ssh/config` that use the key, logs
in to them with it while the file is still on disk, and removes the file only once a host accepted it. For the hosts
it routes, the agent's block runs the same decision before each login, so a refusal is said on the terminal with the
way out, and ends in `Permission denied`, never a password prompt (`agent on --allow-passwords` for hosts that need
one).

**One policy for WARN**, for every gate and the agent: BLOCK is always refused, WARN is let through by default and
refused everywhere with `vswarm policy warn refuse`. `vswarm preflight` exits **0** on PASS and on a WARN the policy
lets through, **2** on a WARN it refuses (or with `--strict`), **3** on BLOCK; `--json` gives the decision as data. A
verdict is reused for two minutes, so gating every `kubectl` call costs about 20 ms. A fresh check takes about 0.2 s.
`vswarm gate status` and `vswarm doctor` also say which gated hosts no longer answer (DNS and the ssh port, 2 s), and
`vswarm gate ssh --prune` drops the ones you confirm.

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
`--sandbox` runs them in the `try` sandbox inside your project folder, through Socket Firewall too when `sfw` is
installed; where there is no sandbox, `--sandbox` is refused and such installs stop rather than run outside one. See
the [guide](docs/guide.md#8-check-packages-before-they-install-guard-and-pkg).
The guard also reads what is inside a package before it installs: install-time code that decodes and runs hidden code,
reads credentials, reaches the network or persists, and what is new since the version before (`vswarm pkg check npm <name>`
reads one without installing).

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

### For a small team

```bash
vswarm team join git@github.com:acme/vswarm-policy.git   # pins the policy's signing keys once you confirm them
vswarm team sync · vswarm team status                     # newer signed policy only · what this machine lacks
vswarm report --json --sign ~/.ssh/device --out ~/reports # a signed report per run, to collect however you like
```

The team policy is a JSON file in a git repository you control, signed with an SSH key: findings accepted for
everyone, the team's own package names, required checks (baseline age, watch, guard) and the hosts the ssh gate
should cover. Unsigned policies, policies signed by another key, a changed list of signers and older policies are
refused. No server, no upload: see [docs/team.md](docs/team.md) and [docs/server-side.md](docs/server-side.md).

## What it checks

| Area | What | Why |
|---|---|---|
| Homebrew | taps, formulae, casks; third-party taps | tampered formulae from unofficial taps |
| npm / bun globals, Python, Cargo | new packages, install scripts, look-alike names | install-time malware, typosquats |
| Known-malicious | exact versions against [OSV](https://osv.dev) `MAL-` records | packages already reported |
| Login jobs | LaunchAgents / LaunchDaemons, login items inside apps, crontab | persistence |
| System extensions | network / endpoint-security system extensions, kernel extensions (macOS) | traffic and file interception |
| Startup files | `.zshrc`, `.bashrc`, `.profile`, fish `conf.d`, `/etc/profile.d`, `environment.d`, `.gitconfig`, `~/.ssh/config`, `authorized_keys`, `/etc/hosts`: added lines that download, preload a library, hook the prompt, wrap sudo, put an odd folder first on PATH, run ssh `LocalCommand` / `Match exec` or git `fsmonitor` | persistence, backdoors, redirection |
| Package manager config | `~/.npmrc`, `pip.conf`, `uv.toml`, `.yarnrc.yml`, cargo config: registries over plain http, bare IPs or look-alike hosts, `script-shell`, runners | every install or build redirected |
| Programs other tools run | kubeconfig exec plugins, AWS `credential_process`, Docker credential helpers and contexts, editor tasks that run when a folder opens, Python `.pth` / `sitecustomize` hooks, global git hooks | code that runs with every CLI call |
| Executables | new programs on PATH and their code signature | dropped binaries |
| Right now | programs running from temp/cache/hidden folders; unsigned or ad-hoc signed programs holding outside connections | active implants |
| Credentials | SSH keys without a passphrase (MED when production hosts use them, LOW otherwise), AWS `AKIA` keys, static kube tokens, plain docker/gh/npm/pypi tokens, Azure, gcloud, Vault and Terraform token files, `.env` files | what a thief would take |
| Editors, browsers | VS Code / Cursor extensions, and ones that did not come from the marketplace; Chrome / Brave / Edge / Arc extensions, their permissions, and side-loaded ones | extension malware |

## Measured, not claimed

`vswarm selftest` builds a fake home, records a clean baseline, plants harmless stand-ins for real attack steps
one at a time (grouped by MITRE ATT&CK technique: LaunchAgents, shell rc, cron and systemd timers, login items,
dylib and LD_PRELOAD hijacks, authorized_keys, ssh and git config, package manager config, kubectl / aws / docker
helpers, editor and browser extensions, MCP configs, Python start-up hooks, Windows Run keys, tasks, services and WMI),
plants benign look-alikes of the same places, and prints what was caught and what raised a false alarm:

```
detected 103/103 (100%) · benign look-alikes quiet 39/39 · false alarms 0
```

Before the rules they led to, the same catalogue measured 55 of 93 (59%), with no false alarms: package manager
config, CLI helpers, Python start-up hooks, editor tasks and several shell-file tricks were not caught at all. Those
numbers cover the cases in [`src/sec/selftest-cases.ts`](src/sec/selftest-cases.ts), which are ours, not every
attack. Adding a case for a technique you have seen is the most useful contribution you can make.

The install guard's name checks, measured on real data with `bun scripts/bench-names.ts` (OSV's `MAL-` records for
npm and PyPI, and download rankings past the 2,000 / 1,000 names the look-alike list holds; 2026-11-07): offline, by
name alone, it stops **8.0% of PyPI's 11,987 malicious names** (18.8% of those reported as typosquats) and **1.9% of
npm's 82,365** (leaving out 140,725 tea.xyz spam packages), with **1.3% and 0.9% false positives** on real packages
ranked 1,001–15,000 and 2,001–17,335. Most malicious packages have names nothing resembles; the guard catches them
with the OSV lookup and the registry's facts (age, downloads, install scripts), which this measurement leaves out on
purpose. See [the guide](docs/guide.md#13-measure-detection-selftest).

## Updates are signed

Releases are git tags signed with the maintainer's SSH key, from v2.6.0 on. The installer checks the newest tag's
signature before installing it, `vswarm install` pins the key, and `vswarm update` from then on moves only to tags
signed by a pinned key, never to an older version: a takeover of the repository or of the maintainer's account cannot
ship code to installed copies without the signing key. `vswarm trust` shows what is pinned; compare it with the
fingerprint in [SECURITY.md](SECURITY.md):

```
SHA256:icVOFCVDfJzfuqeKqZRicZ5TtRp0jZ4g5qfuA9PUe2g
```

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
  api.npmjs.org, api.deps.dev, pypi.org): the same names your package manager is about to send anyway. The archives it
  reads come from registry.npmjs.org and files.pythonhosted.org.
- Credential checks report where and what kind, never the value.
- `vswarm team join` / `sync` run `git clone` / `git fetch` of the team repository you name; `report --json` is written
  locally (to stdout or `--out`) and sent nowhere by vswarm.

## Linux

The same commands, with Linux's own places to hide:

| | macOS | Linux |
| --- | --- | --- |
| login jobs | LaunchAgents / LaunchDaemons | systemd units (user and system), XDG autostart |
| system-wide hooks | | `/etc/ld.so.preload` |
| running programs | `ps`, `lsof` | `/proc`, `ss` |
| `vswarm try` walls | Seatbelt (`sandbox-exec`) | bubblewrap: every home hidden, system read-only, `/run` hidden (Docker, D-Bus, keyring and agent sockets), own network and pid namespace |
| `vswarm try` record | the sandbox's deny log | strace: every path it tried and every address it tried to connect to |
| code signatures | `codesign` | not checked; new programs on PATH are reported as unverified, and loose programs in your home folder holding outside connections are named |

Things that differ: on Linux the code's background processes end with the sandbox (reported as "detaches from the
terminal"); a hidden home is an empty writable folder, so writes there are recorded and thrown away. Ubuntu 24.04
limits user namespaces: `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`, or give bwrap an AppArmor
profile. Inside Docker, run the container with `--security-opt seccomp=unconfined --security-opt apparmor=unconfined
--security-opt systempaths=unconfined`: the sandbox needs a `/proc` of its own and does not run without one. The `try`
proxy never connects to loopback (unless `--localhost`), link-local or cloud metadata addresses, checked on what a name
resolves to.

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
