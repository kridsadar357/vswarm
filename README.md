# vswarm

**Check your own machine before it touches production.**

Attackers increasingly go through the people who hold the keys: a tampered Homebrew package, a "coding
assignment" from a fake recruiter, a typo-squatted npm module. The malware runs as you, uses the credentials your
laptop remembers, and the server on the other end only sees a valid token.

vswarm sits in front of that last step. It keeps a record of what your machine looked like when it was clean, tells
you what changed, finds long-lived credentials that would be worth stealing, and refuses to hand out production
access (ssh, AWS, Kubernetes) from a machine that does not pass.

[ภาษาไทย](README.th.md)

```
$ ssh prod-wallet-01
▼ vswarm preflight · 1172 items · 190 ms
  HIGH  New third-party Homebrew tap: aitools-dev/tools
        from https://github.com/aitools-dev/homebrew-tools
        installed from it: ai-coder 1.4.2
  HIGH  Login job com.apple.updater.helper starts a program that runs from a hidden folder (~/.cache)
BLOCK · do not use this machine for production access · vswarm respond
vswarm: this machine did not pass preflight; run: vswarm preflight
```

## Install

macOS first. Linux works for most checks (no code-signature checks). Needs [Bun](https://bun.sh) and git.

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

## Privacy

- Everything stays on your machine, under `~/.vswarm/sec` with owner-only permissions. No telemetry.
- One network call: package **names and versions** to `api.osv.dev` for the known-malicious check, cached for a day.
  `--offline` skips it; the quiet gate (`preflight --quiet`) only uses the cache.
- Credential checks report where and what kind, never the value.

## Limits

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
