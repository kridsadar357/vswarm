# Security policy

vswarm keeps a developer from becoming the way in: it pauses the risky moments (installing a package, running a
stranger's code, adding an MCP server, reaching production) and checks the machine before credentials leave it. It is
a local tool, not an EDR and not a hard access control; the section
[What vswarm can and cannot protect against](#what-vswarm-can-and-cannot-protect-against) draws the line. People rely
on it at those moments, so a weakness in it matters. Thank you for reporting one.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
[Report a vulnerability](https://github.com/kridsadar357/vswarm/security/advisories/new).

Include what an attacker could do, the steps to reproduce, and the version (`vswarm --version`).
You will get an answer within 7 days. Fixes are released before details are published, and reporters are credited
unless they prefer not to be.

## Signed releases

**Status:** releases are signed from v2.6.0 on. [`trust/allowed_signers`](trust/allowed_signers) lists the release
key. The older tags (v2.1.0, v2.2.0) are unsigned; the installer and `vswarm update` skip them and name them. A copy
installed before v2.6.0 followed `main` without a check; `vswarm update` takes it to the newest signed release and
pins the key from then on.

**What is checked:** releases are git tags signed with the maintainer's SSH key. The
installer checks the newest tag's signature against the key that tag lists before installing it, and `vswarm install`
pins that key on your machine (`~/.vswarm/trust/allowed_signers`). From then on `vswarm update` moves only to tags
signed by a pinned key and never to an older version; tags that do not verify are skipped and named. A takeover of the
repository or of the maintainer's GitHub account cannot then ship code to installed copies without the signing key.

Check the pinned key with `vswarm trust` and compare it with the fingerprint published here and on the release page:

```
release key: SHA256:9WDeb6hMDIq0ry94Hs8t+qW4EegPT0uRkQ0v0w4jpng (ED25519), principal kridsadar357@gmail.com
```

Trust on first use is the weak point: an attacker in control of the repository before your first signed install
could list their own key. Compare the fingerprint through a second channel if that matters to you.

The installers do not run a script from the network for Bun: they use the Bun on your PATH, or download one pinned
Bun release from GitHub and unpack it only when its SHA-256 matches the value written in `install.sh` /
`install.ps1` (taken from that release's `SHASUMS256.txt`).

### For the maintainer: releasing

1. Make the key on your own machine, with a passphrase or on a hardware key; it never goes anywhere else:
   `ssh-keygen -t ed25519 -f ~/.ssh/vswarm_release` (or `-t ed25519-sk` for a FIDO key).
2. Add its public half to `trust/allowed_signers`, one line:
   `kridsadar357@gmail.com namespaces="git" ssh-ed25519 AAAA…`, and commit that with the version bump.
3. Put the fingerprint (`ssh-keygen -lf ~/.ssh/vswarm_release.pub`) in the block above, in the same commit.
4. `scripts/release.sh vX.Y.Z notes.md` signs the tag, verifies it against `trust/allowed_signers`, pushes it and
   creates the GitHub release; paste the fingerprint into the release notes as well.
5. From that release on, installs and updates are signature-checked. Replacing the key later is a change to
   `trust/allowed_signers` in a release signed by the old key; users who pinned the old key see `vswarm update`
   refuse anything else.

## What vswarm can and cannot protect against

vswarm runs as you, on the machine it checks. Malware that already runs as your user can do anything you can: stop
the background watch, remove the ssh gate from `~/.ssh/config`, edit or delete the files under `~/.vswarm`, read the
key vswarm uses to seal them, or simply run `vswarm unlock --force`. vswarm cannot stop that, and does not claim to.
What it does:

- **Finds** what such malware typically leaves behind (login jobs, shell lines, package manager and tool configs,
  packages, MCP servers, binaries, connections) on the next scan, before you use the machine for production, and
  refuses to hand out access when it sees it. With `vswarm watch on`, a write to one of those places on macOS or Linux
  is checked within seconds, not at the next hourly run; malware running as you can still remove the watch first.
  How much the scans and the install guard catch is measured, per technique, by `vswarm selftest` and
  `scripts/bench-names.ts`, on our own planted cases and on OSV's malicious-package names; the numbers and what they
  leave out are in [the guide](docs/guide.md#13-measure-detection-selftest).
- **Seals its own state.** The last verdict, the lock, the baseline and the accepted findings carry an HMAC whose key
  is kept outside `~/.vswarm` (macOS Keychain, the Linux Secret Service when there is one, Windows DPAPI). A file
  edited or forged by hand is not trusted: a cached verdict without a valid seal is never reused, a lock with a bad
  seal still blocks, and, while the key store answers, an append-only incident log with chained seals keeps an
  incident open when the lock file is deleted. While the key store does not answer nothing can be verified, so vswarm
  fails closed: an incident the log ever opened counts as open (a forged "unlock" line cannot close it), and nothing
  is written to a log without its seal, so the agent refuses to sign and `unlock` refuses to unlock until the store
  answers. `keystore.json` (where the key is) is checked against the system store: switched to a plain file while
  the system store still holds vswarm's key, it is a finding. The key reaches the Keychain on `security`'s standard
  input, not its command line. This catches naive tampering and generic "set verdict to pass" tricks. It does
  **not** stop malware that reads the key the way vswarm does: any program running as you can.
- **Moves the ssh check onto the key** with `vswarm agent`. A protected key exists only in the agent's vault
  (encrypted, its wrapping key in the same store as the sealing key), and the agent signs only while the machine
  passes, whatever client or route asks: `ssh -F /dev/null`, an IP address, a GUI client, paramiko, or a deleted
  config block get no signature from a blocked machine, and a copy of `~/.ssh` no longer holds the key. Every
  signature is sealed and chained in its audit log: one whose line cannot be sealed is not made. A protected key
  signs on a verdict at most 30 seconds old, and on PASS only unless protected with `--allow-warn`. It does
  **not** stop malware running as you from asking the agent to sign while the machine passes, reading the agent's
  memory, or reading the wrapping key the way vswarm does. Hardware keys (`-sk`) and short-lived certificates are
  stronger, and combine with it.
- **Gates aws, kubectl and gcloud credentials, and only reminds for the rest.** `vswarm gate aws` (an SSO or
  `credential_process` profile), `vswarm gate kube` (an exec-plugin user) and `vswarm gate gcloud` (a
  workload-identity credential) put preflight in front of the command that produces the credential, so any program
  using that profile, context or configuration gets no new credential from a blocked machine (one already handed out,
  or cached by the tool, stays valid until it expires). Static AWS keys, kube tokens and client certificates cannot
  be gated and are refused. `vswarm gate cmd` and `vswarm gate az` are shell functions: `command <tool>`, a script or
  another program skips them. A bypass of those wrappers is not a vulnerability; a way to make the aws, kubectl or
  gcloud hook hand out a credential while the machine is blocked is.
- **Reads packages before they install.** The install guard downloads the archive a package manager would install,
  checks it against the registry's checksum, and reads it without running it (its own unpacker, with size, file-count,
  path and time limits). It looks for install-time code that decodes and runs hidden code, reads credentials, reaches
  the network or persists, and for what is new since the release before (an account-takeover release). This is
  pattern reading: well-hidden code can get past it, and a package that only misbehaves later is not seen. Install
  scripts run only when you opt in, and then only in the `try` sandbox.
- **Is not the enforcement point** for production. The decision that cannot be bypassed from the laptop belongs on
  the server: short-lived certificates, a bastion or SSH CA that asks for a fresh signed report, device trust in your
  identity provider. See [docs/server-side.md](docs/server-side.md).

## In scope

- Ways to make `vswarm preflight` pass on a machine that should be blocked (bypasses of a rule or of the lock), short
  of reading the sealing key the way vswarm itself does.
- Ways to get a signature from `vswarm agent` with a protected key while the machine is blocked or locked, or to
  read a protected key from its vault or backup, short of reading the wrapping key or the agent's memory.
- Ways to make `vswarm update` or the installer accept a release that is not signed by a pinned key, or an older one.
- Ways to make vswarm run code, change files, or send data it should not (it should only send package names and
  versions to api.osv.dev and the registries, and download package archives from the registries).
- Archives that the package reader reads differently from npm (node-tar) or pip (tarfile, zipfile) without calling
  them damaged: a file the installer would write that vswarm does not see, or sees with other contents.
- Archives that make the package reader write outside its folder, run anything, or exhaust memory or time past its
  limits.
- Credential values ending up in output, reports, or files under `~/.vswarm`.
- Weaknesses in `vswarm respond` that could destroy evidence or damage the machine beyond what the user approved.

## Not a vulnerability

- An attack technique vswarm does not detect yet. Please open an issue or, better, a pull request that adds it to
  `src/sec/selftest-cases.ts`, with a benign look-alike next to it and a rule that catches the one and not the other.
- Malware that already has root, or hides below the operating system. vswarm says so in its README.
- A program running as you that reads the sealing key, stops the watch, edits `~/.ssh/config` or runs
  `vswarm unlock --force`: same-user code can do what you can (see above).
