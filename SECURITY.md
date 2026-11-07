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

- **Finds** what such malware typically leaves behind (login jobs, shell lines, packages, MCP servers, binaries,
  connections) on the next scan, before you use the machine for production, and refuses to hand out access when it
  sees it.
- **Seals its own state.** The last verdict, the lock, the baseline and the accepted findings carry an HMAC whose key
  is kept outside `~/.vswarm` (macOS Keychain, the Linux Secret Service when there is one, Windows DPAPI). A file
  edited or forged by hand is not trusted: a cached verdict without a valid seal is never reused, a lock with a bad
  seal still blocks, and an append-only incident log with chained seals keeps an incident open even when the lock
  file is deleted. This catches naive tampering and generic "set verdict to pass" tricks. It does **not** stop
  malware that reads the key the way vswarm does: any program running as you can.
- **Moves the ssh check onto the key** with `vswarm agent`. A protected key exists only in the agent's vault
  (encrypted, its wrapping key in the same store as the sealing key), and the agent signs only while the machine
  passes, whatever client or route asks: `ssh -F /dev/null`, an IP address, a GUI client, paramiko, or a deleted
  config block get no signature from a blocked machine, and a copy of `~/.ssh` no longer holds the key. It does
  **not** stop malware running as you from asking the agent to sign while the machine passes, reading the agent's
  memory, or reading the wrapping key the way vswarm does. Hardware keys (`-sk`) and short-lived certificates are
  stronger, and combine with it.
- **Gates gcloud's credential, and only reminds for the rest.** `vswarm gate gcloud` puts preflight in front of a
  workload-identity credential's token command, so any program using that configuration gets no new token from a
  blocked machine (a token gcloud already cached stays valid until it expires, about an hour). `vswarm gate cmd` and
  `vswarm gate az` are shell functions: `command <tool>`, a script or another program skips them. A bypass of those
  wrappers is not a vulnerability; a way to make the gcloud hook hand out a token while the machine is blocked is.
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
  versions to api.osv.dev).
- Credential values ending up in output, reports, or files under `~/.vswarm`.
- Weaknesses in `vswarm respond` that could destroy evidence or damage the machine beyond what the user approved.

## Not a vulnerability

- An attack technique vswarm does not detect yet. Please open an issue or, better, a pull request that adds it to
  `src/sec/selftest.ts` with a rule that catches it.
- Malware that already has root, or hides below the operating system. vswarm says so in its README.
- A program running as you that reads the sealing key, stops the watch, edits `~/.ssh/config` or runs
  `vswarm unlock --force`: same-user code can do what you can (see above).
