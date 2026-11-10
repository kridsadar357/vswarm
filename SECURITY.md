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

**Status:** every release is signed, starting with v0.1.0, the first public beta.
[`trust/allowed_signers`](trust/allowed_signers) lists the release key.

Before v0.1.0, development builds were tagged v2.1.0 to v2.9.0. Those tags and their release pages were removed when
numbering restarted at 0.1.0. A copy still on a 2.x build refuses 0.1.0, because updates never go to a lower version.
Run the install command in the README once more, over it; it moves the copy to 0.1.0 and keeps your gates, keys and
settings. Do not uninstall first.

**What is checked:** releases are git tags signed with the maintainer's SSH key. The
installer checks the newest tag's signature against the key that tag lists before installing it, and `vswarm install`
pins that key on your machine (`~/.vswarm/trust/allowed_signers`). From then on `vswarm update` moves only to tags
signed by a pinned key and never to an older version; tags that do not verify are skipped and named. A takeover of the
repository or of the maintainer's GitHub account cannot then ship code to installed copies without the signing key.

Check the pinned key with `vswarm trust` and compare it with the fingerprint published here and on the release page:

```
release key: SHA256:icVOFCVDfJzfuqeKqZRicZ5TtRp0jZ4g5qfuA9PUe2g (ED25519), principal kridsadar357@gmail.com
```

**Earlier key, retired 9 November 2026:** the first release key
(`SHA256:9WDeb6hMDIq0ry94Hs8t+qW4EegPT0uRkQ0v0w4jpng`, which signed development builds 2.6.0 to 2.7.1) was retired
because its passphrase was lost. It never left the maintainer's machine and was not compromised. Nothing from v0.1.0
on is signed by it.

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
   refuse anything else. If the old key is lost, sign with the new one and publish the re-pin steps, as above.

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
  signs on a verdict at most 30 seconds old. BLOCK is always refused; WARN follows **one policy shared with every
  gate** (`vswarm policy`, allow by default, kept sealed; a policy file edited by hand counts as refuse), unless the
  key has a setting of its own (`agent policy --allow-warn | --strict`; keys from 2.7 and older keep the one they
  were protected with). `agent protect` removes a key file only after a login to one of its hosts succeeded with it,
  and the agent's ssh block ends a refused login in "Permission denied" rather than a password prompt. It does
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
  scripts run only when you opt in, and then only in the `try` sandbox. Where the sandbox was promised
  (`guard on --sandbox`) and is not available, the install stops instead of running outside it; a suspicious package
  installs only on an explicit yes at a terminal.
- **Keeps `try` inside its walls.** On Linux the sandbox runs only with a `/proc` of its own pid namespace (without
  one, it refuses to run: the host's `/proc` would expose other processes' `/proc/<pid>/root`). The proxy, even with
  `--net all`, resolves a name first and refuses loopback (unless `--localhost`), link-local and cloud metadata
  addresses, connecting only to the address it checked.
- **Is not the enforcement point** for production. The decision that cannot be bypassed from the laptop belongs on
  the server: short-lived certificates, a bastion or SSH CA that asks for a fresh signed report, device trust in your
  identity provider. See [docs/server-side.md](docs/server-side.md).

## The local dashboard (vswarm ui)

`vswarm ui` serves a page on this machine. What keeps other people and other web pages out of it:

- **This machine only.** It binds `127.0.0.1` on a random free port; there is no option for another address and no
  remote mode. It never listens on `::1`, `0.0.0.0` or a LAN address.
- **A key per run.** Each run makes a random 256-bit key, kept in memory only (never on disk). The browser gets it in
  the URL fragment (`#t=…`), which browsers do not send to servers and servers do not log; the page sends it back as
  `Authorization: Bearer …` on every API request. No cookies. The link is printed in the terminal too: treat it like a
  password for the next 30 minutes.
- **Every request is checked**: the `Host` header must be exactly `127.0.0.1:<port>` (DNS rebinding), and an
  `Origin` or `Sec-Fetch-Site` header, when sent, must be same-origin (CSRF). No CORS headers are ever sent, so a page
  on another site can neither read an answer nor send the `Authorization` header. Everything about the machine is
  under `/api` and needs the key; the static files (page, script, style, language files) are the same for everyone
  and hold no machine data.
- **Nothing changes on a GET.** The three actions (run a check, accept one finding, the language) are POSTs with the
  key and a JSON body. Accepting refuses known-malicious packages, vswarm's own files, team requirements and critical
  findings, and takes only findings from the sealed last check, by a reference that means nothing outside this run.
  Every action is echoed in the terminal. Unprotect, restore, `unlock --force`, respond, policies, gates and uninstall
  are never offered.
- **Headers**: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'
  data:; connect-src 'self'; frame-ancestors 'none'` (no inline script or style), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Frame-Options: DENY`.
- **Output**: finding details are masked already; every string is masked again before it leaves (tokens, URL
  passwords, `--token`-style values, long hex/base64) and the home folder is shown as `~`. The page puts data in with
  `textContent` only, never as HTML.
- **Lifetime**: it stops after 30 minutes without use (the page's own refresh does not count), and on Ctrl+C.
- **`vswarm report --html`** writes a file with no server: its own CSP lets only its exact script and style run (by
  hash) and nothing load; the embedded data is escaped so it cannot close its `<script>` element.

What it does not stop: another program running as you can read the link from your terminal or browser, and use the
page as you would. That is the same-user limit described above; the page offers nothing that the `vswarm` command
does not.

## vswarm setup and the language setting

`vswarm setup` is a guide over the commands that already exist, and has no power of its own: each step calls the
same code as `baseline`, `ok`, `fix`, `watch on`, `guard on`, `agents --inspect`, `gate ssh`, `agent protect` and
`policy`, with the same checks.

- **Asks before every change**, and every question can be answered no. Without a terminal to ask on, it prints the
  plan and changes nothing. `--yes` takes the recommended answers but never decides which hosts are production and
  never moves a key: those need a person.
- **The baseline refusal stands**: over HIGH or CRIT findings nobody marked as theirs, setup does not record the
  starting point, exactly as `vswarm baseline` without `--accept-high` refuses.
- **No passphrase passes through vswarm.** A key with a passphrase is unlocked by ssh's own prompts (`agent protect`'s
  test logins, `ssh-copy-id`, `ssh-keygen -p`); vswarm neither asks for nor stores one. Keys move only through
  `agent protect`, which logs in with the key first and removes the file only after a server accepted it; the recovery
  code is shown once, and setup says to keep it in a password manager.
- **The language** (`vswarm lang`, the dashboard's switch, `ui.json` beside vswarm's state) changes words only, so it
  is not sealed. Verdicts, `--json`, exit codes, logs and every sealed file are the same in any language, and what a
  gate or the agent decides never depends on it.

## In scope

- Ways to make `vswarm preflight` pass on a machine that should be blocked (bypasses of a rule or of the lock), short
  of reading the sealing key the way vswarm itself does.
- Ways to get a signature from `vswarm agent` with a protected key while the machine is blocked or locked, or on a
  WARN that the policy (or the key's own setting) refuses, or to read a protected key from its vault or backup, short
  of reading the wrapping key or the agent's memory.
- Ways to make a gate let a WARN through that `vswarm policy` refuses.
- Code run by `vswarm try` that reaches this machine's loopback services, link-local or cloud metadata addresses
  through the proxy (without `--localhost`), or reads another process's files through `/proc`.
- Ways to make `vswarm update` or the installer accept a release that is not signed by a pinned key, or an older one.
- Ways to make vswarm run code, change files, or send data it should not (it should only send package names and
  versions to api.osv.dev and the registries, and download package archives from the registries).
- Archives that the package reader reads differently from npm (node-tar) or pip (tarfile, zipfile) without calling
  them damaged: a file the installer would write that vswarm does not see, or sees with other contents.
- Archives that make the package reader write outside its folder, run anything, or exhaust memory or time past its
  limits.
- Credential values ending up in output, reports, or files under `~/.vswarm`.
- Ways for a web page, another user on the machine or the network to read from or act through `vswarm ui`
  without the link of that run.
- Weaknesses in `vswarm respond` that could destroy evidence or damage the machine beyond what the user approved.

## Not a vulnerability

- An attack technique vswarm does not detect yet. Please open an issue or, better, a pull request that adds it to
  `src/sec/selftest-cases.ts`, with a benign look-alike next to it and a rule that catches the one and not the other.
- Malware that already has root, or hides below the operating system. vswarm says so in its README.
- A program running as you that reads the sealing key, stops the watch, edits `~/.ssh/config` or runs
  `vswarm unlock --force`: same-user code can do what you can (see above).
