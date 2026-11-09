# Changelog

vswarm is in beta. Versions follow the order of releases; every release from 2.6.0 on is a git tag signed by a key in
[`trust/allowed_signers`](trust/allowed_signers). Full notes for each release are on the
[releases page](https://github.com/kridsadar357/vswarm/releases).

## 2.9.1 (not released yet)

Fixes from an independent review before telling more people to install it.

- **vswarm gone, nobody locked out by the wrong reason.** When `~/.vswarm` was deleted or Bun moved, ssh to a gated
  host said "this machine did not pass preflight", and every `npm install` failed with "no such file". Now:
  - the ssh refusal says "vswarm itself cannot run", with what to do;
  - the install guard lets installs go ahead with a warning that they were not checked;
  - the launcher says which of Bun or vswarm moved, and `vswarm doctor` checks that the launcher runs;
  - blocks written by earlier versions get the new refusal line the first time the new version runs.
- **`try` proxy:** large downloads (npm tarballs) could arrive cut short when the sandboxed side read slowly, and a
  plain-HTTP POST lost its body. Both directions now finish partial writes.
- **`try` on macOS:** code in the sandbox can no longer list other programs' files in `/tmp` and `/var/tmp`.
- **`respond`** stops a process only if it still runs the program the check found (the number may have been reused).
- **Releases** are tagged only after CI passed for that exact commit and the type check, tests and selftest pass
  locally; every release has an entry here.
- **README:** marked beta; Windows marked preview; what "false alarms 0" measures; how to remove vswarm safely.
- **Code:** one reader for vswarm's ssh blocks instead of five copies.

## 2.9.0 (2026-11-09)

- `vswarm agent` on Windows: a named pipe with a random name, a Task Scheduler task at logon, the ssh-config block in
  Windows OpenSSH's form, a Yes/No box for confirm-on-use.
- `vswarm try` on Windows, in an AppContainer: no access to your profile, no network unless through vswarm's proxy
  (after a one-time administrator approval), a job object that stops what the code leaves running.

## 2.8.1 (2026-11-09)

- macOS: `vswarm agent on` waits for the old agent to stop before starting the new one, and says when it did not start.

## 2.8.0 (2026-11-09)

- **New release key** (the first key's passphrase was lost; the key never left the maintainer's machine). Copies on
  2.7.x re-pin once, see [SECURITY.md](SECURITY.md#signed-releases).
- `vswarm setup`, `vswarm ui`, `vswarm report --html`, Thai (`vswarm lang`), plain-language output with numbered
  findings and one command each.

## 2.7.1 (2026-11-07)

- Real-time watch on Linux no longer misses two writes in one clock tick; unsafe package sources warn before a baseline.

## 2.7.0 (2026-11-07)

- `vswarm agent`: the ssh gate moves onto the key. The install guard reads packages before they install. Real-time
  watch on macOS and Linux. Gates for AWS, Kubernetes, gcloud and az.

## 2.6.0 (2026-11-07)

- First signed release: installs and updates check the tag's signature; installers pin a Bun release by SHA-256.
- vswarm's own state is sealed with a key in the Keychain, Secret Service or DPAPI.

## 2.5.0 and earlier (2026-11-06, unsigned)

- 2.5.0: MCP servers inspected in a sandbox with tool pinning, dependency trees checked before install, `vswarm watch`.
- 2.2.0: the install guard. 2.1.0: certificates and canaries. 2.0: "check your own machine before it touches
  production". 1.x was a terminal board for AI coding agents.
