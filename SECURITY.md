# Security policy

vswarm sits in the path to production access, so a weakness in it matters. Thank you for reporting one.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
[Report a vulnerability](https://github.com/kridsadar357/vswarm/security/advisories/new).

Include what an attacker could do, the steps to reproduce, and the version (`vswarm --version`).
You will get an answer within 7 days. Fixes are released before details are published, and reporters are credited
unless they prefer not to be.

## Signed releases

Releases are git tags signed with the maintainer's SSH key; the public key is in
[`trust/allowed_signers`](trust/allowed_signers). The installer checks the newest tag's signature before installing
it and `vswarm install` pins that key on your machine (`~/.vswarm/trust/allowed_signers`). From then on
`vswarm update` moves only to tags signed by a pinned key, and never to an older version. A takeover of the
repository or of the maintainer's GitHub account cannot ship code to installed copies without the signing key.

Check the pinned key with `vswarm trust` and compare it with the fingerprint published here and on the release page:

```
release key: (published with the first signed release)
```

Trust on first use is the weak point: an attacker in control of the repository before your first install could
list their own key. Compare the fingerprint through a second channel if that matters to you.

## In scope

- Ways to make `vswarm preflight` pass on a machine that should be blocked (bypasses of a rule or of the lock).
- Ways to make `vswarm update` or the installer accept a release that is not signed by a pinned key, or an older one.
- Ways to make vswarm run code, change files, or send data it should not (it should only send package names and
  versions to api.osv.dev).
- Credential values ending up in output, reports, or files under `~/.vswarm`.
- Weaknesses in `vswarm respond` that could destroy evidence or damage the machine beyond what the user approved.

## Not a vulnerability

- An attack technique vswarm does not detect yet. Please open an issue or, better, a pull request that adds it to
  `src/sec/selftest.ts` with a rule that catches it.
- Malware that already has root, or hides below the operating system. vswarm says so in its README.
