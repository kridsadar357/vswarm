# Contributing

The most useful contribution is a **new detection**: a technique you have seen used against developers, turned into a
selftest case and a rule that catches it.

## Add a detection

1. In [`src/sec/selftest-cases.ts`](src/sec/selftest-cases.ts), add a case to `CASES`:
   - `plant` writes a harmless stand-in into the fake home (never real malware, never something that runs),
   - `like` says which real attack it imitates (link a public write-up in the PR), `technique` its ATT&CK id,
   - `expect` names the finding that must appear, `min` the least severity it must have.
2. Add the benign look-alike next to it in `BENIGN`: the same place used the ordinary way, either on the clean
   machine (`when: "clean"`, must raise nothing at medium or above) or as an edit after the baseline
   (`when: "change"`, may raise at most `max`).
3. Run `bun src/cli.ts selftest`. It should now miss your case.
4. Make it pass: a collector in `src/sec/collect/` if vswarm does not look at that place yet, then a rule in
   `src/sec/rules.ts` (or `src/sec/secrets.ts` for credentials).
5. `bun test` must stay green, including **zero false alarms** on the benign cases. A change to the look-alike check
   (`src/sec/intel.ts`) is measured on real names too: `bun scripts/bench-names.ts` (a one-time 260 MB download).

## Rules of the house

- **No new runtime dependencies.** vswarm guards the path to production; every dependency is supply-chain surface.
- **Read-only by default.** Only `respond` changes the machine, and only after asking, one step at a time.
- **No values.** Credential checks report where and what kind, never the secret itself, not even in tests' output.
- **Say when you could not look.** A collector that cannot read a place reports a gap (`ctx.gap`) instead of
  returning nothing.
- **Local first.** Network calls need a reason in the README's Privacy section and an `--offline` path.

## Run it

```bash
bun install
bun test
bunx tsc --noEmit
bun src/cli.ts scan --all
```

## Releasing (maintainers)

1. Bump `version` in `package.json` and `src/home.ts`, commit, push `main`, wait for CI.
2. `scripts/release.sh vX.Y.Z notes.md` signs the tag with `~/.ssh/vswarm_release` (or `VSWARM_SIGNING_KEY`),
   verifies it against `trust/allowed_signers`, pushes it and creates the GitHub release.

The signing key never leaves the maintainer's machine; use a passphrase or a hardware key (`ssh-keygen -t ed25519-sk`).
Adding or replacing a key is a change to `trust/allowed_signers` in a release signed by a key users already trust.
See [SECURITY.md](SECURITY.md#for-the-maintainer-releasing) for the key in use and what to do if it is lost.

If you move the installers to another Bun release, change `BUN_VERSION` and every hash in `install.sh` and
`$BunVersion` / `$BunSha256` in `install.ps1`, copied from that release's `SHASUMS256.txt`; `bun test` checks that
both scripts pin the same version and a hash for every platform.
