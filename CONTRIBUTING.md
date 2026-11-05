# Contributing

The most useful contribution is a **new detection**: a technique you have seen used against developers, turned into a
selftest case and a rule that catches it.

## Add a detection

1. In [`src/sec/selftest.ts`](src/sec/selftest.ts), add a case to `CASES`:
   - `plant` writes a harmless stand-in into the fake home (never real malware, never something that runs),
   - `like` says which real attack it imitates (link a public write-up in the PR),
   - `expect` names the finding that must appear, `min` the least severity it must have.
2. Run `bun src/cli.ts selftest`. It should now miss your case.
3. Make it pass: a collector in `src/sec/collect/` if vswarm does not look at that place yet, then a rule in
   `src/sec/rules.ts` (or `src/sec/secrets.ts` for credentials).
4. `bun test` must stay green, including **zero false alarms** on the clean part of the selftest.

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
