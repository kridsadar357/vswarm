# Team mode

A small, shared policy for a team that uses vswarm, without a server. The policy is a JSON file in a git repository
the team controls, signed with an SSH key. Each machine pulls it, checks the signature against keys it pinned when it
joined, and applies it.

It does three things, on purpose no more:

- **shared decisions**: finding ids the whole team expects (accepted once, for everyone) and package names that are
  the team's own (never reported as look-alikes);
- **required checks**: what every machine should have (a recent baseline, the background watch, the install guard,
  the ssh gate on certain hosts); a missing one is a WARN in `scan` and `preflight`;
- **gate patterns**: the hosts the ssh gate should cover, so `vswarm gate ssh --team` sets it up the same everywhere.

Collecting reports is separate and also serverless: `vswarm report --json --out <folder>` writes one signed or
unsigned report per run into a folder you collect however you like (a shared drive, a CI artifact, a git repository).
See [server-side.md](server-side.md) for checking them.

## The repository

```
vswarm-team.json        the policy
vswarm-team.json.sig    its SSH signature (namespace vswarm-team)
allowed_signers         who may sign it, one line per key:
                        alice@acme namespaces="vswarm-team" ssh-ed25519 AAAA…
```

```json
{
  "vswarm-team": 1,
  "name": "acme platform",
  "serial": 7,
  "accept": ["secret:env-files", "conn-unsigned:/usr/local/bin/acme-agent"],
  "allow": { "npm": ["@acme/*", "lodash-acme"], "pip": ["acme-*"] },
  "require": { "baseline": true, "baselineMaxDays": 30, "watch": true, "guard": true, "guardIgnoreScripts": false },
  "gate": { "ssh": ["prod-*", "*.acme.internal"] }
}
```

| Field | Meaning |
| --- | --- |
| `serial` | a whole number that goes up with every change. A machine never moves to a lower one, so an old signed policy cannot be replayed to undo a newer one. |
| `accept` | finding ids (as `vswarm scan` prints them), exact or ending in `*`. Known-malicious packages, findings about vswarm's own files and the team's own requirements are never accepted this way. |
| `allow` | package names that are the team's own, exact or ending in `*`; they are never look-alikes, in scans and in the install guard. |
| `require` | `baseline` (one exists), `baselineMaxDays`, `watch` are checked in every scan; `guard` and `guardIgnoreScripts` are shown by `vswarm team status` (checking them on Windows needs PowerShell, too slow for every gate). |
| `gate.ssh` | ssh host patterns; `vswarm gate ssh --team` adds them, and a check warns about the ones the gate does not cover. |

### Signing it (maintainers)

Make a signing key for the team policy, kept like any production key (a passphrase, or a hardware key):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/acme_policy           # or -t ed25519-sk
echo "alice@acme namespaces=\"vswarm-team\" $(cut -d' ' -f1,2 ~/.ssh/acme_policy.pub)" >> allowed_signers
# edit vswarm-team.json, raise "serial", then:
vswarm team sign vswarm-team.json --key ~/.ssh/acme_policy   # checks the shape, writes vswarm-team.json.sig
git add -A && git commit -m "policy 8" && git push
```

`vswarm team sign` is `ssh-keygen -Y sign -n vswarm-team` after a check of the file; plain `ssh-keygen` works as well.
Publish the key's fingerprint (`ssh-keygen -lf ~/.ssh/acme_policy.pub`) somewhere people can compare it: the team
chat, the wiki, an onboarding document.

## On each machine

```bash
vswarm team join git@github.com:acme/vswarm-policy.git                         # shows the signing keys, asks
vswarm team join git@github.com:acme/vswarm-policy.git --fingerprint SHA256:…  # or names the one you expect
vswarm team sync      # fetch again; only a policy signed by the pinned keys is taken
vswarm team status    # the policy, its keys, and what this machine still lacks
vswarm team leave
```

What `join` and `sync` refuse:

| Situation | Result |
| --- | --- |
| `vswarm-team.json` has no `.sig`, or the signature does not verify | refused; nothing changes on the machine |
| signed by a key that is not in the pinned `allowed_signers` | refused |
| the repository's `allowed_signers` differs from the pinned one (a key added or replaced) | refused: leave and join again after checking with the team; a pull alone never changes who is trusted |
| a lower `serial` than the policy the machine has | refused (a rollback) |
| the copy on the machine was edited by hand | not used, and a check says so; `vswarm team sync` fetches the signed one again |

The clone runs with git hooks, submodules and LFS filters off: fetching a policy runs nothing from the repository.

## Limits

- Trust on first use: whoever controls the repository at `join` time chooses the keys. Compare the fingerprint, or
  use `--fingerprint`.
- The policy changes what vswarm reports on each machine; it is not enforcement. Someone who controls a laptop can
  leave the team or edit vswarm itself. Enforcement belongs on the server ([server-side.md](server-side.md)).
- `accept` patterns are powerful: a broad one (`conn-unsigned:*`) hides that class of finding on every machine. Keep
  them as narrow as the finding ids allow.
