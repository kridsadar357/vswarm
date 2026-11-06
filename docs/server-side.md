# Making the decision on the server

vswarm runs on the laptop it checks. That is what makes it cheap and useful at the risky moments, and it is also its
limit: code already running as you can switch it off, edit `~/.ssh/config`, or read the key vswarm seals its files
with. A check that **cannot** be skipped from the laptop has to live where the laptop cannot reach: the bastion, the
SSH certificate authority, the identity provider.

This page is about that step: what vswarm gives such a server, and three ways to use it. vswarm does not ship a
server; these are patterns, sized for a small team.

## What vswarm emits

```bash
vswarm report --json                                  # a fresh check, as JSON on stdout
vswarm report --json --sign ~/.ssh/vswarm_device      # the same, signed: { "report": "<exact bytes>", "signature": "-----BEGIN SSH SIGNATURE-----…" }
vswarm report --json --sign ~/.ssh/vswarm_device --out ~/reports   # report.json and report.json.sig in a folder
```

The report (`schema: "vswarm-report/1"`):

| Field | |
| --- | --- |
| `host`, `user`, `at` | which machine, which account, when (ISO time) |
| `vswarm` | the version that made it |
| `verdict` | `pass`, `warn` or `block`, as preflight would decide |
| `locked` | present while an incident is open (`incident`, `reason`) |
| `baselineAt` | when the baseline was recorded |
| `findings` | `id`, `rule`, `severity`, `title` of everything above info; never a credential value |
| `notes` | what could not be checked, and why |
| `team` | `name` and `serial` of the team policy this machine follows, if any ([team.md](team.md)) |

The exit code is 3 on BLOCK, 0 otherwise. The signature is an ordinary SSH signature (`ssh-keygen -Y sign`) in the
namespace `vswarm-report`, over the exact bytes of the report. Verify it with stock OpenSSH:

```bash
ssh-keygen -Y verify -f devices_allowed_signers -I alice@laptop-7 -n vswarm-report -s report.json.sig < report.json
```

`devices_allowed_signers` is the list of device keys the server knows, one line each:
`alice@laptop-7 ssh-ed25519 AAAA…`.

### What the signature does and does not prove

- It proves the report came from a holder of that device key, and was not changed on the way.
- It does **not** prove the laptop is clean. Malware running as you can run `vswarm report` itself, or sign a forged
  report with the same key. Use a key that needs a person: a FIDO key (`ssh-keygen -t ed25519-sk`, a touch for every
  signature) or a key with a passphrase in an agent that confirms each use (`ssh-add -c`). Then a silent forgery needs
  the person, not just the account.
- A report is a claim about one moment. The server should refuse a report older than a few minutes (`at`), and one
  that has already been used (keep the hash of the last accepted report per device).

## Pattern 1: an SSH CA that wants a fresh report

The strongest of the three for a small team. Servers trust a CA, not keys (`TrustedUserCAKeys`, see `vswarm ca server`).
The CA runs on a machine developers cannot log in to, and signs a short-lived certificate only when the request comes
with a report that:

1. verifies against the device's key in `devices_allowed_signers`,
2. is at most 5 minutes old and not seen before,
3. says `"verdict": "pass"` (or `warn`, if you allow it) and has no `locked`,
4. names the team policy and serial you require, if you use one.

The developer side is one line before ssh, or a `Match exec` in `~/.ssh/config`:

```bash
vswarm report --json --sign ~/.ssh/vswarm_device | curl -sf --data-binary @- https://ca.internal/sign > ~/.ssh/id_ed25519-cert.pub
```

Because the certificate expires in minutes, an attacker who skips vswarm on the laptop gets no certificate; one who
steals an old certificate gets one that no longer works. `vswarm cert` is the local version of this (the CA key on the
laptop, guarded by its passphrase); moving the CA off the laptop is what makes it enforceable.

## Pattern 2: a bastion that checks before it forwards

If production is reached through a jump host, the jump host can ask for the report as part of the login, for example
with a `ForceCommand` wrapper on the bastion that reads a signed report from the session, verifies it the same way,
and only then opens the onward connection. Keep the check and the device key list on the bastion, owned by root.

## Pattern 3: device trust in your identity provider

Teleport Device Trust, Kolide (1Password Device Trust) and similar products tie access to an enrolled device and
check its posture from an agent the user does not control. They are stronger than any of the patterns above, and the
right answer once a team has them. vswarm fits beside them:

- many of them can run custom checks on the device; the signed report file (`--out`) is something such a check can
  read and require a recent `pass` from (see your vendor's documentation for custom checks);
- vswarm still pauses the risky moments that device trust does not see: the package install, the stranger's repo,
  the new MCP server.

## What stays on the laptop either way

`preflight` and `gate` on the laptop remain useful when the server decides too: they stop you **before** you try,
with a reason and a fix, instead of a refused connection with no explanation. Think of the laptop check as the
warning, and the server check as the lock.
