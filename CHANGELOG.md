# Changelog

vswarm is in beta. Every release is a git tag signed by a key in [`trust/allowed_signers`](trust/allowed_signers);
`vswarm update` takes only those and never goes to a lower version. Full notes for each release are on the
[releases page](https://github.com/kridsadar357/vswarm/releases).

## 0.1.0 (first public beta)

The first release. vswarm checks a developer's own machine before it touches production, and says what it found in
plain words (English and Thai).

- **Check the machine:** `scan`, `baseline`, `diff`, `why`, `fix`, `ok`: login items and services, shell startup
  files, packages (known-malicious through OSV, look-alike names, install scripts), Homebrew sources, programs running
  or talking to the network from odd places, credentials left on disk, AI agent settings and MCP servers.
- **Before production:** `preflight` and `gate` put a check in front of ssh, aws, kubectl, gcloud, az and other
  commands; `agent` keeps production ssh keys in a vault that signs only while the machine passes.
- **Before installing:** `guard` reads npm, pip, brew and other packages before they install; `try` runs code you do
  not trust in a sandbox (macOS, Linux, Windows) and reports what it tried.
- **When something is wrong:** `respond` locks production access, keeps evidence and lists what to change; `unlock`
  once the machine is clean. `watch` checks in the background; `canary` plants decoy credentials.
- **AI agents:** commands that weaken protection (`ok`, `baseline`, `unlock`, `policy warn allow`, taking a gate, the
  guard or the watch away, `uninstall` and others) ask a person first: on the terminal they are at, or in a desktop
  dialog an agent cannot answer. An agent that hits a gate is told to hand it to the user. `vswarm mcp` lets an
  agent read the state, explain a refusal and ask the person a Yes/No question; it cannot unlock or accept anything.
- **Seeing it:** the terminal reads like a checkpoint slip, with the vswarm worm beside the verdict; `vswarm ui` and
  `report --html` show the same in a page.
- **Updates are signed** and checked against the key pinned on your machine.
- **Platforms:** macOS and Linux; Windows is a preview.

Development builds before this release were numbered 2.1.0 to 2.9.0. Their tags and release pages were removed when
numbering restarted at 0.1.0. A copy still on a 2.x build refuses 0.1.0 as older: reinstall it once (`vswarm
uninstall`, then the install command in the README).
