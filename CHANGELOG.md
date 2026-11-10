# Changelog

vswarm is in beta. Every release is a git tag signed by a key in [`trust/allowed_signers`](trust/allowed_signers);
`vswarm update` takes only those and never goes to a lower version. Full notes for each release are on the
[releases page](https://github.com/kridsadar357/vswarm/releases).

## 0.1.1

Fixes from the first days of 0.1.0 on real machines, most of them Windows.

- **Fewer false alarms on Windows:** a program in `%TEMP%` or a hidden folder that a well-known publisher validly
  signed (an installer or updater, such as Visual Studio's `BackgroundDownload.exe`) is listed as LOW with its signer,
  and no longer blocks. Copies of Windows' own programs and programs that run anything (PowerShell, mshta, rundll32
  and the like, also when renamed) stay HIGH.
- **The ssh agent on Windows comes back** within a minute when its process is ended.
- **`vswarm uninstall` is refused while keys are in the vault**, because ssh could not use them afterwards. To move to
  a newer vswarm, run the install command over it; nothing needs uninstalling.
- **`vswarm ui`:** the commands under "Everything else › Done in a terminal" show as rows again, not `[object HTMLDivElement]`.
- **`vswarm hook`:** only a real write to `~/.vswarm` or `~/.ssh/config` counts as editing them by hand; reading them
  is no longer refused.
- **Updates and installs** drop tags the repository removed, so a copy from a 2.x build moves to the newest release.
- `doctor` says when the launcher is not on PATH and how to add it; `uninstall` says how many copies of
  `~/.ssh/config` it leaves.
- `vswarm agent off` stops every vswarm agent process. `agent off`, `gate remove`, `guard off` and `gate cmd --off`
  remove a file (`~/.ssh/config`, a shell or PowerShell profile) that held only vswarm's block, and keep no copy of it.
- `vswarm <command> --help` (or `-h`) shows that command's help instead of refusing the option.

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
  `vswarm hook install claude` checks Claude Code's shell commands before they run, and the check reports an agent
  free to run anything on a machine with production keys that have no passphrase.
- **Feeds:** `vswarm feed add <https url>` follows a signed list of dangerous packages, MCP servers, extensions and
  addresses, compared on this machine; a feed can only add findings.
- **Seeing it:** the terminal reads like a checkpoint slip, with the vswarm worm beside the verdict; `vswarm ui` and
  `report --html` show the same in a page.
- **Updates are signed** and checked against the key pinned on your machine.
- **Platforms:** macOS and Linux; Windows is a preview.

Development builds before this release were numbered 2.1.0 to 2.9.0. Their tags and release pages were removed when
numbering restarted at 0.1.0. A copy still on a 2.x build refuses 0.1.0 as older through `vswarm update`: run the
install command in the README once more, over it. Do not uninstall first: that stops the key vault and takes the
gates out, so ssh with a protected key stops working until they are set up again.
