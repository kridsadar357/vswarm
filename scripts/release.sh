#!/usr/bin/env sh
# Maintainers: check, sign and push a release tag.  scripts/release.sh v2.4.0 [notes-file]
# Uses the SSH key in VSWARM_SIGNING_KEY (default ~/.ssh/vswarm_release), whose public half must be listed in
# trust/allowed_signers. Users' `vswarm update` refuses tags that do not verify against the keys they pinned.
#
# A signed tag reaches every installed copy, so nothing is tagged until: the tree is clean and pushed, main's CI run
# for this exact commit passed (macOS, Linux and Windows), and the type check, the tests and the selftest pass here too.
set -eu
TAG="${1:?usage: scripts/release.sh vX.Y.Z [notes-file]}"
KEY="${VSWARM_SIGNING_KEY:-$HOME/.ssh/vswarm_release}"
cd "$(dirname "$0")/.."
fail() { echo "release: $*" >&2; exit 1; }

[ -f "$KEY" ] || fail "no signing key at $KEY (ssh-keygen -t ed25519 -f $KEY, or -t ed25519-sk for a hardware key)"
grep -qF "$(cut -d' ' -f2 "$KEY.pub")" trust/allowed_signers || fail "the public key $KEY.pub is not in trust/allowed_signers"
case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail "$TAG is not vX.Y.Z" ;; esac
grep -q "\"version\": \"${TAG#v}\"" package.json || fail "package.json is not at ${TAG#v}"
grep -q "^## ${TAG#v}" CHANGELOG.md || fail "CHANGELOG.md has no '## ${TAG#v}' section"

# What is tagged is what CI tested: main, committed, pushed.
[ -z "$(git status --porcelain)" ] || fail "commit your changes first"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || fail "release from main"
git fetch --quiet origin main
HEAD_SHA=$(git rev-parse HEAD)
[ "$HEAD_SHA" = "$(git rev-parse origin/main)" ] || fail "push main first (HEAD is not origin/main)"

command -v gh >/dev/null 2>&1 || fail "gh is needed to check CI (https://cli.github.com)"
CI=$(gh run list --workflow test.yml --branch main --commit "$HEAD_SHA" --limit 1 --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"')
[ "$CI" = "completed success" ] || fail "CI for $HEAD_SHA is '${CI:-not started}': wait for it to pass (gh run watch)"

echo "release: type check, tests and selftest on this machine…"
bunx tsc --noEmit || fail "the type check failed"
bun test >/dev/null 2>&1 || fail "bun test failed (run it to see why)"
bun src/cli.ts selftest >/dev/null 2>&1 || fail "the selftest missed a case or raised a false alarm (bun src/cli.ts selftest)"

git -c gpg.format=ssh -c user.signingkey="$KEY" tag -s "$TAG" -m "vswarm $TAG"
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=trust/allowed_signers verify-tag "$TAG"
git push origin "$TAG"
if [ -n "${2:-}" ]; then gh release create "$TAG" --verify-tag --title "vswarm $TAG" --notes-file "$2"; fi
