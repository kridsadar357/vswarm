#!/usr/bin/env sh
# Maintainers: sign and push a release tag.  scripts/release.sh v2.4.0 [notes-file]
# Uses the SSH key in VSWARM_SIGNING_KEY (default ~/.ssh/vswarm_release), whose public half must be listed in
# trust/allowed_signers. Users' `vswarm update` refuses tags that do not verify against the keys they pinned.
set -eu
TAG="${1:?usage: scripts/release.sh vX.Y.Z [notes-file]}"
KEY="${VSWARM_SIGNING_KEY:-$HOME/.ssh/vswarm_release}"
cd "$(dirname "$0")/.."
[ -f "$KEY" ] || { echo "no signing key at $KEY (ssh-keygen -t ed25519 -f $KEY, or -t ed25519-sk for a hardware key)"; exit 1; }
grep -qF "$(cut -d' ' -f2 "$KEY.pub")" trust/allowed_signers || { echo "the public key $KEY.pub is not in trust/allowed_signers"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "commit your changes first"; exit 1; }
grep -q "\"version\": \"${TAG#v}\"" package.json || { echo "package.json is not at ${TAG#v}"; exit 1; }
git -c gpg.format=ssh -c user.signingkey="$KEY" tag -s "$TAG" -m "vswarm $TAG"
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=trust/allowed_signers verify-tag "$TAG"
git push origin "$TAG"
if [ -n "${2:-}" ] && command -v gh >/dev/null 2>&1; then gh release create "$TAG" --verify-tag --title "vswarm $TAG" --notes-file "$2"; fi
