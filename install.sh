#!/usr/bin/env sh
# vswarm installer for macOS and Linux.
#   curl -fsSL https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.sh | sh
# Installs Bun if missing, puts vswarm in ~/.vswarm/app, then runs `vswarm install` (check your machine before it touches production).
# VSWARM_REPO and VSWARM_REF pick another repository or branch.
set -eu

REPO="${VSWARM_REPO:-https://github.com/kridsadar357/vswarm.git}"
REF="${VSWARM_REF:-main}"
APP="${VSWARM_HOME:-$HOME/.vswarm}/app"

say() { printf '  \033[38;2;180;140;255m▼\033[0m %s\n' "$1"; }
die() { printf '  \033[38;2;255;107;139m✖\033[0m %s\n' "$1" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git is required (macOS: xcode-select --install · Linux: your package manager)"

if command -v bun >/dev/null 2>&1; then
  BUN=$(command -v bun)
elif [ -x "$HOME/.bun/bin/bun" ]; then
  BUN="$HOME/.bun/bin/bun"
else
  command -v unzip >/dev/null 2>&1 || die "unzip is needed to install Bun (Ubuntu/Debian: sudo apt install unzip)"
  say "installing Bun (https://bun.sh)"
  curl -fsSL https://bun.sh/install | bash >/dev/null
  BUN="$HOME/.bun/bin/bun"
  [ -x "$BUN" ] || die "Bun did not install; see https://bun.sh"
fi

if [ -d "$APP/.git" ]; then
  say "updating $APP"
  git -C "$APP" fetch --quiet --tags --force origin
else
  say "downloading vswarm into $APP"
  mkdir -p "$(dirname "$APP")"
  git clone --quiet "$REPO" "$APP"
fi

# Signed releases: when the repository lists release keys, install the newest release tag, and only if its
# signature checks out. `vswarm install` then pins those keys; later updates accept nothing else.
TAG=$(git -C "$APP" tag -l 'v*' --sort=-v:refname | head -n 1)
if [ -z "${VSWARM_REF:-}" ] && [ -n "$TAG" ] && git -C "$APP" show "$TAG:trust/allowed_signers" 2>/dev/null | grep -q '^[^#[:space:]]'; then
  git -C "$APP" show "$TAG:trust/allowed_signers" > "$APP/.release-signers"
  git -C "$APP" -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$APP/.release-signers" verify-tag "$TAG" >/dev/null 2>&1 \
    || { rm -f "$APP/.release-signers"; die "release $TAG is not signed by the key it lists; not installing it"; }
  rm -f "$APP/.release-signers"
  git -C "$APP" checkout --quiet --detach "$TAG"
  say "release $TAG, signature checked"
else
  git -C "$APP" checkout --quiet "$REF"
  git -C "$APP" pull --quiet --ff-only origin "$REF" 2>/dev/null || true
fi

cd "$APP"
"$BUN" install --production --silent >/dev/null 2>&1 || true
# vswarm reads its questions from /dev/tty itself, so they work even though this script came through a pipe.
exec "$BUN" "$APP/src/cli.ts" install "$@"
