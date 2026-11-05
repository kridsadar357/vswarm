#!/usr/bin/env sh
# vswarm installer for macOS and Linux.
#   curl -fsSL https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.sh | sh
# Installs Bun if missing, puts vswarm in ~/.vswarm/app, then runs `vswarm install`.
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
  say "installing Bun (https://bun.sh)"
  curl -fsSL https://bun.sh/install | bash >/dev/null
  BUN="$HOME/.bun/bin/bun"
  [ -x "$BUN" ] || die "Bun did not install; see https://bun.sh"
fi

if [ -d "$APP/.git" ]; then
  say "updating $APP"
  git -C "$APP" fetch --quiet origin "$REF"
  git -C "$APP" checkout --quiet "$REF"
  git -C "$APP" pull --quiet --ff-only origin "$REF"
else
  say "downloading vswarm into $APP"
  mkdir -p "$(dirname "$APP")"
  git clone --quiet --depth 1 --branch "$REF" "$REPO" "$APP"
fi

cd "$APP"
"$BUN" install --production --silent >/dev/null 2>&1 || true
# The installer asks its questions on the terminal even when this script came through a pipe.
if [ -r /dev/tty ]; then exec "$BUN" "$APP/src/cli.ts" install "$@" </dev/tty; fi
exec "$BUN" "$APP/src/cli.ts" install --yes "$@"
