#!/usr/bin/env sh
# vswarm installer for macOS and Linux.
#   curl -fsSL https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.sh | sh
# Uses the Bun on your PATH, or installs a pinned Bun release (checked against the SHA-256 below), puts vswarm in
# ~/.vswarm/app, then runs `vswarm install` (check your machine before it touches production).
# VSWARM_REPO and VSWARM_REF pick another repository or branch.
set -eu

REPO="${VSWARM_REPO:-https://github.com/kridsadar357/vswarm.git}"
REF="${VSWARM_REF:-main}"
APP="${VSWARM_HOME:-$HOME/.vswarm}/app"

say() { printf '  \033[38;2;180;140;255m▼\033[0m %s\n' "$1"; }
die() { printf '  \033[38;2;255;107;139m✖\033[0m %s\n' "$1" >&2; exit 1; }

# ── Bun, pinned
# One Bun release, and the SHA-256 of each zip as published in its SHASUMS256.txt
# (https://github.com/oven-sh/bun/releases/download/bun-v1.3.14/SHASUMS256.txt). A download that does not match is
# not unpacked. Moving to another release means changing the version and every hash here and in install.ps1.
BUN_VERSION=1.3.14
bun_sha256() {
  case "$1" in
    bun-darwin-aarch64) echo d8b96221828ad6f97ac7ac0ab7e95872341af763001e8803e8267652c2652620 ;;
    bun-darwin-x64) echo 4183df3374623e5bab315c547cfa0974533cd457d86b73b639f7a87974cd6633 ;;
    bun-darwin-x64-baseline) echo 3e35ad6f53971a9834bf9e6786e2adf72b5f1921cc9a9c5fde073d2972944076 ;;
    bun-linux-aarch64) echo a27ffb63a8310375836e0d6f668ae17fa8d8d18b88c37c821c65331973a19a3b ;;
    bun-linux-aarch64-musl) echo b98e0ad3625c5c00d1d5b5ff55605c7adddbfae151861e68ade57b2d3b8703bb ;;
    bun-linux-x64) echo 951ee2aee855f08595aeec6225226a298d3fea83a3dcd6465c09cbccdf7e848f ;;
    bun-linux-x64-baseline) echo a063908ae08b7852ca10939bbdc6ceed3ddabce8fb9402dce83d65d73b36e6c7 ;;
    bun-linux-x64-musl) echo 14bd9aedeebf1dba67e8def9531c89bc989ecfdf1de42e5bfcaf1b8cd9294719 ;;
    bun-linux-x64-musl-baseline) echo 56a7d6806cf155536c0178f0ea5fbd098e684fa509ebdb4fc0a7e19fb65382dc ;;
    *) return 1 ;;
  esac
}

# The zip for this machine: system, CPU, musl or glibc, and the baseline build for x64 CPUs without AVX2.
bun_asset() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) return 1 ;;
  esac
  case "$arch" in
    arm64 | aarch64) arch=aarch64 ;;
    x86_64 | amd64) arch=x64 ;;
    *) return 1 ;;
  esac
  # A shell under Rosetta on Apple silicon reports x86_64; the native build is the one to use.
  if [ "$os" = darwin ] && [ "$arch" = x64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = 1 ]; then arch=aarch64; fi
  libc=""
  if [ "$os" = linux ] && { [ -f /etc/alpine-release ] || ls /lib/ld-musl-* >/dev/null 2>&1; }; then libc=-musl; fi
  base=""
  if [ "$arch" = x64 ]; then
    if [ "$os" = darwin ]; then
      sysctl -n machdep.cpu.features machdep.cpu.leaf7_features 2>/dev/null | grep -qi avx2 || base=-baseline
    else
      grep -qi avx2 /proc/cpuinfo 2>/dev/null || base=-baseline
    fi
  fi
  echo "bun-$os-$arch$libc$base"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

install_bun() {
  asset=$(bun_asset) || die "no Bun build for $(uname -s) $(uname -m); install Bun yourself (https://bun.sh) and run this again"
  want=$(bun_sha256 "$asset") || die "no pinned hash for $asset; install Bun yourself (https://bun.sh) and run this again"
  command -v unzip >/dev/null 2>&1 || die "unzip is needed to install Bun (Ubuntu/Debian: sudo apt install unzip)"
  tmp=$(mktemp -d)
  say "installing Bun $BUN_VERSION ($asset), checked against its pinned SHA-256"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$asset.zip" "https://github.com/oven-sh/bun/releases/download/bun-v$BUN_VERSION/$asset.zip" \
    || { rm -rf "$tmp"; die "could not download $asset.zip from github.com/oven-sh/bun"; }
  got=$(sha256_of "$tmp/$asset.zip")
  [ "$got" = "$want" ] || { rm -rf "$tmp"; die "$asset.zip does not match its pinned SHA-256 (got $got); not installing it"; }
  unzip -q "$tmp/$asset.zip" -d "$tmp"
  mkdir -p "$HOME/.bun/bin"
  mv "$tmp/$asset/bun" "$HOME/.bun/bin/bun"
  chmod 755 "$HOME/.bun/bin/bun"
  rm -rf "$tmp"
}

# Tests read the functions above without running the installer.
if [ "${VSWARM_INSTALL_LIB:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi

command -v git >/dev/null 2>&1 || die "git is required (macOS: xcode-select --install · Linux: your package manager)"

if command -v bun >/dev/null 2>&1; then
  BUN=$(command -v bun)
elif [ -x "$HOME/.bun/bin/bun" ]; then
  BUN="$HOME/.bun/bin/bun"
else
  install_bun
  BUN="$HOME/.bun/bin/bun"
  "$BUN" --version >/dev/null 2>&1 || die "Bun did not start; see https://bun.sh"
fi

if [ -d "$APP/.git" ]; then
  say "updating $APP"
  # --prune-tags: a tag removed from the repository goes here too, so an older install cannot pick a withdrawn one.
  git -C "$APP" fetch --quiet --tags --force --prune --prune-tags origin
else
  say "downloading vswarm into $APP"
  mkdir -p "$(dirname "$APP")"
  git clone --quiet "$REPO" "$APP"
fi

# Signed releases: when the repository lists release keys, install the newest release tag, and only if its
# signature checks out. `vswarm install` then pins those keys; later updates accept nothing else. Until the maintainer
# publishes a release key, this installs main as it is, unsigned, and says so.
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
  [ -n "${VSWARM_REF:-}" ] || say "no signed release yet: installed main as it is, without a signature check"
fi

cd "$APP"
"$BUN" install --production --silent >/dev/null 2>&1 || true
# vswarm reads its questions from /dev/tty itself, so they work even though this script came through a pipe.
exec "$BUN" "$APP/src/cli.ts" install "$@"
