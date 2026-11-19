#!/bin/sh
# Installs or upgrades blackthorn on this machine (Linux with systemd):
#
#   curl -fsSL https://github.com/frakw/blackthorn/releases/latest/download/install.sh | sh
#
# It installs the few packages blackthorn needs, downloads `thorn` and checks
# it against the release's SHA256SUMS, installs Claude Code if it is missing,
# and runs `thorn init`, which turns the web UI on and (at a terminal) asks for
# your first web account. Running it again upgrades `thorn` and leaves your
# configuration alone.
#
# Options, given as  ... | sh -s -- OPTIONS
#   --version vX.Y.Z   install that release instead of the latest
#   --binary PATH      install this thorn binary instead of downloading one
#   --no-claude        do not install Claude Code
#   --update-claude    install the latest Claude Code even if one is there
#   --no-web           leave the web UI off on a first install
#
# BLACKTHORN_DOWNLOAD overrides where release files come from (a mirror).
set -eu

REPO=https://github.com/frakw/blackthorn

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'EOF'
blackthorn installer:  curl -fsSL .../install.sh | sh -s -- [OPTIONS]
  --version vX.Y.Z   install that release instead of the latest
  --binary PATH      install this thorn binary instead of downloading one
  --no-claude        do not install Claude Code
  --update-claude    install the latest Claude Code even if one is there
  --no-web           leave the web UI off on a first install
EOF
}

main() {
  version=latest binary="" claude=auto web=""
  while [ $# -gt 0 ]; do
    case $1 in
      --version) [ $# -ge 2 ] || die "--version needs a value"; version=$2; shift 2 ;;
      --binary) [ $# -ge 2 ] || die "--binary needs a path"; binary=$2; shift 2 ;;
      --no-claude) claude=no; shift ;;
      --update-claude) claude=update; shift ;;
      --no-web) web=--no-web; shift ;;
      -h | --help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done

  [ "$(uname -s)" = Linux ] || die "the blackthorn hub runs on Linux (it can manage macOS machines, but not run on one)"
  [ -d /run/systemd/system ] || die "blackthorn needs systemd"
  case $(uname -m) in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "no blackthorn build for $(uname -m)" ;;
  esac
  if [ "$(id -u)" = 0 ]; then
    SUDO=""
  elif have sudo; then
    SUDO=sudo
  else
    die "run this as root (or install sudo)"
  fi

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT TERM
  chmod 755 "$tmp"

  packages

  if [ -n "$binary" ]; then
    say "using $binary"
    cp "$binary" "$tmp/thorn"
  else
    download
  fi
  chmod 755 "$tmp/thorn"

  set --
  if wants_claude; then
    install_claude && set -- --claude-from "$tmp/claude"
  fi
  [ -z "$web" ] || set -- "$@" "$web"

  # init asks for the first web account, so give it the terminal (standard
  # input is this script when piped from curl).
  say "setting up blackthorn"
  if (: </dev/tty) 2>/dev/null; then
    $SUDO "$tmp/thorn" init "$@" </dev/tty
  else
    $SUDO "$tmp/thorn" init "$@" </dev/null
  fi
}

# The programs `thorn init` checks for, installed only when missing.
packages() {
  missing=""
  have tmux || missing="$missing tmux"
  have ssh-agent || missing="$missing ssh"
  have nft || missing="$missing nft"
  have sha256sum || missing="$missing sha256sum"
  [ -n "$missing" ] || return 0
  say "installing packages for:$missing"
  if have apt-get; then
    $SUDO apt-get update -q </dev/null
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q tmux openssh-client nftables coreutils </dev/null
  elif have dnf; then
    $SUDO dnf install -y tmux openssh-clients nftables coreutils </dev/null
  elif have pacman; then
    $SUDO pacman -S --needed --noconfirm tmux openssh nftables coreutils </dev/null
  else
    die "install these yourself, then run this again:$missing"
  fi
}

download() {
  file=thorn-$arch-linux
  if [ -n "${BLACKTHORN_DOWNLOAD:-}" ]; then
    base=$BLACKTHORN_DOWNLOAD
  elif [ "$version" = latest ]; then
    base=$REPO/releases/latest/download
  else
    base=$REPO/releases/download/$version
  fi
  say "downloading $file ($version)"
  curl -fsSL --proto '=https,file' -o "$tmp/$file" "$base/$file" || die "could not download $base/$file"
  curl -fsSL --proto '=https,file' -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "could not download $base/SHA256SUMS"
  grep " $file\$" "$tmp/SHA256SUMS" >"$tmp/sum" || die "SHA256SUMS has no entry for $file"
  (cd "$tmp" && sha256sum -c --quiet sum) || die "checksum mismatch for $file: not installing it"
  mv "$tmp/$file" "$tmp/thorn"
}

# Claude Code is wanted unless it is already where spaces run it from, or in
# a home directory `thorn init` copies it from.
wants_claude() {
  case $claude in
    no) return 1 ;;
    update) return 0 ;;
  esac
  [ ! -x /usr/local/bin/claude ] || return 1
  [ ! -x "$HOME/.local/bin/claude" ] || return 1
  return 0
}

# Anthropic's own installer, run into a throwaway home; thorn init then copies
# the binary to /usr/local/bin, root-owned, where spaces cannot change it.
install_claude() {
  say "installing Claude Code"
  if ! curl -fsSL https://claude.ai/install.sh -o "$tmp/claude-install.sh"; then
    echo "warning: could not download the Claude Code installer; install it later with: sudo thorn init --claude-from <path>" >&2
    return 1
  fi
  mkdir "$tmp/claude-home"
  if ! HOME=$tmp/claude-home CLAUDE_INSTALL_ALLOW_SUDO=1 bash "$tmp/claude-install.sh" </dev/null >"$tmp/claude.log" 2>&1; then
    cat "$tmp/claude.log" >&2
    echo "warning: Claude Code was not installed; install it later with: sudo thorn init --claude-from <path>" >&2
    return 1
  fi
  src=$(readlink -f "$tmp/claude-home/.local/bin/claude" 2>/dev/null) && [ -x "$src" ] ||
    { echo "warning: the Claude Code installer left no binary" >&2; return 1; }
  cp "$src" "$tmp/claude"
  chmod 755 "$tmp/claude"
  rm -rf "$tmp/claude-home"
}

main "$@"
