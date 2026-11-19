#!/bin/sh
# Installs or upgrades blackthorn on this machine (Linux with systemd):
#
#   curl -fsSL https://github.com/frakw/blackthorn/releases/latest/download/install.sh | sh
#
# It installs the few packages blackthorn needs, downloads `thorn` and checks
# it against the release's SHA256SUMS, installs Claude Code if it is missing,
# offers to install Tailscale (at a terminal, when it is missing), and runs
# `thorn init`, which turns the web UI on and (at a terminal) asks which
# devices may administer the hub and for your first web account. Running it
# again upgrades `thorn` and leaves your configuration alone.
#
# Options, given as  ... | sh -s -- OPTIONS
#   --version vX.Y.Z   install that release instead of the latest
#   --binary PATH      install this thorn binary instead of downloading one
#   --no-claude        do not install Claude Code
#   --update-claude    install the latest Claude Code even if one is there
#   --no-web           leave the web UI off on a first install
#   --tailscale        install Tailscale without asking (if missing)
#   --no-tailscale     do not offer Tailscale
#   --login-server URL Tailscale coordination server (e.g. your headscale)
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
  --tailscale        install Tailscale without asking (if missing)
  --no-tailscale     do not offer Tailscale
  --login-server URL Tailscale coordination server (e.g. your headscale)
EOF
}

main() {
  version=latest binary="" claude=auto web="" tailscale=ask login_server=""
  while [ $# -gt 0 ]; do
    case $1 in
      --version) [ $# -ge 2 ] || die "--version needs a value"; version=$2; shift 2 ;;
      --binary) [ $# -ge 2 ] || die "--binary needs a path"; binary=$2; shift 2 ;;
      --no-claude) claude=no; shift ;;
      --update-claude) claude=update; shift ;;
      --no-web) web=--no-web; shift ;;
      --tailscale) tailscale=yes; shift ;;
      --no-tailscale) tailscale=no; shift ;;
      --login-server) [ $# -ge 2 ] || die "--login-server needs a URL"; login_server=$2; shift 2 ;;
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
  tailscale_setup

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
  if tty_ok; then
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

# Someone at the terminal to ask (stdin is this script when piped from curl).
tty_ok() { (: </dev/tty) 2>/dev/null; }

ask() { # ask "question" default -> answer in $REPLY
  printf '%s ' "$1" >/dev/tty
  read -r REPLY </dev/tty || REPLY=""
  [ -n "$REPLY" ] || REPLY=$2
}

# Tailscale lets only your own devices reach the hub, without opening any
# port to the internet. Offered when it is missing; installed with
# Tailscale's own installer (their package repository).
tailscale_setup() {
  [ "$tailscale" != no ] || return 0
  have tailscale && return 0
  if [ "$tailscale" = ask ]; then
    tty_ok || return 0
    echo "Tailscale is not installed. With it, only your own devices can reach this hub (no port open to the internet)." >/dev/tty
    ask "Install Tailscale now? [Y/n]" y
    case $REPLY in [Nn]*) return 0 ;; esac
    if [ -z "$login_server" ]; then
      ask "Coordination server: Enter for Tailscale's own, or your headscale URL (https://...):" ""
      login_server=$REPLY
    fi
  fi
  say "installing Tailscale"
  curl -fsSL https://tailscale.com/install.sh -o "$tmp/tailscale-install.sh" || die "could not download the Tailscale installer"
  $SUDO sh "$tmp/tailscale-install.sh" </dev/null || die "the Tailscale installer failed"
  tty_ok || { echo "Tailscale installed; connect it with: sudo tailscale up"; return 0; }
  say "connecting to your tailnet (open the link it shows to approve this machine)"
  if [ -n "$login_server" ]; then
    $SUDO tailscale up --login-server "$login_server" </dev/tty || echo "warning: tailscale up failed; run it again later" >&2
  else
    $SUDO tailscale up </dev/tty || echo "warning: tailscale up failed; run it again later" >&2
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
