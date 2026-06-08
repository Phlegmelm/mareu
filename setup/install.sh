#!/usr/bin/env bash
#
# Mareu installer for Linux and macOS.
#
# Builds the release binary, links/copies it onto your PATH, and installs shell
# completions and the man page. Idempotent — safe to re-run.
#
# Usage:
#   setup/install.sh [options]
#
# Options:
#   --copy            Copy the binary instead of symlinking (default: symlink)
#   --bindir DIR      Install dir for the binary (default: ~/.local/bin)
#   --system          Install to /usr/local (uses sudo); implies --copy
#   --no-build        Skip `cargo build --release` (use an existing binary)
#   --add-path        Append the bindir to your shell rc if it's not on PATH
#   --no-completions  Skip shell-completion installation
#   --no-man          Skip man-page installation
#   --dry-run         Print what would happen without changing anything
#   -h, --help        This help
set -euo pipefail

# ── resolve paths ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

COPY=0
SYSTEM=0
BUILD=1
ADD_PATH=0
DO_COMPLETIONS=1
DO_MAN=1
DRY=0
BINDIR="${HOME}/.local/bin"

while [ $# -gt 0 ]; do
  case "$1" in
    --copy) COPY=1 ;;
    --bindir) BINDIR="$2"; shift ;;
    --system) SYSTEM=1; COPY=1; BINDIR="/usr/local/bin" ;;
    --no-build) BUILD=0 ;;
    --add-path) ADD_PATH=1 ;;
    --no-completions) DO_COMPLETIONS=0 ;;
    --no-man) DO_MAN=0 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

XDG_DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
XDG_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}"
BIN_SRC="$REPO_DIR/target/release/mareu"

say() { printf '  %s\n' "$*"; }
run() {
  if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else eval "$@"; fi
}
SUDO=""
[ "$SYSTEM" = 1 ] && SUDO="sudo"

echo "▸ mareu install  (repo: $REPO_DIR)"
case "$(uname -s)" in
  Linux)  say "platform: Linux" ;;
  Darwin) say "platform: macOS" ;;
  *) echo "  this installer is for Linux/macOS; use setup/install.ps1 on Windows" >&2; exit 1 ;;
esac

# ── toolchain ───────────────────────────────────────────────────────────────
if [ "$BUILD" = 1 ]; then
  command -v cargo >/dev/null 2>&1 || { echo "  cargo not found — install Rust from https://rustup.rs" >&2; exit 1; }
  say "building release binary…"
  run "(cd \"$REPO_DIR\" && cargo build --release)"
fi
[ "$DRY" = 1 ] || [ -x "$BIN_SRC" ] || { echo "  binary not found at $BIN_SRC (run without --no-build)" >&2; exit 1; }

# ── install binary ──────────────────────────────────────────────────────────
run "$SUDO mkdir -p \"$BINDIR\""
DEST="$BINDIR/mareu"
if [ "$COPY" = 1 ]; then
  say "copying  $BIN_SRC -> $DEST"
  run "$SUDO cp -f \"$BIN_SRC\" \"$DEST\""
  run "$SUDO chmod +x \"$DEST\""
else
  say "linking  $DEST -> $BIN_SRC"
  run "ln -sfn \"$BIN_SRC\" \"$DEST\""
fi

# Use the freshly-installed binary to emit completions/man (works in dry-run via src).
GEN_BIN="$BIN_SRC"

# ── completions ─────────────────────────────────────────────────────────────
if [ "$DO_COMPLETIONS" = 1 ]; then
  BASH_DIR="$XDG_DATA/bash-completion/completions"
  ZSH_DIR="$XDG_DATA/zsh/site-functions"
  FISH_DIR="$XDG_CONFIG/fish/completions"
  say "installing completions (bash, zsh, fish)"
  run "mkdir -p \"$BASH_DIR\" \"$ZSH_DIR\" \"$FISH_DIR\""
  run "\"$GEN_BIN\" completions bash > \"$BASH_DIR/mareu\""
  run "\"$GEN_BIN\" completions zsh  > \"$ZSH_DIR/_mareu\""
  run "\"$GEN_BIN\" completions fish > \"$FISH_DIR/mareu.fish\""
  say "  zsh: ensure 'fpath+=($ZSH_DIR)' precedes 'compinit' in ~/.zshrc"
fi

# ── man page ────────────────────────────────────────────────────────────────
if [ "$DO_MAN" = 1 ]; then
  MAN_DIR="$XDG_DATA/man/man1"
  say "installing man page -> $MAN_DIR"
  run "mkdir -p \"$MAN_DIR\""
  run "\"$GEN_BIN\" man --dir \"$MAN_DIR\""
fi

# ── PATH check ──────────────────────────────────────────────────────────────
case ":$PATH:" in
  *":$BINDIR:"*) say "PATH: $BINDIR already on PATH ✓" ;;
  *)
    if [ "$ADD_PATH" = 1 ]; then
      RC="$HOME/.bashrc"; [ -n "${ZSH_VERSION:-}" ] || case "${SHELL:-}" in *zsh) RC="$HOME/.zshrc";; esac
      LINE="export PATH=\"$BINDIR:\$PATH\""
      say "adding $BINDIR to PATH in $RC"
      run "grep -qsF '$LINE' \"$RC\" || printf '\n# mareu\n%s\n' '$LINE' >> \"$RC\""
      say "  open a new shell or: source $RC"
    else
      say "NOTE: $BINDIR is not on your PATH. Add it, or re-run with --add-path:"
      say "      export PATH=\"$BINDIR:\$PATH\""
    fi
    ;;
esac

echo "▸ done. Try:  mareu --version   (or:  mareu recon ./src --filter pre-auth)"
