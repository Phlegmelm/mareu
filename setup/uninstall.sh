#!/usr/bin/env bash
#
# Mareu uninstaller for Linux and macOS. Removes the binary, completions, and
# man page installed by setup/install.sh. Does not edit your shell rc.
#
# Usage: setup/uninstall.sh [--bindir DIR] [--system] [--dry-run]
set -euo pipefail

DRY=0
SYSTEM=0
BINDIR="${HOME}/.local/bin"
while [ $# -gt 0 ]; do
  case "$1" in
    --bindir) BINDIR="$2"; shift ;;
    --system) SYSTEM=1; BINDIR="/usr/local/bin" ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

XDG_DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
XDG_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}"
SUDO=""; [ "$SYSTEM" = 1 ] && SUDO="sudo"

rm_path() {
  if [ -e "$1" ] || [ -L "$1" ]; then
    if [ "$DRY" = 1 ]; then printf '  [dry-run] rm %s\n' "$1"; else $SUDO rm -f "$1"; printf '  removed %s\n' "$1"; fi
  fi
}

echo "▸ mareu uninstall"
rm_path "$BINDIR/mareu"
rm_path "$XDG_DATA/bash-completion/completions/mareu"
rm_path "$XDG_DATA/zsh/site-functions/_mareu"
rm_path "$XDG_CONFIG/fish/completions/mareu.fish"
rm_path "$XDG_DATA/man/man1/mareu.1"
# subcommand man pages, if any
for f in "$XDG_DATA"/man/man1/mareu-*.1; do [ -e "$f" ] && rm_path "$f"; done

echo "  note: config (~/.config/mareu) and sessions (data dir) are left intact."
echo "▸ done."
