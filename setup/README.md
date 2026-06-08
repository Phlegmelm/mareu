# Mareu setup

One-command install for each platform. Every script is **idempotent** (safe to
re-run) and supports `--dry-run` / `-DryRun` to preview actions.

## Linux / macOS

```bash
# from the repo root
./setup/install.sh
```

By default this:
1. runs `cargo build --release`,
2. **symlinks** `target/release/mareu` into `~/.local/bin`,
3. installs bash/zsh/fish completions, and
4. installs the man page into `~/.local/share/man/man1`.

Useful flags:

| Flag | Effect |
|------|--------|
| `--copy` | copy the binary instead of symlinking |
| `--bindir DIR` | install the binary somewhere else |
| `--system` | install to `/usr/local` (uses `sudo`; implies `--copy`) |
| `--add-path` | append the bindir to your shell rc if it's not on PATH |
| `--no-build` / `--no-completions` / `--no-man` | skip a step |
| `--dry-run` | preview without changing anything |

Uninstall:

```bash
./setup/uninstall.sh            # add --system if you installed with --system
```

> **Symlink vs copy:** the default symlink means a later `cargo build --release`
> is picked up automatically. If you move or delete the repo, re-run with
> `--copy` for a standalone install.

## Windows

From PowerShell (no admin needed — installs to your user profile and user PATH):

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\install.ps1
```

…or from `cmd` / double-click:

```bat
setup\install.cmd
```

This copies `mareu.exe` to `%LOCALAPPDATA%\Programs\mareu`, adds that folder to
your **user** PATH, and wires PowerShell tab-completion into your profile.

Useful flags:

| Flag | Effect |
|------|--------|
| `-Symlink` | symlink instead of copy — **requires an elevated shell or Developer Mode**; falls back to copy otherwise |
| `-Dest DIR` | install somewhere else |
| `-NoBuild` / `-NoCompletions` | skip a step |
| `-DryRun` | preview without changing anything |

To symlink (so rebuilds propagate), run an **Administrator** PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\install.ps1 -Symlink
```

Uninstall:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\uninstall.ps1
```

Open a new terminal afterward so PATH changes take effect.

## What gets installed where

| | Linux/macOS | Windows |
|---|---|---|
| binary | `~/.local/bin/mareu` | `%LOCALAPPDATA%\Programs\mareu\mareu.exe` |
| completions | `bash-completion`, zsh `site-functions`, fish `completions` | `_mareu.completion.ps1`, sourced from `$PROFILE` |
| man page | `~/.local/share/man/man1` | — (no man on Windows) |
| config (created on first use) | `~/.config/mareu` | `%APPDATA%\mareu` |
| sessions | `~/.local/share/mareu` | `%LOCALAPPDATA%\mareu` |

Uninstall scripts leave config and sessions intact.
