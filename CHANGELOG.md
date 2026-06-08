# Changelog

All notable changes to Mareu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
semantic versioning once the CLI contract is declared stable at `1.0`.

## [0.4.0] — 2026-06-08

First public push. Implements RFC-0001 milestones **v0.1–v0.4** (offline core,
AI layer, sessions, REPL) — **cross-platform on Linux, macOS, and Windows**
(the RFC's original "Linux + macOS only" non-goal was lifted).

### Added

- **CLI surface** (`clap` derive): `recon`, `analyze`, `scaffold`, `session`,
  `shell`, `report`, `config`, `banner`, `completions`, `man`.
- **Opt-in AI layer** — global `--ai` / `--no-ai` / `--dry-run`; AI is never the
  default. `--dry-run` prints the fully assembled prompt and makes no API call.
- **Providers** (real `reqwest` impls, streaming): OpenRouter, Anthropic,
  OpenAI-compatible, Ollama. Automatic fallback to `ai.fallback` on error.
  Live `config providers` health checks.
- **Static analysis** — attack-surface mapping, flag-pattern scan
  (`aho-corasick`), CWE heuristics, and a light taint pass that promotes sinks
  consuming tainted input.
- **Scaffolding** — Handlebars templates for bof/uaf/fmt/proto/reproducer/report
  with a machine-readable header and the `--unsafe` gate. Honest **intent check**
  (RFC §4.2) declines named-external-target framing.
- **Assembly scaffolds** (`--lang asm`) — programmatically generated, null-free
  `execve` shellcode plus egghunter/loader/ret2 for x86_64/x86/aarch64 in
  NASM/Intel and GNU as/AT&T (`--syntax both` emits a pair). Verified to
  assemble with GNU `as`.
- **`--decompile`** — disassembles a binary via `objdump`/`llvm-objdump` and
  analyzes the result (feeds the AI path).
- **Sessions** — flat, git-friendly file store; notes, history, artifacts,
  context, export/import, and an active-session pointer.
- **REPL** — rustyline loop with slash-commands (`/recon`, `/analyze`,
  `/scaffold`, `/load`, `/context`, `/ai`, `/model`, `/provider`, `/prompt`,
  `/note`, `/export`, …).
- **Output** — colored box-drawing text, markdown, and a stable JSON schema
  (see `docs/json-schema.md`); honors `--no-color`/`NO_COLOR`/tty; streaming.
- **Config** — 5-layer precedence, `${ENV}` interpolation, secret masking.
- **Docs** — README, `docs/json-schema.md`, `docs/configuration.md`,
  `docs/asm-reference.md`, `SECURITY.md`, dual `LICENSE-MIT`/`LICENSE-APACHE`.
- **Tests** — 13 unit + 6 integration tests.

### Cross-platform notes

- Paths via `dirs` (`%APPDATA%` / `Application Support` / XDG).
- TLS via `rustls` (no OpenSSL/schannel build dependency).
- ANSI VT enabled on Windows; `$EDITOR`/`$PAGER` fall back to `notepad`/`more`.
- Closed downstream pipe (`| head`) exits cleanly instead of panicking.

### Known limitations

- `report` supports markdown only (html/pdf pending).
- MCP server mode (RFC §13.4) and the ambient Claude-Code provider are not yet
  implemented (RFC v0.5).
- REPL tab-completion is basic (history + reverse-search).
- egghunter/loader asm are correct-by-shape scaffolds requiring on-target
  syscall/badchar verification, per the SCAFFOLD contract.
