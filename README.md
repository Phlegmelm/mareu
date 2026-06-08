# Mareu

**A terminal utility for vulnerability research, exploit development, and security tooling.**

```
  ███╗   ███╗ █████╗ ██████╗ ███████╗██╗   ██╗
  ████╗ ████║██╔══██╗██╔══██╗██╔════╝██║   ██║
  ██╔████╔██║███████║██████╔╝█████╗  ██║   ██║
  ██║╚██╔╝██║██╔══██║██╔══██╗██╔══╝  ██║   ██║
  ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗╚██████╔╝
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝
```

Mareu accelerates the three phases of vulnerability research that consume the
most time: attack-surface mapping, root-cause analysis, and PoC scaffolding. It
lives in your shell, reads your code, and does one thing per invocation. It can
optionally use a language model — but that is a flag you pass (`--ai`), not a
mode you are put in.

It is not a scanner. It does not run Nmap. It has no dashboard.

> This implementation covers RFC-0001 milestones **v0.1–v0.4** (offline core,
> AI layer, sessions, REPL) and runs on **Linux, macOS, and Windows**.

---

## Design principles (RFC §2)

- **The Unix contract.** Reads stdin, writes stdout, exits nonzero on failure.
  Every subcommand is independently useful and pipeable.
- **Transparency over magic.** `--dry-run` prints the exact assembled prompt
  before anything leaves your machine. No telemetry. No hidden heuristics.
- **Offline-first.** The static core (recon, analyze, scaffold templates,
  sessions) works with **no network access**. AI is additive.
- **Competence assumed.** No disclaimers, no hand-holding. Built for people who
  are the professional.

---

## Install

```bash
cargo build --release
# binary at ./target/release/mareu  (mareu.exe on Windows)
```

Requires a Rust toolchain (1.74+). No system libraries beyond what `rustls`
bundles — TLS is pure-Rust, so the same `cargo build` works on all three
platforms.

---

## Quick start

```bash
# Map the attack surface of a tree, focused on pre-auth paths (no AI, offline)
mareu recon ./src --filter pre-auth

# Pipe a file into root-cause analysis with CWE + CVSS
cat src/parser.c | mareu analyze --finding "missing bounds check before memcpy" --cwe --cvss

# Line-focused analysis
mareu analyze src/parser.c --line 247

# Generate a UAF crash reproducer with ASAN (template, offline)
mareu scaffold --type reproducer --class uaf --vuln "CVE-2026-XXXX ksmbd" --asan

# Machine-readable output for tooling / Claude Code / jq
mareu analyze src/tls.c --line 312 --cwe --output json | jq .findings

# Turn on AI assistance (requires a configured provider)
mareu analyze src/parser.c --line 247 --ai

# Inspect exactly what would be sent — nothing leaves the machine
mareu analyze src/parser.c --line 247 --ai --dry-run
```

---

## The AI layer is opt-in (RFC §3)

`mareu analyze foo.c` runs **only** deterministic static analysis. `--ai` calls
the configured provider. AI-sourced content is rendered in a visually distinct
`[AI]` block so you always know which parts came from inference.

| Flag | Effect |
|------|--------|
| `--ai` | Enable the AI layer for this invocation |
| `--no-ai` | Hard-disable AI even if `ai.default = true` (scripting escape hatch) |
| `--dry-run` | Print the assembled prompt + context, make **no** API call |

Set `ai.default = true` in config to flip the default; `--no-ai` still overrides
per-invocation.

### Providers (RFC §8)

| Provider | Key | Notes |
|----------|-----|-------|
| `openrouter` | `OPENROUTER_API_KEY` | Routes to Claude, GPT, Gemini, Mistral, … |
| `anthropic` | `ANTHROPIC_API_KEY` | Direct Messages API |
| `openai` | `OPENAI_API_KEY` | Any OpenAI-compatible endpoint via `base_url` |
| `ollama` | — | Local, keyless, **works air-gapped** (the default) |

```bash
mareu config providers          # key status + reachability for every provider
mareu config set provider.default openrouter
mareu config set ai.default true
```

The default provider is `ollama` so a fresh install is fully functional offline.

---

## Subcommands (RFC §9)

| Command | Purpose |
|---------|---------|
| `mareu recon <target>` | Map attack surface of a source tree or file |
| `mareu analyze [file]` | Root-cause analysis (stdin or file) |
| `mareu scaffold` | Generate PoC / exploit / reproducer / report scaffolding |
| `mareu session` | Manage named research sessions |
| `mareu shell` | Interactive REPL for sustained work |
| `mareu report` | Disclosure-ready report from a session or stdin |
| `mareu config` | Configuration management |
| `mareu banner` | Print the banner (cycle styles) |
| `mareu completions <shell>` | Shell completion script (bash/zsh/fish/powershell/elvish) |
| `mareu man [--dir D]` | Generate man page(s) |

Run `mareu <cmd> --help` for the full flag surface.

```bash
# Binary analysis via objdump
mareu analyze ./target_binary --decompile --ai

# Shell completions
mareu completions bash > /etc/bash_completion.d/mareu
mareu completions powershell | Out-String | Invoke-Expression   # Windows
```

### Scaffolding & the honest policy (RFC §4)

Mareu generates real, runnable starting points per bug class (BOF, UAF, format
string, protocol fuzzers, crash reproducers, disclosure reports). Every artifact
carries a machine-readable header stating what it is, what was assumed, and
whether AI touched it.

- `--unsafe` unlocks aggressive output (full exploit scaffolds, ROP/shellcode
  stubs). Without it you get crash reproducers, sanitizer harnesses, and offset
  tooling. The distinction is logged in the header.
- The **intent check** declines requests framed as "attack this named external
  host" (e.g. `--vuln "pwn target.victim.com"`) — reframe in terms of the bug
  class and it proceeds. See `SECURITY.md`.

```bash
# Crash-level (no --unsafe)
mareu scaffold --type poc --class bof --vuln "stack overflow in verify_pac_checksums"

# Full exploit scaffold (gated)
mareu scaffold --type exploit --class bof --vuln "stack overflow in verify_pac_checksums" --unsafe --ai
```

#### Assembly scaffolds (`--lang asm`)

Generated programmatically (correct by construction), not from `.hbs` templates.
Artifacts are selected by `--class`: `shellcode` (null-free `execve("/bin/sh")`),
`egghunter` (access(2)-based), `loader` (mmap-RWX stager), `ret2` (proof/`win`
stub). `--arch` picks `x86_64` (default), `x86`, or `aarch64`. `--syntax` picks
`nasm`, `gas`, or `both` (default — emits a matched `.nasm` + `.s` pair; non-x86
arches collapse to GNU `as`).

```bash
# null-free x86_64 execve shellcode in NASM/Intel and GNU as/AT&T
mareu scaffold --type exploit --class shellcode --lang asm --unsafe --save

# aarch64 variant (GNU as)
mareu scaffold --type exploit --class shellcode --lang asm --arch aarch64 --unsafe
```

There is **no silent fallback**: asking for an offline language with no template
(e.g. `--lang rust` without `--ai`) is a clear error, not C mislabeled as Rust.

---

## Sessions & the REPL (RFC §9.4–§9.5, §12)

Sessions are flat, human-readable, git-friendly files under the platform data
directory (`%APPDATA%\mareu` / `~/Library/Application Support/mareu` /
`~/.local/share/mareu`).

```bash
mareu session new ksmbd --target ./ksmbd
mareu shell --session ksmbd --ai     # sustained work with /slash-commands
mareu session export ksmbd > report.md
```

In the REPL: `/recon`, `/analyze`, `/scaffold`, `/load`, `/context`, `/ai`,
`/model`, `/provider`, `/prompt`, `/note`, `/export`, `/help`, `/exit`.

---

## Configuration (RFC §10)

Resolution order (later wins): compiled defaults → user config → `./.mareu.toml`
→ `MAREU_*` env vars → CLI flags. `config/default.toml` documents every key.

```bash
mareu config show         # fully resolved config (secrets masked)
mareu config edit         # open the user config in $EDITOR
```

API keys support `${ENV_VAR}` interpolation and are never printed by
`config show`.

---

## Output (RFC §5, §14)

`--output text` (default, boxed + colored) · `markdown` · `json`. Color respects
`--no-color` and the `NO_COLOR` standard and auto-disables when stdout is not a
terminal, so pipes stay clean. AI output streams by default (`--no-stream` to
buffer).

---

## Documentation

- [`docs/json-schema.md`](docs/json-schema.md) — the stable `--output json` API contract
- [`docs/configuration.md`](docs/configuration.md) — every config key + precedence
- [`docs/asm-reference.md`](docs/asm-reference.md) — assembly scaffold reference
- [`CHANGELOG.md`](CHANGELOG.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option.

See [`SECURITY.md`](SECURITY.md) for the responsible-disclosure statement and how
to report a vulnerability in Mareu itself.
