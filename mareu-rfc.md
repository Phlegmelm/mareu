# RFC-0001: Mareu
### A Terminal Utility for Vulnerability Research, Exploit Development, and Security Tooling

**Status:** Draft  
**Author:** @ReproBro  
**Revision:** 0.2  
**Created:** 2026-06-08  

---

## Table of Contents

1. [What Is Mareu](#1-what-is-mareu)
2. [Design Philosophy](#2-design-philosophy)
3. [The AI Layer — Opt-In, Not Default](#3-the-ai-layer--opt-in-not-default)
4. [PoC and Exploit Code — The Honest Policy](#4-poc-and-exploit-code--the-honest-policy)
5. [Terminal Output & Visual Identity](#5-terminal-output--visual-identity)
6. [ASCII Banner](#6-ascii-banner)
7. [Architecture](#7-architecture)
8. [Provider Abstraction](#8-provider-abstraction)
9. [Subcommand Surface](#9-subcommand-surface)
10. [Configuration](#10-configuration)
11. [Prompt Architecture](#11-prompt-architecture)
12. [Session State Format](#12-session-state-format)
13. [Claude Code Integration](#13-claude-code-integration)
14. [Output Rendering](#14-output-rendering)
15. [Crate Dependencies](#15-crate-dependencies)
16. [Non-Goals (v0.1)](#16-non-goals-v01)
17. [Open Questions](#17-open-questions)
18. [Milestones](#18-milestones)

---

## 1. What Is Mareu

Mareu is a terminal utility for people who find bugs in software for a living, for sport, or out of compulsion. It accelerates the three phases of vulnerability research that consume the most time without producing insight: attack surface mapping, root-cause analysis, and PoC scaffolding.

It is not a scanner. It does not run Nmap. It does not wrap Nuclei templates. It does not have a dashboard.

It lives in your shell, it reads your code, and it does one thing per invocation with no ceremony. It can optionally use a language model to assist — but that is a flag you pass, not a mode you are put in.

The target audience is not beginner security students. It is anyone who does real vulnerability research: independent researchers, red teamers, CTF players at the top end, bug bounty hunters going after pre-auth RCE, audit engineers, and people writing their own tooling. Mareu is written for people who would be annoyed by most security tools.

---

## 2. Design Philosophy

### 2.1 The Unix Contract

Mareu is a Unix tool. It reads from stdin. It writes to stdout. It exits nonzero on failure. Every subcommand is independently useful, independently composable, and independently scriptable. Nothing requires a prior step. Nothing produces output you cannot pipe somewhere else.

This is not a stylistic choice — it is the design constraint from which everything else follows. A tool that breaks the Unix contract is not a tool; it is an application pretending to be one.

### 2.2 Transparency Over Magic

Every decision Mareu makes is inspectable. Every prompt it constructs can be printed with `--dry-run`. Every config value has a documented precedence order. Every file it touches lives in a path the user chose or agreed to.

There are no hidden heuristics. There is no telemetry. There is no "smart mode" that silently changes behavior. When Mareu does something, you can find out why in one command.

This matters especially for the AI layer. The model is not a black box embedded in the tool. It is a provider — one that can be swapped, disabled, or prompted differently. The system prompt is a file you can read and edit. The assembled context is a string you can inspect before it leaves your machine.

### 2.3 Competence as a Default Assumption

Mareu assumes you know what you are doing. It does not add disclaimers. It does not ask if you are sure. It does not refuse to analyze dangerous-looking code. It does not suggest you consult a professional.

The tool is designed for people who are the professional.

This assumption permeates everything: the defaults, the output verbosity, the error messages, the prompt tone, the PoC generation behavior. Mareu treats the user as someone who would be insulted by hand-holding, because they would be.

### 2.4 Offline-First

Mareu must be fully functional with no network access. The AI features are an optional enhancement. The core tooling — surface mapping via static analysis hooks, PoC templating, report generation, session management — works completely offline. This is not a fallback mode. It is the primary mode. AI is additive.

This matters for air-gapped labs, VMs with no external routing, and people who simply do not want their code leaving their machine.

### 2.5 The Tool Does Not Have Opinions About Your Research

Mareu does not have a built-in ethics engine. It does not maintain a list of prohibited targets. It does not detect "intent." It is a tool. The person operating it is responsible for how it is used. Responsible disclosure is not enforced by Mareu — it is practiced by researchers who already understand what it means.

The project will include, in the README and documentation, a clear statement about responsible disclosure norms and what the authors expect from users. This is not a terms-of-service substitution; it is a statement of values. The distinction matters.

### 2.6 Longevity Over Features

Mareu is written in Rust because the goal is a tool that compiles on a machine ten years from now without dependency rot. The dependency footprint is kept small. Async is used only where genuinely needed (provider HTTP calls). The session format is flat files, not a database. The config format is TOML, not YAML with anchors. Nothing about Mareu should require archaeology to understand in two years.

New features are added when they have a clear use case that cannot be served by the existing command surface plus Unix pipes.

### 2.7 Aesthetic Seriousness

The terminal output looks good. This is not vanity. A tool that looks like it was written by someone who cares is a tool that gets used. The banner, the colors, the column alignment, the status indicators — all of it is considered. None of it is gratuitous.

The visual language is: deep purple foundation with bright yellow as the high-contrast accent, box-drawing characters for structure, no emoji in default mode, dense information layout rather than padded whitespace.

---

## 3. The AI Layer — Opt-In, Not Default

### 3.1 Core Principle

Running `mareu analyze foo.c` does **not** call a language model. It runs static analysis and produces structured output from Mareu's own logic. Running `mareu analyze foo.c --ai` calls the configured provider.

AI is a flag, not the default. This is non-negotiable and is baked into the CLI contract from day one. Changing this in a future version would be a breaking change and would require a major version bump.

### 3.2 Why

Several categories of users do not want AI involvement:

- Researchers in air-gapped or restricted environments
- People who have assessed LLM-assisted analysis and found the noise-to-signal ratio unacceptable for their workflow
- People who object on principle to routing their research through a commercial API
- People who want deterministic, reproducible output in CI/automation
- People who are simply not interested

None of these positions require justification. The tool should not make a judgment about them.

### 3.3 `--ai` Flag Behavior

When `--ai` is passed:

1. Mareu checks for a configured provider in the active config. If none exists, it exits with a clear error and a pointer to `mareu config providers`.
2. It assembles the context: system prompt template + static analysis output + injected files + session history (if session is active).
3. It prints a one-line status to stderr indicating which provider and model are being used.
4. It streams the response to stdout.
5. If a session is active and `auto_save = true`, it appends the turn to `history.jsonl`.

The `--ai` flag can be aliased via config so power users who always want it can set `ai.default = true`. The behavior is still inspectable — `mareu config show` will show the override.

### 3.4 `--no-ai` Override

If `ai.default = true` is set in config, passing `--no-ai` hard-disables the AI layer for that invocation. This is the escape hatch for scripting and automation.

### 3.5 Provider Status

`mareu config providers` prints a table of all configured providers, their status (key present / reachable / model valid), and the active default. This is the first thing to run when something is not working.

### 3.6 What AI Does and Does Not Do

AI-assisted mode feeds Mareu's own static output *plus* the raw input to the model. The model does not replace the static analysis; it annotates it. In the output, AI-generated content is visually distinguished from Mareu's own analysis (see §5).

This matters for trust calibration. A researcher should be able to read Mareu's output and know which parts came from deterministic logic and which came from inference.

---

## 4. PoC and Exploit Code — The Honest Policy

### 4.1 The Problem

Most AI-integrated security tools either (a) refuse to generate exploit code entirely, producing useless hedged output, or (b) generate it without comment, ignoring that the quality and safety of generated PoC code varies enormously and the researcher needs to know what they are getting.

Neither approach is honest.

### 4.2 Mareu's Position

Mareu generates PoC and exploit scaffolding. This is a core feature, not an edge case. The target audience are people who write this code as part of their work. Refusing to help them is not a safety measure — it is an inconvenience that sends them to a different tool.

The honest constraints are:

**What Mareu generates well:**
- Crash reproducers (ASAN/UBSAN harnesses, de Bruijn offset tooling)
- Protocol fuzzing scaffolds
- Integer overflow / heap layout analysis stubs
- Forged packet constructors for protocol bugs
- Shellcode stubs with documented assumptions
- Full PoC scaffolds for well-understood bug classes (stack BOF, heap UAF, format string, type confusion)
- Disclosure-ready writeup templates

**What Mareu generates with caveats clearly stated in output:**
- Exploit chains involving multiple components (the chain logic is scaffolded; the glue between stages may require manual work)
- Kernel exploits (generated scaffold will note kernel version assumptions and what needs to be verified)
- ASLR/PIE bypass scaffolding (generated with explicit notes about what leak primitive is assumed)

**What Mareu does not generate:**
- Weaponized, deployment-ready malware targeting specific production infrastructure
- Code explicitly designed to harm third parties who have not consented to security testing

This distinction is not about the code itself — most exploit code is dual-use by definition. It is about intent expressed in the request. `mareu scaffold --type exploit --vuln "UAF in ksmbd"` generates a kernel UAF exploit scaffold. `mareu scaffold --type exploit --vuln "pwn target.victim.com"` is a different kind of request and Mareu will say so.

### 4.3 The `--scaffold` Quality Disclaimer

Every generated scaffold includes a machine-readable header:

```
# mareu scaffold — generated 2026-06-08
# vuln:   UAF in ksmbd knocking handler (CVE-XXXX-YYYY)
# class:  kernel UAF / type confusion
# arch:   x86_64 assumed
# status: SCAFFOLD — not tested, verify offsets, check kernel version
# --ai:   false (template-generated)
```

When `--ai` is used, the header includes the model used and a note that the code is AI-generated and requires manual verification. This is not a legal disclaimer. It is a quality signal. Generated PoC code is a starting point, not a finished product, and the output says so.

### 4.4 The `--unsafe` Flag

Some scaffold types are gated behind `--unsafe`. This is not a safety measure in the "we're preventing harm" sense. It is a deliberate friction point that forces the researcher to express explicit intent for the most aggressive output modes (e.g., full weaponized exploit with ROP chain, rather than crash reproducer). The flag exists to distinguish "I want a PoC that crashes the process" from "I want a working exploit with a payload." Both are legitimate; they are different things and should be different commands.

---

## 5. Terminal Output & Visual Identity

### 5.1 Design Language

Mareu's terminal output follows a strict visual grammar:

**Color palette (default dark terminal):**
```
Background:  terminal default (no forced background)
Primary:     #D4BAFF  — soft lavender — used for body text
Accent:      #9B59FF  — deep violet — used for findings, warnings, section markers
Highlight:   #FFE033  — bright yellow — used for high-severity findings, key values
Dim:         #6B5C8A  — muted purple — used for metadata, timestamps, file paths
Success:     #C8FF57  — acid yellow-green — used for pass/clean/confirmed states
Info:        #BF9FFF  — light purple — used for AI-generated content markers
Border:      #3D2B5E  — dark violet — used for box-drawing
```

All colors are configurable and can be disabled with `--no-color` or `NO_COLOR=1` (respects the `NO_COLOR` standard).

**Typography conventions:**
- Section headers: uppercase, preceded by `▸` marker
- File paths: dim, always relative when possible
- Findings: numbered, left-aligned, with severity prefix
- Code inline: not colored — terminal monospace is enough
- AI-sourced content: prefixed with `[AI]` marker in light purple
- Metadata: right-aligned where space allows, dim

### 5.2 Output Anatomy

A typical `mareu analyze` invocation produces:

```
▸ ANALYSIS  src/parser.c:247
  target    src/parser.c
  focus     line 247 — recv() return value unchecked
  provider  — (static only)

  ┌─ FINDING 1 ─────────────────────────────────────────────────────────┐
  │ SEVERITY   HIGH                                                      │
  │ CLASS      CWE-252 — Unchecked Return Value                          │
  │ LINE       247                                                       │
  │ REACHABLE  pre-auth, network-reachable via parse_client_hello()     │
  │                                                                      │
  │ recv() at line 247 does not check for -1 or 0 return. On EINTR or  │
  │ connection close, n is passed directly to memcpy as a size          │
  │ argument. On 64-bit, -1 casts to SIZE_MAX.                          │
  │                                                                      │
  │ PATCH VECTOR  check n <= 0 before memcpy; handle EINTR with retry   │
  └──────────────────────────────────────────────────────────────────────┘

  ┌─ FINDING 2 ─────────────────────────────────────────────────────────┐
  │ SEVERITY   MEDIUM                                                    │
  │ ...                                                                  │
  └──────────────────────────────────────────────────────────────────────┘

  ─────────────────────────────────────────────────────────────────────
  2 finding(s)  ·  1 high  ·  1 medium  ·  0 low
  time: 0.3s  ·  lines analyzed: 847  ·  session: —
```

When `--ai` is active, AI-generated analysis is rendered in a visually distinct block:

```
  ┌─ [AI] EXTENDED ANALYSIS ────────────────────────────────────────────┐
  │ model: anthropic/claude-sonnet-4-5 via openrouter                   │
  │                                                                      │
  │ The recv() issue at line 247 is exploitable if the attacker can     │
  │ induce a partial read. On Linux, MSG_WAITALL prevents partial reads  │
  │ for TCP but is not used here. The -1 → SIZE_MAX path through        │
  │ memcpy is a classic pre-auth write primitive...                      │
  └──────────────────────────────────────────────────────────────────────┘
```

### 5.3 Verbosity Levels

| Flag | Level | Output |
|------|-------|--------|
| `-q` / `--quiet` | 0 | Findings only, no metadata |
| (default) | 1 | Standard output as above |
| `-v` | 2 | Includes file context snippets |
| `-vv` | 3 | Includes assembled prompt (when `--ai`), full token usage |
| `-vvv` | 4 | Debug: includes raw API request/response JSON |

### 5.4 JSON Output

`--output json` produces machine-readable output suitable for piping to `jq`, feeding into CI, or building tooling on top of Mareu:

```json
{
  "command": "analyze",
  "target": "src/parser.c",
  "timestamp": "2026-06-08T14:22:01Z",
  "ai_used": false,
  "findings": [
    {
      "id": 1,
      "severity": "HIGH",
      "cwe": "CWE-252",
      "line": 247,
      "reachable": true,
      "pre_auth": true,
      "summary": "recv() return value unchecked; n passed to memcpy as size",
      "patch_vector": "check n <= 0 before memcpy"
    }
  ],
  "summary": { "total": 2, "high": 1, "medium": 1, "low": 0 },
  "duration_ms": 312
}
```

### 5.5 Progress and Streaming

When streaming AI output, Mareu shows a spinner on stderr that does not pollute stdout:

```
  ⠸ querying anthropic/claude-sonnet-4-5...
```

The spinner disappears when output begins. Stdout is clean for piping even during streaming.

---

## 6. ASCII Banner

The banner prints on interactive invocations and in the REPL. It is suppressed when stdin is a pipe, when `--quiet` is passed, and when `MAREU_NO_BANNER=1` is set.

### 6.1 Full Banner (REPL / `mareu --version`)

```
                              
  ███╗   ███╗ █████╗ ██████╗ ███████╗██╗   ██╗
  ████╗ ████║██╔══██╗██╔══██╗██╔════╝██║   ██║
  ██╔████╔██║███████║██████╔╝█████╗  ██║   ██║
  ██║╚██╔╝██║██╔══██║██╔══██╗██╔══╝  ██║   ██║
  ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗╚██████╔╝
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ 

  vulnerability research utility  ·  v0.1.0
  @Phlegmelm  ·  github.com/phlegmelm/mareu
  ─────────────────────────────────────────
  ai: disabled  ·  session: none  ·  provider: —
```

### 6.2 Compact Banner (subcommand invocation)

```
  mareu v0.1.0  ·  @Phlegmelm
```

Printed to stderr only, suppressed with `-q`.

### 6.3 Banner Alternatives

The config key `banner.style` accepts three values:

| Value | Output |
|-------|--------|
| `full` | Block letter banner with status line |
| `compact` | Single line |
| `none` | No banner |

A future `mareu banner` subcommand can cycle through available styles for the README and documentation.

### 6.4 Design Notes on the Banner

The block-letter style is intentional. It reads at a glance in a terminal multiplexer pane. The name `MAREU` has clean geometry in block letters — the M and U are strong anchors. The status line below the banner serves a functional purpose: it tells you immediately whether AI is enabled and whether a session is active before you type a single command.

The banner should not use color by default — it should render cleanly in any terminal palette. When color is enabled, the block letters are rendered in deep violet, the `·` separators in bright yellow, and the metadata line in muted purple.

---

## 7. Architecture

```
mareu/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── SECURITY.md                   # Responsible disclosure statement
├── config/
│   └── default.toml              # Compiled-in defaults
├── prompts/                      # System prompt templates (compiled into binary)
│   ├── recon.md
│   ├── analyze.md
│   ├── scaffold.md
│   └── shell.md
├── src/
│   ├── main.rs                   # Clap entrypoint, banner, dispatch
│   ├── cli/
│   │   ├── mod.rs                # Shared CLI types, --ai flag injection
│   │   ├── recon.rs
│   │   ├── analyze.rs
│   │   ├── scaffold.rs
│   │   ├── session.rs
│   │   ├── config.rs
│   │   └── shell.rs
│   ├── repl/
│   │   ├── mod.rs                # rustyline REPL loop
│   │   └── commands.rs           # Slash-command dispatch
│   ├── provider/
│   │   ├── mod.rs                # Provider trait + registry
│   │   ├── openrouter.rs
│   │   ├── anthropic.rs
│   │   ├── openai.rs             # OpenAI-compatible (covers many endpoints)
│   │   └── ollama.rs
│   ├── analysis/
│   │   ├── mod.rs                # Static analysis orchestration
│   │   ├── surface.rs            # Attack surface mapping (non-AI)
│   │   ├── taint.rs              # Simple taint tracking
│   │   └── cwe.rs                # CWE classification heuristics
│   ├── scaffold/
│   │   ├── mod.rs                # Template registry
│   │   ├── templates/            # Handlebars scaffold templates
│   │   │   ├── poc_bof.c.hbs
│   │   │   ├── poc_uaf.c.hbs
│   │   │   ├── poc_fmt.c.hbs
│   │   │   ├── poc_proto.py.hbs
│   │   │   ├── reproducer.c.hbs
│   │   │   └── report.md.hbs
│   │   └── header.rs             # Generated scaffold header block
│   ├── session/
│   │   ├── mod.rs
│   │   └── store.rs
│   ├── context/
│   │   └── mod.rs                # Context assembly + token budget management
│   ├── output/
│   │   ├── mod.rs
│   │   ├── render.rs             # Terminal rendering (boxes, colors, alignment)
│   │   ├── json.rs               # JSON serialization
│   │   └── stream.rs             # Streaming output handler
│   └── config/
│       ├── mod.rs
│       └── schema.rs             # Config struct with serde defaults
└── tests/
    ├── integration/
    └── fixtures/                 # Sample C files for integration tests
```

---

## 8. Provider Abstraction

All AI backends implement a single async trait:

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse>;
    async fn stream(&self, req: CompletionRequest, tx: Sender<String>) -> Result<()>;
    async fn health(&self) -> Result<ProviderStatus>;
    fn name(&self) -> &str;
    fn model(&self) -> &str;
}

pub struct CompletionRequest {
    pub system:   Option<String>,
    pub messages: Vec<Message>,
    pub model:    String,
    pub stream:   bool,
    pub max_tokens: Option<u32>,
}

pub struct CompletionResponse {
    pub content:    String,
    pub model_used: String,
    pub usage:      Option<TokenUsage>,
    pub latency_ms: u64,
}

pub struct ProviderStatus {
    pub name:       String,
    pub reachable:  bool,
    pub model_valid: bool,
    pub key_present: bool,
    pub message:    Option<String>,
}
```

**Supported providers (v0.1):**

| Provider | Key | Notes |
|----------|-----|-------|
| OpenRouter | `openrouter` | Default; routes to any model including Claude, GPT, Gemini, Mistral |
| Anthropic | `anthropic` | Direct API |
| OpenAI-compatible | `openai` | Works with any OpenAI-compatible endpoint (Together, Groq, etc.) |
| Ollama | `ollama` | Local; no key; works air-gapped |

Adding a new provider is `impl Provider for YourStruct` in a new file under `src/provider/`, plus registration in `mod.rs`. No other changes required.

---

## 9. Subcommand Surface

### 9.1 `mareu recon`

Map attack surface of a source tree, binary, or protocol spec.

```
USAGE:
    mareu recon [OPTIONS] <TARGET>

ARGS:
    <TARGET>    Path to source tree, binary, or protocol spec

OPTIONS:
    -t, --type <TYPE>       source|binary|protocol [default: auto-detect]
    -f, --filter <FILTER>   Surface focus: "pre-auth", "network", "parser", "ipc", etc.
    -d, --depth <N>         Traversal depth for source trees [default: unlimited]
        --entry <FN>        Known entry point function name (repeatable)
        --ai                Enable AI-assisted surface annotation
        --dry-run           Print assembled context without sending
    -o, --output <FMT>      text|json|markdown [default: text]
    -q / -v / -vv / -vvv    Verbosity
```

**Without `--ai`:** Mareu walks the source tree and produces a structured list of: network-reachable entry points (functions that directly follow `accept()`, `recv()`, `read()` chains), parser entry points, auth gate locations, and flag sites (suspicious patterns: unchecked returns, integer operations before alloc, sprintf/strcpy/memcpy with user-influenced size).

**With `--ai`:** The surface map is sent to the model with a recon prompt. The model annotates each entry point with exploitability assessment and suggests audit priority order.

```bash
# Typical usage
mareu recon ./src --filter pre-auth --ai

# Pipe a file list into recon
fd -e c . src/ | mareu recon --type source --filter parser

# Recon a binary
mareu recon ./target_binary --type binary --ai
```

---

### 9.2 `mareu analyze`

Root-cause analysis of a suspected vulnerability.

```
USAGE:
    mareu analyze [OPTIONS] [FILE]

ARGS:
    [FILE]    Source file or binary (or stdin)

OPTIONS:
    -l, --line <LINE>       Focus on specific line or range (e.g. 247 or 240:260)
    -f, --finding <TEXT>    Describe the suspected issue
    -c, --context <FILE>    Additional context files (repeatable)
    -w, --cwe               Suggest CWE classification
    -s, --cvss              Generate CVSS 3.1 vector
        --decompile         Treat input as binary; run objdump/Ghidra before analysis
        --ai                Enable AI-assisted analysis
        --dry-run           Print assembled context without sending
    -o, --output <FMT>      text|json|markdown
    --session <NAME>        Attach to named session
```

```bash
# Classic pipe usage
cat src/kdc/do_as_req.c | mareu analyze --finding "missing bounds check before memcpy" --cwe --cvss --ai

# Line-focused
mareu analyze src/parser.c --line 247 --ai

# Binary analysis (requires objdump in PATH)
mareu analyze ./target --decompile --ai
```

---

### 9.3 `mareu scaffold`

Generate PoC, exploit, or reproducer scaffolding.

```
USAGE:
    mareu scaffold [OPTIONS]

OPTIONS:
    -t, --type <TYPE>       poc|exploit|reproducer|harness|fuzzer|report
    -v, --vuln <TEXT>       Vulnerability description or CVE identifier
    -l, --lang <LANG>       c|python|rust|asm|bash [default: c]
    -c, --class <CLASS>     bof|uaf|fmt|race|proto|logic|oob|infoleak
    -f, --file <FILE>       Attach relevant source/headers (repeatable)
        --asan              Include ASAN-friendly patterns
        --arch <ARCH>       x86_64|aarch64|x86 [default: x86_64]
        --template <PATH>   Use custom .hbs template instead of built-in
        --ai                AI-assisted scaffold generation
        --unsafe            Enable aggressive output modes (full exploit, ROP stub)
        --dry-run           Print template + context without generating
    -o, --output <FMT>      text|json|file (writes to ./mareu_scaffold_<ts>/)
    --session <NAME>        Attach; saves artifact to session store
```

**Template system:** Without `--ai`, scaffold uses Handlebars templates compiled into the binary. Templates are real, runnable starting points for each bug class — not pseudocode. With `--ai`, the template output is sent to the model for augmentation with vuln-specific logic.

**The `--unsafe` gate:** Without `--unsafe`, scaffold generates crash reproducers, ASAN harnesses, and offset tooling. With `--unsafe`, scaffold generates full exploit scaffolds including shellcode stubs, ROP chain placeholders, and payload delivery code. The distinction is explicit and logged in the scaffold header.

```bash
# UAF reproducer with ASAN
mareu scaffold --type reproducer --class uaf --vuln "CVE-2026-XXXX ksmbd" --asan

# Full PoC with AI + unsafe
mareu scaffold --type poc --class bof --vuln "stack overflow in verify_pac_checksums" --ai --unsafe --lang c

# Protocol fuzzing harness
mareu scaffold --type fuzzer --class proto --vuln "SMB2 NEGOTIATE malformed dialect list" --lang python
```

---

### 9.4 `mareu session`

Manage named research sessions.

```
USAGE:
    mareu session <SUBCOMMAND>

SUBCOMMANDS:
    new <NAME>          Create new session with optional target
    list                List all sessions (table: name, target, last active, size)
    show <NAME>         Print session conversation and notes
    attach <NAME>       Set active session for subsequent commands
    detach              Clear active session
    note <NAME> <TEXT>  Append a note to session
    edit <NAME>         Open session notes in $EDITOR
    rm <NAME>           Delete session (with confirmation)
    export <NAME>       Export as disclosure-ready markdown report
    import <FILE>       Import a session from exported markdown
```

---

### 9.5 `mareu shell`

Interactive REPL for sustained target work.

```
USAGE:
    mareu shell [OPTIONS]

OPTIONS:
    -s, --session <NAME>    Attach to existing session
    -t, --target <PATH>     Set initial target context
        --ai                Enable AI by default in shell
```

The REPL maintains conversation history for the session, with full readline support (history, reverse search, tab completion on slash-commands and file paths).

**Slash-commands:**

| Command | Description |
|---------|-------------|
| `/recon [path]` | Run recon on target |
| `/analyze <file> [line]` | Inline analysis |
| `/scaffold [type]` | Launch scaffold wizard |
| `/load <file>` | Inject file into active context |
| `/drop <file>` | Remove file from context |
| `/context` | Show currently loaded context and token count |
| `/note <text>` | Append note to session |
| `/clear` | Clear conversation buffer (keep session and context) |
| `/prompt` | Print assembled system prompt |
| `/model <id>` | Switch model mid-session |
| `/provider <name>` | Switch provider mid-session |
| `/ai` | Toggle AI on/off for this session |
| `/save` | Force flush to session store |
| `/export` | Export current session to markdown |
| `/help` | Print slash-command reference |
| `/exit` | Quit |

---

### 9.6 `mareu config`

Configuration management.

```
USAGE:
    mareu config <SUBCOMMAND>

SUBCOMMANDS:
    show                Print fully resolved config (merged: defaults + file + env)
    set <KEY> <VAL>     Set config value
    unset <KEY>         Remove config override
    edit                Open config file in $EDITOR
    providers           Table: all providers, key status, reachability
    reset               Restore default config (with confirmation)
```

---

### 9.7 `mareu report`

Generate disclosure-ready report from a session or from ad-hoc input.

```
USAGE:
    mareu report [OPTIONS]

OPTIONS:
    -s, --session <NAME>    Build report from session
    -t, --template <PATH>   Custom report template
    -f, --format <FMT>      markdown|html|pdf [default: markdown]
        --ai                AI-assisted writeup generation
    -o, --out <FILE>        Output file [default: stdout]
```

Produces a structured report: executive summary, technical finding blocks (CVSS, CWE, reproduction steps, patch recommendation), timeline, and credits. The template is a Handlebars `.md.hbs` file; the default is compiled into the binary.

---

## 10. Configuration

Config resolution order (later overrides earlier):

1. Compiled-in defaults
2. `$XDG_CONFIG_HOME/mareu/config.toml` (default: `~/.config/mareu/config.toml`)
3. `.mareu.toml` in current directory (project-local config)
4. Environment variables (`MAREU_*`)
5. CLI flags

```toml
[provider]
default = "openrouter"

[provider.openrouter]
api_key  = "${OPENROUTER_API_KEY}"   # env var interpolation
model    = "anthropic/claude-sonnet-4-5"
base_url = "https://openrouter.ai/api/v1"
timeout  = 60

[provider.anthropic]
api_key  = "${ANTHROPIC_API_KEY}"
model    = "claude-sonnet-4-20250514"

[provider.openai]
api_key  = "${OPENAI_API_KEY}"
model    = "gpt-4o"
base_url = "https://api.openai.com/v1"   # override for compatible endpoints

[provider.ollama]
base_url = "http://localhost:11434"
model    = "llama3.1:70b"

[ai]
default        = false          # Set true to enable AI without --ai flag
max_tokens     = 8192
temperature    = 0.2            # Low temp for analysis; bump for creative scaffolding
fallback       = "ollama"       # Provider to fall back to on rate limit/error

[output]
format         = "text"         # text | markdown | json
color          = true
pager          = true           # pipe long output through $PAGER
no_color_env   = true           # respect NO_COLOR env var

[banner]
style          = "full"         # full | compact | none

[context]
max_tokens     = 100000
include_stdin  = true           # auto-include stdin when piped

[session]
store_path     = "~/.local/share/mareu/sessions"
auto_save      = true

[scaffold]
unsafe_default = false          # require --unsafe for aggressive output
header_comment = true           # include machine-readable scaffold header

[analysis]
# Patterns to flag as interesting during static surface mapping
flag_patterns  = [
    "memcpy", "strcpy", "sprintf", "recv", "read", "mmap",
    "malloc", "realloc", "free", "strlen"
]
pre_auth_markers = ["before_auth", "unauthenticated", "anon"]
```

---

## 11. Prompt Architecture

System prompts live in `prompts/` as Markdown templates and are compiled into the binary via `include_str!`. They are the single most important tunable in the entire tool — the quality of AI-assisted output is almost entirely determined by the system prompt.

### 11.1 Prompt Design Principles

- **No caveats in output.** The model is instructed to produce technical analysis directly. No "I should note that..." preambles.
- **Researcher-level assumptions.** The model is told the user is a professional vulnerability researcher who does not need basic concepts explained.
- **Structured output.** Prompts instruct the model to produce output that Mareu can parse: labeled sections, consistent severity vocabulary, CWE notation.
- **Explicit hallucination guard.** Prompts instruct the model to say "cannot determine from provided context" rather than invent offsets, addresses, or behavior it cannot see in the code.

### 11.2 Prompt Template Variables

```
{{target}}           — file path or binary name
{{focus}}            — user-provided finding description
{{context_files}}    — injected file contents
{{session_history}}  — prior turns (if session active)
{{static_output}}    — Mareu's own static analysis output
{{cwe_requested}}    — boolean, triggers CWE output block
{{cvss_requested}}   — boolean, triggers CVSS output block
{{arch}}             — target architecture
{{unsafe_mode}}      — boolean, unlocks aggressive output
```

### 11.3 Inspecting Prompts

`--dry-run` on any AI-enabled command prints the fully assembled prompt and context to stdout before any API call. This is the primary debugging tool and the primary transparency mechanism.

`/prompt` in the REPL does the same for the current session state.

---

## 12. Session State Format

```
~/.local/share/mareu/sessions/<name>/
├── meta.toml           # target, created_at, last_active, provider, model
├── history.jsonl       # conversation turns (newline-delimited JSON)
├── notes.md            # freeform analyst notes
├── context.toml        # currently loaded files and their token counts
└── artifacts/          # generated files
    ├── poc_001.c
    ├── poc_002.py
    └── report_draft.md
```

The format is deliberately human-readable and git-friendly. Sessions can be committed to a private repo, diffed, and shared. The `export` command assembles everything into a single structured markdown document suitable for a disclosure package.

---

## 13. Claude Code Integration

### 13.1 What This Means

Claude Code is Anthropic's agentic coding tool — a terminal assistant with file system access, command execution, and multi-turn context. Mareu and Claude Code are complementary: Mareu is purpose-built for the vulnerability research workflow; Claude Code is a general-purpose coding agent. The integration makes each more useful.

### 13.2 Mareu as a Claude Code Tool

Mareu exposes a `--output json` mode on all commands specifically so Claude Code can call it as a subprocess and parse the output. From a Claude Code session working on a security audit:

```
# Claude Code invoking Mareu as a tool
$ mareu analyze src/tls.c --line 312 --cwe --output json | jq .findings
```

Claude Code reads the structured findings, reasons about them, and can then invoke `mareu scaffold` to generate a reproducer — all within a single agentic session. The JSON schema is stable and documented; it is an explicit API contract, not an internal implementation detail.

### 13.3 Claude Code as a Mareu Backend

When Mareu is used interactively inside a Claude Code session, the `--ai` flag can be configured to route through the ambient Claude Code context rather than making a separate API call. Config key: `provider.default = "claude_code_ambient"`. This provider implementation reads `CLAUDE_CODE_SESSION_ID` from the environment (set by Claude Code) and uses the in-process context rather than a new conversation.

This means: when you are already in a Claude Code session auditing a codebase, `mareu analyze foo.c --ai` uses the same model context Claude Code has, with all the files Claude Code already loaded. No redundant context upload.

### 13.4 Mareu as a Claude Code MCP Server

Mareu exposes an optional MCP (Model Context Protocol) server mode:

```bash
mareu mcp --port 3456
```

When running, Claude Code can connect to it as a local MCP server and invoke Mareu's capabilities as tools:

| Tool name | Description |
|-----------|-------------|
| `mareu_recon` | Run attack surface mapping |
| `mareu_analyze` | Analyze a file or function |
| `mareu_scaffold` | Generate PoC/exploit scaffold |
| `mareu_session_context` | Return current session state as structured data |

This turns Mareu from a standalone tool into a Claude Code capability — available to be called by the agent as part of a larger audit workflow, without the researcher having to manually invoke it.

### 13.5 Shared Session State

When a Claude Code session and a Mareu session are both active on the same target, they can share state via the session store. Claude Code reads `~/.local/share/mareu/sessions/<name>/` as structured context. Mareu appends Claude Code's findings as session notes. The session becomes the single source of truth for the audit, regardless of which tool generated each piece.

### 13.6 Workflow Example

```
Researcher opens Claude Code on a target codebase.
Claude Code + Mareu MCP server = Claude Code has access to mareu_recon, mareu_analyze.

Claude Code:  "Run recon on src/ filtering for pre-auth network surfaces"
→ mareu_recon fires, returns structured JSON surface map
Claude Code:  "Analyze the top 3 entry points"  
→ mareu_analyze fires 3x with --ai, returns findings
Claude Code:  "Generate a reproducer for finding 1"
→ mareu_scaffold fires, writes poc_001.c to session artifacts/
Researcher:   opens shell, reviews poc_001.c, edits offsets, runs it
Researcher:   `mareu session note crashtest "confirmed crash on Linux 6.6.28"`
Claude Code:  "Draft the disclosure report"
→ mareu_report fires with --ai, uses full session history
```

End-to-end audit workflow, from recon to draft disclosure, in a single shared session.

---

## 14. Output Rendering

Three output modes, controlled by `--output`:

| Mode | Flag | Use case |
|------|------|----------|
| `text` | default | Interactive terminal use |
| `markdown` | `--output markdown` | Pipe to `glow`, copy to notes |
| `json` | `--output json` | Automation, Claude Code, `jq` |

Streaming is on by default. Disable with `--no-stream` for use in scripts that buffer stdout.

The pager (`$PAGER`, default `less -R`) is used automatically when output exceeds terminal height. Disable with `--no-pager`.

---

## 15. Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` (4.x, derive) | CLI parsing |
| `tokio` | Async runtime |
| `reqwest` | HTTP client for provider APIs |
| `serde` / `serde_json` | Serialization |
| `toml` | Config parsing |
| `async-trait` | Provider trait |
| `rustyline` | REPL readline support |
| `handlebars` | Scaffold template engine |
| `indicatif` | Spinner and progress bars |
| `anyhow` | Error handling |
| `dirs` | XDG path resolution |
| `termcolor` | Cross-platform ANSI color |
| `crossterm` | Terminal control (box drawing, cursor) |
| `chrono` | Timestamps |
| `tokio-stream` | Streaming API responses |
| `aho-corasick` | Fast pattern matching for static surface scan |

Total dependency count is kept small. No macros-heavy frameworks. No async runtimes beyond tokio.

---

## 16. Non-Goals (v0.1)

- No GUI, TUI canvas, or web interface
- No automatic CVE submission or MITRE API integration
- No built-in disassembler (calls `objdump` / external tools)
- No network scanning, port scanning, or active probing
- No sandboxing or execution of generated PoC code
- No multi-user collaboration or shared sessions over a network
- No plugin system (yet — see Open Questions)
- No Windows support in v0.1 (Linux + macOS only)

---

## 17. Open Questions

**Q1: Plugin system.** Should Mareu support user-defined subcommands as external binaries (`mareu-foo` convention, like `git`)? Low priority for v0.1 but architecturally worth deciding early.

**Q2: Prompt versioning.** Prompts are compiled into the binary. This means a prompt update requires a new release. A `--prompt-dir` flag pointing to an external directory would allow prompt iteration without recompilation. Worth adding in v0.2.

**Q3: Context window management for large trees.** The current design puts the user in control of what gets piped in. For large source trees, a summarization pre-pass (run by the model) could produce a compact index that fits in the context window. This is a meaningful feature for real-world codebases (Apache httpd, OpenSSL) but adds complexity.

**Q4: Provider fallback.** Should Mareu automatically retry on a fallback provider when the primary returns 429 or 5xx? The `ai.fallback` config key is already specced; the question is whether this is automatic or requires `--fallback`.

**Q5: Offline mode flag.** A `--offline` flag that hard-errors if any network call would be made, for air-gapped use. Currently Ollama achieves this implicitly; an explicit flag makes it scriptable.

**Q6: Binary analysis depth.** The current design calls external tools (`objdump`, Ghidra headless) for binary analysis. An optional `capstone` integration for inline disassembly would reduce the external dependency surface.

---

## 18. Milestones

| Milestone | Scope | Notes |
|-----------|-------|-------|
| **v0.1 — Skeleton** | Clap CLI, Provider trait, OpenRouter impl, `mareu analyze` with pipe support, JSON output, banner | First thing students can actually use |
| **v0.2 — Core commands** | `mareu recon` (static, no AI), `mareu scaffold` (templates, no AI), streaming output, `--dry-run` | Useful offline |
| **v0.3 — AI layer** | `--ai` flag across all commands, Anthropic + Ollama providers, prompt templates, verbosity levels | Full AI integration |
| **v0.4 — Sessions** | Session store, `mareu shell` REPL, slash-commands, session export | Sustained research workflows |
| **v0.5 — Claude Code** | MCP server mode, JSON API stabilization, ambient context provider | Claude Code integration |
| **v0.6 — Polish** | Config management UI, `mareu report`, provider health checks, full test coverage | Community release |
| **v1.0** | Stable CLI contract, documented JSON schema, SECURITY.md, responsible disclosure statement, release binaries | Public GitHub release |

---

## Appendix A — Responsible Disclosure Statement

Mareu is a tool for security research. The authors expect users to:

- Obtain authorization before testing systems they do not own
- Follow coordinated disclosure norms when reporting findings to vendors
- Not use this tool to harm third parties or production systems without consent

This is a statement of values, not an enforceable contract. The authors understand that the tool is dual-use, that most users are researchers acting in good faith, and that the security community is better served by capable, honest tooling than by tools that refuse to function.

---

## Appendix B — `SECURITY.md`

Mareu itself may have security vulnerabilities. If you find one:

- Do not open a public issue
- Email `[YOUR EMAIL HERE]` or reach out via `@Phlegmelm` on GitHub with a description and reproduction steps
- Allow 90 days for a fix before public disclosure

We will credit researchers in the changelog unless anonymity is requested.
