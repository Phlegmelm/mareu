# Contributing to Mareu

Thanks for your interest. Mareu is a tool for professional vulnerability
researchers; contributions are held to that bar — correct, dense, and honest.

## Principles (non-negotiable)

These come from RFC-0001 §2 and shape every review:

- **The Unix contract.** Read stdin, write stdout, exit nonzero on failure.
  Every subcommand stays independently useful and pipeable.
- **AI is opt-in.** Nothing calls a model without `--ai` (or `ai.default`).
  `--dry-run` must always print the exact context before anything leaves the
  machine.
- **Offline-first.** The static core must work with no network. Don't add a
  feature that only works online without an offline counterpart.
- **No magic, no silent fallback.** If the tool can't do what was asked, it says
  so. (See the scaffold language guard for the pattern.)
- **Transparency over hand-holding.** No disclaimers in output; the operator is
  the professional.

## Development

```bash
cargo build            # debug
cargo test             # 13 unit + 6 integration tests
cargo build --release  # stripped, LTO
cargo clippy           # keep it warning-clean
cargo fmt              # rustfmt before submitting
```

The project must stay **warning-clean** and pass on Linux, macOS, and Windows.
Use `PathBuf`/`dirs` for paths, `rustls` for TLS, and never assume a POSIX-only
tool exists without a fallback (see `util::editor`/`pager` and
`analyze::disassemble`).

## Adding a provider

Implement the `Provider` trait in a new file under `src/provider/`, then add one
arm to `provider::build`. No other changes required (RFC §8).

## Adding a scaffold template

Drop a `.hbs` under `src/scaffold/templates/`, register it in
`scaffold::select_template`, and ensure the generated output **compiles/parses**
in its language. Assembly artifacts are generated in `src/scaffold/asm.rs` and
must assemble (verify with `as`/`nasm`).

## Prompts

System prompts live in `prompts/*.md` and are compiled in via `include_str!`.
They are the single biggest lever on AI output quality — follow the existing
tone (no caveats, researcher-level assumptions, explicit hallucination guard).

## Tests

Add unit tests next to the logic (`#[cfg(test)]`) and end-to-end behavior to
`tests/cli.rs`. Anything touching the JSON schema must keep `docs/json-schema.md`
accurate — it's a public contract.

## Security

To report a vulnerability *in Mareu itself*, see `SECURITY.md` — do not open a
public issue.
