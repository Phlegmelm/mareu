# Configuration Reference

## Resolution order (RFC §10)

Later layers override earlier ones:

1. **Compiled-in defaults** (`config/default.toml`, baked into the binary)
2. **User config** — `<config_dir>/mareu/config.toml`
3. **Project-local** — `./.mareu.toml`
4. **Environment** — `MAREU_*` variables
5. **CLI flags**

`<config_dir>` is platform-resolved via the `dirs` crate:

| Platform | User config path |
|----------|------------------|
| Linux | `$XDG_CONFIG_HOME/mareu/config.toml` (default `~/.config/mareu/config.toml`) |
| macOS | `~/Library/Application Support/mareu/config.toml` |
| Windows | `%APPDATA%\mareu\config.toml` |

```bash
mareu config show     # fully resolved config, secrets masked
mareu config edit     # open user config in $EDITOR (seeded from defaults)
mareu config set provider.default openrouter
mareu config unset ai.default
mareu config reset    # restore defaults (--yes to skip confirm)
```

## Environment overrides

`MAREU_<SECTION>_<KEY>` maps to `section.key`. The first underscore-delimited
token is the section; the remainder (re-joined) is the key:

```bash
MAREU_PROVIDER_DEFAULT=openrouter   # -> provider.default
MAREU_AI_MAX_TOKENS=16384           # -> ai.max_tokens
MAREU_OUTPUT_COLOR=false            # -> output.color
```

Values are parsed as bool/int/float when possible, else string.

## `${ENV}` interpolation

Any string value may reference an environment variable; it is expanded at load
time. Unset variables expand to empty (which, for `api_key`, means "no key").

```toml
[provider.openrouter]
api_key = "${OPENROUTER_API_KEY}"
```

`config show` masks any populated `api_key` to `***set***` — secrets are never
printed.

## Keys

| Key | Default | Notes |
|-----|---------|-------|
| `provider.default` | `ollama` | active provider (keyless default works offline) |
| `provider.<name>.api_key` | per provider | supports `${ENV}`; omit for keyless |
| `provider.<name>.model` | per provider | model id |
| `provider.<name>.base_url` | per provider | override for compatible endpoints |
| `provider.<name>.timeout` | `60`–`120` | request timeout (seconds) |
| `ai.default` | `false` | enable AI without `--ai` (`--no-ai` overrides) |
| `ai.max_tokens` | `8192` | completion cap |
| `ai.temperature` | `0.2` | low for analysis; raise for creative scaffolding |
| `ai.fallback` | `""` | provider to retry on error (auto) |
| `output.format` | `text` | `text` \| `markdown` \| `json` |
| `output.color` | `true` | disabled by `--no-color`, `NO_COLOR`, or non-tty |
| `output.pager` | `true` | page long output via `$PAGER` |
| `output.no_color_env` | `true` | honor the `NO_COLOR` standard |
| `banner.style` | `full` | `full` \| `compact` \| `none` |
| `context.max_tokens` | `100000` | context-injection budget |
| `context.include_stdin` | `true` | auto-include piped stdin |
| `session.store_path` | `""` | `""` = platform data dir; supports `~` and `${ENV}` |
| `session.auto_save` | `true` | append turns to session history |
| `scaffold.unsafe_default` | `false` | treat every scaffold as `--unsafe` |
| `scaffold.header_comment` | `true` | emit the machine-readable header |
| `analysis.flag_patterns` | (list) | dangerous-sink tokens the scanner flags |
| `analysis.pre_auth_markers` | (list) | substrings that mark a pre-auth region |

## Custom OpenAI-compatible providers

Add a `[provider.<name>]` table with a `base_url`; it's treated as an
OpenAI-compatible endpoint and selectable via `provider.default = "<name>"`.

```toml
[provider.groq]
api_key  = "${GROQ_API_KEY}"
model    = "llama-3.3-70b-versatile"
base_url = "https://api.groq.com/openai/v1"
```
