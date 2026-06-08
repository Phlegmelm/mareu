# Mareu

**a lil terminal gremlin for finding bugs in other people's code (with permission, obviously).**

```
  ███╗   ███╗ █████╗ ██████╗ ███████╗██╗   ██╗
  ████╗ ████║██╔══██╗██╔══██╗██╔════╝██║   ██║
  ██╔████╔██║███████║██████╔╝█████╗  ██║   ██║
  ██║╚██╔╝██║██╔══██║██╔══██╗██╔══╝  ██║   ██║
  ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗╚██████╔╝
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝
```

okay so. you know that feeling when you're staring at 40,000 lines of C and somewhere in there is a `memcpy` that's gonna ruin somebody's whole week? Mareu finds that `memcpy`. it lives in your terminal, it reads your code, it does one (1) thing per command and then it shuts up. revolutionary, i know.

it is **not** a scanner. it does not run nmap. it does not have a dashboard. if you wanted a dashboard go open jira and be sad over there.

## the vibe

- **does one thing, pipes anywhere.** stdin in, stdout out, exits angry on failure. true unix gremlin behavior.
- **the AI is OPT-IN.** `mareu analyze foo.c` does NOT phone a robot. you have to literally ask for the robot with `--ai`. we will not sneak a robot into your air-gapped lab. that's just rude.
- **works completely offline.** no internet? no problem. the robot is optional seasoning, not the meal.
- **treats you like an adult.** no "are you sure?", no "please consult a professional." you ARE the professional. go forth.

## just gimme the thing

```bash
# linux / mac (symlinks it onto your PATH, sets up completions, the works)
./setup/install.sh

# windows (no admin needed, it's polite)
powershell -ExecutionPolicy Bypass -File .\setup\install.ps1
```

both are idempotnet (safe to run a million times) and have a `--dry-run` so you can chicken out and just *look*. full deets + uninstall in [`setup/README.md`](setup/README.md).

prefer to do it yourself? `cargo build --release` and the binary plops out in `target/release`. that's it. rustls means no openssl nightmares, works the same on all three OSes, no you don't have to fight a C compiler.

## stuff you can type at it

```bash
# what's the attack surface here, focus on the scary pre-auth bits
mareu recon ./src --filter pre-auth

# i think THIS line is cursed, tell me about it
cat src/parser.c | mareu analyze --finding "this memcpy looks unhinged" --cwe --cvss

# gimme a crash reproducer, no robot, just templates
mareu scaffold --type reproducer --class uaf --vuln "that ksmbd thing"

# robots ON (you asked for it)
mareu analyze src/parser.c --line 247 --ai

# show me EXACTLY what you'd send the robot before you send it. trust no one.
mareu analyze src/parser.c --line 247 --ai --dry-run

# json for when a script (or a Claude) is reading instead of a human
mareu analyze src/tls.c --output json | jq .findings
```

yes it generates exploit-y scaffolding. yes including **assembly** — null-free `execve` shellcode and friends for x86_64/x86/aarch64 in both nasm and gas flavors. it'll even spit out both at once. it does NOT write "pwn my-ex's-startup.com" malware though; ask it nicely about a *bug class* instead and it'll happily oblige. (it's principled, not a coward. there's a difference, we wrote it down in [`SECURITY.md`](SECURITY.md).)

## the boring (good) docs

when you actually need real words instead of jokes:

- 📦 [`docs/json-schema.md`](docs/json-schema.md) — the `--output json` contract, for tooling + Claude Code
- ⚙️ [`docs/configuration.md`](docs/configuration.md) — every knob, every env var, how it all resolves
- 💀 [`docs/asm-reference.md`](docs/asm-reference.md) — the assembly scaffolds in detail
- 🛠️ [`setup/README.md`](setup/README.md) — install/uninstall flags
- 📝 [`CHANGELOG.md`](CHANGELOG.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md)

theres a `mareu --help` too. and `mareu <command> --help`. it's a whole thing.

## the fine print but make it quick

dual-licensed [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), pick your fighter.

be cool: get authorization, follow coordinated disclosure, don't be the reason we can't have nice tools. Mareu assumes you already know this because you're not a menace. the slightly-more-serious version is in [`SECURITY.md`](SECURITY.md) — it's also where you yell at us if *Mareu itself* has a bug (privately! don't open a public issue, c'mon).

---

*built in rust so it still compiles in 2036 when the rest of your toolchain has bit-rotted into dust. you're welcome.*
