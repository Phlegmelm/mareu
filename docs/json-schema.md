# Mareu JSON Output Schema

`--output json` is a **stable, documented API contract** (RFC §13), not an
internal detail. Claude Code, CI gates, and `jq`-driven tooling can build on it.
Fields may be *added* in a minor release; existing fields will not change
meaning or type without a major version bump.

All commands that produce findings/artifacts support `--output json`. JSON is
always emitted uncolored and unpaged, with a single top-level object per
invocation.

---

## `analyze`

```jsonc
{
  "command": "analyze",
  "target": "src/parser.c",          // path, "<stdin>", or "<file> (disasm)"
  "timestamp": "2026-06-08T14:22:01Z",
  "ai_used": false,
  "focus": "missing bounds check",   // null unless --finding given
  "findings": [
    {
      "id": 1,                       // 1-based, sorted by severity desc then line
      "severity": "CRITICAL",        // CRITICAL | HIGH | MEDIUM | LOW | INFO
      "cwe": "CWE-787",              // omitted if unclassified
      "line": 8,                     // omitted if not line-attributable
      "reachable": true,             // network- or taint-reachable
      "pre_auth": true,
      "summary": "memcpy() at line 8 — Out-of-bounds Write",
      "detail": "Call to memcpy() in parse_client_hello()...",
      "patch_vector": "bound the copy; prefer strlcpy/snprintf...",
      "origin": "static"             // static | ai
    }
  ],
  "cvss": "CVSS:3.1/AV:N/AC:L/...",  // null unless --cvss given
  "ai_block": null,                  // string of [AI] extended analysis if --ai
  "summary": { "total": 3, "critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0 },
  "lines_analyzed": 16,
  "duration_ms": 5
}
```

Severity ordering (ascending risk): `INFO < LOW < MEDIUM < HIGH < CRITICAL`.
The taint pass promotes a sink one notch when it consumes a tainted variable.

### Example

```bash
mareu analyze src/tls.c --line 312 --cwe --output json | jq '.findings[] | select(.pre_auth)'
```

---

## `recon`

```jsonc
{
  "command": "recon",
  "target": "./src",
  "timestamp": "2026-06-08T14:22:01Z",
  "ai_used": false,
  "filter": "pre-auth",              // null unless --filter given
  "files_scanned": 42,
  "entries": [
    {
      "name": "parse_client_hello",
      "file": "src/parser.c",
      "line": 6,
      "kind": "network",             // network | parser | auth-gate | flag-site
      "pre_auth": true,
      "note": "reads attacker-controlled bytes off the wire",
      "severity": "HIGH"
    }
  ],
  "ai_block": null,                  // ranked audit plan string if --ai
  "duration_ms": 12
}
```

---

## `scaffold`

```jsonc
{
  "command": "scaffold",
  "type": "exploit",
  "lang": "asm",
  "filename": "mareu_asm_shellcode_execve_sh.nasm",
  "ai_used": false,
  "unsafe": true,
  "saved": ["mareu_scaffold_20260608T1422/...nasm"],  // paths if --save / --session
  "files": [                         // every emitted artifact (asm --syntax both -> 2)
    { "filename": "mareu_asm_shellcode_execve_sh.nasm", "body": "..." },
    { "filename": "mareu_asm_shellcode_execve_sh.s",    "body": "..." }
  ],
  "body": "..."                      // the primary artifact body
}
```

The **intent check** (RFC §4.2) is enforced before JSON is produced: a refused
request prints to stderr and exits `2` with no stdout. The `exploit` type
without `--unsafe` exits `1`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | runtime error (bad input, provider failure, missing tool, gated `--type exploit`) |
| `2` | scaffold intent refusal (named external target without bug-class framing) |

A closed downstream pipe (`| head`) is a clean exit, not an error.
