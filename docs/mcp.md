# Mareu as an MCP server (Claude Code integration)

Mareu can run as a [Model Context Protocol](https://modelcontextprotocol.io)
server so an agent like **Claude Code** can call its capabilities as tools
mid-audit (RFC §13.4).

```bash
mareu mcp
```

Transport is **newline-delimited JSON-RPC 2.0 over stdio** — the standard for
local MCP servers. Mareu writes nothing but protocol messages to stdout;
diagnostics go to stderr. The tools run the **deterministic, offline** engine
(no `--ai`), so the agent gets reproducible structured output to reason over.

> HTTP/SSE transport (`--port`) is not implemented yet — it prints a clear
> message pointing you back to stdio.

## Wire it into Claude Code

Add an entry to your MCP config (project `.mcp.json` or the user config), using
the absolute path to the binary if it isn't on PATH:

```json
{
  "mcpServers": {
    "mareu": {
      "command": "mareu",
      "args": ["mcp"]
    }
  }
}
```

Or via the CLI:

```bash
claude mcp add mareu -- mareu mcp
```

Then, inside a Claude Code session, the agent can call `mareu_recon`,
`mareu_analyze`, `mareu_scaffold`, and `mareu_session_context` directly.

## Tools

| Tool | Arguments | Returns |
|------|-----------|---------|
| `mareu_recon` | `target` (req), `filter`, `depth` | attack-surface entry points (kind, severity, pre-auth) |
| `mareu_analyze` | `file` **or** `content`, `finding`, `line`, `cwe`, `cvss` | findings (CWE, severity, reachability, patch vector) |
| `mareu_scaffold` | `type`, `class`, `lang`, `arch`, `vuln`, `unsafe`, `syntax`, `egg` | scaffold body + filename (+ extra files) |
| `mareu_session_context` | `name` (default: active) | session metadata, notes, conversation turns |

The result of `tools/call` is the same **JSON schema** the CLI emits with
`--output json` (see [`json-schema.md`](json-schema.md)), wrapped as a text
content block.

## Try it without an agent

You can drive the server by hand to see the protocol:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mareu_analyze","arguments":{"file":"src/parser.c","cwe":true}}}' \
  | mareu mcp
```

Each response comes back as one JSON line. `initialize` → server info,
`tools/list` → the four tools with input schemas, `tools/call` → the structured
result.

## A typical flow

1. Agent: *"recon `src/` for pre-auth network surfaces"* → `mareu_recon`
2. Agent: *"analyze the top entry point"* → `mareu_analyze`
3. Agent: *"generate a UAF reproducer for it"* → `mareu_scaffold`
4. You review the artifact, run it, and `mareu session note ...` your findings.

End-to-end audit, recon → reproducer, with Mareu doing the deterministic heavy
lifting and the agent doing the reasoning.
