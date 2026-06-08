//! MCP (Model Context Protocol) server mode — RFC §13.4.
//!
//! Exposes Mareu's static capabilities as tools an MCP client (e.g. Claude
//! Code) can call: `mareu_recon`, `mareu_analyze`, `mareu_scaffold`, and
//! `mareu_session_context`. Transport is newline-delimited JSON-RPC 2.0 over
//! **stdio** — the standard for local MCP servers. Nothing but JSON-RPC is ever
//! written to stdout; diagnostics go to stderr.
//!
//! Tools run the deterministic, offline engine (no `--ai`) so an agent gets
//! reproducible structured output it can reason over.

use crate::analysis::{surface, ReconResult};
use crate::cli::{Ctx, McpArgs};
use crate::output::json as jsonenv;
use crate::scaffold::{self, ScaffoldRequest};
use crate::session::Store;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL_VERSION: &str = "2024-11-05";

pub async fn serve(ctx: &Ctx, args: &McpArgs) -> Result<i32> {
    if let Some(port) = args.port {
        // The Streamable-HTTP transport isn't built yet; be explicit rather
        // than silently doing something else.
        eprintln!(
            "mareu mcp: HTTP transport (--port {port}) is not implemented yet.\n\
             Use stdio instead — run `mareu mcp` with no --port and configure your\n\
             client with:  {{\"command\": \"mareu\", \"args\": [\"mcp\"]}}"
        );
        return Ok(1);
    }

    eprintln!("mareu mcp: stdio server ready ({} tools)", TOOLS.len());

    let mut reader = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let resp = error(Value::Null, -32700, &format!("parse error: {e}"));
                write_msg(&mut stdout, &resp).await?;
                continue;
            }
        };

        if let Some(resp) = handle(ctx, &msg).await {
            write_msg(&mut stdout, &resp).await?;
        }
    }
    Ok(0)
}

async fn write_msg(out: &mut tokio::io::Stdout, v: &Value) -> Result<()> {
    out.write_all(v.to_string().as_bytes()).await?;
    out.write_all(b"\n").await?;
    out.flush().await?;
    Ok(())
}

fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Returns the response to send, or `None` for notifications (no reply).
async fn handle(ctx: &Ctx, msg: &Value) -> Option<Value> {
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = msg.get("id").cloned();
    let params = msg.get("params").cloned().unwrap_or(json!({}));

    // Notifications have no id; we must not reply to them.
    let is_notification = id.is_none();
    let id = id.unwrap_or(Value::Null);

    match method {
        "initialize" => {
            let pv = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(PROTOCOL_VERSION)
                .to_string();
            Some(result(
                id,
                json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "mareu", "version": env!("CARGO_PKG_VERSION") },
                }),
            ))
        }
        "notifications/initialized" | "notifications/cancelled" => None,
        "ping" => Some(result(id, json!({}))),
        "tools/list" => Some(result(id, json!({ "tools": tool_list() }))),
        "tools/call" => {
            if is_notification {
                return None;
            }
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            Some(match call_tool(ctx, name, &arguments).await {
                Ok(value) => result(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": jsonenv::to_string(&value) }],
                        "isError": false,
                    }),
                ),
                Err(e) => result(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": format!("error: {e}") }],
                        "isError": true,
                    }),
                ),
            })
        }
        _ => {
            if is_notification {
                None
            } else {
                Some(error(id, -32601, &format!("method not found: {method}")))
            }
        }
    }
}

// ── tool registry ───────────────────────────────────────────────────────────

struct ToolDef {
    name: &'static str,
    description: &'static str,
}

const TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "mareu_recon",
        description: "Map the attack surface of a source file or tree (static). Returns entry points with kind, severity, pre-auth flag.",
    },
    ToolDef {
        name: "mareu_analyze",
        description: "Root-cause analysis of a file or inline source (static). Returns findings with CWE, severity, reachability, patch vector.",
    },
    ToolDef {
        name: "mareu_scaffold",
        description: "Generate PoC/exploit/reproducer scaffolding (templates + asm). Returns the artifact body and filename.",
    },
    ToolDef {
        name: "mareu_session_context",
        description: "Return a named (or the active) research session's structured state: metadata, notes, and conversation turns.",
    },
];

fn tool_list() -> Vec<Value> {
    TOOLS
        .iter()
        .map(|t| json!({ "name": t.name, "description": t.description, "inputSchema": schema(t.name) }))
        .collect()
}

fn schema(name: &str) -> Value {
    match name {
        "mareu_recon" => json!({
            "type": "object",
            "properties": {
                "target": { "type": "string", "description": "Path to a source file or tree" },
                "filter": { "type": "string", "description": "pre-auth | network | parser | auth-gate | flag-site" },
                "depth":  { "type": "integer", "description": "Max traversal depth" }
            },
            "required": ["target"]
        }),
        "mareu_analyze" => json!({
            "type": "object",
            "properties": {
                "file":    { "type": "string", "description": "Path to a source file" },
                "content": { "type": "string", "description": "Inline source (alternative to file)" },
                "finding": { "type": "string", "description": "Suspected issue description" },
                "line":    { "type": "string", "description": "Line or range, e.g. 247 or 240:260" },
                "cwe":     { "type": "boolean" },
                "cvss":    { "type": "boolean" }
            }
        }),
        "mareu_scaffold" => json!({
            "type": "object",
            "properties": {
                "type":   { "type": "string", "description": "poc | exploit | reproducer | harness | fuzzer | report" },
                "class":  { "type": "string", "description": "bof | uaf | fmt | proto | shellcode | egghunter | loader | ret2" },
                "lang":   { "type": "string", "description": "c | python | asm | … (inferred for asm classes)" },
                "arch":   { "type": "string", "description": "x86_64 | x86 | aarch64" },
                "vuln":   { "type": "string" },
                "unsafe": { "type": "boolean", "description": "Aggressive output (full exploit/ROP/shellcode)" },
                "syntax": { "type": "string", "description": "nasm | gas | both (asm only)" },
                "egg":    { "type": "string", "description": "egghunter tag, hex" }
            }
        }),
        "mareu_session_context" => json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Session name (default: the active session)" }
            }
        }),
        _ => json!({ "type": "object" }),
    }
}

// ── tool execution ──────────────────────────────────────────────────────────

async fn call_tool(ctx: &Ctx, name: &str, args: &Value) -> Result<Value> {
    let cfg = ctx.cfg();
    match name {
        "mareu_recon" => {
            let target = args.get("target").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("'target' is required"))?;
            let filter = args.get("filter").and_then(|v| v.as_str());
            let depth = args.get("depth").and_then(|v| v.as_u64()).map(|d| d as usize);
            let (entries, scanned) =
                surface::recon_tree(Path::new(target), filter, depth, &cfg.analysis);
            let res = ReconResult {
                target: target.to_string(),
                filter: filter.map(str::to_string),
                files_scanned: scanned,
                entries,
                ai_used: false,
                ai_block: None,
            };
            Ok(jsonenv::recon(&res, &ctx.timestamp, 0))
        }
        "mareu_analyze" => {
            let (target, content) = match (
                args.get("file").and_then(|v| v.as_str()),
                args.get("content").and_then(|v| v.as_str()),
            ) {
                (Some(f), _) => (f.to_string(), std::fs::read_to_string(f)
                    .map_err(|e| anyhow!("reading {f}: {e}"))?),
                (None, Some(c)) => ("<inline>".to_string(), c.to_string()),
                (None, None) => return Err(anyhow!("provide 'file' or 'content'")),
            };
            let finding = args.get("finding").and_then(|v| v.as_str());
            let line_filter = match args.get("line").and_then(|v| v.as_str()) {
                Some(s) => Some(parse_line(s)?),
                None => None,
            };
            let cwe = args.get("cwe").and_then(|v| v.as_bool()).unwrap_or(true);
            let cvss = args.get("cvss").and_then(|v| v.as_bool()).unwrap_or(false);
            let res = surface::analyze_file(
                &target, &content, finding, line_filter, cwe, cvss, &cfg.analysis,
            );
            Ok(jsonenv::analysis(&res, &ctx.timestamp, 0))
        }
        "mareu_scaffold" => {
            let kind = args.get("type").and_then(|v| v.as_str()).unwrap_or("poc").to_string();
            let class = args.get("class").and_then(|v| v.as_str()).map(str::to_string);
            let arch = args.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64").to_string();
            let vuln = args.get("vuln").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let unsafe_mode = args.get("unsafe").and_then(|v| v.as_bool()).unwrap_or(false);
            let syntax = args.get("syntax").and_then(|v| v.as_str()).unwrap_or("both").to_string();
            let egg = args.get("egg").and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches("0x").to_ascii_lowercase());
            let lang = match args.get("lang").and_then(|v| v.as_str()) {
                Some(l) => l.to_string(),
                None => infer_lang(class.as_deref(), args.get("syntax").is_some()),
            };
            if let Some(msg) = scaffold::intent_block(&vuln) {
                return Err(anyhow!(msg));
            }
            let req = ScaffoldRequest {
                kind,
                vuln,
                lang,
                class,
                arch,
                asan: args.get("asan").and_then(|v| v.as_bool()).unwrap_or(false),
                unsafe_mode,
                ai: false,
                model: None,
                custom_template: None,
                header_comment: true,
                timestamp: ctx.timestamp.get(..10).unwrap_or(&ctx.timestamp).to_string(),
                asm_syntax: syntax,
                egg,
            };
            let s = scaffold::generate(&req)?;
            let files: Vec<Value> = std::iter::once(json!({ "filename": s.filename, "body": s.body }))
                .chain(s.extra.iter().map(|e| json!({ "filename": e.filename, "body": e.body })))
                .collect();
            Ok(json!({
                "filename": s.filename,
                "lang": s.lang,
                "files": files,
                "body": s.body,
            }))
        }
        "mareu_session_context" => {
            let store = Store::open(cfg)?;
            let name = match args.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => store.active()?.ok_or_else(|| anyhow!("no active session; pass 'name'"))?,
            };
            let meta = store.load_meta(&name)?;
            let notes = store.read_notes(&name)?;
            let turns = store.read_history(&name)?;
            Ok(json!({
                "name": name,
                "meta": meta,
                "notes": notes,
                "turns": turns,
            }))
        }
        other => Err(anyhow!("unknown tool: {other}")),
    }
}

fn parse_line(spec: &str) -> Result<(usize, usize)> {
    if let Some((a, b)) = spec.split_once(':') {
        let lo: usize = a.trim().parse()?;
        let hi: usize = b.trim().parse()?;
        Ok((lo.min(hi), lo.max(hi)))
    } else {
        let n: usize = spec.trim().parse()?;
        Ok((n, n))
    }
}

fn infer_lang(class: Option<&str>, syntax_given: bool) -> String {
    let asm_class = class
        .map(|c| {
            matches!(
                c.to_ascii_lowercase().as_str(),
                "shellcode" | "egghunter" | "egg" | "loader" | "stager" | "ret2" | "rop"
                    | "win" | "proof" | "syscall"
            )
        })
        .unwrap_or(false);
    if asm_class || syntax_given {
        "asm".into()
    } else {
        "c".into()
    }
}
