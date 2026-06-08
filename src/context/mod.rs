//! Context assembly and token-budget management (RFC §11).
//!
//! Prompts are Markdown templates compiled into the binary. They are rendered
//! with Handlebars (HTML escaping disabled, so source code survives intact).
//! The assembled prompt is the single inspectable artifact `--dry-run` and
//! `/prompt` print.

use anyhow::{Context, Result};
use handlebars::Handlebars;
use serde_json::{json, Value};
use std::path::Path;

// Compiled-in system prompts.
pub const ANALYZE_PROMPT: &str = include_str!("../../prompts/analyze.md");
pub const RECON_PROMPT: &str = include_str!("../../prompts/recon.md");
pub const SCAFFOLD_PROMPT: &str = include_str!("../../prompts/scaffold.md");
pub const SHELL_PROMPT: &str = include_str!("../../prompts/shell.md");

/// Very rough token estimate (~4 chars/token). Good enough for budgeting.
pub fn estimate_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

/// Render a prompt template with the given variables. Escaping is disabled so
/// `<`, `>`, `&`, and quotes in code pass through verbatim.
pub fn render(template: &str, vars: &Value) -> Result<String> {
    let mut hb = Handlebars::new();
    hb.register_escape_fn(handlebars::no_escape);
    hb.set_strict_mode(false);
    hb.render_template(template, vars)
        .context("rendering prompt template")
}

/// A file loaded for injection into context.
pub struct ContextFile {
    pub path: String,
    pub content: String,
    pub tokens: usize,
}

/// Read context files from disk, skipping unreadable ones (with a note).
pub fn load_files(paths: &[String]) -> Vec<ContextFile> {
    let mut out = Vec::new();
    for p in paths {
        match std::fs::read_to_string(p) {
            Ok(content) => {
                let tokens = estimate_tokens(&content);
                out.push(ContextFile {
                    path: p.clone(),
                    content,
                    tokens,
                });
            }
            Err(e) => out.push(ContextFile {
                path: p.clone(),
                content: format!("<<could not read {p}: {e}>>"),
                tokens: 0,
            }),
        }
    }
    out
}

/// Format injected files as fenced blocks, stopping when the token budget is
/// exhausted. Returns the formatted string and the number of files included.
pub fn format_files(files: &[ContextFile], budget: usize) -> (String, usize) {
    let mut out = String::new();
    let mut used = 0usize;
    let mut included = 0usize;
    for f in files {
        if used + f.tokens > budget && included > 0 {
            out.push_str(&format!(
                "\n<<context budget reached; {} file(s) omitted>>\n",
                files.len() - included
            ));
            break;
        }
        let lang = lang_hint(&f.path);
        out.push_str(&format!(
            "\n## {}\n\n```{lang}\n{}\n```\n",
            f.path, f.content
        ));
        used += f.tokens;
        included += 1;
    }
    (out, included)
}

fn lang_hint(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("c") | Some("h") => "c",
        Some("cc") | Some("cpp") | Some("cxx") | Some("hpp") => "cpp",
        Some("rs") => "rust",
        Some("py") => "python",
        Some("go") => "go",
        Some("js") | Some("ts") => "javascript",
        Some("asm") | Some("s") => "asm",
        _ => "",
    }
}

/// Build the variable object shared across prompt renders.
#[allow(clippy::too_many_arguments)]
pub fn vars(
    target: &str,
    focus: &str,
    context_files: &str,
    session_history: &str,
    static_output: &str,
    arch: &str,
    class: &str,
    lang: &str,
    cwe_requested: bool,
    cvss_requested: bool,
    unsafe_mode: bool,
) -> Value {
    json!({
        "target": target,
        "focus": focus,
        "context_files": if context_files.is_empty() { "(none provided)" } else { context_files },
        "session_history": session_history,
        "static_output": static_output,
        "arch": arch,
        "class": class,
        "lang": lang,
        "cwe_requested": cwe_requested,
        "cvss_requested": cvss_requested,
        "unsafe_mode": unsafe_mode,
    })
}
