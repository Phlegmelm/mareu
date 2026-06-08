//! `mareu scaffold` — PoC/exploit/reproducer generation (RFC §9.3, §4).

use super::Ctx;
use crate::context;
use crate::scaffold::{self, ScaffoldRequest};
use crate::session::Store;
use crate::util;
use anyhow::{bail, Result};
use clap::Args;
use serde_json::json;

#[derive(Args, Debug)]
pub struct ScaffoldArgs {
    /// Scaffold type: poc | exploit | reproducer | harness | fuzzer | report
    #[arg(short = 't', long = "type", value_name = "TYPE", default_value = "poc")]
    pub r#type: String,

    /// Vulnerability description or CVE identifier
    /// (long-only: `-v` is the global verbosity flag)
    #[arg(long = "vuln", value_name = "TEXT")]
    pub vuln: Option<String>,

    /// Language: c | python | rust | asm | bash
    /// (inferred as asm for shellcode/egghunter/loader/ret2 classes or when
    /// --syntax is given; otherwise defaults to c)
    #[arg(short = 'l', long = "lang", value_name = "LANG")]
    pub lang: Option<String>,

    /// Bug class: bof | uaf | fmt | race | proto | logic | oob | infoleak
    #[arg(short = 'c', long = "class", value_name = "CLASS")]
    pub class: Option<String>,

    /// Attach relevant source/headers (repeatable)
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: Vec<String>,

    /// Include ASAN-friendly build/patterns
    #[arg(long = "asan")]
    pub asan: bool,

    /// Target architecture
    #[arg(long = "arch", value_name = "ARCH", default_value = "x86_64")]
    pub arch: String,

    /// Use a custom .hbs template instead of the built-in
    #[arg(long = "template", value_name = "PATH")]
    pub template: Option<String>,

    /// Assembler syntax for --lang asm: nasm | gas | both [default: both]
    #[arg(long = "syntax", value_name = "SYN")]
    pub syntax: Option<String>,

    /// EGG tag (hex) for the egghunter, e.g. 0xdeadbeef or 9090905090905090.
    /// Repeated to the arch tag size (8 bytes x86_64, 4 bytes x86); prepend it
    /// TWICE before your payload.
    #[arg(long = "egg", value_name = "HEX")]
    pub egg: Option<String>,

    /// Enable aggressive output modes (full exploit, ROP/shellcode stubs)
    #[arg(long = "unsafe")]
    pub r#unsafe: bool,

    /// Write the artifact to ./mareu_scaffold_<ts>/ (and the session, if any)
    #[arg(long = "save")]
    pub save: bool,

    /// Attach to a named session (saves artifact to its store)
    #[arg(long = "session", value_name = "NAME")]
    pub session: Option<String>,
}

pub async fn exec(ctx: &Ctx, args: &ScaffoldArgs) -> Result<i32> {
    let vuln = args.vuln.clone().unwrap_or_default();

    // Intent check (RFC §4.2): refuse "attack this named external host".
    if let Some(msg) = scaffold::intent_block(&vuln) {
        eprintln!("mareu: {msg}");
        return Ok(2);
    }

    // The `exploit` type is gated behind --unsafe (RFC §4.4).
    if args.r#type == "exploit" && !args.r#unsafe && !ctx.cfg().scaffold.unsafe_default {
        bail!(
            "scaffold --type exploit requires --unsafe (full exploit output is gated).\n\
             Without it, use --type poc/reproducer for a crash-level scaffold."
        );
    }

    let unsafe_mode = args.r#unsafe || ctx.cfg().scaffold.unsafe_default;
    let date = ctx
        .timestamp
        .get(..10)
        .unwrap_or(&ctx.timestamp)
        .to_string();

    // Validate/clean the egg tag (hex, optional 0x), if given.
    let egg = match &args.egg {
        Some(raw) => Some(clean_egg(raw)?),
        None => None,
    };

    // Resolve language: explicit --lang wins; otherwise infer asm from an
    // asm-specific class or the presence of --syntax, else default to c.
    let lang = resolve_lang(args);
    let asm_syntax = args.syntax.clone().unwrap_or_else(|| "both".into());

    let req = ScaffoldRequest {
        kind: args.r#type.clone(),
        vuln: vuln.clone(),
        lang,
        class: args.class.clone(),
        arch: args.arch.clone(),
        asan: args.asan,
        unsafe_mode,
        ai: ctx.ai,
        model: ctx.provider_label(),
        custom_template: args.template.clone(),
        header_comment: ctx.cfg().scaffold.header_comment,
        timestamp: date,
        asm_syntax,
        egg,
    };

    let mut scaffold = scaffold::generate(&req)?;

    // AI augmentation.
    if ctx.ai {
        let system = build_prompt(ctx, &req, &scaffold.template_only, &args.file)?;
        let user = format!("Augment the scaffold for: {vuln}");
        if ctx.dry_run {
            println!("===== SYSTEM PROMPT =====\n{system}\n");
            println!("===== USER MESSAGE =====\n{user}");
            return Ok(0);
        }
        match crate::airun::run(ctx, system, user, "scaffold").await {
            Ok(text) => {
                let code = extract_code(&text);
                // Re-attach the header (which already records ai=true).
                let header_end = scaffold.body.find("\n\n").map(|i| i + 2).unwrap_or(0);
                let header = &scaffold.body[..header_end];
                scaffold.body = format!("{header}{code}");
            }
            Err(e) => ctx
                .ui
                .status(&format!("  ai error: {e}; emitting template scaffold")),
        }
    } else if ctx.dry_run {
        // Dry-run without AI: show the template that *would* be sent.
        println!(
            "===== SCAFFOLD TEMPLATE (no --ai) =====\n{}",
            scaffold.template_only
        );
        return Ok(0);
    }

    // Save to disk / session if requested.
    let mut saved_paths = Vec::new();
    // All artifacts (primary + any extra syntaxes) as (filename, body) pairs.
    let artifacts: Vec<(&str, &str)> =
        std::iter::once((scaffold.filename.as_str(), scaffold.body.as_str()))
            .chain(
                scaffold
                    .extra
                    .iter()
                    .map(|e| (e.filename.as_str(), e.body.as_str())),
            )
            .collect();

    if args.save {
        let dir = format!(
            "mareu_scaffold_{}",
            ctx.timestamp
                .replace([':', '-'], "")
                .get(..15)
                .unwrap_or("ts")
        );
        std::fs::create_dir_all(&dir)?;
        for (fname, body) in &artifacts {
            let path = std::path::Path::new(&dir).join(fname);
            std::fs::write(&path, body)?;
            saved_paths.push(path.to_string_lossy().to_string());
        }
    }
    if let Some(name) = &args.session {
        if let Ok(store) = Store::open(ctx.cfg()) {
            if store.exists(name) {
                for (fname, body) in &artifacts {
                    let p = store.write_artifact(name, fname, body)?;
                    saved_paths.push(p.to_string_lossy().to_string());
                }
                let _ = store.append_note(
                    name,
                    &format!("scaffold {} → {}", req.kind, scaffold.filename),
                );
            }
        }
    }

    // Emit.
    match ctx.format() {
        crate::output::OutputFormat::Json => {
            let files: Vec<_> = artifacts
                .iter()
                .map(|(f, b)| json!({ "filename": f, "body": b }))
                .collect();
            let v = json!({
                "command": "scaffold",
                "type": req.kind,
                "lang": scaffold.lang,
                "filename": scaffold.filename,
                "ai_used": ctx.ai,
                "unsafe": unsafe_mode,
                "saved": saved_paths,
                "files": files,
                "body": scaffold.body,
            });
            util::emit(&serde_json::to_string_pretty(&v).unwrap(), false);
        }
        _ => {
            // Code goes to stdout verbatim so it pipes/copies cleanly. When more
            // than one artifact is produced (e.g. asm --syntax both), separate
            // them with a clear banner and suggest --save for per-file output.
            let mut out = String::new();
            for (i, (fname, body)) in artifacts.iter().enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                if artifacts.len() > 1 {
                    out.push_str(&format!("// ===== {fname} =====\n"));
                }
                out.push_str(body);
            }
            util::emit(&out, ctx.cfg().output.pager && !ctx.no_pager);
            if artifacts.len() > 1 && saved_paths.is_empty() {
                ctx.ui.status("  note: multiple files concatenated above — use --save to write them separately");
            }
            for p in &saved_paths {
                ctx.ui.status(&format!("  written: {p}"));
            }
        }
    }
    Ok(0)
}

/// Validate and normalize an egg tag: strip an optional `0x`, lowercase, and
/// ensure it's non-empty hex.
fn clean_egg(raw: &str) -> Result<String> {
    let h = raw
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase();
    if h.is_empty() || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("--egg must be hex (e.g. 0xdeadbeef or 9090905090905090), got '{raw}'");
    }
    Ok(h)
}

/// Decide the scaffold language when `--lang` is omitted: infer `asm` from an
/// asm-specific class or the presence of `--syntax`, else default to `c`.
fn resolve_lang(args: &ScaffoldArgs) -> String {
    if let Some(l) = &args.lang {
        return l.clone();
    }
    let asm_class = args
        .class
        .as_deref()
        .map(|c| {
            matches!(
                c.to_ascii_lowercase().as_str(),
                "shellcode"
                    | "execve"
                    | "sh"
                    | "shell"
                    | "egghunter"
                    | "egg"
                    | "loader"
                    | "stager"
                    | "stage"
                    | "ret2"
                    | "rop"
                    | "win"
                    | "proof"
                    | "syscall"
            )
        })
        .unwrap_or(false);
    if asm_class || args.syntax.is_some() {
        "asm".into()
    } else {
        "c".into()
    }
}

fn build_prompt(
    ctx: &Ctx,
    req: &ScaffoldRequest,
    template: &str,
    attach: &[String],
) -> Result<String> {
    let files = context::load_files(attach);
    let (ctx_block, _) = context::format_files(&files, ctx.cfg().context.max_tokens as usize);
    let vars = context::vars(
        &req.vuln,
        &req.vuln,
        &ctx_block,
        "",
        template,
        &req.arch,
        req.class.as_deref().unwrap_or("unspecified"),
        &req.lang,
        false,
        false,
        req.unsafe_mode,
    );
    context::render(context::SCAFFOLD_PROMPT, &vars)
}

/// Extract the first fenced code block from a model response, else return the
/// whole text (the model was asked for a single code block).
fn extract_code(text: &str) -> String {
    if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        // Skip the language tag line.
        let body_start = after.find('\n').map(|i| i + 1).unwrap_or(0);
        let body = &after[body_start..];
        if let Some(end) = body.find("```") {
            return body[..end].trim_end().to_string();
        }
    }
    text.trim().to_string()
}
