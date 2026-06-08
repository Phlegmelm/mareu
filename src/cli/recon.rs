//! `mareu recon` — attack-surface mapping (RFC §9.1).

use super::Ctx;
use crate::analysis::{surface, Entry, ReconResult};
use crate::context;
use crate::output::{json, render, OutputFormat};
use crate::util;
use anyhow::{bail, Result};
use clap::Args;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Args, Debug)]
pub struct ReconArgs {
    /// Path to a source tree or file (or a newline file-list on stdin)
    pub target: Option<String>,

    /// Surface type: source | binary | protocol (auto-detect by default)
    #[arg(short = 't', long = "type", value_name = "TYPE")]
    pub r#type: Option<String>,

    /// Surface focus: pre-auth | network | parser | auth-gate | flag-site
    #[arg(short = 'f', long = "filter", value_name = "FILTER")]
    pub filter: Option<String>,

    /// Traversal depth for source trees (unlimited by default)
    #[arg(short = 'd', long = "depth", value_name = "N")]
    pub depth: Option<usize>,

    /// Known entry-point function name (repeatable)
    #[arg(long = "entry", value_name = "FN")]
    pub entry: Vec<String>,
}

pub async fn exec(ctx: &Ctx, args: &ReconArgs) -> Result<i32> {
    let start = Instant::now();
    let cfg = &ctx.cfg().analysis;
    let filter = args.filter.as_deref();

    // Resolve the file set and run the shared recon engine.
    let (mut entries, scanned): (Vec<Entry>, usize) = match &args.target {
        None => {
            // stdin file-list mode.
            let Some(list) = util::read_stdin() else {
                bail!("no target given and no file list on stdin");
            };
            let files: Vec<PathBuf> = list
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.is_file())
                .collect();
            surface::recon_files(&files, filter, cfg)
        }
        Some(t) => {
            let root = PathBuf::from(t);
            if !root.exists() {
                bail!("target does not exist: {}", root.display());
            }
            surface::recon_tree(&root, filter, args.depth, cfg)
        }
    };
    if scanned == 0 {
        bail!("no source files found at the given target");
    }

    // Honor explicitly supplied entry points by boosting matching entries.
    if !args.entry.is_empty() {
        for e in &mut entries {
            if args.entry.iter().any(|n| e.name.contains(n.as_str())) {
                e.note = format!("{} (declared entry point)", e.note);
            }
        }
    }
    entries.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));

    let target = args
        .target
        .clone()
        .unwrap_or_else(|| "<stdin file list>".into());
    let mut result = ReconResult {
        target,
        filter: args.filter.clone(),
        files_scanned: scanned,
        entries,
        ai_used: false,
        ai_block: None,
    };

    if ctx.ai {
        let system = build_prompt(ctx, &result)?;
        let user = "Produce the ranked audit plan as instructed.".to_string();
        if ctx.dry_run {
            println!("===== SYSTEM PROMPT =====\n{system}\n");
            println!("===== USER MESSAGE =====\n{user}");
            return Ok(0);
        }
        match crate::airun::run(ctx, system, user, "recon").await {
            Ok(text) => {
                result.ai_used = true;
                result.ai_block = Some(text.trim().to_string());
            }
            Err(e) => ctx.ui.status(&format!("  ai error: {e}")),
        }
    }

    let dur = start.elapsed().as_millis();
    match ctx.format() {
        OutputFormat::Json => {
            let v = json::recon(&result, &ctx.timestamp, dur);
            util::emit(&json::to_string(&v), false);
        }
        OutputFormat::Markdown => {
            util::emit(&render::recon_md(&result), ctx.cfg().output.pager && !ctx.no_pager);
        }
        OutputFormat::Text => {
            let text = render::recon(&ctx.ui, &result, ctx.provider_label().as_deref(), dur);
            util::emit(&text, ctx.cfg().output.pager && !ctx.no_pager);
        }
    }
    Ok(0)
}

fn build_prompt(_ctx: &Ctx, res: &ReconResult) -> Result<String> {
    let mut static_text = String::new();
    for e in &res.entries {
        static_text.push_str(&format!(
            "- [{}] {} {}:{} ({}) pre_auth={} — {}\n",
            e.severity.label(),
            e.kind,
            e.file,
            e.line,
            e.name,
            e.pre_auth,
            e.note
        ));
    }
    if static_text.is_empty() {
        static_text.push_str("(no entry points surfaced)");
    }
    let vars = context::vars(
        &res.target,
        res.filter.as_deref().unwrap_or("(none)"),
        "",
        "",
        &static_text,
        "x86_64",
        "",
        "",
        false,
        false,
        false,
    );
    context::render(context::RECON_PROMPT, &vars)
}
