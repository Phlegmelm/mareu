//! `mareu recon` — attack-surface mapping (RFC §9.1).

use super::Ctx;
use crate::analysis::{surface, Entry, ReconResult};
use crate::context;
use crate::output::{json, render, OutputFormat};
use crate::util;
use anyhow::{bail, Result};
use clap::Args;
use std::path::{Path, PathBuf};
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

const SOURCE_EXTS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "rs", "py", "go", "js", "ts", "java", "rb", "php",
];

pub async fn exec(ctx: &Ctx, args: &ReconArgs) -> Result<i32> {
    let start = Instant::now();

    // Collect the file list.
    let files = gather_files(args)?;
    if files.is_empty() {
        bail!("no source files found at the given target");
    }

    let cfg = &ctx.cfg().analysis;
    let mut entries: Vec<Entry> = Vec::new();
    let mut scanned = 0usize;
    for f in &files {
        let Ok(content) = std::fs::read_to_string(f) else {
            continue;
        };
        scanned += 1;
        let rel = relative(f);
        entries.extend(surface::recon_file(&rel, &content, args.filter.as_deref(), cfg));
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

fn gather_files(args: &ReconArgs) -> Result<Vec<PathBuf>> {
    // stdin file-list mode.
    if args.target.is_none() {
        if let Some(list) = util::read_stdin() {
            let files: Vec<PathBuf> = list
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.is_file())
                .collect();
            return Ok(files);
        }
        bail!("no target given and no file list on stdin");
    }
    let root = PathBuf::from(args.target.as_ref().unwrap());
    if root.is_file() {
        return Ok(vec![root]);
    }
    if !root.exists() {
        bail!("target does not exist: {}", root.display());
    }
    let mut out = Vec::new();
    walk(&root, &root, 0, args.depth, &mut out);
    Ok(out)
}

fn walk(root: &Path, dir: &Path, depth: usize, max: Option<usize>, out: &mut Vec<PathBuf>) {
    if let Some(m) = max {
        if depth > m {
            return;
        }
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        // Skip VCS and dependency dirs that add noise.
        if p.is_dir() {
            if matches!(name.as_ref(), ".git" | "node_modules" | "target" | "vendor" | "build" | ".svn") {
                continue;
            }
            walk(root, &p, depth + 1, max, out);
        } else if is_source(&p) {
            out.push(p);
        }
    }
}

fn is_source(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .map(|e| SOURCE_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn relative(p: &Path) -> String {
    std::env::current_dir()
        .ok()
        .and_then(|cwd| p.strip_prefix(&cwd).ok().map(|r| r.to_path_buf()))
        .unwrap_or_else(|| p.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
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
