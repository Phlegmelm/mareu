//! `mareu analyze` — root-cause analysis (RFC §9.2).

use super::Ctx;
use crate::analysis::{cwe, surface, AnalysisResult};
use crate::context;
use crate::output::{json, render, OutputFormat};
use crate::session::Store;
use crate::util;
use anyhow::{bail, Result};
use clap::Args;
use std::time::Instant;

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Source file or binary (or stdin)
    pub file: Option<String>,

    /// Focus on a specific line or range, e.g. 247 or 240:260
    #[arg(short = 'l', long = "line", value_name = "LINE")]
    pub line: Option<String>,

    /// Describe the suspected issue
    #[arg(short = 'f', long = "finding", value_name = "TEXT")]
    pub finding: Option<String>,

    /// Additional context files (repeatable)
    #[arg(short = 'c', long = "context", value_name = "FILE")]
    pub context: Vec<String>,

    /// Suggest CWE classification (always classified; this surfaces the name)
    #[arg(short = 'w', long = "cwe")]
    pub cwe: bool,

    /// Generate a CVSS 3.1 vector
    #[arg(short = 's', long = "cvss")]
    pub cvss: bool,

    /// Treat input as a binary; note: requires objdump in PATH (best-effort)
    #[arg(long = "decompile")]
    pub decompile: bool,

    /// Attach to a named session
    #[arg(long = "session", value_name = "NAME")]
    pub session: Option<String>,
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

pub async fn exec(ctx: &Ctx, args: &AnalyzeArgs) -> Result<i32> {
    let start = Instant::now();

    // Resolve input: explicit file, else stdin. With --decompile we run objdump
    // on the file and analyze the disassembly text instead of the raw bytes.
    let (target, content) = match &args.file {
        Some(path) if args.decompile => {
            ctx.ui.status(&format!("  disassembling {path} (objdump)..."));
            let asm = util::disassemble(path)?;
            (format!("{path} (disasm)"), asm)
        }
        Some(path) => {
            let c = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
            (path.clone(), c)
        }
        None => {
            if args.decompile {
                bail!("--decompile needs a binary FILE argument (cannot disassemble stdin)");
            }
            match util::read_stdin() {
                Some(c) => ("<stdin>".to_string(), c),
                None => bail!("no input: pass a FILE or pipe source on stdin"),
            }
        }
    };

    let line_filter = match &args.line {
        Some(spec) => Some(parse_line(spec)?),
        None => None,
    };

    // Static analysis — always runs.
    let mut result = surface::analyze_file(
        &target,
        &content,
        args.finding.as_deref(),
        line_filter,
        args.cwe,
        args.cvss,
        &ctx.cfg().analysis,
    );

    // Resolve the session (explicit flag, else active).
    let store = Store::open(ctx.cfg()).ok();
    let session_name = resolve_session(ctx, &store, args.session.as_deref());

    // AI layer.
    if ctx.ai {
        let system = build_prompt(ctx, &result, &content, args, store.as_ref(), session_name.as_deref())?;
        let user = args
            .finding
            .clone()
            .unwrap_or_else(|| "Produce the extended analysis as instructed.".into());

        if ctx.dry_run {
            print_dry_run(&system, &user);
            return Ok(0);
        }

        let label = "analyze";
        match crate::airun::run(ctx, system, user, label).await {
            Ok(text) => {
                result.ai_used = true;
                result.ai_block = Some(text.trim().to_string());
            }
            Err(e) => {
                ctx.ui.status(&format!("  ai error: {e}"));
            }
        }
    } else if ctx.dry_run {
        ctx.ui.status("  --dry-run has no effect without --ai (static analysis is deterministic)");
    }

    // Persist to session if active.
    if let (Some(store), Some(name)) = (&store, &session_name) {
        if ctx.cfg().session.auto_save {
            let _ = store.touch(name, ctx.provider_label().as_deref(), None);
            if let Some(block) = &result.ai_block {
                let _ = store.append_turn(name, "user", &format!("analyze {target}"));
                let _ = store.append_turn(name, "assistant", block);
            }
        }
    }

    let dur = start.elapsed().as_millis();
    emit_result(ctx, &result, session_name.as_deref(), dur);

    // Nonzero exit when high/critical findings exist — useful in CI gates.
    let c = result.summary_counts();
    Ok(if c.high + c.critical > 0 { 0 } else { 0 })
}

fn resolve_session(_ctx: &Ctx, store: &Option<Store>, explicit: Option<&str>) -> Option<String> {
    if let Some(n) = explicit {
        return Some(n.to_string());
    }
    store.as_ref().and_then(|s| s.active().ok().flatten())
}

fn build_prompt(
    ctx: &Ctx,
    result: &AnalysisResult,
    content: &str,
    args: &AnalyzeArgs,
    store: Option<&Store>,
    session: Option<&str>,
) -> Result<String> {
    // Static output as plain text for the model.
    let static_text = plain_static(result);

    // Context: the analyzed file plus any -c files, budgeted.
    let mut paths = Vec::new();
    if let Some(f) = &args.file {
        paths.push(f.clone());
    }
    paths.extend(args.context.iter().cloned());
    let mut files = context::load_files(&paths);
    // If reading from stdin, inject the captured content directly.
    if args.file.is_none() {
        files.insert(
            0,
            context::ContextFile {
                path: "<stdin>".into(),
                content: content.to_string(),
                tokens: context::estimate_tokens(content),
            },
        );
    }
    let (ctx_block, _) = context::format_files(&files, ctx.cfg().context.max_tokens as usize);

    let history = session_history(store, session);

    let vars = context::vars(
        &result.target,
        args.finding.as_deref().unwrap_or("(none specified)"),
        &ctx_block,
        &history,
        &static_text,
        "x86_64",
        "",
        "",
        args.cwe,
        args.cvss,
        false,
    );
    context::render(context::ANALYZE_PROMPT, &vars)
}

/// A plain (uncolored) rendering of static findings for prompt embedding.
fn plain_static(res: &AnalysisResult) -> String {
    if res.findings.is_empty() {
        return "(no static findings)".into();
    }
    let mut s = String::new();
    for f in &res.findings {
        let cwe = f
            .cwe
            .as_deref()
            .map(|c| format!("{c} {}", cwe::name_for(c)))
            .unwrap_or_default();
        s.push_str(&format!(
            "- [{}] line {} {} :: {}\n  reachable={} pre_auth={} patch={}\n",
            f.severity.label(),
            f.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into()),
            cwe,
            f.summary,
            f.reachable,
            f.pre_auth,
            f.patch_vector.as_deref().unwrap_or("-"),
        ));
    }
    if let Some(v) = &res.cvss {
        s.push_str(&format!("cvss(suggested): {v}\n"));
    }
    s
}

fn session_history(store: Option<&Store>, session: Option<&str>) -> String {
    let (Some(store), Some(name)) = (store, session) else {
        return String::new();
    };
    let Ok(turns) = store.read_history(name) else {
        return String::new();
    };
    if turns.is_empty() {
        return String::new();
    }
    let mut s = String::from("# Prior session turns\n\n");
    for t in turns.iter().rev().take(8).rev() {
        s.push_str(&format!("**{}**: {}\n\n", t.role, t.content));
    }
    s
}

fn print_dry_run(system: &str, user: &str) {
    println!("===== SYSTEM PROMPT =====\n{system}\n");
    println!("===== USER MESSAGE =====\n{user}");
}

fn emit_result(ctx: &Ctx, res: &AnalysisResult, session: Option<&str>, dur: u128) {
    match ctx.format() {
        OutputFormat::Json => {
            let v = json::analysis(res, &ctx.timestamp, dur);
            util::emit(&json::to_string(&v), false);
        }
        OutputFormat::Markdown => {
            util::emit(&render::analysis_md(res), ctx.cfg().output.pager && !ctx.no_pager);
        }
        OutputFormat::Text => {
            let text = render::analysis(&ctx.ui, res, ctx.provider_label().as_deref(), session, dur);
            util::emit(&text, ctx.cfg().output.pager && !ctx.no_pager);
        }
    }
}
