//! `mareu report` — generate a disclosure-ready report (RFC §9.7).
//!
//! Three sources, in priority: a named session (concrete, assembled from its
//! notes/history/artifacts), stdin (ad-hoc finding text), or — with neither —
//! the blank report template as a starting point. `--ai` drafts a polished
//! writeup from the assembled material.

use super::Ctx;
use crate::context;
use crate::scaffold::{self, ScaffoldRequest};
use crate::session::Store;
use crate::util;
use anyhow::{bail, Result};
use clap::Args;

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Build the report from a named session
    #[arg(short = 's', long = "session", value_name = "NAME")]
    pub session: Option<String>,

    /// Custom report template (.hbs)
    #[arg(short = 't', long = "template", value_name = "PATH")]
    pub template: Option<String>,

    /// Output format (markdown supported; html/pdf are not yet implemented)
    #[arg(short = 'f', long = "format", value_name = "FMT", default_value = "markdown")]
    pub format: String,

    /// Write to a file instead of stdout
    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<String>,
}

pub async fn exec(ctx: &Ctx, args: &ReportArgs) -> Result<i32> {
    match args.format.to_ascii_lowercase().as_str() {
        "markdown" | "md" => {}
        other => bail!("report format '{other}' is not implemented yet (markdown only)"),
    }

    // Gather the raw material.
    let (material, vuln) = if let Some(name) = &args.session {
        let store = Store::open(ctx.cfg())?;
        if !store.exists(name) {
            bail!("no such session '{name}'");
        }
        (store.export(name)?, format!("session: {name}"))
    } else if let Some(stdin) = util::read_stdin() {
        (stdin, "ad-hoc finding".to_string())
    } else {
        // Nothing to build from: emit the blank template skeleton.
        let blank = blank_template(ctx, args)?;
        return emit(ctx, args, &blank);
    };

    let body = if ctx.ai {
        let system = build_prompt(&material, &vuln)?;
        let user =
            "Draft the disclosure report from the material above. Fill every section you can; \
             mark unknowns as TODO."
                .to_string();
        if ctx.dry_run {
            println!("===== SYSTEM PROMPT =====\n{system}\n");
            println!("===== USER MESSAGE =====\n{user}");
            return Ok(0);
        }
        match crate::airun::run(ctx, system, user, "report").await {
            Ok(text) => text.trim().to_string(),
            Err(e) => {
                ctx.ui.status(&format!("  ai error: {e}; emitting raw material"));
                material
            }
        }
    } else {
        // No AI: the concrete session export is itself a usable report.
        material
    };

    emit(ctx, args, &body)
}

fn blank_template(ctx: &Ctx, args: &ReportArgs) -> Result<String> {
    let req = ScaffoldRequest {
        kind: "report".into(),
        vuln: "<title>".into(),
        lang: "markdown".into(),
        class: Some("<class>".into()),
        arch: "<target>".into(),
        asan: false,
        unsafe_mode: false,
        ai: false,
        model: None,
        custom_template: args.template.clone(),
        header_comment: false,
        timestamp: ctx.timestamp.clone(),
        asm_syntax: "both".into(),
        egg: None,
    };
    Ok(scaffold::generate(&req)?.body)
}

fn build_prompt(material: &str, vuln: &str) -> Result<String> {
    let vars = context::vars(
        vuln, vuln, "", "", material, "x86_64", "", "", false, false, false,
    );
    // Reuse the scaffold prompt's tone but instruct report writing via the
    // dedicated report header; the analyze prompt is closest in intent.
    context::render(REPORT_PROMPT, &vars)
}

const REPORT_PROMPT: &str = r#"You are Mareu's disclosure-report writer, working for a professional
vulnerability researcher. Produce a clear, vendor-ready report in Markdown.
No disclaimers, no hedging. Be precise and technical.

Structure: Executive Summary, Affected (component/versions/CWE/CVSS),
Technical Detail (root cause with file:line), Reproduction (numbered steps),
Impact, Suggested Remediation, Timeline, Credits.

Where a fact is not present in the material, write `TODO` rather than inventing
versions, offsets, or addresses.

# Material

{{static_output}}

Write the report now."#;

fn emit(ctx: &Ctx, args: &ReportArgs, body: &str) -> Result<i32> {
    match &args.out {
        Some(path) => {
            std::fs::write(path, body)?;
            ctx.ui.status(&format!("  written: {path}"));
        }
        None => util::emit(body, ctx.cfg().output.pager && !ctx.no_pager),
    }
    Ok(0)
}
