//! High-level terminal renderers for command results. Produces the boxed,
//! color-aligned text output described in RFC §5.2.

use super::{
    boxed, indent, wrap, Cell, Painter, Rgb, Ui, ACCENT, BORDER, DIM, HIGHLIGHT, INFO, PRIMARY,
    SUCCESS, BOX_WIDTH,
};
use crate::analysis::{cwe, AnalysisResult, Entry, ReconResult, Severity};

const LABEL_W: usize = 11;

fn severity_color(s: Severity) -> Rgb {
    match s {
        Severity::Critical | Severity::High => HIGHLIGHT,
        Severity::Medium => ACCENT,
        Severity::Low => PRIMARY,
        Severity::Info => DIM,
    }
}

/// A `LABEL    value` row with a dim label and optionally colored value.
fn kv(p: &Painter, label: &str, value: &str, color: Option<Rgb>) -> Cell {
    let mut c = Cell::new();
    c.paint(p, DIM, label);
    if label.chars().count() < LABEL_W {
        c.pad(LABEL_W - label.chars().count());
    }
    match color {
        Some(col) => {
            c.paint(p, col, value);
        }
        None => {
            c.paint(p, PRIMARY, value);
        }
    }
    c
}

fn prose_rows(p: &Painter, text: &str) -> Vec<Cell> {
    wrap(text, BOX_WIDTH)
        .into_iter()
        .map(|l| {
            let mut c = Cell::new();
            c.paint(p, PRIMARY, &l);
            c
        })
        .collect()
}

/// Render a single finding as a titled box.
fn finding_box(p: &Painter, f: &crate::analysis::Finding) -> String {
    let mut rows: Vec<Cell> = Vec::new();
    rows.push(kv(
        p,
        "SEVERITY",
        f.severity.label(),
        Some(severity_color(f.severity)),
    ));
    if let Some(cwe_id) = &f.cwe {
        let v = format!("{cwe_id} — {}", cwe::name_for(cwe_id));
        rows.push(kv(p, "CLASS", &v, Some(PRIMARY)));
    }
    if let Some(line) = f.line {
        rows.push(kv(p, "LINE", &line.to_string(), Some(HIGHLIGHT)));
    }
    let reach = match (f.reachable, f.pre_auth) {
        (true, true) => "pre-auth, network/attacker-reachable".to_string(),
        (true, false) => "reachable from attacker-influenced input".to_string(),
        (false, true) => "pre-auth path".to_string(),
        (false, false) => "no reachability evidence (static)".to_string(),
    };
    rows.push(kv(p, "REACHABLE", &reach, Some(PRIMARY)));

    rows.push(Cell::new());
    rows.extend(prose_rows(p, &f.detail));

    if let Some(pv) = &f.patch_vector {
        rows.push(Cell::new());
        let mut head = Cell::new();
        head.paint(p, SUCCESS, "PATCH VECTOR");
        rows.push(head);
        rows.extend(prose_rows(p, pv));
    }

    let title = format!("FINDING {}", f.id);
    boxed(p, &title, &rows, BORDER)
}

/// Render the `[AI] EXTENDED ANALYSIS` block (RFC §5.2).
fn ai_box(p: &Painter, model: Option<&str>, text: &str) -> String {
    let mut rows = Vec::new();
    if let Some(m) = model {
        let mut c = Cell::new();
        c.paint(p, INFO, &format!("model: {m}"));
        rows.push(c);
        rows.push(Cell::new());
    }
    rows.extend(
        wrap(text, BOX_WIDTH)
            .into_iter()
            .map(|l| {
                let mut c = Cell::new();
                c.paint(p, INFO, &l);
                c
            }),
    );
    boxed(p, "[AI] EXTENDED ANALYSIS", &rows, INFO)
}

/// Full `analyze` text output.
pub fn analysis(
    ui: &Ui,
    res: &AnalysisResult,
    provider: Option<&str>,
    session: Option<&str>,
    duration_ms: u128,
) -> String {
    let p = ui.painter();
    let mut out = String::new();

    out.push_str(&ui.section("ANALYSIS", &res.target));
    out.push('\n');

    if ui.verbosity >= 1 {
        out.push_str(&format!("  {} {}\n", p.paint(DIM, "target   "), res.target));
        if let Some(focus) = &res.focus {
            out.push_str(&format!("  {} {}\n", p.paint(DIM, "focus    "), focus));
        }
        let prov = provider.unwrap_or("— (static only)");
        out.push_str(&format!("  {} {}\n", p.paint(DIM, "provider "), prov));
    }
    out.push('\n');

    for f in &res.findings {
        out.push_str(&indent(&finding_box(&p, f)));
        out.push_str("\n\n");
    }

    if res.findings.is_empty() {
        out.push_str(&format!(
            "  {}\n\n",
            p.paint(SUCCESS, "no findings from static analysis")
        ));
    }

    if let Some(block) = &res.ai_block {
        out.push_str(&indent(&ai_box(&p, provider, block)));
        out.push_str("\n\n");
    }

    if let Some(v) = &res.cvss {
        out.push_str(&format!("  {} {}\n", p.paint(DIM, "cvss     "), p.paint(HIGHLIGHT, v)));
    }

    if ui.verbosity >= 1 {
        let c = res.summary_counts();
        let rule = "─".repeat(BOX_WIDTH + 2);
        out.push_str(&format!("  {}\n", p.paint(BORDER, &rule)));
        out.push_str(&format!(
            "  {} finding(s)  ·  {} crit  ·  {} high  ·  {} medium  ·  {} low\n",
            c.total, c.critical, c.high, c.medium, c.low
        ));
        let sess = session.unwrap_or("—");
        out.push_str(&p.paint(
            DIM,
            &format!(
                "  time: {:.1}s  ·  lines analyzed: {}  ·  session: {}\n",
                duration_ms as f64 / 1000.0,
                res.lines_analyzed,
                sess
            ),
        ));
    }

    out
}

/// Full `recon` text output.
pub fn recon(ui: &Ui, res: &ReconResult, provider: Option<&str>, duration_ms: u128) -> String {
    let p = ui.painter();
    let mut out = String::new();

    out.push_str(&ui.section("RECON", &res.target));
    out.push('\n');
    if ui.verbosity >= 1 {
        if let Some(f) = &res.filter {
            out.push_str(&format!("  {} {}\n", p.paint(DIM, "filter   "), f));
        }
        out.push_str(&format!(
            "  {} {}\n",
            p.paint(DIM, "scanned  "),
            format!("{} file(s)", res.files_scanned)
        ));
        let prov = provider.unwrap_or("— (static only)");
        out.push_str(&format!("  {} {}\n", p.paint(DIM, "provider "), prov));
    }
    out.push('\n');

    if res.entries.is_empty() {
        out.push_str(&format!("  {}\n", p.paint(DIM, "no entry points surfaced")));
    }

    for e in &res.entries {
        out.push_str(&entry_line(&p, e));
        out.push('\n');
    }

    if let Some(block) = &res.ai_block {
        out.push('\n');
        out.push_str(&indent(&ai_box(&p, provider, block)));
        out.push('\n');
    }

    if ui.verbosity >= 1 {
        let rule = "─".repeat(BOX_WIDTH + 2);
        out.push_str(&format!("\n  {}\n", p.paint(BORDER, &rule)));
        out.push_str(&p.paint(
            DIM,
            &format!(
                "  {} entry point(s)  ·  time: {:.1}s\n",
                res.entries.len(),
                duration_ms as f64 / 1000.0
            ),
        ));
    }

    out
}

fn entry_line(p: &Painter, e: &Entry) -> String {
    let sev = severity_color(e.severity);
    let marker = p.paint(sev, "▸");
    let kind = p.paint(ACCENT, &format!("[{:<9}]", e.kind));
    let loc = p.paint(DIM, &format!("{}:{}", e.file, e.line));
    let pre = if e.pre_auth {
        p.paint(HIGHLIGHT, " pre-auth")
    } else {
        String::new()
    };
    format!(
        "  {marker} {kind} {}{}\n      {} · {}",
        p.paint(PRIMARY, &e.name),
        pre,
        loc,
        p.paint(DIM, &e.note)
    )
}

/// Markdown rendering of an analysis (for `--output markdown`).
pub fn analysis_md(res: &AnalysisResult) -> String {
    let mut s = String::new();
    s.push_str(&format!("# Analysis — {}\n\n", res.target));
    if let Some(f) = &res.focus {
        s.push_str(&format!("**Focus:** {f}\n\n"));
    }
    s.push_str(&format!("**AI used:** {}\n\n", res.ai_used));
    if res.findings.is_empty() {
        s.push_str("_No findings from static analysis._\n\n");
    }
    for f in &res.findings {
        s.push_str(&format!("## Finding {} — {}\n\n", f.id, f.severity.label()));
        if let Some(c) = &f.cwe {
            s.push_str(&format!("- **Class:** {c} — {}\n", cwe::name_for(c)));
        }
        if let Some(l) = f.line {
            s.push_str(&format!("- **Line:** {l}\n"));
        }
        s.push_str(&format!(
            "- **Reachable:** {} · **Pre-auth:** {}\n\n",
            f.reachable, f.pre_auth
        ));
        s.push_str(&format!("{}\n\n", f.detail));
        if let Some(pv) = &f.patch_vector {
            s.push_str(&format!("**Patch vector:** {pv}\n\n"));
        }
    }
    if let Some(v) = &res.cvss {
        s.push_str(&format!("**CVSS 3.1 (suggested):** `{v}`\n\n"));
    }
    if let Some(block) = &res.ai_block {
        s.push_str("## [AI] Extended Analysis\n\n");
        s.push_str(block);
        s.push_str("\n\n");
    }
    let c = res.summary_counts();
    s.push_str(&format!(
        "---\n\n_{} finding(s): {} critical, {} high, {} medium, {} low_\n",
        c.total, c.critical, c.high, c.medium, c.low
    ));
    s
}

/// Markdown rendering of a recon result.
pub fn recon_md(res: &ReconResult) -> String {
    let mut s = String::new();
    s.push_str(&format!("# Recon — {}\n\n", res.target));
    if let Some(f) = &res.filter {
        s.push_str(&format!("**Filter:** {f}\n\n"));
    }
    s.push_str(&format!("**Files scanned:** {}\n\n", res.files_scanned));
    if res.entries.is_empty() {
        s.push_str("_No entry points surfaced._\n\n");
    } else {
        s.push_str("| Severity | Kind | Entry | Location | Pre-auth |\n");
        s.push_str("|---|---|---|---|---|\n");
        for e in &res.entries {
            s.push_str(&format!(
                "| {} | {} | {} | {}:{} | {} |\n",
                e.severity.label(),
                e.kind,
                e.name,
                e.file,
                e.line,
                e.pre_auth
            ));
        }
        s.push('\n');
    }
    if let Some(block) = &res.ai_block {
        s.push_str("## [AI] Ranked Audit Plan\n\n");
        s.push_str(block);
        s.push('\n');
    }
    s
}

