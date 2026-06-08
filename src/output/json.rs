//! JSON output envelopes (RFC §5.4). Stable, documented shape so Claude Code
//! and `jq`-driven tooling can build on it.

use crate::analysis::{AnalysisResult, ReconResult};
use serde_json::json;

/// Envelope for `analyze --output json`.
pub fn analysis(res: &AnalysisResult, timestamp: &str, duration_ms: u128) -> serde_json::Value {
    let c = res.summary_counts();
    json!({
        "command": "analyze",
        "target": res.target,
        "timestamp": timestamp,
        "ai_used": res.ai_used,
        "focus": res.focus,
        "findings": res.findings,
        "cvss": res.cvss,
        "ai_block": res.ai_block,
        "summary": {
            "total": c.total,
            "critical": c.critical,
            "high": c.high,
            "medium": c.medium,
            "low": c.low,
            "info": c.info,
        },
        "lines_analyzed": res.lines_analyzed,
        "duration_ms": duration_ms,
    })
}

/// Envelope for `recon --output json`.
pub fn recon(res: &ReconResult, timestamp: &str, duration_ms: u128) -> serde_json::Value {
    json!({
        "command": "recon",
        "target": res.target,
        "timestamp": timestamp,
        "ai_used": res.ai_used,
        "filter": res.filter,
        "files_scanned": res.files_scanned,
        "entries": res.entries,
        "ai_block": res.ai_block,
        "duration_ms": duration_ms,
    })
}

/// Pretty-print a JSON value with a trailing newline.
pub fn to_string(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string())
}
