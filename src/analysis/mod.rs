//! Static analysis: attack-surface mapping, flag-pattern scanning, CWE
//! heuristics, and a light taint pass. None of this calls a model — it is the
//! deterministic core that `--ai` later *annotates* (RFC §3.6).

pub mod cwe;
pub mod surface;
pub mod taint;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Severity vocabulary. Ordered so `cmp` reflects risk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

/// Where a finding came from — keeps trust calibration honest (RFC §3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Static,
    Ai,
}

/// A single analysis finding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: u32,
    pub severity: Severity,
    /// CWE identifier like "CWE-252" when classified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub reachable: bool,
    pub pre_auth: bool,
    /// One-line summary.
    pub summary: String,
    /// Longer prose detail.
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_vector: Option<String>,
    pub origin: Origin,
}

/// The result of an `analyze` run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focus: Option<String>,
    pub findings: Vec<Finding>,
    pub lines_analyzed: usize,
    pub ai_used: bool,
    /// Free-form AI extended-analysis block (rendered separately, marked [AI]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_block: Option<String>,
    /// Optional CVSS 3.1 vector string when `--cvss` requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<String>,
}

impl AnalysisResult {
    pub fn summary_counts(&self) -> SeverityCounts {
        let mut c = SeverityCounts::default();
        for f in &self.findings {
            match f.severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
                Severity::Info => c.info += 1,
            }
        }
        c.total = self.findings.len();
        c
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// A discovered attack-surface entry point (recon).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// Function or location name.
    pub name: String,
    pub file: String,
    pub line: usize,
    /// Category: "network", "parser", "auth-gate", "flag-site".
    pub kind: String,
    pub pre_auth: bool,
    /// Short reason this surfaced.
    pub note: String,
    pub severity: Severity,
}

/// The result of a `recon` run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconResult {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    pub files_scanned: usize,
    pub entries: Vec<Entry>,
    pub ai_used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_block: Option<String>,
}
