//! CWE classification heuristics.
//!
//! These are deliberately simple lexical heuristics, not a full data-flow
//! engine. They map a flagged sink (and nearby context) to the most likely CWE
//! so the static layer produces a useful default that AI can refine.

use super::Severity;

/// A classified sink category.
pub struct CweClass {
    pub id: &'static str,
    pub name: &'static str,
    pub default_severity: Severity,
    pub patch_vector: &'static str,
}

/// Classify a flagged token/sink to a CWE. Returns `None` for tokens that are
/// only weakly interesting on their own.
pub fn classify(token: &str) -> Option<CweClass> {
    let t = token.to_ascii_lowercase();
    let c = match t.as_str() {
        "strcpy" | "strcat" | "sprintf" | "gets" | "memcpy" | "alloca" => CweClass {
            id: "CWE-787",
            name: "Out-of-bounds Write",
            default_severity: Severity::High,
            patch_vector: "bound the copy; prefer strlcpy/snprintf or a length-checked memcpy",
        },
        "recv" | "read" => CweClass {
            id: "CWE-252",
            name: "Unchecked Return Value",
            default_severity: Severity::Medium,
            patch_vector: "check the return value for <= 0 before using it as a size or index",
        },
        "malloc" | "realloc" | "calloc" | "mmap" => CweClass {
            id: "CWE-190",
            name: "Integer Overflow in Allocation Size",
            default_severity: Severity::Medium,
            patch_vector: "validate size arithmetic for overflow before allocating",
        },
        "free" => CweClass {
            id: "CWE-416",
            name: "Use After Free / Double Free",
            default_severity: Severity::High,
            patch_vector: "null the pointer after free; verify no later dereference or second free",
        },
        "strlen" => CweClass {
            id: "CWE-125",
            name: "Out-of-bounds Read",
            default_severity: Severity::Low,
            patch_vector: "ensure the buffer is NUL-terminated within bounds before strlen",
        },
        "system" | "exec" | "popen" => CweClass {
            id: "CWE-78",
            name: "OS Command Injection",
            default_severity: Severity::High,
            patch_vector: "avoid the shell; use execve with a fixed argv and validated arguments",
        },
        _ => return None,
    };
    Some(c)
}

/// Human-readable name for a CWE id we emit.
pub fn name_for(id: &str) -> &'static str {
    match id {
        "CWE-787" => "Out-of-bounds Write",
        "CWE-252" => "Unchecked Return Value",
        "CWE-190" => "Integer Overflow in Allocation Size",
        "CWE-416" => "Use After Free / Double Free",
        "CWE-125" => "Out-of-bounds Read",
        "CWE-78" => "OS Command Injection",
        _ => "Unclassified",
    }
}

/// Suggest a CVSS 3.1 vector string for a finding given coarse properties.
/// This is a heuristic skeleton the researcher is expected to refine, not an
/// authoritative score.
pub fn cvss_vector(severity: Severity, pre_auth: bool, network: bool) -> String {
    let av = if network { "N" } else { "L" };
    let pr = if pre_auth { "N" } else { "L" };
    let (c, i, a) = match severity {
        Severity::Critical | Severity::High => ("H", "H", "H"),
        Severity::Medium => ("L", "L", "L"),
        _ => ("L", "N", "N"),
    };
    format!("CVSS:3.1/AV:{av}/AC:L/PR:{pr}/UI:N/S:U/C:{c}/I:{i}/A:{a}")
}
