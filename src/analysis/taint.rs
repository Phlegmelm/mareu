//! A deliberately small taint pass.
//!
//! It identifies variables assigned (directly) from a taint *source* — network
//! reads, environment, argv, file reads — and reports whether a given line uses
//! any of them. This is not interprocedural and does not track aliasing; it is
//! a cheap signal to raise confidence that a flagged sink touches attacker
//! input.

use std::collections::BTreeSet;

/// Functions whose return value (or out-parameter) is attacker-influenced.
const SOURCE_FNS: &[&str] = &[
    "recv",
    "recvfrom",
    "read",
    "fread",
    "fgets",
    "getenv",
    "scanf",
    "sscanf",
    "getline",
    "json_loads",
    "atoi",
    "strtol",
];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Extract the left-hand identifier of a simple `lhs = ...;` assignment.
fn assigned_ident(line: &str) -> Option<&str> {
    let eq = line.find('=')?;
    // Avoid ==, !=, <=, >=.
    let bytes = line.as_bytes();
    if line[eq..].starts_with("==") {
        return None;
    }
    if eq > 0 && matches!(bytes[eq - 1], b'!' | b'<' | b'>' | b'=') {
        return None;
    }
    let lhs = line[..eq].trim();
    // Take the last identifier on the LHS (handles `int n` and `*p`).
    lhs.rsplit(|c: char| !is_ident_char(c))
        .find(|s| !s.is_empty())
}

/// Collect variables tainted by a direct assignment from a source function, or
/// passed by-address to a source (`recv(fd, &buf, ...)`).
pub fn tainted_variables(content: &str) -> BTreeSet<String> {
    let mut tainted = BTreeSet::new();
    for line in content.lines() {
        let calls_source = SOURCE_FNS.iter().any(|f| {
            // crude whole-word-ish containment with a following '('
            line.find(f)
                .map(|i| line[i + f.len()..].trim_start().starts_with('('))
                .unwrap_or(false)
        });
        if !calls_source {
            continue;
        }
        if let Some(v) = assigned_ident(line) {
            tainted.insert(v.to_string());
        }
        // Out-parameters: `recv(fd, buf, ...)` / `read(fd, &buf, ...)`.
        if let Some(open) = line.find('(') {
            if let Some(close) = line[open..].find(')') {
                let args = &line[open + 1..open + close];
                for arg in args.split(',').skip(1) {
                    let a = arg.trim().trim_start_matches('&').trim();
                    let ident: String = a.chars().take_while(|&c| is_ident_char(c)).collect();
                    if ident.len() > 1 {
                        tainted.insert(ident);
                    }
                }
            }
        }
    }
    tainted
}

/// Does `line` reference any tainted variable as a whole word?
pub fn line_uses_any(line: &str, vars: &BTreeSet<String>) -> bool {
    if vars.is_empty() {
        return false;
    }
    let bytes = line.as_bytes();
    for v in vars {
        let mut start = 0;
        while let Some(pos) = line[start..].find(v.as_str()) {
            let s = start + pos;
            let e = s + v.len();
            let before = s == 0 || !is_ident_char(bytes[s - 1] as char);
            let after = e >= line.len() || !is_ident_char(bytes[e] as char);
            if before && after {
                return true;
            }
            start = e;
        }
    }
    false
}
