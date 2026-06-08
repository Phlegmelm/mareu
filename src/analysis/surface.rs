//! Attack-surface mapping and flag-site scanning (the non-AI core of `recon`
//! and `analyze`).
//!
//! The scanner is lexical: it finds calls to dangerous/interesting functions on
//! word boundaries, attributes each to its enclosing function, and applies a
//! handful of reachability/pre-auth heuristics. It is intentionally heuristic —
//! the value is fast, deterministic surfacing, not soundness.

use super::cwe;
use super::{AnalysisResult, Entry, Finding, Origin, Severity};
use crate::config::AnalysisConfig;
use aho_corasick::AhoCorasick;
use std::path::{Path, PathBuf};

/// Source file extensions recon will scan when walking a tree.
pub const SOURCE_EXTS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "rs", "py", "go", "js", "ts", "java", "rb", "php",
];

/// Tokens that indicate the code reads from the network.
const NETWORK_TOKENS: &[&str] = &[
    "recv", "recvfrom", "recvmsg", "accept", "accept4", "WSARecv", "SSL_read",
];
/// Tokens that indicate a parser/deserialization entry point.
const PARSER_TOKENS: &[&str] = &[
    "parse",
    "decode",
    "deserialize",
    "unmarshal",
    "scan",
    "tokenize",
    "read_",
];
/// Tokens that indicate an authentication/authorization gate.
const AUTH_TOKENS: &[&str] = &[
    "authenticate",
    "auth_check",
    "check_auth",
    "verify_password",
    "login",
    "is_authorized",
    "require_auth",
    "check_perm",
];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// A flagged call site.
struct FlagSite {
    line: usize,
    token: String,
}

/// Find whole-word occurrences of any pattern, one record per match.
fn find_flag_sites(content: &str, patterns: &[String]) -> Vec<FlagSite> {
    if patterns.is_empty() {
        return Vec::new();
    }
    let ac = match AhoCorasick::new(patterns) {
        Ok(ac) => ac,
        Err(_) => return Vec::new(),
    };
    let mut sites = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        // Skip obvious comment lines to cut noise.
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with('#') {
            continue;
        }
        for m in ac.find_iter(line) {
            let (s, e) = (m.start(), m.end());
            let bytes = line.as_bytes();
            let before_ok = s == 0 || !is_ident_char(bytes[s - 1] as char);
            let after_ok = e >= line.len() || !is_ident_char(bytes[e] as char);
            // Require a following '(' (allowing whitespace) so we match calls,
            // not incidental substrings or declarations.
            let rest = line[e..].trim_start();
            let looks_like_call = rest.starts_with('(');
            if before_ok && after_ok && looks_like_call {
                sites.push(FlagSite {
                    line: idx + 1,
                    token: patterns
                        .iter()
                        .find(|p| line[s..e].eq_ignore_ascii_case(p))
                        .cloned()
                        .unwrap_or_else(|| line[s..e].to_string()),
                });
            }
        }
    }
    sites
}

/// Name of the function enclosing `line_no` (1-based), best-effort.
fn enclosing_function(content: &str, line_no: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut i = line_no.min(lines.len());
    while i > 0 {
        let l = lines[i - 1];
        // A definition heuristic: contains '(' and ends with '{' (or the next
        // non-empty line is '{'), and has an identifier just before '('.
        if let Some(paren) = l.find('(') {
            // The brace may sit after the ')' on the same line, possibly with a
            // trailing comment (`) {  // ...`), or on the next line.
            let opens_block = l[paren..].contains('{')
                || lines
                    .get(i)
                    .map(|n| n.trim_start().starts_with('{'))
                    .unwrap_or(false);
            if opens_block {
                let head = &l[..paren];
                if let Some(name) = head
                    .rsplit(|c: char| !is_ident_char(c))
                    .find(|s| !s.is_empty())
                {
                    // Skip control keywords masquerading as calls.
                    if !matches!(name, "if" | "for" | "while" | "switch" | "return") {
                        return Some(name.to_string());
                    }
                }
            }
        }
        i -= 1;
    }
    None
}

fn has_token(content: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|t| content.contains(t))
}

fn line_has_pre_auth(content: &str, line_no: usize, markers: &[String]) -> bool {
    // Pre-auth if a marker appears in the enclosing function name or within a
    // small window above the site.
    if let Some(fname) = enclosing_function(content, line_no) {
        let f = fname.to_ascii_lowercase();
        if markers.iter().any(|m| f.contains(&m.to_ascii_lowercase())) {
            return true;
        }
    }
    let lines: Vec<&str> = content.lines().collect();
    let start = line_no.saturating_sub(15);
    for l in lines.iter().take(line_no).skip(start) {
        let low = l.to_ascii_lowercase();
        if markers
            .iter()
            .any(|m| low.contains(&m.to_ascii_lowercase()))
        {
            return true;
        }
    }
    false
}

/// Run static analysis over a single file's content.
pub fn analyze_file(
    target: &str,
    content: &str,
    focus: Option<&str>,
    line_filter: Option<(usize, usize)>,
    want_cwe: bool,
    want_cvss: bool,
    cfg: &AnalysisConfig,
) -> AnalysisResult {
    let network = has_token(content, NETWORK_TOKENS);
    let tainted = super::taint::tainted_variables(content);
    let lines: Vec<&str> = content.lines().collect();
    let sites = find_flag_sites(content, &cfg.flag_patterns);
    let mut findings = Vec::new();
    let mut id = 0u32;

    for site in sites {
        if let Some((lo, hi)) = line_filter {
            if site.line < lo || site.line > hi {
                continue;
            }
        }
        let Some(class) = cwe::classify(&site.token) else {
            continue;
        };
        id += 1;
        let pre_auth = line_has_pre_auth(content, site.line, &cfg.pre_auth_markers);
        // A sink that consumes a tainted variable is reachable, and one notch
        // more severe than the lexical default.
        let site_line = lines.get(site.line - 1).copied().unwrap_or("");
        let tainted_here = super::taint::line_uses_any(site_line, &tainted);
        let reachable = network || tainted_here;
        let severity = if tainted_here {
            match class.default_severity {
                Severity::Low => Severity::Medium,
                Severity::Medium => Severity::High,
                Severity::High => Severity::Critical,
                other => other,
            }
        } else {
            class.default_severity
        };
        let fname = enclosing_function(content, site.line).unwrap_or_else(|| "?".into());
        let summary = format!("{}() at line {} — {}", site.token, site.line, class.name);
        let detail = format!(
            "Call to {}() in {}(). Classified as {} ({}). {}{}",
            site.token,
            fname,
            class.name,
            class.id,
            if network {
                "Network-reachable input flows into this region. "
            } else {
                ""
            },
            if pre_auth {
                "Reached before an authentication gate."
            } else {
                ""
            }
        );
        // CWE is always classified; `--cwe` additionally surfaces the full name
        // in the finding detail (handled at render time). The struct field is
        // always populated so JSON consumers get it unconditionally.
        let _ = want_cwe;
        findings.push(Finding {
            id,
            severity,
            cwe: Some(class.id.to_string()),
            line: Some(site.line),
            reachable,
            pre_auth,
            summary,
            detail,
            patch_vector: Some(class.patch_vector.to_string()),
            origin: Origin::Static,
        });
    }

    // Sort by severity desc, then line asc, and re-number.
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));
    for (i, f) in findings.iter_mut().enumerate() {
        f.id = (i + 1) as u32;
    }

    let cvss = if want_cvss {
        let top = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        let pre_auth = findings.iter().any(|f| f.pre_auth);
        Some(cwe::cvss_vector(top, pre_auth, network))
    } else {
        None
    };

    AnalysisResult {
        target: target.to_string(),
        focus: focus.map(str::to_string),
        lines_analyzed: content.lines().count(),
        findings,
        ai_used: false,
        ai_block: None,
        cvss,
    }
}

/// Map the attack surface of a single file into entry points.
pub fn recon_file(
    file: &str,
    content: &str,
    filter: Option<&str>,
    cfg: &AnalysisConfig,
) -> Vec<Entry> {
    let mut entries = Vec::new();
    let network = has_token(content, NETWORK_TOKENS);

    // Network / parser / auth-gate entry points, attributed by enclosing fn.
    let mut seen = std::collections::BTreeSet::new();
    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        let kind = if NETWORK_TOKENS.iter().any(|t| line.contains(t)) {
            Some("network")
        } else if AUTH_TOKENS.iter().any(|t| line.contains(t)) {
            Some("auth-gate")
        } else if PARSER_TOKENS.iter().any(|t| line.contains(t)) {
            Some("parser")
        } else {
            None
        };

        let Some(kind) = kind else { continue };
        let fname = enclosing_function(content, line_no).unwrap_or_else(|| "?".into());
        let key = (fname.clone(), kind);
        if !seen.insert(key) {
            continue;
        }
        let pre_auth = line_has_pre_auth(content, line_no, &cfg.pre_auth_markers);
        let severity = match kind {
            "network" if pre_auth => Severity::High,
            "network" => Severity::Medium,
            "parser" => Severity::Medium,
            "auth-gate" => Severity::Info,
            _ => Severity::Low,
        };
        let note = match kind {
            "network" => "reads attacker-controlled bytes off the wire",
            "parser" => "decodes/parses untrusted input",
            "auth-gate" => "authentication / authorization boundary",
            _ => "",
        }
        .to_string();
        entries.push(Entry {
            name: fname,
            file: file.to_string(),
            line: line_no,
            kind: kind.to_string(),
            pre_auth: pre_auth || (kind == "network" && network),
            note,
            severity,
        });
    }

    // Flag sites become "flag-site" entries (low-signal but useful in surface).
    for site in find_flag_sites(content, &cfg.flag_patterns) {
        let fname = enclosing_function(content, site.line).unwrap_or_else(|| "?".into());
        if seen.insert((format!("{fname}:{}", site.line), "flag-site")) {
            entries.push(Entry {
                name: format!("{fname} → {}()", site.token),
                file: file.to_string(),
                line: site.line,
                kind: "flag-site".to_string(),
                pre_auth: line_has_pre_auth(content, site.line, &cfg.pre_auth_markers),
                note: format!("dangerous sink: {}()", site.token),
                severity: Severity::Low,
            });
        }
    }

    filter_entries(&mut entries, filter);
    entries.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));
    entries
}

/// Retain only entries matching a surface filter (kind, note substring,
/// pre-auth, or the "network" shortcut).
fn filter_entries(entries: &mut Vec<Entry>, filter: Option<&str>) {
    let Some(filter) = filter else { return };
    let f = filter.to_ascii_lowercase();
    entries.retain(|e| {
        e.kind.contains(&f)
            || e.note.to_ascii_lowercase().contains(&f)
            || (f.contains("pre-auth") && e.pre_auth)
            || (f == "network" && e.kind == "network")
    });
}

/// Classify a called symbol (from disassembly) into a surface category.
fn classify_symbol(
    sym: &str,
    _cfg: &AnalysisConfig,
) -> Option<(&'static str, Severity, &'static str)> {
    if NETWORK_TOKENS
        .iter()
        .any(|t| sym.contains(&t.to_ascii_lowercase()))
    {
        return Some(("network", Severity::High, "reads network input"));
    }
    if AUTH_TOKENS.iter().any(|t| sym.contains(t)) {
        return Some(("auth-gate", Severity::Info, "auth/authz boundary"));
    }
    if PARSER_TOKENS.iter().any(|t| sym.contains(t)) {
        return Some(("parser", Severity::Medium, "parses/decodes input"));
    }
    if let Some(class) = cwe::classify(sym) {
        return Some(("flag-site", class.default_severity, "dangerous sink"));
    }
    None
}

/// Map the attack surface of a **binary** from its objdump disassembly.
///
/// Walks the dump tracking the enclosing function (`<addr> <name>:` headers) and
/// surfaces `call`/PLT-`jmp` sites to interesting symbols (network, parser,
/// auth, dangerous libc sinks), attributed to their caller.
pub fn recon_disasm(
    file: &str,
    disasm: &str,
    cfg: &AnalysisConfig,
    filter: Option<&str>,
) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut current_fn = String::from("?");
    let mut seen = std::collections::BTreeSet::new();

    for (idx, line) in disasm.lines().enumerate() {
        let trimmed = line.trim();

        // Function header: "0000000000001139 <main>:"
        if trimmed.ends_with(">:") {
            if let Some(s) = trimmed.find('<') {
                current_fn = trimmed[s + 1..trimmed.len() - 2].to_string();
            }
            continue;
        }

        // Instruction: "  1140:\tcall   1030 <recv@plt>"
        let Some((addr_part, instr)) = trimmed.split_once(':') else {
            continue;
        };
        let instr = instr.trim();
        let mnem = instr.split_whitespace().next().unwrap_or("");
        if mnem != "call" && mnem != "jmp" {
            continue;
        }
        // Extract the symbol inside <...>.
        let Some(lt) = instr.rfind('<') else { continue };
        let Some(gt_rel) = instr[lt..].find('>') else {
            continue;
        };
        let raw_sym = &instr[lt + 1..lt + gt_rel];
        let had_plt = raw_sym.contains("@plt");
        if mnem == "jmp" && !had_plt {
            continue; // local jumps are control flow, not calls of interest
        }
        // Clean: drop @plt/@got suffix and +0x.. offset.
        let sym: String = raw_sym
            .chars()
            .take_while(|&c| c != '@' && c != '+')
            .collect();
        let sym_l = sym.to_ascii_lowercase();
        if sym_l.is_empty() {
            continue;
        }
        let Some((kind, severity, note_kind)) = classify_symbol(&sym_l, cfg) else {
            continue;
        };
        if !seen.insert((current_fn.clone(), sym_l.clone())) {
            continue;
        }
        let pre_auth = cfg.pre_auth_markers.iter().any(|m| {
            current_fn
                .to_ascii_lowercase()
                .contains(&m.to_ascii_lowercase())
        });
        entries.push(Entry {
            name: format!("{current_fn} → {sym}()"),
            file: file.to_string(),
            line: idx + 1,
            kind: kind.to_string(),
            pre_auth,
            note: format!("{note_kind}: calls {sym} @ 0x{}", addr_part.trim()),
            severity,
        });
    }

    filter_entries(&mut entries, filter);
    entries.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));
    entries
}

/// Run recon over an explicit list of files. Returns (sorted entries, files
/// actually read).
pub fn recon_files(
    files: &[PathBuf],
    filter: Option<&str>,
    cfg: &AnalysisConfig,
) -> (Vec<Entry>, usize) {
    let mut entries = Vec::new();
    let mut scanned = 0usize;
    for f in files {
        if let Ok(content) = std::fs::read_to_string(f) {
            scanned += 1;
            entries.extend(recon_file(&relative(f), &content, filter, cfg));
        }
    }
    entries.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));
    (entries, scanned)
}

/// Run recon over a path: a single file, or a source tree walked to `depth`.
pub fn recon_tree(
    root: &Path,
    filter: Option<&str>,
    depth: Option<usize>,
    cfg: &AnalysisConfig,
) -> (Vec<Entry>, usize) {
    if root.is_file() {
        return recon_files(&[root.to_path_buf()], filter, cfg);
    }
    let mut files = Vec::new();
    walk(root, 0, depth, &mut files);
    recon_files(&files, filter, cfg)
}

/// Recursively collect source files, skipping VCS/dependency/build dirs.
pub fn walk(dir: &Path, depth: usize, max: Option<usize>, out: &mut Vec<PathBuf>) {
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
        if p.is_dir() {
            if matches!(
                name.as_ref(),
                ".git" | "node_modules" | "target" | "vendor" | "build" | ".svn"
            ) {
                continue;
            }
            walk(&p, depth + 1, max, out);
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

/// Path relative to the CWD when possible, with forward slashes for display.
pub fn relative(p: &Path) -> String {
    std::env::current_dir()
        .ok()
        .and_then(|cwd| p.strip_prefix(&cwd).ok().map(|r| r.to_path_buf()))
        .unwrap_or_else(|| p.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AnalysisConfig;

    const SRC: &str = r#"
int parse_client_hello(int fd) {
    char buf[64];
    int n = recv(fd, buf, 4096, 0);
    char dst[16];
    memcpy(dst, buf, n);
    return n;
}
"#;

    #[test]
    fn taint_promotes_memcpy_to_critical() {
        let cfg = AnalysisConfig::default();
        let res = analyze_file("t.c", SRC, None, None, true, false, &cfg);
        let memcpy = res
            .findings
            .iter()
            .find(|f| f.summary.contains("memcpy"))
            .expect("memcpy finding");
        // recv() taints `n`; memcpy(dst, buf, n) consumes it → bumped a notch.
        assert_eq!(memcpy.severity, Severity::Critical);
        assert!(memcpy.reachable);
        assert_eq!(memcpy.cwe.as_deref(), Some("CWE-787"));
    }

    #[test]
    fn enclosing_function_resolves_through_brace_comment() {
        let src = "int foo(int x) {  // trailing comment\n  strcpy(a, b);\n}\n";
        let cfg = AnalysisConfig::default();
        let res = analyze_file("t.c", src, None, None, false, false, &cfg);
        assert!(res.findings.iter().any(|f| f.detail.contains("foo()")));
    }

    #[test]
    fn line_filter_restricts_findings() {
        let cfg = AnalysisConfig::default();
        let res = analyze_file("t.c", SRC, None, Some((6, 6)), false, false, &cfg);
        assert_eq!(res.findings.len(), 1);
        assert_eq!(res.findings[0].line, Some(6));
    }

    #[test]
    fn recon_surfaces_network_entry() {
        let cfg = AnalysisConfig::default();
        let entries = recon_file("t.c", SRC, None, &cfg);
        assert!(entries.iter().any(|e| e.kind == "network"));
    }

    #[test]
    fn recon_disasm_attributes_calls_to_caller() {
        let dump = "\
0000000000001139 <parse_packet>:
    1140:\tcall   1030 <recv@plt>
    1150:\tcall   1040 <memcpy@plt>
000000000000119a <main>:
    11a0:\tcall   1050 <printf@plt>
    11b0:\tjmp    1060 <strcpy@plt>
";
        let cfg = AnalysisConfig::default();
        let entries = recon_disasm("bin", dump, &cfg, None);
        assert!(entries.iter().any(|e| e.kind == "network"
            && e.name.contains("parse_packet")
            && e.name.contains("recv")));
        assert!(entries.iter().any(|e| e.name.contains("memcpy")));
        assert!(entries
            .iter()
            .any(|e| e.name.contains("strcpy") && e.name.contains("main")));
        // printf isn't an interesting sink → not surfaced.
        assert!(!entries.iter().any(|e| e.name.contains("printf")));
    }

    #[test]
    fn recon_disasm_filter_applies() {
        let dump = "\
0000000000001139 <handler>:
    1140:\tcall   1030 <recv@plt>
    1150:\tcall   1040 <strcpy@plt>
";
        let cfg = AnalysisConfig::default();
        let entries = recon_disasm("bin", dump, &cfg, Some("network"));
        assert!(entries.iter().all(|e| e.kind == "network"));
        assert_eq!(entries.len(), 1);
    }
}
