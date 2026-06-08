//! Scaffold generation (RFC §4, §9.3). Handlebars templates compiled into the
//! binary produce real, runnable starting points per bug class. The `--unsafe`
//! gate selects aggressive output via template conditionals; the intent check
//! distinguishes "give me a bug-class PoC" from "attack this named host".

pub mod asm;
pub mod header;

use anyhow::{anyhow, bail, Result};
use handlebars::Handlebars;
use serde_json::json;

use header::{comment_prefix, Header};

// Compiled-in templates.
const T_REPRODUCER: &str = include_str!("templates/reproducer.c.hbs");
const T_BOF: &str = include_str!("templates/poc_bof.c.hbs");
const T_UAF: &str = include_str!("templates/poc_uaf.c.hbs");
const T_FMT: &str = include_str!("templates/poc_fmt.c.hbs");
const T_PROTO: &str = include_str!("templates/poc_proto.py.hbs");
const T_REPORT: &str = include_str!("templates/report.md.hbs");

#[derive(Clone, Debug)]
pub struct ScaffoldRequest {
    /// poc | exploit | reproducer | harness | fuzzer | report
    pub kind: String,
    pub vuln: String,
    /// c | python | rust | asm | bash
    pub lang: String,
    /// bof | uaf | fmt | race | proto | logic | oob | infoleak
    pub class: Option<String>,
    pub arch: String,
    pub asan: bool,
    pub unsafe_mode: bool,
    pub ai: bool,
    pub model: Option<String>,
    /// Path to a custom `.hbs` template overriding the built-in selection.
    pub custom_template: Option<String>,
    pub header_comment: bool,
    pub timestamp: String,
    /// For `--lang asm`: nasm | gas | both.
    pub asm_syntax: String,
    /// Egg tag (cleaned hex, no `0x`) for the egghunter artifact.
    pub egg: Option<String>,
}

/// An additional generated file beyond the primary (e.g. the second assembler
/// syntax when `--syntax both` is requested).
pub struct ExtraFile {
    pub filename: String,
    pub body: String,
}

pub struct Scaffold {
    /// Suggested output filename (no directory).
    pub filename: String,
    /// Header + rendered template (the artifact written to disk).
    pub body: String,
    /// Rendered template without the header — fed to AI / shown in `--dry-run`.
    pub template_only: String,
    pub lang: String,
    /// Extra files emitted alongside the primary (empty for most scaffolds).
    pub extra: Vec<ExtraFile>,
}

/// Languages for which an offline (no-AI) template exists. Asking for any other
/// language without `--ai` is an explicit error rather than a silent C fallback.
fn offline_lang_supported(lang: &str) -> bool {
    matches!(
        lang,
        "" | "c" | "cpp" | "c++" | "python" | "py" | "asm" | "s" | "markdown" | "md"
    )
}

/// Pick the built-in template for a (kind, class) pair and report the effective
/// language (proto/report force their own language).
fn select_template(req: &ScaffoldRequest) -> (&'static str, &'static str, &'static str) {
    // returns (template, ext, lang)
    let class = req.class.as_deref().unwrap_or("");
    match (req.kind.as_str(), class) {
        ("report", _) => (T_REPORT, "md", "markdown"),
        (_, "proto") => (T_PROTO, "py", "python"),
        ("fuzzer", _) | ("harness", _) => {
            if req.lang == "python" {
                (T_PROTO, "py", "python")
            } else {
                (T_REPRODUCER, "c", "c")
            }
        }
        (_, "bof") => (T_BOF, "c", "c"),
        (_, "uaf") => (T_UAF, "c", "c"),
        (_, "fmt") => (T_FMT, "c", "c"),
        // reproducer or unknown class → generic reproducer
        _ => (T_REPRODUCER, "c", "c"),
    }
}

/// Generate a scaffold. Does not write to disk — the caller decides.
pub fn generate(req: &ScaffoldRequest) -> Result<Scaffold> {
    // Assembly is generated programmatically (see `asm`), not from templates.
    if matches!(req.lang.as_str(), "asm" | "s") {
        return generate_asm(req);
    }

    // No silent fallback: refuse an offline language we have no template for.
    if !req.ai && !offline_lang_supported(&req.lang) {
        bail!(
            "no offline template for --lang {}; pass --ai for model-generated output, \
             or use --lang c|python|asm",
            req.lang
        );
    }

    let (template, ext, lang) = if let Some(path) = &req.custom_template {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("reading custom template {path}: {e}"))?;
        // Leak the string for a 'static lifetime is overkill; render directly.
        return render_with(req, &content, "c", &req.lang);
    } else {
        select_template(req)
    };
    render_with(req, template, ext, lang)
}

fn render_with(req: &ScaffoldRequest, template: &str, ext: &str, lang: &str) -> Result<Scaffold> {
    let mut hb = Handlebars::new();
    hb.register_escape_fn(handlebars::no_escape);
    hb.set_strict_mode(false);

    let data = json!({
        "vuln": req.vuln,
        "class": req.class.clone().unwrap_or_else(|| "unspecified".into()),
        "arch": req.arch,
        "lang": lang,
        "asan": req.asan,
        "unsafe": req.unsafe_mode,
    });
    let rendered = hb
        .render_template(template, &data)
        .map_err(|e| anyhow!("rendering scaffold template: {e}"))?;

    let body = if req.header_comment {
        let h = Header {
            vuln: &req.vuln,
            class: req.class.as_deref().unwrap_or("unspecified"),
            arch: &req.arch,
            unsafe_mode: req.unsafe_mode,
            ai: req.ai,
            model: req.model.as_deref(),
            timestamp: &req.timestamp,
        };
        format!("{}{}\n{}", h.render(lang), comment_prefix(lang), rendered)
    } else {
        rendered.clone()
    };

    let slug = slugify(&req.vuln);
    let filename = format!(
        "mareu_{}_{}.{ext}",
        req.kind,
        if slug.is_empty() {
            "scaffold".into()
        } else {
            slug
        }
    );

    Ok(Scaffold {
        filename,
        body,
        template_only: rendered,
        lang: lang.to_string(),
        extra: Vec::new(),
    })
}

/// Generate assembly artifact(s). With `--syntax both` (the default) this emits
/// a NASM/Intel primary and a GNU as/AT&T extra (or just the GAS variant for
/// non-x86 arches, where NASM does not apply).
fn generate_asm(req: &ScaffoldRequest) -> Result<Scaffold> {
    let artifact = asm::resolve_artifact(req.class.as_deref(), &req.kind);
    let meta = asm::Meta {
        artifact,
        arch: &req.arch,
        vuln: &req.vuln,
        unsafe_mode: req.unsafe_mode,
        ai: req.ai,
        model: req.model.as_deref(),
        timestamp: &req.timestamp,
        header_comment: req.header_comment,
        egg: req.egg.as_deref(),
    };
    let syntaxes = asm::syntaxes_from(&req.asm_syntax);
    let mut files = asm::build(&meta, &syntaxes);
    if files.is_empty() {
        bail!("no assembly produced for arch '{}'", req.arch);
    }
    let primary = files.remove(0);
    let extra = files
        .into_iter()
        .map(|f| ExtraFile {
            filename: f.filename,
            body: f.body,
        })
        .collect();
    Ok(Scaffold {
        filename: primary.filename,
        template_only: primary.body.clone(),
        body: primary.body,
        lang: primary.lang,
        extra,
    })
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().take(40) {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if matches!(c, ' ' | '-' | '_') && !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

/// The intent check from RFC §4.2. Returns an explanatory message when the
/// `vuln` string reads as "attack this specific named external target" rather
/// than "scaffold this bug class". Conservative by design — it keys on an
/// aggressive verb aimed at a bare hostname/URL/IP with no vuln-class framing.
pub fn intent_block(vuln: &str) -> Option<String> {
    let low = vuln.to_ascii_lowercase();
    let aggressive = [
        "pwn ",
        "hack ",
        "attack ",
        "own ",
        "break into ",
        "compromise ",
    ]
    .iter()
    .any(|v| low.contains(v));
    if !aggressive {
        return None;
    }
    // Looks like a concrete external target?
    let has_url = low.contains("http://") || low.contains("https://");
    let has_host = looks_like_host(&low);
    let has_ip = looks_like_ip(&low);
    if !(has_url || has_host || has_ip) {
        return None;
    }
    // If it also names a bug class / CVE, treat it as legitimate framing.
    let framed = low.contains("cve-")
        || [
            "bof",
            "uaf",
            "overflow",
            "use-after-free",
            "format string",
            "injection",
            "type confusion",
            "race",
            "oob",
            "out-of-bounds",
            "infoleak",
        ]
        .iter()
        .any(|k| low.contains(k));
    if framed {
        return None;
    }
    Some(format!(
        "'{vuln}' names a specific external target.\n\
         Mareu scaffolds bug classes, not attacks on named third-party\n\
         infrastructure. Reframe in terms of the vulnerability itself —\n\
         the bug class, the CVE, the affected component — e.g.\n\
         `--class uaf --vuln \"UAF in ksmbd session handler\"`."
    ))
}

fn looks_like_host(s: &str) -> bool {
    // crude: a token like `word.word` with a plausible TLD
    for tok in s.split_whitespace() {
        let t = tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
        if let Some(dot) = t.rfind('.') {
            let tld = &t[dot + 1..];
            if tld.len() >= 2
                && tld.chars().all(|c| c.is_ascii_alphabetic())
                && t[..dot].contains(|c: char| c.is_ascii_alphabetic())
            {
                return true;
            }
        }
    }
    false
}

fn looks_like_ip(s: &str) -> bool {
    for tok in s.split_whitespace() {
        let t = tok.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(kind: &str, class: &str, unsafe_mode: bool) -> ScaffoldRequest {
        ScaffoldRequest {
            kind: kind.into(),
            vuln: "test bug".into(),
            lang: "c".into(),
            class: Some(class.into()),
            arch: "x86_64".into(),
            asan: true,
            unsafe_mode,
            ai: false,
            model: None,
            custom_template: None,
            header_comment: true,
            timestamp: "2026-06-08".into(),
            asm_syntax: "both".into(),
            egg: None,
        }
    }

    #[test]
    fn bof_template_includes_header_and_compiles_shape() {
        let s = generate(&req("poc", "bof", false)).unwrap();
        assert!(s.body.contains("// status: SCAFFOLD"));
        assert!(s.body.contains("int main"));
        assert!(s.filename.ends_with(".c"));
        // safe mode must not emit the ROP marker
        assert!(!s.body.contains("ROP_CHAIN_TODO"));
    }

    #[test]
    fn unsafe_unlocks_rop_section() {
        let s = generate(&req("poc", "bof", true)).unwrap();
        assert!(s.body.contains("ROP_CHAIN_TODO"));
        assert!(s.body.contains("UNSAFE"));
    }

    #[test]
    fn proto_forces_python() {
        let s = generate(&req("fuzzer", "proto", false)).unwrap();
        assert_eq!(s.lang, "python");
        assert!(s.body.starts_with("#")); // python comment header
    }

    #[test]
    fn intent_blocks_named_host_without_framing() {
        assert!(intent_block("pwn target.victim.com").is_some());
        assert!(intent_block("attack 10.0.0.5").is_some());
    }

    #[test]
    fn intent_allows_bug_framing_and_plain_descriptions() {
        assert!(intent_block("UAF in ksmbd session handler").is_none());
        assert!(intent_block("attack the format string bug in target.victim.com").is_none());
        assert!(intent_block("stack overflow in verify_pac_checksums").is_none());
    }
}
