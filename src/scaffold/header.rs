//! The machine-readable scaffold header block (RFC §4.3). It is a quality
//! signal, not a legal disclaimer: every generated artifact says what it is,
//! what was assumed, and whether AI touched it.

/// Comment-line prefix for a language.
pub fn comment_prefix(lang: &str) -> &'static str {
    match lang {
        "python" | "py" | "bash" | "sh" => "#",
        "asm" | "s" => ";",
        _ => "//", // c, cpp, rust, …
    }
}

pub struct Header<'a> {
    pub vuln: &'a str,
    pub class: &'a str,
    pub arch: &'a str,
    pub unsafe_mode: bool,
    pub ai: bool,
    pub model: Option<&'a str>,
    pub timestamp: &'a str,
}

impl Header<'_> {
    pub fn render(&self, lang: &str) -> String {
        let c = comment_prefix(lang);
        let mut s = String::new();
        let mut line = |k: &str, v: &str| s.push_str(&format!("{c} {k:<8}{v}\n"));

        line("mareu", &format!("scaffold — generated {}", self.timestamp));
        line("vuln:", self.vuln);
        line("class:", self.class);
        line("arch:", &format!("{} assumed", self.arch));
        line(
            "mode:",
            if self.unsafe_mode {
                "UNSAFE — aggressive output (full exploit / ROP / shellcode stubs)"
            } else {
                "safe — crash reproducer / sanitizer harness / offset tooling"
            },
        );
        line(
            "status:",
            "SCAFFOLD — not tested, verify offsets, check target version",
        );
        match (self.ai, self.model) {
            (true, Some(m)) => line(
                "--ai:",
                &format!("true ({m}) — AI-generated, verify before use"),
            ),
            (true, None) => line("--ai:", "true — AI-generated, verify before use"),
            (false, _) => line("--ai:", "false (template-generated)"),
        }
        s
    }
}
