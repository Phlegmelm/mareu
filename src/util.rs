//! Small cross-platform helpers: stdin capture, paging, and `$EDITOR`/`$PAGER`
//! resolution with sane Windows fallbacks.

use anyhow::Result;
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, Stdio};

/// Read all of stdin to a string. Returns `None` if stdin is a terminal (no
/// piped input) or empty.
pub fn read_stdin() -> Option<String> {
    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_ok() && !buf.trim().is_empty() {
        Some(buf)
    } else {
        None
    }
}

pub fn stdin_piped() -> bool {
    !std::io::stdin().is_terminal()
}

pub fn stdout_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Disassemble a binary with objdump (or llvm-objdump). Returns the textual
/// disassembly to feed into analysis/recon/AI. Cross-platform: tries common
/// tool names in PATH and reports clearly when none is found. Intel syntax,
/// raw bytes suppressed.
pub fn disassemble(path: &str) -> Result<String> {
    let candidates = [
        ("objdump", vec!["-d", "-M", "intel", "--no-show-raw-insn", path]),
        ("llvm-objdump", vec!["-d", "--x86-asm-syntax=intel", path]),
        ("gobjdump", vec!["-d", "-M", "intel", path]),
    ];
    let mut last_err = String::new();
    for (tool, args) in candidates {
        match Command::new(tool).args(&args).output() {
            Ok(out) if out.status.success() => {
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
            }
            Ok(out) => {
                last_err = format!("{tool}: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
            Err(e) => last_err = format!("{tool}: {e}"),
        }
    }
    anyhow::bail!(
        "could not disassemble {path}: no working objdump in PATH ({last_err}).\n\
         Install binutils (objdump) or LLVM (llvm-objdump), or pipe disassembly on stdin."
    )
}

/// Resolve the user's editor, falling back per-platform.
pub fn editor() -> String {
    if let Ok(e) = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")) {
        if !e.trim().is_empty() {
            return e;
        }
    }
    if cfg!(windows) {
        "notepad".to_string()
    } else {
        "vi".to_string()
    }
}

/// Open `path` in the user's editor, inheriting the terminal.
pub fn open_in_editor(path: &std::path::Path) -> Result<()> {
    let ed = editor();
    // Support editors specified with arguments, e.g. "code --wait".
    let mut parts = ed.split_whitespace();
    let prog = parts.next().unwrap_or("vi");
    let mut cmd = Command::new(prog);
    for a in parts {
        cmd.arg(a);
    }
    cmd.arg(path);
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("editor exited with status {status}");
    }
    Ok(())
}

/// Print `text`, paging through `$PAGER` when stdout is a terminal, paging is
/// enabled, and the content is taller than the terminal. Otherwise prints
/// directly (keeping pipes clean).
///
/// A closed downstream pipe (`| head`) is a normal, graceful exit — not a panic.
pub fn emit(text: &str, pager_enabled: bool) {
    let use_pager = pager_enabled && stdout_tty() && taller_than_screen(text);
    if !use_pager {
        write_stdout(text);
        if !text.ends_with('\n') {
            write_stdout("\n");
        }
        return;
    }
    if try_page(text).is_err() {
        write_stdout(text);
    }
}

/// Write to stdout, exiting cleanly if the reader has gone away.
fn write_stdout(s: &str) {
    use std::io::ErrorKind;
    let mut out = std::io::stdout();
    if let Err(e) = out.write_all(s.as_bytes()).and_then(|_| out.flush()) {
        if e.kind() == ErrorKind::BrokenPipe {
            // Downstream closed (e.g. `mareu ... | head`): exit quietly.
            std::process::exit(0);
        }
        // Any other write error is genuinely fatal.
        std::process::exit(1);
    }
}

fn taller_than_screen(text: &str) -> bool {
    let rows = std::env::var("LINES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(24);
    text.lines().count() > rows.saturating_sub(1)
}

fn pager_cmd() -> String {
    if let Ok(p) = std::env::var("PAGER") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    if cfg!(windows) {
        "more".to_string()
    } else {
        "less -R".to_string()
    }
}

fn try_page(text: &str) -> Result<()> {
    let pager = pager_cmd();
    let mut parts = pager.split_whitespace();
    let prog = parts.next().unwrap_or("more");
    let mut cmd = Command::new(prog);
    for a in parts {
        cmd.arg(a);
    }
    let mut child = cmd.stdin(Stdio::piped()).spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(text.as_bytes())?;
    }
    child.wait()?;
    Ok(())
}
