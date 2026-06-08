//! ASCII banner (RFC §6). Block-letter MAREU with a functional status line.
//! Suppressed when stdin is piped, `--quiet` is set, or `MAREU_NO_BANNER=1`.

use crate::output::{Ui, ACCENT, DIM, HIGHLIGHT};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const BLOCK: &str = r#"  ███╗   ███╗ █████╗ ██████╗ ███████╗██╗   ██╗
  ████╗ ████║██╔══██╗██╔══██╗██╔════╝██║   ██║
  ██╔████╔██║███████║██████╔╝█████╗  ██║   ██║
  ██║╚██╔╝██║██╔══██║██╔══██╗██╔══╝  ██║   ██║
  ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗╚██████╔╝
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ "#;

/// Bright-yellow separator when color is on.
fn sep(ui: &Ui) -> String {
    ui.painter().paint(HIGHLIGHT, "·")
}

/// Full block banner with a status line.
pub fn full(ui: &Ui, status: &str) -> String {
    let p = ui.painter();
    let block = BLOCK
        .lines()
        .map(|l| p.paint(ACCENT, l))
        .collect::<Vec<_>>()
        .join("\n");
    let dot = sep(ui);
    let rule = p.paint(DIM, "  ─────────────────────────────────────────");
    format!(
        "\n{block}\n\n  {} {dot} {}\n  {} {dot} {}\n{rule}\n  {}\n",
        p.paint(DIM, "vulnerability research utility"),
        p.paint(DIM, &format!("v{VERSION}")),
        p.paint(DIM, "@Phlegmelm"),
        p.paint(DIM, "github.com/phlegmelm/mareu"),
        p.paint(DIM, status),
    )
}

/// Single-line compact banner (printed to stderr on subcommand invocation).
pub fn compact(ui: &Ui) -> String {
    let p = ui.painter();
    format!(
        "  {} {} {} {}",
        p.paint(ACCENT, &format!("mareu v{VERSION}")),
        sep(ui),
        p.paint(DIM, "@Phlegmelm"),
        "",
    )
}

/// Whether the banner should be shown at all this invocation.
pub fn suppressed(quiet: bool, stdin_piped: bool) -> bool {
    quiet
        || stdin_piped
        || std::env::var("MAREU_NO_BANNER").map(|v| v == "1").unwrap_or(false)
}
