//! Streaming output handler.
//!
//! AI responses stream token-by-token. We show a spinner on **stderr** while
//! waiting for the first byte, then clear it and write the body to **stdout** so
//! piped consumers get a clean stream even mid-generation (RFC §5.5).

use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;

/// Consume streamed chunks, returning the full concatenated text.
///
/// `label` is shown next to the spinner (e.g. "querying anthropic/...").
/// The spinner only renders when stderr is a terminal.
pub async fn consume(mut rx: Receiver<String>, label: &str, spinner_enabled: bool) -> String {
    let spinner = if spinner_enabled {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("  {spinner} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message(label.to_string());
        pb.enable_steady_tick(Duration::from_millis(90));
        Some(pb)
    } else {
        None
    };

    let mut full = String::new();
    let mut started = false;
    let stdout = std::io::stdout();

    while let Some(chunk) = rx.recv().await {
        if !started {
            if let Some(pb) = &spinner {
                pb.finish_and_clear();
            }
            started = true;
        }
        full.push_str(&chunk);
        let mut h = stdout.lock();
        let _ = h.write_all(chunk.as_bytes());
        let _ = h.flush();
    }

    if let Some(pb) = &spinner {
        if !started {
            pb.finish_and_clear();
        }
    }
    if started {
        println!();
    }
    full
}
