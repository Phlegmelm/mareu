//! Named research sessions. Flat, human-readable, git-friendly files (RFC §12):
//!
//! ```text
//! <store>/<name>/
//! ├── meta.toml         target, created_at, last_active, provider, model
//! ├── history.jsonl     conversation turns (newline-delimited JSON)
//! ├── notes.md          freeform analyst notes
//! ├── context.toml      currently loaded files + token counts
//! └── artifacts/        generated files
//! ```

pub mod store;

pub use store::Store;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub created_at: String,
    pub last_active: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// One conversation turn, stored as a line in `history.jsonl`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Turn {
    pub ts: String,
    /// "user" or "assistant".
    pub role: String,
    pub content: String,
}

/// A file loaded into the session context (`context.toml`).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ContextState {
    #[serde(default)]
    pub files: Vec<ContextEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextEntry {
    pub path: String,
    pub tokens: usize,
}

/// Summary row for `session list`.
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub name: String,
    pub target: Option<String>,
    pub last_active: String,
    /// Total size on disk in bytes.
    pub size: u64,
}
