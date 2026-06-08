//! Filesystem-backed session store. Cross-platform: the root resolves to the
//! platform data dir (or a configured path) and all paths are built with
//! `PathBuf`, so Windows/macOS/Linux behave identically.

use super::{ContextEntry, ContextState, Meta, SessionInfo, Turn};
use crate::config::{self, Config};
use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open (and lazily create) the session store rooted per config.
    pub fn open(cfg: &Config) -> Result<Self> {
        let root = config::resolve_store_path(cfg)?;
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating session store at {}", root.display()))?;
        Ok(Self { root })
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.dir(name).join("meta.toml").exists()
    }

    fn now() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    /// Create a new session. Errors if it already exists.
    pub fn create(&self, name: &str, target: Option<String>) -> Result<Meta> {
        validate_name(name)?;
        if self.exists(name) {
            bail!("session '{name}' already exists");
        }
        let dir = self.dir(name);
        std::fs::create_dir_all(dir.join("artifacts"))?;
        let now = Self::now();
        let meta = Meta {
            name: name.to_string(),
            target,
            created_at: now.clone(),
            last_active: now,
            provider: None,
            model: None,
        };
        self.save_meta(&meta)?;
        std::fs::write(dir.join("notes.md"), format!("# Notes — {name}\n\n"))?;
        std::fs::write(dir.join("history.jsonl"), "")?;
        self.save_context(name, &ContextState::default())?;
        Ok(meta)
    }

    pub fn load_meta(&self, name: &str) -> Result<Meta> {
        let path = self.dir(name).join("meta.toml");
        let text =
            std::fs::read_to_string(&path).map_err(|_| anyhow!("no such session '{name}'"))?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save_meta(&self, meta: &Meta) -> Result<()> {
        let path = self.dir(&meta.name).join("meta.toml");
        std::fs::write(path, toml::to_string_pretty(meta)?)?;
        Ok(())
    }

    /// Touch `last_active` (and optionally provider/model) after activity.
    pub fn touch(&self, name: &str, provider: Option<&str>, model: Option<&str>) -> Result<()> {
        let mut meta = self.load_meta(name)?;
        meta.last_active = Self::now();
        if let Some(p) = provider {
            meta.provider = Some(p.to_string());
        }
        if let Some(m) = model {
            meta.model = Some(m.to_string());
        }
        self.save_meta(&meta)
    }

    pub fn append_turn(&self, name: &str, role: &str, content: &str) -> Result<()> {
        let turn = Turn {
            ts: Self::now(),
            role: role.to_string(),
            content: content.to_string(),
        };
        let path = self.dir(name).join("history.jsonl");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{}", serde_json::to_string(&turn)?)?;
        Ok(())
    }

    pub fn read_history(&self, name: &str) -> Result<Vec<Turn>> {
        let path = self.dir(name).join("history.jsonl");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut turns = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(t) = serde_json::from_str::<Turn>(line) {
                turns.push(t);
            }
        }
        Ok(turns)
    }

    pub fn append_note(&self, name: &str, text: &str) -> Result<()> {
        if !self.exists(name) {
            bail!("no such session '{name}'");
        }
        let path = self.dir(name).join("notes.md");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "- [{}] {}", Self::now(), text)?;
        Ok(())
    }

    pub fn read_notes(&self, name: &str) -> Result<String> {
        Ok(std::fs::read_to_string(self.dir(name).join("notes.md")).unwrap_or_default())
    }

    pub fn notes_path(&self, name: &str) -> PathBuf {
        self.dir(name).join("notes.md")
    }

    pub fn load_context(&self, name: &str) -> Result<ContextState> {
        let path = self.dir(name).join("context.toml");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        Ok(toml::from_str(&text).unwrap_or_default())
    }

    pub fn save_context(&self, name: &str, ctx: &ContextState) -> Result<()> {
        let path = self.dir(name).join("context.toml");
        std::fs::write(path, toml::to_string_pretty(ctx)?)?;
        Ok(())
    }

    pub fn add_context_file(&self, name: &str, path: &str, tokens: usize) -> Result<()> {
        let mut ctx = self.load_context(name)?;
        ctx.files.retain(|f| f.path != path);
        ctx.files.push(ContextEntry {
            path: path.to_string(),
            tokens,
        });
        self.save_context(name, &ctx)
    }

    pub fn drop_context_file(&self, name: &str, path: &str) -> Result<bool> {
        let mut ctx = self.load_context(name)?;
        let before = ctx.files.len();
        ctx.files.retain(|f| f.path != path);
        let removed = ctx.files.len() != before;
        self.save_context(name, &ctx)?;
        Ok(removed)
    }

    /// Write a generated artifact into the session; returns its path.
    pub fn write_artifact(&self, name: &str, filename: &str, content: &str) -> Result<PathBuf> {
        let dir = self.dir(name).join("artifacts");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(filename);
        std::fs::write(&path, content)?;
        Ok(path)
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        if !self.exists(name) {
            bail!("no such session '{name}'");
        }
        std::fs::remove_dir_all(self.dir(name))?;
        // Clear the active pointer if it referenced this session.
        if self.active()?.as_deref() == Some(name) {
            self.detach()?;
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SessionInfo>> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Ok(out);
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let Ok(meta) = self.load_meta(&name) else {
                continue;
            };
            out.push(SessionInfo {
                name: meta.name,
                target: meta.target,
                last_active: meta.last_active,
                size: dir_size(&p),
            });
        }
        out.sort_by(|a, b| b.last_active.cmp(&a.last_active));
        Ok(out)
    }

    // ── active-session pointer ─────────────────────────────────────────────

    fn active_path(&self) -> PathBuf {
        self.root.join(".active")
    }

    pub fn active(&self) -> Result<Option<String>> {
        let p = self.active_path();
        if !p.exists() {
            return Ok(None);
        }
        let name = std::fs::read_to_string(p)?.trim().to_string();
        if name.is_empty() || !self.exists(&name) {
            Ok(None)
        } else {
            Ok(Some(name))
        }
    }

    pub fn attach(&self, name: &str) -> Result<()> {
        if !self.exists(name) {
            bail!("no such session '{name}'");
        }
        std::fs::write(self.active_path(), name)?;
        Ok(())
    }

    pub fn detach(&self) -> Result<()> {
        let p = self.active_path();
        if p.exists() {
            std::fs::remove_file(p)?;
        }
        Ok(())
    }

    /// Assemble a single disclosure-ready markdown document (RFC §9.4 export).
    pub fn export(&self, name: &str) -> Result<String> {
        let meta = self.load_meta(name)?;
        let notes = self.read_notes(name)?;
        let history = self.read_history(name)?;
        let ctx = self.load_context(name)?;

        let mut s = String::new();
        s.push_str(&format!("# Mareu Session — {}\n\n", meta.name));
        s.push_str(&format!(
            "- **target:** {}\n",
            meta.target.as_deref().unwrap_or("—")
        ));
        s.push_str(&format!("- **created:** {}\n", meta.created_at));
        s.push_str(&format!("- **last active:** {}\n", meta.last_active));
        if let Some(p) = &meta.provider {
            s.push_str(&format!("- **provider:** {p}\n"));
        }
        if let Some(m) = &meta.model {
            s.push_str(&format!("- **model:** {m}\n"));
        }
        s.push('\n');

        s.push_str("## Notes\n\n");
        s.push_str(notes.trim());
        s.push_str("\n\n");

        if !ctx.files.is_empty() {
            s.push_str("## Loaded Context\n\n");
            for f in &ctx.files {
                s.push_str(&format!("- `{}` (~{} tokens)\n", f.path, f.tokens));
            }
            s.push('\n');
        }

        s.push_str("## Conversation\n\n");
        for t in &history {
            s.push_str(&format!("### {} · {}\n\n{}\n\n", t.role, t.ts, t.content));
        }

        // List artifacts.
        let art = self.dir(name).join("artifacts");
        if let Ok(rd) = std::fs::read_dir(&art) {
            let files: Vec<String> = rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            if !files.is_empty() {
                s.push_str("## Artifacts\n\n");
                for f in files {
                    s.push_str(&format!("- `artifacts/{f}`\n"));
                }
                s.push('\n');
            }
        }
        Ok(s)
    }

    /// Import a session from a previously exported markdown file. Creates a new
    /// session whose notes hold the imported document (best-effort; the export
    /// format is human-first, not a strict round-trip).
    pub fn import(&self, file: &str) -> Result<String> {
        let text = std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;
        // Derive a name from the first heading or the filename.
        let name = text
            .lines()
            .find_map(|l| l.strip_prefix("# Mareu Session — "))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| {
                Path::new(file)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "imported".into())
            });
        let name = unique_name(self, &sanitize(&name));
        self.create(&name, None)?;
        std::fs::write(self.dir(&name).join("notes.md"), text)?;
        Ok(name)
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("session name cannot be empty");
    }
    if name.chars().any(|c| {
        matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control()
    }) {
        bail!("invalid session name '{name}': avoid path separators and reserved characters");
    }
    if name.starts_with('.') {
        bail!("session name cannot start with '.'");
    }
    Ok(())
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn unique_name(store: &Store, base: &str) -> String {
    if !store.exists(base) {
        return base.to_string();
    }
    for i in 2..1000 {
        let cand = format!("{base}_{i}");
        if !store.exists(&cand) {
            return cand;
        }
    }
    base.to_string()
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                total += dir_size(&p);
            } else if let Ok(m) = e.metadata() {
                total += m.len();
            }
        }
    }
    total
}
