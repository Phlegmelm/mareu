//! Configuration loading, merging, and mutation.
//!
//! Resolution order (later overrides earlier), per RFC §10:
//!   1. Compiled-in defaults ([`schema::Config::default`])
//!   2. `<config_dir>/mareu/config.toml`
//!   3. `.mareu.toml` in the current directory (project-local)
//!   4. Environment variables (`MAREU_*`)
//!   5. CLI flags (applied by the caller after load)
//!
//! Merging is done at the `toml::Value` level so partial layers deep-merge
//! correctly, then the merged tree is deserialized into [`Config`].

mod schema;

pub use schema::*;

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

/// The bundled default config, kept in sync with [`Config::default`]. Shipped
/// so `mareu config edit` on a fresh install starts from a documented file.
pub const DEFAULT_TOML: &str = include_str!("../../config/default.toml");

/// Fully-resolved configuration plus the paths it was assembled from.
#[derive(Debug, Clone)]
#[allow(dead_code)] // user_path/project_path are retained for diagnostics
pub struct Loaded {
    pub config: Config,
    /// The user config file path (may not exist yet).
    pub user_path: PathBuf,
    /// The project-local `.mareu.toml`, if one was found.
    pub project_path: Option<PathBuf>,
}

/// Directory holding the user config file (`<config_dir>/mareu`).
pub fn config_dir() -> Result<PathBuf> {
    // `dirs::config_dir` maps to %APPDATA% (Windows), ~/Library/Application
    // Support (macOS), and $XDG_CONFIG_HOME or ~/.config (Linux).
    let base = dirs::config_dir().ok_or_else(|| anyhow!("could not determine config directory"))?;
    Ok(base.join("mareu"))
}

/// Path to the user config file.
pub fn user_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// Platform data directory for sessions etc. (`<data_dir>/mareu`).
pub fn data_dir() -> Result<PathBuf> {
    let base = dirs::data_dir().ok_or_else(|| anyhow!("could not determine data directory"))?;
    Ok(base.join("mareu"))
}

/// Load and merge all configuration layers (excluding CLI flags).
pub fn load() -> Result<Loaded> {
    let user_path = user_config_path()?;

    // Layer 1: compiled defaults, as a toml Value tree.
    let mut merged = toml::Value::try_from(Config::default())
        .context("serializing default config")?;

    // Layer 2: user config file.
    if user_path.exists() {
        let text = std::fs::read_to_string(&user_path)
            .with_context(|| format!("reading {}", user_path.display()))?;
        let val: toml::Value = toml::from_str(&text)
            .with_context(|| format!("parsing {}", user_path.display()))?;
        merge(&mut merged, val);
    }

    // Layer 3: project-local `.mareu.toml`.
    let project_path = {
        let p = Path::new(".mareu.toml");
        if p.exists() {
            let text = std::fs::read_to_string(p).context("reading .mareu.toml")?;
            let val: toml::Value = toml::from_str(&text).context("parsing .mareu.toml")?;
            merge(&mut merged, val);
            Some(p.to_path_buf())
        } else {
            None
        }
    };

    // Layer 4: MAREU_* environment overrides.
    apply_env_overrides(&mut merged);

    // Interpolate `${ENV}` references throughout string values.
    interpolate_env(&mut merged);

    let config: Config = merged.try_into().context("deserializing merged config")?;
    Ok(Loaded {
        config,
        user_path,
        project_path,
    })
}

/// Resolve the session store path, expanding `~`, `${ENV}`, and empty-default.
pub fn resolve_store_path(cfg: &Config) -> Result<PathBuf> {
    let raw = cfg.session.store_path.trim();
    if raw.is_empty() {
        return Ok(data_dir()?.join("sessions"));
    }
    Ok(expand_path(raw))
}

/// Expand a leading `~` to the home directory. (Env vars are already
/// interpolated during load.)
pub fn expand_path(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    if s == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(s)
}

/// Deep-merge `over` into `base`: tables merge key-by-key, everything else
/// replaces wholesale.
fn merge(base: &mut toml::Value, over: toml::Value) {
    match (base, over) {
        (toml::Value::Table(b), toml::Value::Table(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(slot) => merge(slot, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

/// Apply `MAREU_SECTION_KEY=value` env vars onto the merged tree. Underscores
/// after the first split the path; e.g. `MAREU_PROVIDER_DEFAULT` →
/// `provider.default`, `MAREU_AI_MAX_TOKENS` → `ai.max_tokens`.
fn apply_env_overrides(merged: &mut toml::Value) {
    for (key, val) in std::env::vars() {
        let Some(rest) = key.strip_prefix("MAREU_") else {
            continue;
        };
        if rest.is_empty() {
            continue;
        }
        let path: Vec<String> = rest.split('_').map(|s| s.to_ascii_lowercase()).collect();
        // Try the longest section.key split that lands on an existing leaf.
        // Simplest robust rule: first token is the section, the remainder
        // (re-joined with '_') is the key — matches the snake_case field names.
        if path.len() < 2 {
            continue;
        }
        let section = &path[0];
        let field = path[1..].join("_");
        set_dotted(merged, &[section.clone(), field], parse_scalar(&val));
    }
}

/// Recursively interpolate `${VAR}` occurrences inside every string value.
fn interpolate_env(val: &mut toml::Value) {
    match val {
        toml::Value::String(s) => {
            if s.contains("${") {
                *s = interpolate_str(s);
            }
        }
        toml::Value::Array(a) => a.iter_mut().for_each(interpolate_env),
        toml::Value::Table(t) => t.iter_mut().for_each(|(_, v)| interpolate_env(v)),
        _ => {}
    }
}

fn interpolate_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = s[i + 2..].find('}') {
                let name = &s[i + 2..i + 2 + end];
                out.push_str(&std::env::var(name).unwrap_or_default());
                i = i + 2 + end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Best-effort scalar parse for env-supplied values: bool, integer, float, else
/// string.
fn parse_scalar(s: &str) -> toml::Value {
    if let Ok(b) = s.parse::<bool>() {
        return toml::Value::Boolean(b);
    }
    if let Ok(i) = s.parse::<i64>() {
        return toml::Value::Integer(i);
    }
    if let Ok(f) = s.parse::<f64>() {
        return toml::Value::Float(f);
    }
    toml::Value::String(s.to_string())
}

/// Set a value at a dotted path, creating intermediate tables as needed.
fn set_dotted(root: &mut toml::Value, path: &[String], value: toml::Value) {
    if path.is_empty() {
        return;
    }
    if !root.is_table() {
        *root = toml::Value::Table(toml::map::Map::new());
    }
    let table = root.as_table_mut().unwrap();
    if path.len() == 1 {
        table.insert(path[0].clone(), value);
        return;
    }
    let entry = table
        .entry(path[0].clone())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    set_dotted(entry, &path[1..], value);
}

/// Read the user config file as a toml tree (empty table if absent).
pub fn read_user_tree() -> Result<toml::Value> {
    let path = user_config_path()?;
    if path.exists() {
        let text = std::fs::read_to_string(&path)?;
        Ok(toml::from_str(&text)?)
    } else {
        Ok(toml::Value::Table(toml::map::Map::new()))
    }
}

/// Persist a toml tree to the user config file, creating the directory.
pub fn write_user_tree(tree: &toml::Value) -> Result<PathBuf> {
    let path = user_config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(tree)?;
    std::fs::write(&path, text)?;
    Ok(path)
}

/// `mareu config set <key> <val>`: write a dotted override into the user file.
pub fn set_value(key: &str, raw: &str) -> Result<PathBuf> {
    let mut tree = read_user_tree()?;
    let path: Vec<String> = key.split('.').map(str::to_string).collect();
    if path.is_empty() {
        return Err(anyhow!("empty config key"));
    }
    set_dotted(&mut tree, &path, parse_scalar(raw));
    write_user_tree(&tree)
}

/// `mareu config unset <key>`: remove a dotted override from the user file.
pub fn unset_value(key: &str) -> Result<PathBuf> {
    let mut tree = read_user_tree()?;
    let segs: Vec<&str> = key.split('.').collect();
    remove_dotted(&mut tree, &segs);
    write_user_tree(&tree)
}

fn remove_dotted(root: &mut toml::Value, path: &[&str]) {
    if path.is_empty() {
        return;
    }
    let Some(table) = root.as_table_mut() else {
        return;
    };
    if path.len() == 1 {
        table.remove(path[0]);
        return;
    }
    if let Some(child) = table.get_mut(path[0]) {
        remove_dotted(child, &path[1..]);
    }
}
