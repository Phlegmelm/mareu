//! Configuration schema with serde defaults.
//!
//! Every field has a default so a completely empty config file (or no file at
//! all) still produces a fully-populated, valid [`Config`]. Defaults here are
//! the compiled-in layer (precedence level 1 in §10 of the RFC).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub provider: ProviderConfig,
    pub ai: AiConfig,
    pub output: OutputConfig,
    pub banner: BannerConfig,
    pub context: ContextConfig,
    pub session: SessionConfig,
    pub scaffold: ScaffoldConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderConfig {
    /// Name of the active default provider (key into the maps below).
    pub default: String,
    pub openrouter: ProviderEntry,
    pub anthropic: ProviderEntry,
    pub openai: ProviderEntry,
    pub ollama: ProviderEntry,
    /// User-defined extra providers keyed by name (OpenAI-compatible).
    #[serde(flatten)]
    pub extra: BTreeMap<String, ProviderEntry>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            default: "ollama".into(),
            openrouter: ProviderEntry {
                api_key: Some("${OPENROUTER_API_KEY}".into()),
                model: Some("anthropic/claude-sonnet-4-5".into()),
                base_url: Some("https://openrouter.ai/api/v1".into()),
                timeout: 60,
            },
            anthropic: ProviderEntry {
                api_key: Some("${ANTHROPIC_API_KEY}".into()),
                model: Some("claude-sonnet-4-5".into()),
                base_url: Some("https://api.anthropic.com".into()),
                timeout: 60,
            },
            openai: ProviderEntry {
                api_key: Some("${OPENAI_API_KEY}".into()),
                model: Some("gpt-4o".into()),
                base_url: Some("https://api.openai.com/v1".into()),
                timeout: 60,
            },
            ollama: ProviderEntry {
                api_key: None,
                model: Some("llama3.1:8b".into()),
                base_url: Some("http://localhost:11434".into()),
                timeout: 120,
            },
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderEntry {
    /// API key; supports `${ENV_VAR}` interpolation. `None` for keyless (Ollama).
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    /// Request timeout in seconds.
    pub timeout: u64,
}

impl Default for ProviderEntry {
    fn default() -> Self {
        Self {
            api_key: None,
            model: None,
            base_url: None,
            timeout: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    /// When true, AI is on without `--ai`; `--no-ai` disables per-invocation.
    pub default: bool,
    pub max_tokens: u32,
    pub temperature: f64,
    /// Provider name to fall back to on rate-limit/error (empty = no fallback).
    pub fallback: String,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            default: false,
            max_tokens: 8192,
            temperature: 0.2,
            fallback: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub format: String,
    pub color: bool,
    pub pager: bool,
    pub no_color_env: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "text".into(),
            color: true,
            pager: true,
            no_color_env: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BannerConfig {
    /// full | compact | none
    pub style: String,
}

impl Default for BannerConfig {
    fn default() -> Self {
        Self {
            style: "full".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContextConfig {
    pub max_tokens: u32,
    pub include_stdin: bool,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_tokens: 100_000,
            include_stdin: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Empty means "use the platform data dir" (resolved at runtime).
    pub store_path: String,
    pub auto_save: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            store_path: String::new(),
            auto_save: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScaffoldConfig {
    pub unsafe_default: bool,
    pub header_comment: bool,
}

impl Default for ScaffoldConfig {
    fn default() -> Self {
        Self {
            unsafe_default: false,
            header_comment: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    pub flag_patterns: Vec<String>,
    pub pre_auth_markers: Vec<String>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            flag_patterns: [
                "memcpy", "strcpy", "strcat", "sprintf", "gets", "recv", "read",
                "mmap", "malloc", "realloc", "alloca", "free", "strlen", "system",
                "exec", "popen",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            pre_auth_markers: ["before_auth", "unauthenticated", "anon", "pre_auth"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}
