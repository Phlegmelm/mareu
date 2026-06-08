//! Provider abstraction (RFC §8). Every AI backend implements [`Provider`].
//! Adding a backend is a new file plus one arm in [`build`].

pub mod anthropic;
pub mod ollama;
pub mod openai;
pub mod openrouter;

use crate::config::Config;
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc::Sender;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    /// "user" or "assistant".
    pub role: String,
    pub content: String,
}

impl Message {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: content.into(),
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".into(),
            content: content.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompletionRequest {
    pub system: Option<String>,
    pub messages: Vec<Message>,
    pub model: String,
    pub stream: bool,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenUsage {
    pub prompt: u32,
    pub completion: u32,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // model_used/usage/latency_ms are part of the RFC §8 contract
pub struct CompletionResponse {
    pub content: String,
    pub model_used: String,
    pub usage: Option<TokenUsage>,
    pub latency_ms: u64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // name/model_valid are part of the RFC §8 contract
pub struct ProviderStatus {
    pub name: String,
    pub reachable: bool,
    pub model_valid: bool,
    pub key_present: bool,
    pub message: Option<String>,
}

#[async_trait]
pub trait Provider: Send + Sync {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse>;
    /// Stream the response, pushing text deltas to `tx`; returns the full text.
    async fn stream(&self, req: CompletionRequest, tx: Sender<String>) -> Result<CompletionResponse>;
    async fn health(&self) -> Result<ProviderStatus>;
    fn name(&self) -> &str;
    fn model(&self) -> &str;
}

/// Names of the built-in providers, in display order.
pub const BUILTINS: &[&str] = &["openrouter", "anthropic", "openai", "ollama"];

/// Build the named provider from resolved config.
pub fn build(cfg: &Config, name: &str) -> Result<Box<dyn Provider>> {
    let entry = match name {
        "openrouter" => &cfg.provider.openrouter,
        "anthropic" => &cfg.provider.anthropic,
        "openai" => &cfg.provider.openai,
        "ollama" => &cfg.provider.ollama,
        other => cfg
            .provider
            .extra
            .get(other)
            .ok_or_else(|| anyhow!("unknown provider '{other}'; see `mareu config providers`"))?,
    };

    let model = entry.model.clone().unwrap_or_default();
    let base_url = entry.base_url.clone().unwrap_or_default();
    let timeout = Duration::from_secs(entry.timeout.max(1));
    // An interpolated key that resolved to empty means "absent".
    let key = entry.api_key.clone().filter(|k| !k.trim().is_empty());

    let p: Box<dyn Provider> = match name {
        "anthropic" => Box::new(anthropic::Anthropic::new(key, model, base_url, timeout)?),
        "ollama" => Box::new(ollama::Ollama::new(model, base_url, timeout)?),
        "openrouter" => Box::new(openrouter::OpenRouter::new(key, model, base_url, timeout)?),
        // openai + any user-defined OpenAI-compatible endpoint
        _ => Box::new(openai::OpenAiCompatible::new(
            name.to_string(),
            key,
            model,
            base_url,
            timeout,
        )?),
    };
    Ok(p)
}

// ── shared HTTP helpers ────────────────────────────────────────────────────

pub(crate) fn client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("mareu/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// What a single streamed line decodes to.
pub(crate) enum Chunk {
    Delta(String),
    Done,
    Ignore,
}

/// Pump a streaming HTTP body line-by-line through `parse`, forwarding text
/// deltas to `tx` and accumulating the full string.
pub(crate) async fn pump<F>(
    resp: reqwest::Response,
    tx: &Sender<String>,
    parse: F,
) -> Result<String>
where
    F: Fn(&str) -> Chunk,
{
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("provider returned {status}: {}", body.trim());
    }
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut full = String::new();

    while let Some(item) = stream.next().await {
        let bytes = item?;
        buf.push_str(&String::from_utf8_lossy(&bytes));
        // Process complete lines; keep the trailing partial in `buf`.
        while let Some(nl) = buf.find('\n') {
            let line: String = buf.drain(..=nl).collect();
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            match parse(line) {
                Chunk::Delta(d) => {
                    if !d.is_empty() {
                        full.push_str(&d);
                        // Best-effort send; ignore if the consumer dropped.
                        let _ = tx.send(d).await;
                    }
                }
                Chunk::Done => return Ok(full),
                Chunk::Ignore => {}
            }
        }
    }
    // Flush any final buffered line.
    let line = buf.trim();
    if !line.is_empty() {
        if let Chunk::Delta(d) = parse(line) {
            full.push_str(&d);
            let _ = tx.send(d).await;
        }
    }
    Ok(full)
}
