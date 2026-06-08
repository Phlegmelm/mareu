//! Anthropic Messages API provider (direct).

use super::{client, pump, Chunk, CompletionRequest, CompletionResponse, Provider, ProviderStatus, TokenUsage};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

const API_VERSION: &str = "2023-06-01";

pub struct Anthropic {
    key: Option<String>,
    model: String,
    base_url: String,
    http: reqwest::Client,
}

impl Anthropic {
    pub fn new(
        key: Option<String>,
        model: String,
        base_url: String,
        timeout: Duration,
    ) -> Result<Self> {
        let base = if base_url.trim().is_empty() {
            "https://api.anthropic.com".to_string()
        } else {
            base_url.trim_end_matches('/').to_string()
        };
        Ok(Self {
            key,
            model,
            base_url: base,
            http: client(timeout)?,
        })
    }

    fn endpoint(&self) -> String {
        format!("{}/v1/messages", self.base_url)
    }

    fn body(&self, req: &CompletionRequest, stream: bool) -> serde_json::Value {
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|m| json!({"role": m.role, "content": m.content}))
            .collect();
        let mut b = json!({
            "model": if req.model.is_empty() { &self.model } else { &req.model },
            // Anthropic requires max_tokens; default if the caller omitted it.
            "max_tokens": req.max_tokens.unwrap_or(4096),
            "messages": messages,
            "stream": stream,
        });
        if let Some(sys) = &req.system {
            b["system"] = json!(sys);
        }
        if let Some(t) = req.temperature {
            b["temperature"] = json!(t);
        }
        b
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow!("anthropic: no API key (set ANTHROPIC_API_KEY)"))?;
        Ok(rb
            .header("x-api-key", key)
            .header("anthropic-version", API_VERSION))
    }
}

#[async_trait]
impl Provider for Anthropic {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        let start = Instant::now();
        let rb = self.http.post(self.endpoint()).json(&self.body(&req, false));
        let resp = self.auth(rb)?.send().await?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().await?;
        if !status.is_success() {
            bail!("anthropic returned {status}: {v}");
        }
        let content = v["content"]
            .as_array()
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| b["text"].as_str())
                    .collect::<String>()
            })
            .unwrap_or_default();
        let usage = v.get("usage").map(|u| TokenUsage {
            prompt: u["input_tokens"].as_u64().unwrap_or(0) as u32,
            completion: u["output_tokens"].as_u64().unwrap_or(0) as u32,
        });
        Ok(CompletionResponse {
            content,
            model_used: v["model"].as_str().unwrap_or(&self.model).to_string(),
            usage,
            latency_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn stream(&self, req: CompletionRequest, tx: Sender<String>) -> Result<CompletionResponse> {
        let start = Instant::now();
        let rb = self.http.post(self.endpoint()).json(&self.body(&req, true));
        let resp = self.auth(rb)?.send().await?;
        let content = pump(resp, &tx, parse_sse_line).await?;
        Ok(CompletionResponse {
            content,
            model_used: self.model.clone(),
            usage: None,
            latency_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn health(&self) -> Result<ProviderStatus> {
        let key_present = self.key.is_some();
        let model_valid = !self.model.is_empty();
        let url = format!("{}/v1/models", self.base_url);
        let mut rb = self.http.get(url).header("anthropic-version", API_VERSION);
        if let Some(k) = &self.key {
            rb = rb.header("x-api-key", k);
        }
        let (reachable, message) = match rb.send().await {
            Ok(r) => (true, Some(format!("HTTP {}", r.status().as_u16()))),
            Err(e) => (false, Some(e.to_string())),
        };
        Ok(ProviderStatus {
            name: "anthropic".into(),
            reachable,
            model_valid,
            key_present,
            message,
        })
    }

    fn name(&self) -> &str {
        "anthropic"
    }
    fn model(&self) -> &str {
        &self.model
    }
}

fn parse_sse_line(line: &str) -> Chunk {
    // Anthropic emits `event:` and `data:` lines; we only act on data.
    let Some(data) = line.strip_prefix("data:") else {
        return Chunk::Ignore;
    };
    let data = data.trim();
    match serde_json::from_str::<serde_json::Value>(data) {
        Ok(v) => match v["type"].as_str() {
            Some("content_block_delta") => {
                Chunk::Delta(v["delta"]["text"].as_str().unwrap_or_default().to_string())
            }
            Some("message_stop") => Chunk::Done,
            _ => Chunk::Ignore,
        },
        Err(_) => Chunk::Ignore,
    }
}
