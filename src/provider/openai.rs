//! OpenAI-compatible chat-completions provider. Covers the OpenAI API itself
//! plus any compatible endpoint (Together, Groq, local servers, …) via
//! `base_url`. OpenRouter reuses this shape with extra headers (see
//! `openrouter.rs`).

use super::{client, pump, Chunk, CompletionRequest, CompletionResponse, Message, Provider, ProviderStatus, TokenUsage};
use anyhow::{bail, Result};
use async_trait::async_trait;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

pub struct OpenAiCompatible {
    name: String,
    key: Option<String>,
    model: String,
    base_url: String,
    http: reqwest::Client,
    /// Extra headers (header-name, value) sent on every request.
    extra_headers: Vec<(String, String)>,
}

impl OpenAiCompatible {
    pub fn new(
        name: String,
        key: Option<String>,
        model: String,
        base_url: String,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            name,
            key,
            model,
            base_url: base_url.trim_end_matches('/').to_string(),
            http: client(timeout)?,
            extra_headers: Vec::new(),
        })
    }

    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    fn endpoint(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }

    /// Build the OpenAI chat messages array, folding `system` in as the first
    /// message.
    fn build_messages(req: &CompletionRequest) -> Vec<serde_json::Value> {
        let mut msgs = Vec::new();
        if let Some(sys) = &req.system {
            msgs.push(json!({"role": "system", "content": sys}));
        }
        for m in &req.messages {
            msgs.push(json!({"role": m.role, "content": m.content}));
        }
        msgs
    }

    fn body(&self, req: &CompletionRequest, stream: bool) -> serde_json::Value {
        let mut b = json!({
            "model": if req.model.is_empty() { &self.model } else { &req.model },
            "messages": Self::build_messages(req),
            "stream": stream,
        });
        if let Some(mt) = req.max_tokens {
            b["max_tokens"] = json!(mt);
        }
        if let Some(t) = req.temperature {
            b["temperature"] = json!(t);
        }
        b
    }

    fn apply_headers(&self, mut rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(k) = &self.key {
            rb = rb.bearer_auth(k);
        }
        for (h, v) in &self.extra_headers {
            rb = rb.header(h.as_str(), v.as_str());
        }
        rb
    }
}

#[async_trait]
impl Provider for OpenAiCompatible {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        let start = Instant::now();
        let rb = self
            .http
            .post(self.endpoint())
            .json(&self.body(&req, false));
        let resp = self.apply_headers(rb).send().await?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().await?;
        if !status.is_success() {
            bail!("{} returned {status}: {v}", self.name);
        }
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let usage = v.get("usage").map(|u| TokenUsage {
            prompt: u["prompt_tokens"].as_u64().unwrap_or(0) as u32,
            completion: u["completion_tokens"].as_u64().unwrap_or(0) as u32,
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
        let resp = self.apply_headers(rb).send().await?;
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
        // Probe the models endpoint with a short timeout.
        let url = format!("{}/models", self.base_url);
        let rb = self.apply_headers(self.http.get(url));
        let (reachable, message) = match rb.send().await {
            Ok(r) => (true, Some(format!("HTTP {}", r.status().as_u16()))),
            Err(e) => (false, Some(e.to_string())),
        };
        Ok(ProviderStatus {
            name: self.name.clone(),
            reachable,
            model_valid,
            key_present,
            message,
        })
    }

    fn name(&self) -> &str {
        &self.name
    }
    fn model(&self) -> &str {
        &self.model
    }
}

/// Parse a single SSE line from an OpenAI-style stream.
pub(crate) fn parse_sse_line(line: &str) -> Chunk {
    let Some(data) = line.strip_prefix("data:") else {
        return Chunk::Ignore;
    };
    let data = data.trim();
    if data == "[DONE]" {
        return Chunk::Done;
    }
    match serde_json::from_str::<serde_json::Value>(data) {
        Ok(v) => {
            let delta = v["choices"][0]["delta"]["content"]
                .as_str()
                .unwrap_or_default();
            Chunk::Delta(delta.to_string())
        }
        Err(_) => Chunk::Ignore,
    }
}

/// Convenience constructor used by tests/other providers.
#[allow(dead_code)]
pub(crate) fn user_only(text: &str) -> Vec<Message> {
    vec![Message::user(text)]
}
