//! Ollama provider — local, keyless, air-gap friendly. Uses the `/api/chat`
//! endpoint, which streams newline-delimited JSON objects.

use super::{client, pump, Chunk, CompletionRequest, CompletionResponse, Provider, ProviderStatus};
use anyhow::{bail, Result};
use async_trait::async_trait;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

pub struct Ollama {
    model: String,
    base_url: String,
    http: reqwest::Client,
}

impl Ollama {
    pub fn new(model: String, base_url: String, timeout: Duration) -> Result<Self> {
        let base = if base_url.trim().is_empty() {
            "http://localhost:11434".to_string()
        } else {
            base_url.trim_end_matches('/').to_string()
        };
        Ok(Self {
            model,
            base_url: base,
            http: client(timeout)?,
        })
    }

    fn endpoint(&self) -> String {
        format!("{}/api/chat", self.base_url)
    }

    fn body(&self, req: &CompletionRequest, stream: bool) -> serde_json::Value {
        let mut messages = Vec::new();
        if let Some(sys) = &req.system {
            messages.push(json!({"role": "system", "content": sys}));
        }
        for m in &req.messages {
            messages.push(json!({"role": m.role, "content": m.content}));
        }
        let mut b = json!({
            "model": if req.model.is_empty() { &self.model } else { &req.model },
            "messages": messages,
            "stream": stream,
        });
        if let Some(t) = req.temperature {
            b["options"] = json!({ "temperature": t });
        }
        b
    }
}

#[async_trait]
impl Provider for Ollama {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        let start = Instant::now();
        let resp = self
            .http
            .post(self.endpoint())
            .json(&self.body(&req, false))
            .send()
            .await?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().await?;
        if !status.is_success() {
            bail!("ollama returned {status}: {v}");
        }
        let content = v["message"]["content"].as_str().unwrap_or_default().to_string();
        Ok(CompletionResponse {
            content,
            model_used: v["model"].as_str().unwrap_or(&self.model).to_string(),
            usage: None,
            latency_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn stream(&self, req: CompletionRequest, tx: Sender<String>) -> Result<CompletionResponse> {
        let start = Instant::now();
        let resp = self
            .http
            .post(self.endpoint())
            .json(&self.body(&req, true))
            .send()
            .await?;
        let content = pump(resp, &tx, parse_ndjson_line).await?;
        Ok(CompletionResponse {
            content,
            model_used: self.model.clone(),
            usage: None,
            latency_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn health(&self) -> Result<ProviderStatus> {
        let url = format!("{}/api/tags", self.base_url);
        let (reachable, model_valid, message) = match self.http.get(url).send().await {
            Ok(r) => {
                let ok = r.status().is_success();
                let tags: serde_json::Value = r.json().await.unwrap_or(json!({}));
                let present = tags["models"]
                    .as_array()
                    .map(|m| {
                        m.iter()
                            .any(|x| x["name"].as_str() == Some(self.model.as_str()))
                    })
                    .unwrap_or(false);
                (
                    ok,
                    present || !self.model.is_empty(),
                    Some(if present {
                        "model pulled".into()
                    } else {
                        format!("model '{}' not pulled (run `ollama pull`)", self.model)
                    }),
                )
            }
            Err(e) => (false, false, Some(e.to_string())),
        };
        Ok(ProviderStatus {
            name: "ollama".into(),
            reachable,
            model_valid,
            key_present: true, // keyless: never blocks on a missing key
            message,
        })
    }

    fn name(&self) -> &str {
        "ollama"
    }
    fn model(&self) -> &str {
        &self.model
    }
}

fn parse_ndjson_line(line: &str) -> Chunk {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(v) => {
            if v["done"].as_bool().unwrap_or(false) {
                // Final object may still carry no content; treat as done.
                return Chunk::Done;
            }
            Chunk::Delta(v["message"]["content"].as_str().unwrap_or_default().to_string())
        }
        Err(_) => Chunk::Ignore,
    }
}
