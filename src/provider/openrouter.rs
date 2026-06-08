//! OpenRouter provider — OpenAI-compatible chat completions with OpenRouter's
//! recommended attribution headers. Routes to any model OpenRouter exposes
//! (Claude, GPT, Gemini, Mistral, …) via the `model` config key.

use super::openai::OpenAiCompatible;
use super::{CompletionRequest, CompletionResponse, Provider, ProviderStatus};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

pub struct OpenRouter {
    inner: OpenAiCompatible,
}

impl OpenRouter {
    pub fn new(
        key: Option<String>,
        model: String,
        base_url: String,
        timeout: Duration,
    ) -> Result<Self> {
        let base = if base_url.trim().is_empty() {
            "https://openrouter.ai/api/v1".to_string()
        } else {
            base_url
        };
        let inner = OpenAiCompatible::new("openrouter".into(), key, model, base, timeout)?
            .with_headers(vec![
                (
                    "HTTP-Referer".into(),
                    "https://github.com/phlegmelm/mareu".into(),
                ),
                ("X-Title".into(), "mareu".into()),
            ]);
        Ok(Self { inner })
    }
}

#[async_trait]
impl Provider for OpenRouter {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        self.inner.complete(req).await
    }
    async fn stream(
        &self,
        req: CompletionRequest,
        tx: Sender<String>,
    ) -> Result<CompletionResponse> {
        self.inner.stream(req, tx).await
    }
    async fn health(&self) -> Result<ProviderStatus> {
        self.inner.health().await
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn model(&self) -> &str {
        self.inner.model()
    }
}
