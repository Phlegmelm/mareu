//! AI execution path shared by `analyze`, `recon`, `scaffold`, and the REPL.
//!
//! Handles provider construction, the stderr status line (RFC §3.3.3), the
//! choice between streaming and buffered completion, and automatic fallback to
//! `ai.fallback` on provider error (RFC Open-Q4: implemented as automatic).

use crate::cli::Ctx;
use crate::output::{stream, ACCENT, DIM};
use crate::provider::{self, CompletionRequest, Message};
use anyhow::{anyhow, Context, Result};
use std::io::IsTerminal;

/// Run an AI completion. `system` is the assembled system prompt; `user` is the
/// operator-facing instruction/message. Streams to stdout for text output.
pub async fn run(ctx: &Ctx, system: String, user: String, label: &str) -> Result<String> {
    let cfg = ctx.cfg();
    let primary = cfg.provider.default.clone();

    // Build the primary provider; surface a clear pointer if misconfigured.
    let prov = provider::build(cfg, &primary)
        .with_context(|| "building AI provider (see `mareu config providers`)")?;

    let req = CompletionRequest {
        system: Some(system),
        messages: vec![Message::user(user)],
        model: prov.model().to_string(),
        stream: !ctx.no_stream && ctx.ui.format == crate::output::OutputFormat::Text,
        max_tokens: Some(cfg.ai.max_tokens),
        temperature: Some(cfg.ai.temperature as f32),
    };

    // Status line to stderr (kept off stdout so pipes stay clean).
    let p = ctx.ui.painter();
    if ctx.ui.verbosity >= 1 {
        eprintln!(
            "{} {} {}",
            p.paint(ACCENT, "▸"),
            p.paint(DIM, "provider"),
            format_args!("{}/{}", prov.name(), prov.model())
        );
    }

    match dispatch(ctx, prov.as_ref(), req.clone(), label).await {
        Ok(text) => Ok(text),
        Err(e) => {
            let fb = cfg.ai.fallback.trim();
            if fb.is_empty() || fb == primary {
                return Err(e);
            }
            ctx.ui.status(&p.paint(
                DIM,
                &format!("  primary failed ({e}); falling back to {fb}"),
            ));
            let fallback = provider::build(cfg, fb)
                .with_context(|| format!("building fallback provider '{fb}'"))?;
            let mut req = req;
            req.model = fallback.model().to_string();
            dispatch(ctx, fallback.as_ref(), req, label).await
        }
    }
}

async fn dispatch(
    ctx: &Ctx,
    prov: &dyn provider::Provider,
    req: CompletionRequest,
    label: &str,
) -> Result<String> {
    if req.stream {
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
        let spinner = std::io::stderr().is_terminal() && ctx.ui.verbosity >= 1;
        let label = format!("querying {}/{}...", prov.name(), prov.model());
        let consumer = tokio::spawn(async move { stream::consume(rx, &label, spinner).await });
        let prov_res = prov.stream(req, tx).await;
        let streamed = consumer
            .await
            .map_err(|e| anyhow!("stream consumer: {e}"))?;
        match prov_res {
            Ok(resp) => Ok(if resp.content.is_empty() {
                streamed
            } else {
                resp.content
            }),
            Err(e) => Err(e),
        }
    } else {
        let _ = label;
        let resp = prov.complete(req).await?;
        Ok(resp.content)
    }
}
