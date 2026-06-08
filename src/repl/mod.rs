//! Interactive REPL for sustained target work (RFC §9.5).
//!
//! Maintains per-session conversation history and loaded context across turns.
//! Non-slash input is sent to the AI (when enabled); slash-commands drive the
//! tooling. Readline history and reverse-search come from rustyline.

mod commands;
mod complete;

use crate::cli::shell::ShellArgs;
use crate::cli::Ctx;
use crate::context;
use crate::output::{OutputFormat, ACCENT, DIM, INFO, PRIMARY, SUCCESS};
use crate::provider::Message;
use crate::session::Store;
use anyhow::Result;
use rustyline::error::ReadlineError;

struct State {
    session: Option<String>,
    target: Option<String>,
    ai: bool,
    provider_override: Option<String>,
    model_override: Option<String>,
    context_files: Vec<(String, String)>,
    history: Vec<Message>,
}

pub async fn run(ctx: &Ctx, args: &ShellArgs) -> Result<i32> {
    let p = ctx.ui.painter();
    let store = Store::open(ctx.cfg()).ok();

    let mut state = State {
        session: args
            .session
            .clone()
            .or_else(|| store.as_ref().and_then(|s| s.active().ok().flatten())),
        target: args.target.clone(),
        ai: ctx.ai,
        provider_override: None,
        model_override: None,
        context_files: Vec::new(),
        history: Vec::new(),
    };

    // Ensure the named session exists & is attached.
    if let (Some(store), Some(name)) = (&store, &state.session) {
        if !store.exists(name) {
            let _ = store.create(name, state.target.clone());
        }
        let _ = store.attach(name);
        // Pre-load prior conversation into the buffer.
        if let Ok(turns) = store.read_history(name) {
            for t in turns.iter().rev().take(12).rev() {
                state.history.push(Message {
                    role: t.role.clone(),
                    content: t.content.clone(),
                });
            }
        }
    }

    if ctx.cfg().banner.style != "none" && ctx.ui.verbosity >= 1 {
        println!(
            "{}",
            crate::banner::full(&ctx.ui, &status_line(ctx, &state))
        );
    }
    println!(
        "  {}",
        p.paint(DIM, "type /help for commands, /exit to quit")
    );

    let mut rl = complete::editor()?;

    loop {
        let prompt = make_prompt(ctx, &state);
        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line.as_str());
                if line.starts_with('/') {
                    match handle_slash(ctx, &mut state, store.as_ref(), &line).await {
                        ControlFlow::Continue => {}
                        ControlFlow::Exit => break,
                    }
                } else {
                    chat(ctx, &mut state, store.as_ref(), &line).await;
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("  {}", p.paint(DIM, "(^C — /exit to quit)"));
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        }
    }

    println!("  {}", p.paint(ACCENT, "session ended"));
    Ok(0)
}

enum ControlFlow {
    Continue,
    Exit,
}

// rustyline measures prompt width by byte length, so embedded ANSI would
// misplace the cursor — keep the prompt plain.
fn make_prompt(_ctx: &Ctx, state: &State) -> String {
    let ai = if state.ai { "ai" } else { "--" };
    let sess = state.session.as_deref().unwrap_or("-");
    format!("mareu {sess}·{ai} › ")
}

fn status_line(_ctx: &Ctx, state: &State) -> String {
    let ai = if state.ai { "enabled" } else { "disabled" };
    let sess = state.session.as_deref().unwrap_or("none");
    let prov = state.provider_override.as_deref().unwrap_or("default");
    format!("ai: {ai}  ·  session: {sess}  ·  provider: {prov}")
}

async fn handle_slash(
    ctx: &Ctx,
    state: &mut State,
    store: Option<&Store>,
    line: &str,
) -> ControlFlow {
    let p = ctx.ui.painter();
    let (cmd, rest) = commands::split(line);
    match cmd {
        "/exit" | "/quit" | "/q" => return ControlFlow::Exit,
        "/help" | "/?" => println!("{}", commands::HELP),
        "/ai" => {
            state.ai = !state.ai;
            println!(
                "  ai {}",
                if state.ai {
                    p.paint(SUCCESS, "on")
                } else {
                    p.paint(DIM, "off")
                }
            );
        }
        "/clear" => {
            state.history.clear();
            println!("  {}", p.paint(DIM, "conversation buffer cleared"));
        }
        "/context" => print_context(ctx, state),
        "/load" => {
            if rest.is_empty() {
                println!("  usage: /load <file>");
            } else {
                match std::fs::read_to_string(rest) {
                    Ok(c) => {
                        let tokens = context::estimate_tokens(&c);
                        state.context_files.retain(|(p, _)| p != rest);
                        state.context_files.push((rest.to_string(), c));
                        if let (Some(store), Some(name)) = (store, &state.session) {
                            let _ = store.add_context_file(name, rest, tokens);
                        }
                        println!(
                            "  {} loaded {rest} (~{tokens} tokens)",
                            p.paint(SUCCESS, "✓")
                        );
                    }
                    Err(e) => println!("  {} {rest}: {e}", p.paint(DIM, "error")),
                }
            }
        }
        "/drop" => {
            let before = state.context_files.len();
            state.context_files.retain(|(p, _)| p != rest);
            if let (Some(store), Some(name)) = (store, &state.session) {
                let _ = store.drop_context_file(name, rest);
            }
            if state.context_files.len() != before {
                println!("  {} dropped {rest}", p.paint(SUCCESS, "✓"));
            } else {
                println!("  not loaded: {rest}");
            }
        }
        "/note" => {
            if let (Some(store), Some(name)) = (store, &state.session) {
                let _ = store.append_note(name, rest);
                println!("  {} note saved", p.paint(SUCCESS, "✓"));
            } else {
                println!("  no active session for notes");
            }
        }
        "/save" => {
            if let (Some(store), Some(name)) = (store, &state.session) {
                let _ = store.touch(name, None, None);
                println!("  {} saved", p.paint(SUCCESS, "✓"));
            }
        }
        "/export" => {
            if let (Some(store), Some(name)) = (store, &state.session) {
                if let Ok(md) = store.export(name) {
                    print!("{md}");
                }
            } else {
                println!("  no active session to export");
            }
        }
        "/prompt" => {
            let sys = build_shell_system(state);
            println!("{}", p.paint(DIM, "===== SYSTEM PROMPT ====="));
            println!("{sys}");
        }
        "/model" => {
            if rest.is_empty() {
                println!(
                    "  current model override: {}",
                    state.model_override.as_deref().unwrap_or("(default)")
                );
            } else {
                state.model_override = Some(rest.to_string());
                println!("  {} model → {rest}", p.paint(SUCCESS, "✓"));
            }
        }
        "/provider" => {
            if rest.is_empty() {
                println!(
                    "  current provider override: {}",
                    state.provider_override.as_deref().unwrap_or("(default)")
                );
            } else {
                state.provider_override = Some(rest.to_string());
                println!("  {} provider → {rest}", p.paint(SUCCESS, "✓"));
            }
        }
        "/analyze" => slash_analyze(ctx, state, rest).await,
        "/recon" => slash_recon(ctx, state, rest).await,
        "/scaffold" => slash_scaffold(ctx, state, rest).await,
        other => println!("  unknown command: {other} (try /help)"),
    }
    ControlFlow::Continue
}

fn print_context(ctx: &Ctx, state: &State) {
    let p = ctx.ui.painter();
    if state.context_files.is_empty() {
        println!("  {}", p.paint(DIM, "no context loaded"));
        return;
    }
    let mut total = 0;
    for (path, content) in &state.context_files {
        let t = context::estimate_tokens(content);
        total += t;
        println!(
            "  {} {:<40} ~{t} tokens",
            p.paint(ACCENT, "▸"),
            p.paint(PRIMARY, path)
        );
    }
    println!("  {}", p.paint(DIM, &format!("total ~{total} tokens")));
}

/// Build a Ctx variant reflecting the REPL's live AI/provider/model state.
fn sub_ctx(ctx: &Ctx, state: &State) -> Ctx {
    let mut c = ctx.clone();
    c.ai = state.ai;
    if let Some(prov) = &state.provider_override {
        c.loaded.config.provider.default = prov.clone();
    }
    if let Some(model) = &state.model_override {
        // Override the active provider's model.
        let name = c.loaded.config.provider.default.clone();
        if let Some(entry) = match name.as_str() {
            "openrouter" => Some(&mut c.loaded.config.provider.openrouter),
            "anthropic" => Some(&mut c.loaded.config.provider.anthropic),
            "openai" => Some(&mut c.loaded.config.provider.openai),
            "ollama" => Some(&mut c.loaded.config.provider.ollama),
            _ => c.loaded.config.provider.extra.get_mut(&name),
        } {
            entry.model = Some(model.clone());
        }
    }
    c
}

async fn slash_analyze(ctx: &Ctx, state: &State, rest: &str) {
    let toks = commands::tokenize(rest);
    if toks.is_empty() {
        println!("  usage: /analyze <file> [line|lo:hi]");
        return;
    }
    let args = crate::cli::analyze::AnalyzeArgs {
        file: Some(toks[0].clone()),
        line: toks.get(1).cloned(),
        finding: None,
        context: state.context_files.iter().map(|(p, _)| p.clone()).collect(),
        cwe: true,
        cvss: false,
        decompile: false,
        session: state.session.clone(),
    };
    let c = sub_ctx(ctx, state);
    if let Err(e) = crate::cli::analyze::exec(&c, &args).await {
        println!("  error: {e}");
    }
}

async fn slash_recon(ctx: &Ctx, state: &State, rest: &str) {
    let target = if rest.is_empty() {
        state.target.clone()
    } else {
        Some(rest.to_string())
    };
    if target.is_none() {
        println!("  usage: /recon <path>  (or set a target with -t at launch)");
        return;
    }
    let args = crate::cli::recon::ReconArgs {
        target,
        r#type: None,
        filter: None,
        depth: None,
        entry: Vec::new(),
    };
    let c = sub_ctx(ctx, state);
    if let Err(e) = crate::cli::recon::exec(&c, &args).await {
        println!("  error: {e}");
    }
}

async fn slash_scaffold(ctx: &Ctx, state: &State, rest: &str) {
    let toks = commands::tokenize(rest);
    if toks.is_empty() {
        println!("  usage: /scaffold <type> [class] \"<vuln description>\"");
        return;
    }
    let kind = toks[0].clone();
    let (class, vuln) = match toks.len() {
        1 => (None, String::new()),
        2 => (None, toks[1].clone()),
        _ => (Some(toks[1].clone()), toks[2..].join(" ")),
    };
    let args = crate::cli::scaffold::ScaffoldArgs {
        r#type: kind,
        vuln: Some(vuln),
        lang: None,
        class,
        file: state.context_files.iter().map(|(p, _)| p.clone()).collect(),
        asan: false,
        arch: "x86_64".into(),
        template: None,
        syntax: None,
        egg: None,
        r#unsafe: false,
        save: false,
        session: state.session.clone(),
    };
    let c = sub_ctx(ctx, state);
    if let Err(e) = crate::cli::scaffold::exec(&c, &args).await {
        println!("  error: {e}");
    }
}

fn build_shell_system(state: &State) -> String {
    let files: Vec<context::ContextFile> = state
        .context_files
        .iter()
        .map(|(path, content)| context::ContextFile {
            path: path.clone(),
            content: content.clone(),
            tokens: context::estimate_tokens(content),
        })
        .collect();
    let (ctx_block, _) = context::format_files(&files, 100_000);
    let mut hist = String::new();
    if !state.history.is_empty() {
        hist.push_str("# Conversation so far\n\n");
        for m in state.history.iter().rev().take(10).rev() {
            hist.push_str(&format!("**{}**: {}\n\n", m.role, m.content));
        }
    }
    let vars = context::vars(
        state.target.as_deref().unwrap_or("(none)"),
        "",
        &ctx_block,
        &hist,
        "",
        "x86_64",
        "",
        "",
        false,
        false,
        false,
    );
    context::render(context::SHELL_PROMPT, &vars).unwrap_or_default()
}

async fn chat(ctx: &Ctx, state: &mut State, store: Option<&Store>, line: &str) {
    let p = ctx.ui.painter();
    if !state.ai {
        println!(
            "  {}",
            p.paint(DIM, "ai is off — toggle with /ai, or use a slash-command")
        );
        return;
    }
    let system = build_shell_system(state);
    // Force text streaming in the REPL.
    let mut c = sub_ctx(ctx, state);
    c.ui.format = OutputFormat::Text;
    print!("  {} ", p.paint(INFO, "[AI]"));
    match crate::airun::run(&c, system, line.to_string(), "shell").await {
        Ok(text) => {
            let reply = text.trim().to_string();
            state.history.push(Message::user(line.to_string()));
            state.history.push(Message::assistant(reply.clone()));
            if let (Some(store), Some(name)) = (store, &state.session) {
                let _ = store.append_turn(name, "user", line);
                let _ = store.append_turn(name, "assistant", &reply);
                let _ = store.touch(name, Some(&c.loaded.config.provider.default), None);
            }
        }
        Err(e) => println!("  error: {e}"),
    }
}
