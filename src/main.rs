//! Mareu — a terminal utility for vulnerability research, exploit development,
//! and security tooling. Entry point: parse the CLI, resolve config and the
//! output context, optionally print the banner, and dispatch.

mod airun;
mod analysis;
mod banner;
mod cli;
mod config;
mod context;
mod mcp;
mod output;
mod provider;
mod repl;
mod scaffold;
mod session;
mod util;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands, Ctx};
use output::{OutputFormat, Ui};
use std::io::IsTerminal;

/// Write a shell completion script to stdout.
fn generate_completions(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "mareu", &mut std::io::stdout());
}

/// Render man pages — either into `dir` (one per subcommand) or the top-level
/// page to stdout.
fn generate_man(dir: Option<&str>) -> anyhow::Result<i32> {
    let cmd = Cli::command();
    match dir {
        Some(d) => {
            std::fs::create_dir_all(d)?;
            clap_mangen::generate_to(cmd, d)?;
            eprintln!("man pages written to {d}/");
        }
        None => {
            let mut buf = Vec::new();
            clap_mangen::Man::new(cmd).render(&mut buf)?;
            use std::io::Write;
            std::io::stdout().write_all(&buf)?;
        }
    }
    Ok(0)
}

#[tokio::main]
async fn main() {
    // On Windows, switch the console into ANSI/VT mode so our truecolor escapes
    // render instead of printing literally. No-op elsewhere.
    #[cfg(windows)]
    let _ = enable_ansi_support::enable_ansi_support();

    let code = match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("mareu: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

async fn run() -> anyhow::Result<i32> {
    let cli = Cli::parse();
    let g = &cli.global;

    // Generators don't need config or output context — handle them first.
    match &cli.command {
        Some(Commands::Completions(a)) => {
            generate_completions(a.shell);
            return Ok(0);
        }
        Some(Commands::Man(a)) => {
            return generate_man(a.dir.as_deref());
        }
        _ => {}
    }

    let loaded = config::load()?;

    // ── resolve output context ─────────────────────────────────────────────
    let stdin_piped = util::stdin_piped();
    let stdout_tty = std::io::stdout().is_terminal();

    let format = resolve_format(g, &loaded.config)?;

    let color = resolve_color(g, &loaded.config, stdout_tty, format);

    let verbosity = if g.quiet {
        0
    } else {
        (1 + g.verbose).min(4)
    };

    let ai = if g.no_ai {
        false
    } else {
        g.ai || loaded.config.ai.default
    };

    let ui = Ui {
        color,
        verbosity,
        format,
    };

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let ctx = Ctx {
        loaded,
        ui,
        ai,
        dry_run: g.dry_run,
        no_stream: g.no_stream,
        no_pager: g.no_pager,
        timestamp,
    };

    // ── banner ─────────────────────────────────────────────────────────────
    let style = ctx.cfg().banner.style.clone();
    match &cli.command {
        None => {
            // No subcommand: print the full banner (interactive) and a hint.
            if !banner::suppressed(g.quiet, stdin_piped) && style != "none" {
                let status = format!(
                    "ai: {}  ·  session: {}  ·  provider: {}",
                    if ai { "enabled" } else { "disabled" },
                    "none",
                    ctx.cfg().provider.default,
                );
                println!("{}", banner::full(&ctx.ui, &status));
            }
            eprintln!("  run `mareu --help` for usage");
            return Ok(0);
        }
        Some(_) => {
            // Compact banner to stderr for non-shell subcommands.
            if !banner::suppressed(g.quiet, stdin_piped)
                && style == "full"
                && !matches!(cli.command, Some(Commands::Shell(_)) | Some(Commands::Mcp(_)))
            {
                eprintln!("{}", banner::compact(&ctx.ui));
            }
        }
    }

    // ── dispatch ───────────────────────────────────────────────────────────
    match cli.command.as_ref().unwrap() {
        Commands::Recon(a) => cli::recon::exec(&ctx, a).await,
        Commands::Analyze(a) => cli::analyze::exec(&ctx, a).await,
        Commands::Scaffold(a) => cli::scaffold::exec(&ctx, a).await,
        Commands::Session(a) => cli::session::exec(&ctx, a).await,
        Commands::Shell(a) => cli::shell::exec(&ctx, a).await,
        Commands::Report(a) => cli::report::exec(&ctx, a).await,
        Commands::Mcp(a) => mcp::serve(&ctx, a).await,
        Commands::Config(a) => cli::config::exec(&ctx, a).await,
        // Handled before config load.
        Commands::Completions(_) | Commands::Man(_) => unreachable!(),
        Commands::Banner(a) => {
            let style = a.style.as_deref().unwrap_or("full");
            match style {
                "compact" => println!("{}", banner::compact(&ctx.ui)),
                "none" => {}
                _ => {
                    let status = format!(
                        "ai: {}  ·  session: none  ·  provider: {}",
                        if ai { "enabled" } else { "disabled" },
                        ctx.cfg().provider.default
                    );
                    println!("{}", banner::full(&ctx.ui, &status));
                }
            }
            Ok(0)
        }
    }
}

fn resolve_format(g: &cli::GlobalArgs, cfg: &config::Config) -> anyhow::Result<OutputFormat> {
    let raw = g.output.clone().unwrap_or_else(|| cfg.output.format.clone());
    raw.parse::<OutputFormat>().map_err(|e| anyhow::anyhow!(e))
}

fn resolve_color(
    g: &cli::GlobalArgs,
    cfg: &config::Config,
    stdout_tty: bool,
    format: OutputFormat,
) -> bool {
    if g.no_color || format != OutputFormat::Text {
        return false;
    }
    // Respect the NO_COLOR standard.
    if cfg.output.no_color_env && std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    cfg.output.color && stdout_tty
}
