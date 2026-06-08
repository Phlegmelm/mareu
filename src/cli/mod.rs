//! CLI surface (clap derive) and the shared execution context.
//!
//! Global flags (`--ai`, `--no-ai`, `--dry-run`, `--output`, `-q`/`-v`,
//! `--no-color`, …) are defined once and marked `global` so they work before or
//! after the subcommand. Per RFC §3.3 the `--ai` flag is part of the CLI
//! contract from day one.

pub mod analyze;
pub mod config;
pub mod recon;
pub mod report;
pub mod scaffold;
pub mod session;
pub mod shell;

use crate::config::Loaded;
use crate::output::{OutputFormat, Ui};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "mareu",
    version,
    about = "A terminal utility for vulnerability research, exploit development, and security tooling",
    long_about = None,
    disable_help_subcommand = true,
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    /// Enable the AI layer for this invocation
    #[arg(long, global = true)]
    pub ai: bool,

    /// Hard-disable the AI layer (overrides `ai.default = true`)
    #[arg(long = "no-ai", global = true, conflicts_with = "ai")]
    pub no_ai: bool,

    /// Print the assembled prompt/context without calling a provider
    #[arg(long = "dry-run", global = true)]
    pub dry_run: bool,

    /// Output format: text | json | markdown
    #[arg(short = 'o', long = "output", global = true, value_name = "FMT")]
    pub output: Option<String>,

    /// Findings only, no metadata, no banner
    #[arg(short = 'q', long = "quiet", global = true)]
    pub quiet: bool,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short = 'v', action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Disable color (also respects NO_COLOR)
    #[arg(long = "no-color", global = true)]
    pub no_color: bool,

    /// Disable streaming of AI output (buffer then print)
    #[arg(long = "no-stream", global = true)]
    pub no_stream: bool,

    /// Never page output
    #[arg(long = "no-pager", global = true)]
    pub no_pager: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Map attack surface of a source tree or file
    Recon(recon::ReconArgs),
    /// Root-cause analysis of a suspected vulnerability
    Analyze(analyze::AnalyzeArgs),
    /// Generate PoC, exploit, or reproducer scaffolding
    Scaffold(scaffold::ScaffoldArgs),
    /// Manage named research sessions
    Session(session::SessionArgs),
    /// Interactive REPL for sustained target work
    Shell(shell::ShellArgs),
    /// Generate a disclosure-ready report from a session or stdin
    Report(report::ReportArgs),
    /// Run as an MCP server (stdio) so Claude Code can call Mareu as tools
    Mcp(McpArgs),
    /// Configuration management
    Config(config::ConfigArgs),
    /// Print the banner (and cycle styles)
    Banner(BannerArgs),
    /// Generate shell completion script (bash|zsh|fish|powershell|elvish)
    Completions(CompletionsArgs),
    /// Generate the man page(s)
    Man(ManArgs),
}

#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Target shell
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Args, Debug)]
pub struct ManArgs {
    /// Directory to write man pages into (prints the top-level page to stdout
    /// when omitted)
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<String>,
}

#[derive(Args, Debug)]
pub struct McpArgs {
    /// Serve over HTTP on this port instead of stdio (not yet implemented)
    #[arg(long = "port", value_name = "PORT")]
    pub port: Option<u16>,

    /// Default session for `mareu_session_context` when none is named
    #[arg(short = 's', long = "session", value_name = "NAME")]
    pub session: Option<String>,
}

#[derive(Args, Debug)]
pub struct BannerArgs {
    /// Style to print: full | compact | none
    #[arg(value_name = "STYLE")]
    pub style: Option<String>,
}

/// Shared, resolved execution context handed to each command.
#[derive(Clone)]
pub struct Ctx {
    pub loaded: Loaded,
    pub ui: Ui,
    /// Resolved AI-enabled state for this invocation.
    pub ai: bool,
    pub dry_run: bool,
    pub no_stream: bool,
    pub no_pager: bool,
    /// RFC-3339 timestamp captured at startup (stable across the run).
    pub timestamp: String,
}

impl Ctx {
    pub fn cfg(&self) -> &crate::config::Config {
        &self.loaded.config
    }

    pub fn format(&self) -> OutputFormat {
        self.ui.format
    }

    /// Provider+model label for status lines, or None when AI is off.
    pub fn provider_label(&self) -> Option<String> {
        if !self.ai {
            return None;
        }
        let cfg = self.cfg();
        let name = &cfg.provider.default;
        crate::provider::build(cfg, name)
            .ok()
            .map(|p| format!("{}/{}", p.name(), p.model()))
    }
}
