//! `mareu session` — manage named research sessions (RFC §9.4).

use super::Ctx;
use crate::output::{ACCENT, DIM, HIGHLIGHT, PRIMARY, SUCCESS};
use crate::session::Store;
use crate::util;
use anyhow::{bail, Result};
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub cmd: SessionCmd,
}

#[derive(Subcommand, Debug)]
pub enum SessionCmd {
    /// Create a new session
    New {
        name: String,
        #[arg(short, long)]
        target: Option<String>,
    },
    /// List all sessions
    List,
    /// Print a session's conversation and notes
    Show { name: String },
    /// Set the active session for subsequent commands
    Attach { name: String },
    /// Clear the active session
    Detach,
    /// Append a note to a session
    Note { name: String, text: Vec<String> },
    /// Open session notes in $EDITOR
    Edit { name: String },
    /// Delete a session
    Rm {
        name: String,
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
    /// Export a session as disclosure-ready markdown
    Export {
        name: String,
        /// Write to a file (long-only: `-o` is the global output flag)
        #[arg(long = "out", value_name = "FILE")]
        out: Option<String>,
    },
    /// Import a session from exported markdown
    Import { file: String },
}

pub async fn exec(ctx: &Ctx, args: &SessionArgs) -> Result<i32> {
    let store = Store::open(ctx.cfg())?;
    let p = ctx.ui.painter();

    match &args.cmd {
        SessionCmd::New { name, target } => {
            store.create(name, target.clone())?;
            store.attach(name)?;
            println!(
                "{} created and attached session '{}'",
                p.paint(SUCCESS, "✓"),
                name
            );
        }
        SessionCmd::List => {
            let sessions = store.list()?;
            let active = store.active()?;
            if sessions.is_empty() {
                println!("  {}", p.paint(DIM, "no sessions"));
                return Ok(0);
            }
            println!("{}", ctx.ui.section("SESSIONS", ""));
            for s in sessions {
                let mark = if active.as_deref() == Some(&s.name) {
                    p.paint(HIGHLIGHT, "●")
                } else {
                    p.paint(DIM, "·")
                };
                println!(
                    "  {mark} {:<20} {}  {}  {}",
                    p.paint(PRIMARY, &s.name),
                    p.paint(DIM, &format!("{:>8}", human_size(s.size))),
                    p.paint(DIM, &s.last_active),
                    p.paint(DIM, s.target.as_deref().unwrap_or("—")),
                );
            }
        }
        SessionCmd::Show { name } => {
            if !store.exists(name) {
                bail!("no such session '{name}'");
            }
            let md = store.export(name)?;
            util::emit(&md, ctx.cfg().output.pager && !ctx.no_pager);
        }
        SessionCmd::Attach { name } => {
            store.attach(name)?;
            println!("{} attached '{}'", p.paint(SUCCESS, "✓"), name);
        }
        SessionCmd::Detach => {
            store.detach()?;
            println!("{} detached", p.paint(ACCENT, "·"));
        }
        SessionCmd::Note { name, text } => {
            if text.is_empty() {
                bail!("note text is empty");
            }
            store.append_note(name, &text.join(" "))?;
            println!("{} note added to '{}'", p.paint(SUCCESS, "✓"), name);
        }
        SessionCmd::Edit { name } => {
            if !store.exists(name) {
                bail!("no such session '{name}'");
            }
            util::open_in_editor(&store.notes_path(name))?;
        }
        SessionCmd::Rm { name, yes } => {
            if !store.exists(name) {
                bail!("no such session '{name}'");
            }
            if !yes && !confirm(&format!("delete session '{name}'? [y/N] "))? {
                println!("  aborted");
                return Ok(0);
            }
            store.remove(name)?;
            println!("{} removed '{}'", p.paint(SUCCESS, "✓"), name);
        }
        SessionCmd::Export { name, out } => {
            let md = store.export(name)?;
            match out {
                Some(path) => {
                    std::fs::write(path, &md)?;
                    ctx.ui.status(&format!("  written: {path}"));
                }
                None => util::emit(&md, ctx.cfg().output.pager && !ctx.no_pager),
            }
        }
        SessionCmd::Import { file } => {
            let name = store.import(file)?;
            println!("{} imported as session '{}'", p.paint(SUCCESS, "✓"), name);
        }
    }
    Ok(0)
}

fn confirm(prompt: &str) -> Result<bool> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        // Non-interactive: refuse destructive default, require -y.
        bail!("refusing to proceed non-interactively; pass --yes");
    }
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn human_size(bytes: u64) -> String {
    const U: [&str; 4] = ["B", "K", "M", "G"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}{}", U[0])
    } else {
        format!("{v:.1}{}", U[i])
    }
}
