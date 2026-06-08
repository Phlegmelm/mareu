//! `mareu config` — configuration management (RFC §9.6).

use super::Ctx;
use crate::config;
use crate::output::{DIM, HIGHLIGHT, PRIMARY, SUCCESS};
use crate::provider;
use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub cmd: ConfigCmd,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the fully resolved config (defaults + file + env)
    Show,
    /// Set a config value (dotted key), e.g. provider.default openrouter
    Set { key: String, value: String },
    /// Remove a config override
    Unset { key: String },
    /// Open the user config file in $EDITOR
    Edit,
    /// Show all providers, key status, and reachability
    Providers,
    /// Restore default config
    Reset {
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
}

pub async fn exec(ctx: &Ctx, args: &ConfigArgs) -> Result<i32> {
    let p = ctx.ui.painter();
    match &args.cmd {
        ConfigCmd::Show => {
            let mut tree = toml::Value::try_from(ctx.cfg())?;
            mask_secrets(&mut tree);
            crate::util::emit(&toml::to_string_pretty(&tree)?, false);
        }
        ConfigCmd::Set { key, value } => {
            let path = config::set_value(key, value)?;
            println!("{} {} = {}  →  {}", p.paint(SUCCESS, "✓"), key, value, path.display());
        }
        ConfigCmd::Unset { key } => {
            let path = config::unset_value(key)?;
            println!("{} unset {}  →  {}", p.paint(SUCCESS, "✓"), key, path.display());
        }
        ConfigCmd::Edit => {
            let path = config::user_config_path()?;
            if !path.exists() {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, config::DEFAULT_TOML)?;
            }
            crate::util::open_in_editor(&path)?;
        }
        ConfigCmd::Providers => {
            print_providers(ctx).await?;
        }
        ConfigCmd::Reset { yes } => {
            use std::io::{IsTerminal, Write};
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("refusing to reset non-interactively; pass --yes");
                }
                print!("reset config to defaults? [y/N] ");
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    println!("  aborted");
                    return Ok(0);
                }
            }
            let path = config::user_config_path()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, config::DEFAULT_TOML)?;
            println!("{} reset → {}", p.paint(SUCCESS, "✓"), path.display());
        }
    }
    Ok(0)
}

async fn print_providers(ctx: &Ctx) -> Result<()> {
    let cfg = ctx.cfg();
    let p = ctx.ui.painter();
    println!("{}", ctx.ui.section("PROVIDERS", ""));
    println!(
        "  {:<12} {:<7} {:<10} {:<28} {}",
        p.paint(DIM, "name"),
        p.paint(DIM, "key"),
        p.paint(DIM, "reachable"),
        p.paint(DIM, "model"),
        p.paint(DIM, "status"),
    );

    for name in provider::BUILTINS {
        let active = *name == cfg.provider.default;
        match provider::build(cfg, name) {
            Ok(prov) => {
                let st = prov.health().await.ok();
                let (key, reach, msg, model) = match st {
                    Some(s) => (
                        if s.key_present { "yes" } else { "—" },
                        if s.reachable { "yes" } else { "no" },
                        s.message.unwrap_or_default(),
                        prov.model().to_string(),
                    ),
                    None => ("?", "?", "health check failed".into(), prov.model().to_string()),
                };
                let key_c = if key == "yes" { SUCCESS } else { DIM };
                let reach_c = if reach == "yes" { SUCCESS } else { DIM };
                let name_disp = if active {
                    format!("{} *", name)
                } else {
                    name.to_string()
                };
                println!(
                    "  {:<12} {:<7} {:<10} {:<28} {}",
                    p.paint(if active { HIGHLIGHT } else { PRIMARY }, &name_disp),
                    p.paint(key_c, key),
                    p.paint(reach_c, reach),
                    p.paint(DIM, &truncate(&model, 28)),
                    p.paint(DIM, &truncate(&msg, 30)),
                );
            }
            Err(e) => {
                println!("  {:<12} {}", name, p.paint(DIM, &e.to_string()));
            }
        }
    }
    println!("\n  {} = active default", p.paint(HIGHLIGHT, "*"));
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Replace populated `api_key` values with a marker so `config show` never
/// prints a live secret.
fn mask_secrets(v: &mut toml::Value) {
    match v {
        toml::Value::Table(t) => {
            for (k, val) in t.iter_mut() {
                if k == "api_key" {
                    if let toml::Value::String(s) = val {
                        if !s.is_empty() && !s.contains("${") {
                            *s = "***set***".into();
                        }
                    }
                } else {
                    mask_secrets(val);
                }
            }
        }
        toml::Value::Array(a) => a.iter_mut().for_each(mask_secrets),
        _ => {}
    }
}
