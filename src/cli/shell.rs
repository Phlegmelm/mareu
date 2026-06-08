//! `mareu shell` — interactive REPL (RFC §9.5). Thin entry point; the loop lives
//! in [`crate::repl`].

use super::Ctx;
use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct ShellArgs {
    /// Attach to an existing session
    #[arg(short = 's', long = "session", value_name = "NAME")]
    pub session: Option<String>,

    /// Set the initial target context
    #[arg(short = 't', long = "target", value_name = "PATH")]
    pub target: Option<String>,
}

pub async fn exec(ctx: &Ctx, args: &ShellArgs) -> Result<i32> {
    crate::repl::run(ctx, args).await
}
