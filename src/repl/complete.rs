//! Tab-completion for the REPL: slash-commands and file paths.
//!
//! Provides a rustyline [`Helper`] whose completer offers the slash-command
//! names when the cursor is on the leading `/<word>`, and delegates to a
//! filename completer for commands that take a path argument.

use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::FileHistory;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor, Helper};

/// All slash-commands, used for completion (kept in sync with `commands::HELP`).
const COMMANDS: &[&str] = &[
    "/recon",
    "/analyze",
    "/scaffold",
    "/load",
    "/drop",
    "/context",
    "/note",
    "/clear",
    "/prompt",
    "/model",
    "/provider",
    "/ai",
    "/save",
    "/export",
    "/help",
    "/exit",
];

/// Slash-commands whose argument is a file path.
const FILE_COMMANDS: &[&str] = &["/load", "/drop", "/analyze"];

pub struct MareuHelper {
    files: FilenameCompleter,
}

impl MareuHelper {
    fn new() -> Self {
        Self {
            files: FilenameCompleter::new(),
        }
    }
}

impl Completer for MareuHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let head = &line[..pos];

        // First token starting with '/': complete the command name itself.
        if head.starts_with('/') && !head.contains(char::is_whitespace) {
            let matches: Vec<Pair> = COMMANDS
                .iter()
                .filter(|c| c.starts_with(head))
                .map(|c| Pair {
                    display: (*c).to_string(),
                    replacement: (*c).to_string(),
                })
                .collect();
            return Ok((0, matches));
        }

        // Path argument for file-taking commands: delegate to the filename
        // completer (it computes its own replacement start).
        let first = head.split_whitespace().next().unwrap_or("");
        if FILE_COMMANDS.contains(&first) {
            return self.files.complete(line, pos, ctx);
        }

        // Otherwise (chat text, non-file commands): no completion.
        Ok((pos, Vec::new()))
    }
}

// The remaining Helper supertraits use their default (no-op) behavior.
impl Hinter for MareuHelper {
    type Hint = String;
}
impl Highlighter for MareuHelper {}
impl Validator for MareuHelper {}
impl Helper for MareuHelper {}

/// Build a configured rustyline editor with completion enabled.
pub fn editor() -> rustyline::Result<Editor<MareuHelper, FileHistory>> {
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .build();
    let mut rl: Editor<MareuHelper, FileHistory> = Editor::with_config(config)?;
    rl.set_helper(Some(MareuHelper::new()));
    Ok(rl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyline::history::FileHistory;

    fn complete(line: &str) -> (usize, Vec<String>) {
        let h = MareuHelper::new();
        let hist = FileHistory::new();
        let ctx = Context::new(&hist);
        let (start, pairs) = h.complete(line, line.len(), &ctx).unwrap();
        (start, pairs.into_iter().map(|p| p.replacement).collect())
    }

    #[test]
    fn completes_partial_slash_command() {
        let (start, cands) = complete("/an");
        assert_eq!(start, 0);
        assert_eq!(cands, vec!["/analyze".to_string()]);
    }

    #[test]
    fn bare_slash_lists_all_commands() {
        let (_, cands) = complete("/");
        assert!(cands.contains(&"/recon".to_string()));
        assert!(cands.contains(&"/exit".to_string()));
        assert_eq!(cands.len(), COMMANDS.len());
    }

    #[test]
    fn chat_text_yields_no_completion() {
        let (_, cands) = complete("how does this work");
        assert!(cands.is_empty());
    }

    #[test]
    fn non_file_command_arg_yields_no_completion() {
        // /scaffold's args aren't file paths, so no filename completion kicks in.
        let (_, cands) = complete("/scaffold poc bo");
        assert!(cands.is_empty());
    }
}
