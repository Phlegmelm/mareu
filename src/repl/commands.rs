//! Slash-command reference and parsing for the REPL.

pub const HELP: &str = "\
slash-commands:
  /recon [path]          run static recon on a target (AI if /ai is on)
  /analyze <file> [line] analyze a file (line or lo:hi optional)
  /scaffold <type> ...   generate a scaffold (e.g. /scaffold poc bof \"desc\")
  /load <file>           inject a file into the active context
  /drop <file>           remove a file from the context
  /context               show loaded context and token estimate
  /note <text>           append a note to the session
  /clear                 clear the conversation buffer (keep context+session)
  /prompt                print the assembled system prompt
  /model <id>            switch model for this session
  /provider <name>       switch provider for this session
  /ai                    toggle AI on/off for this session
  /save                  flush state to the session store
  /export                export the session to markdown (stdout)
  /help                  this reference
  /exit                  quit (Ctrl-D also works)
";

/// Split a slash-command line into (command, rest).
pub fn split(line: &str) -> (&str, &str) {
    let line = line.trim();
    match line.split_once(char::is_whitespace) {
        Some((cmd, rest)) => (cmd, rest.trim()),
        None => (line, ""),
    }
}

/// A tiny shell-style tokenizer that respects double quotes (for /scaffold).
pub fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
