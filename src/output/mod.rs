//! Terminal output: palette, color-aware painting, box-drawing primitives, and
//! the [`Ui`] handle threaded through the command layer.
//!
//! The visual grammar follows RFC §5: a deep-violet foundation with bright
//! yellow accents, box-drawing characters for structure, no emoji in default
//! mode. All color is gated on [`Ui::color`] so `--no-color`, `NO_COLOR`, and
//! non-tty stdout degrade to clean plain text suitable for piping.

pub mod json;
pub mod render;
pub mod stream;

use std::str::FromStr;

/// 24-bit color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

// Palette — RFC §5.1.
pub const PRIMARY: Rgb = Rgb(0xD4, 0xBA, 0xFF); // soft lavender — body text
pub const ACCENT: Rgb = Rgb(0x9B, 0x59, 0xFF); // deep violet — section markers
pub const HIGHLIGHT: Rgb = Rgb(0xFF, 0xE0, 0x33); // bright yellow — high severity / key values
pub const DIM: Rgb = Rgb(0x6B, 0x5C, 0x8A); // muted purple — metadata
pub const SUCCESS: Rgb = Rgb(0xC8, 0xFF, 0x57); // acid yellow-green — clean/confirmed
pub const INFO: Rgb = Rgb(0xBF, 0x9F, 0xFF); // light purple — AI-generated markers
pub const BORDER: Rgb = Rgb(0x3D, 0x2B, 0x5E); // dark violet — box drawing

/// Output serialization format (`--output`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
}

impl FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "text" | "txt" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            other => Err(format!(
                "unknown output format: {other} (text|json|markdown)"
            )),
        }
    }
}

/// Color-aware painter. Cheap to copy; carries only the enabled flag.
#[derive(Clone, Copy, Debug)]
pub struct Painter {
    pub enabled: bool,
}

impl Painter {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Wrap `text` in a truecolor SGR sequence when color is enabled.
    pub fn paint(&self, c: Rgb, text: &str) -> String {
        if self.enabled {
            format!("\x1b[38;2;{};{};{}m{text}\x1b[0m", c.0, c.1, c.2)
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// A single horizontal line of content built from colored segments. Tracks the
/// *visible* width separately from the colored byte length so boxes align
/// regardless of embedded SGR sequences.
#[derive(Default)]
pub struct Cell {
    rendered: String,
    visible: usize,
}

impl Cell {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append uncolored text.
    #[allow(dead_code)] // part of the Cell builder API
    pub fn text(&mut self, s: &str) -> &mut Self {
        self.visible += s.chars().count();
        self.rendered.push_str(s);
        self
    }

    /// Append colored text.
    pub fn paint(&mut self, p: &Painter, c: Rgb, s: &str) -> &mut Self {
        self.visible += s.chars().count();
        self.rendered.push_str(&p.paint(c, s));
        self
    }

    /// Append `n` spaces.
    pub fn pad(&mut self, n: usize) -> &mut Self {
        self.visible += n;
        for _ in 0..n {
            self.rendered.push(' ');
        }
        self
    }

    #[allow(dead_code)] // part of the Cell builder API
    pub fn visible_len(&self) -> usize {
        self.visible
    }

    /// Render padded to `width` visible columns (truncation is the caller's
    /// responsibility — content is pre-wrapped).
    fn render_to(&self, width: usize) -> String {
        let mut s = self.rendered.clone();
        if self.visible < width {
            s.push_str(&" ".repeat(width - self.visible));
        }
        s
    }
}

/// Default inner content width for boxes (visible columns between the borders).
pub const BOX_WIDTH: usize = 70;

/// Draw a titled box around pre-built [`Cell`] rows.
///
/// ```text
/// ┌─ TITLE ──────────────────┐
/// │ ...row content...        │
/// └──────────────────────────┘
/// ```
pub fn boxed(p: &Painter, title: &str, rows: &[Cell], border: Rgb) -> String {
    let w = BOX_WIDTH;
    let mut out = String::new();

    // Top border with embedded title. Total inner span is `w + 2` (the single
    // space of padding on each side of a row), so the title + fill must sum to
    // that for the corners to line up with the bottom border.
    let title_part = format!("─ {title} ");
    let title_vis = title_part.chars().count();
    let fill = (w + 2).saturating_sub(title_vis);
    let top = format!("┌{}{}┐", title_part, "─".repeat(fill));
    out.push_str(&p.paint(border, &top));
    out.push('\n');

    for row in rows {
        let bar = p.paint(border, "│");
        out.push_str(&format!("{bar} {} {bar}\n", row.render_to(w)));
    }

    let bottom = format!("└{}┘", "─".repeat(w + 2));
    out.push_str(&p.paint(border, &bottom));
    out
}

/// Indent every line of `block` by two spaces (the standard left gutter).
pub fn indent(block: &str) -> String {
    block
        .lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wrap `text` to `width` columns on word boundaries.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut cur = String::new();
        for word in paragraph.split_whitespace() {
            if cur.is_empty() {
                cur.push_str(word);
            } else if cur.chars().count() + 1 + word.chars().count() <= width {
                cur.push(' ');
                cur.push_str(word);
            } else {
                lines.push(std::mem::take(&mut cur));
                cur.push_str(word);
            }
        }
        if !cur.is_empty() {
            lines.push(cur);
        }
    }
    lines
}

/// The output handle carried through command execution.
#[derive(Clone, Copy, Debug)]
pub struct Ui {
    pub color: bool,
    /// 0=quiet .. 4=debug (RFC §5.3).
    pub verbosity: u8,
    pub format: OutputFormat,
}

impl Ui {
    pub fn painter(&self) -> Painter {
        Painter::new(self.color)
    }

    /// A `▸ SECTION` header line (uppercased), per the typography conventions.
    pub fn section(&self, title: &str, subject: &str) -> String {
        let p = self.painter();
        format!(
            "{} {}  {}",
            p.paint(ACCENT, "▸"),
            p.bold(&p.paint(ACCENT, &title.to_uppercase())),
            p.paint(DIM, subject)
        )
    }

    /// Write a status line to stderr (kept off stdout so pipes stay clean).
    pub fn status(&self, msg: &str) {
        if self.verbosity == 0 {
            return;
        }
        eprintln!("{msg}");
    }
}
