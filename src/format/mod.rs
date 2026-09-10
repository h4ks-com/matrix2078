//! IRC в‡„ Matrix text formatting, ported from matrix2051 (AGPL-3.0),
//! `lib/format/{common,irc2matrix,matrix2irc}.ex` by Valentin Lorentz.
//!
//! * Matrix `org.matrix.custom.html` в†’ mIRC control codes (incl. the
//!   extended 16вЂ“98 color range and `\x04RRGGBB` hex colors).
//! * mIRC control codes в†’ Matrix plain body (with `*`, `/`, `_`, `~`, `` ` ``
//!   markers) + `formatted_body` HTML (bold/italic/underline/strike/mono,
//!   `data-mx-color`/`data-mx-bg-color` fonts, linkified URLs and mxids).

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// mini HTML parser (whitelist subset of org.matrix.custom.html)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Node {
    Element { name: String, attrs: Vec<(String, String)>, children: Vec<Node> },
    Text(String),
    Comment,
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let end = rest.find(';').filter(|&e| e <= 12);
        let Some(end) = end else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let repl = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()))
                .and_then(char::from_u32),
        };
        match repl {
            Some(c) => out.push(c),
            None => out.push_str(&rest[..=end]),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Percent-decode a path segment (for matrix.to URLs).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 < bytes.len() + 1 {
            let hex = bytes.get(i + 1..i + 3).and_then(|h| {
                std::str::from_utf8(h).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
            });
            match hex {
                Some(b) => {
                    out.push(b);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_attrs(s: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        // name
        let name_end = rest.find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_owned();
        rest = rest[name_end..].trim_start();
        let value = if let Some(r) = rest.strip_prefix('=') {
            let r = r.trim_start();
            if let Some(r2) = r.strip_prefix('"') {
                let end = r2.find('"').unwrap_or(r2.len());
                rest = r2.get(end + 1..).unwrap_or("").trim_start();
                r2[..end].to_owned()
            } else {
                let end = r.find(char::is_whitespace).unwrap_or(r.len());
                rest = r[end..].trim_start();
                r[..end].to_owned()
            }
        } else {
            String::new()
        };
        if !name.is_empty() {
            attrs.push((name.to_ascii_lowercase(), decode_entities(&value)));
        }
    }
    attrs
}

/// Parse a whitelist subset of HTML into a tree. Unknown tags are kept as
/// transparent elements (their children still render), like matrix2051's
/// default `transform` clause.
fn parse_html(s: &str) -> Vec<Node> {
    let mut stack: Vec<(String, Vec<(String, String)>, Vec<Node>)> = Vec::new();
    let mut top: Vec<Node> = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut text = String::new();
    let push_text = |text: &mut String,
                         top: &mut Vec<Node>,
                         stack: &mut Vec<(String, Vec<(String, String)>, Vec<Node>)>| {
        if !text.is_empty() {
            let node = Node::Text(decode_entities(&std::mem::take(text)));
            match stack.last_mut() {
                Some((_, _, children)) => children.push(node),
                None => top.push(node),
            }
        }
    };
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if s[i..].starts_with("<!--") {
                push_text(&mut text, &mut top, &mut stack);
                match s[i..].find("-->") {
                    Some(end) => {
                        match stack.last_mut() {
                            Some((_, _, children)) => children.push(Node::Comment),
                            None => top.push(Node::Comment),
                        }
                        i += end + 3;
                    }
                    None => {
                        i = bytes.len();
                    }
                }
                continue;
            }
            let Some(tag_end_rel) = s[i..].find('>') else { break };
            let inner = &s[i + 1..i + tag_end_rel];
            let closing = inner.starts_with('/');
            let selfclosing = inner.ends_with('/');
            let inner = inner.trim_start_matches('/').trim_end_matches('/').trim();
            push_text(&mut text, &mut top, &mut stack);
            let name_end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
            let name = inner[..name_end].to_ascii_lowercase();
            let attrs = if inner.len() > name_end { parse_attrs(&inner[name_end..]) } else { Vec::new() };
            if closing {
                // pop until the matching open tag (tolerating bad nesting)
                if let Some(pos) = stack.iter().rposition(|(n, _, _)| *n == name) {
                    while stack.len() > pos + 1 {
                        let (n, a, children) = stack.pop().expect("non-empty");
                        let done = Node::Element { name: n, attrs: a, children };
                        match stack.last_mut() {
                            Some((_, _, c)) => c.push(done),
                            None => top.push(done),
                        }
                    }
                    let (n, a, children) = stack.pop().expect("non-empty");
                    let done = Node::Element { name: n, attrs: a, children };
                    match stack.last_mut() {
                        Some((_, _, c)) => c.push(done),
                        None => top.push(done),
                    }
                }
            } else if !selfclosing {
                stack.push((name, attrs, Vec::new()));
            } else {
                let node = Node::Element { name, attrs, children: Vec::new() };
                match stack.last_mut() {
                    Some((_, _, children)) => children.push(node),
                    None => top.push(node),
                }
            }
            i += tag_end_rel + 1;
        } else {
            // collect until '<'
            let end = s[i..].find('<').map(|e| i + e).unwrap_or(bytes.len());
            text.push_str(&s[i..end]);
            i = end;
        }
    }
    push_text(&mut text, &mut top, &mut stack);
    while let Some((n, a, children)) = stack.pop() {
        let node = Node::Element { name: n, attrs: a, children };
        match stack.last_mut() {
            Some((_, _, c)) => c.push(node),
            None => top.push(node),
        }
    }
    top
}

// ---------------------------------------------------------------------------
// Matrix HTML в†’ IRC
// ---------------------------------------------------------------------------

fn irc_char_for_tag(tag: &str) -> &'static str {
    match tag {
        "strong" | "b" => "\u{2}",
        "pre" | "code" => "\u{11}",
        "em" | "i" => "\u{1d}",
        "del" | "strike" | "s" => "\u{1e}",
        "u" => "\u{1f}",
        _ => "",
    }
}

#[derive(Clone, Default)]
struct M2IState {
    preserve_whitespace: bool,
    /// (fg, bg) as RRGGBB strings without '#'
    color: (Option<String>, Option<String>),
}

fn irc_color_code(fg: &Option<String>, bg: &Option<String>) -> String {
    match (fg, bg) {
        (None, None) => "\u{3}99,99".to_owned(), // reset
        (fg, None) => format!("\u{4}{}", fg.as_deref().unwrap_or_default()),
        // set both fg and bg, then reset fg
        (None, bg) => format!("\u{4}000000,{}\u{3}99", bg.as_deref().unwrap_or_default()),
        (fg, bg) => format!("\u{4}{},{}", fg.as_deref().unwrap_or_default(), bg.as_deref().unwrap_or_default()),
    }
}

/// Trim a leading `#` off an HTML color, keep only 6 hex digits.
fn norm_color(c: &str) -> Option<String> {
    let c = c.trim_start_matches('#');
    if c.len() == 6 && c.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(c.to_ascii_uppercase())
    } else {
        None
    }
}

fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn transform_m2i(nodes: &[Node], state: &M2IState) -> String {
    let mut out = String::new();
    for node in &collapse_paragraphs(nodes) {
        match node {
            Node::Comment => {}
            Node::Text(t) => {
                if state.preserve_whitespace {
                    out.push_str(t);
                } else {
                    // collapse newline runs into a single space
                    static RE: OnceLock<regex::Regex> = OnceLock::new();
                    let re = RE.get_or_init(|| {
                        regex::Regex::new(r"([\n\r]+ ?[\n\r]*| [\n\r]+)").expect("newline regex")
                    });
                    out.push_str(&re.replace_all(t, " "));
                }
            }
            Node::Element { name, attrs, children } => match name.as_str() {
                "mx-reply" => {}
                "a" => {
                    let link = attr(attrs, "href");
                    match link {
                        Some(link) => {
                            if let Some(id) = matrix_to_target(link) {
                                out.push_str(&id);
                            } else {
                                let text = transform_m2i(children, state);
                                if text == link {
                                    out.push_str(link);
                                } else {
                                    out.push_str(&format!("{text} <{link}>"));
                                }
                            }
                        }
                        None => out.push_str(&transform_m2i(children, state)),
                    }
                }
                "br" => out.push('\n'),
                "ol" | "ul" => {
                    out.push('\n');
                    out.push_str(&transform_m2i(children, state));
                }
                "li" => {
                    out.push_str("* ");
                    out.push_str(&transform_m2i(children, state));
                    out.push('\n');
                }
                "font" | "span" => {
                    let fg = attr(attrs, "data-mx-color").and_then(norm_color);
                    let bg = attr(attrs, "data-mx-bg-color").and_then(norm_color);
                    if fg.is_none() && bg.is_none() {
                        out.push_str(&transform_m2i(children, state));
                    } else {
                        let restored = irc_color_code(&state.color.0, &state.color.1);
                        let mut inner = state.clone();
                        inner.color = (fg.clone(), bg.clone());
                        out.push_str(&irc_color_code(&fg, &bg));
                        out.push_str(&transform_m2i(children, &inner));
                        out.push_str(&restored);
                    }
                }
                _ => {
                    // simple formatting tags
                    let mut inner = state.clone();
                    if name == "pre" {
                        inner.preserve_whitespace = true;
                    }
                    let ch = irc_char_for_tag(name);
                    out.push_str(ch);
                    out.push_str(&transform_m2i(children, &inner));
                    out.push_str(ch);
                }
            },
        }
    }
    out
}

/// Rewrite runs of `<p>` siblings into spans separated by explicit `<br>`
/// nodes (port of matrix2051's `paragraph_to_newline`).
fn collapse_paragraphs(nodes: &[Node]) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::new();
    let mut idx = 0;
    while idx < nodes.len() {
        let node = &nodes[idx];
        if let Node::Element { name, children: pchildren, .. } = node {
            if name == "p" {
                let span = |c: &Vec<Node>| Node::Element {
                    name: "span".into(),
                    attrs: vec![],
                    children: c.clone(),
                };
                out.push(span(pchildren));
                idx += 1;
                while let Some(Node::Element { name, children: next_children, .. }) = nodes.get(idx) {
                    if name != "p" {
                        break;
                    }
                    out.push(Node::Element { name: "br".into(), attrs: vec![], children: vec![] });
                    out.push(span(next_children));
                    idx += 1;
                }
                continue;
            }
        }
        out.push(node.clone());
        idx += 1;
    }
    out
}

/// If the link is a matrix.to permalink to a user/room, return the decoded id.
fn matrix_to_target(link: &str) -> Option<String> {
    let rest = link.strip_prefix("https://matrix.to/#/")?;
    let seg = rest.split(['/', '?']).next()?;
    if seg.is_empty() {
        return None;
    }
    let decoded = percent_decode(seg);
    match decoded.chars().next()? {
        '@' => Some(decoded),
        '!' | '#' => Some(decoded),
        _ => None,
    }
}

/// Convert `org.matrix.custom.html` to IRC-formatted text.
/// Returns the empty string when nothing renders; callers fall back to the
/// plain body (matrix2051: `M51.Format.matrix2irc(html) || body`).
pub fn matrix_to_irc(html: &str) -> String {
    let tree = parse_html(html);
    transform_m2i(&tree, &M2IState::default()).trim().to_owned()
}

/// Strip rich-reply fallback lines (`> ...`) from a plain body, per the
/// Matrix spec's fallback-stripping algorithm.
pub fn strip_reply_fallback(body: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for line in body.split('\n') {
        if line.starts_with("> ") {
            continue;
        }
        out.push(line);
    }
    out.join("\n").trim_start_matches('\n').to_owned()
}

// ---------------------------------------------------------------------------
// IRC в†’ Matrix
// ---------------------------------------------------------------------------

/// IRC color numbers 00вЂ“98 в†’ hex, index 99 (reset) maps to `None`.
/// Port of matrix2051's `@color2hex` table (modern.ircdocs.horse colors 16вЂ“98).
const COLOR2HEX: [&str; 99] = [
    // 00вЂ“15
    "#FFFFFF", "#000000", "#0000FF", "#009300", "#FF0000", "#7F0000", "#9C009C", "#FC7F00",
    "#FFFF00", "#00FC00", "#009393", "#00FFFF", "#0080FF", "#FF00FF", "#7F7F7F", "#D2D2D2",
    // 16
    "#470000", "#472100", "#474700", "#324700", "#004700", "#00472C", "#004747", "#002747",
    "#000047", "#2E0047", "#470047", "#47002A",
    // 28
    "#740000", "#743A00", "#747400", "#517400", "#007400", "#007449", "#007474", "#004074",
    "#000074", "#4B0074", "#740074", "#740045",
    // 40
    "#B50000", "#B56300", "#B5B500", "#7DB500", "#00B500", "#00B571", "#00B5B5", "#0063B5",
    "#0000B5", "#7500B5", "#B500B5", "#B5006B",
    // 52
    "#FF0000", "#FF8C00", "#FFFF00", "#B2FF00", "#00FF00", "#00FFA0", "#00FFFF", "#008CFF",
    "#0000FF", "#A500FF", "#FF00FF", "#FF0098",
    // 64
    "#FF5959", "#FFB459", "#FFFF71", "#CFFF60", "#6FFF6F", "#65FFC9", "#6DFFFF", "#59B4FF",
    "#5959FF", "#C459FF", "#FF66FF", "#FF59BC",
    // 76
    "#FF9C9C", "#FFD39C", "#FFFF9C", "#E2FF9C", "#9CFF9C", "#9CFFDB", "#9CFFFF", "#9CD3FF",
    "#9C9CFF", "#DC9CFF", "#FF9CFF", "#FF94D3",
    // 88
    "#000000", "#131313", "#282828", "#363636", "#4D4D4D", "#656565", "#818181", "#9F9F9F",
    "#BCBCBC", "#E2E2E2", "#FFFFFF",
];

fn color2hex(n: usize) -> Option<&'static str> {
    match n {
        0..=98 => Some(COLOR2HEX[n]),
        _ => None, // 99 = reset
    }
}

#[derive(Clone, PartialEq)]
struct I2MState {
    bold: bool,
    italic: bool,
    underlined: bool,
    strike: bool,
    monospace: bool,
    /// (fg, bg) hex with '#'
    color: (Option<String>, Option<String>),
}

impl Default for I2MState {
    fn default() -> Self {
        Self {
            bold: false,
            italic: false,
            underlined: false,
            strike: false,
            monospace: false,
            color: (None, None),
        }
    }
}

/// A token: either literal text or one IRC control code.
#[derive(Debug, PartialEq)]
enum Token {
    Text(String),
    Ctrl(String),
}

fn tokenize_irc(text: &str) -> Vec<Token> {
    let mut tokens: Vec<Token> = Vec::new();
    let push_text = |tokens: &mut Vec<Token>, s: String| {
        if s.is_empty() {
            return;
        }
        match tokens.last_mut() {
            Some(Token::Text(t)) => t.push_str(&s),
            _ => tokens.push(Token::Text(s)),
        }
    };
    let mut cur = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{2}' | '\u{11}' | '\u{1d}' | '\u{1e}' | '\u{1f}' | '\u{f}' => {
                push_text(&mut tokens, std::mem::take(&mut cur));
                tokens.push(Token::Ctrl(c.to_string()));
            }
            '\u{3}' => {
                // decimal color: awful format, normalize to CC or CC,CC
                let mut spec = String::new();
                let mut count = 0;
                while count < 2 {
                    match chars.peek() {
                        Some(d) if d.is_ascii_digit() => {
                            spec.push(*d);
                            chars.next();
                            count += 1;
                        }
                        _ => break,
                    }
                }
                if count == 0 {
                    // lone \x03 resets color
                } else if chars.peek() == Some(&',') {
                    if spec.len() == 1 {
                        spec = format!("0{spec}");
                    }
                    spec.push(',');
                    chars.next();
                    let mut bg = String::new();
                    while bg.len() < 2 {
                        match chars.peek() {
                            Some(d) if d.is_ascii_digit() => {
                                bg.push(*d);
                                chars.next();
                            }
                            _ => break,
                        }
                    }
                    if bg.is_empty() {
                        // trailing comma: keep it, spec is fg-only
                    } else {
                        if bg.len() == 1 {
                            bg = format!("0{bg}");
                        }
                        spec.push_str(&bg);
                    }
                } else if spec.len() == 1 {
                    spec = format!("0{spec}");
                }
                push_text(&mut tokens, std::mem::take(&mut cur));
                tokens.push(Token::Ctrl(format!("\u{3}{spec}")));
            }
            '\u{4}' => {
                // hex color: RRGGBB[,RRGGBB]
                let take_hex = |chars: &mut std::iter::Peekable<std::str::Chars>, n: usize| -> String {
                    let mut s = String::new();
                    while s.chars().count() < n {
                        match chars.peek() {
                            Some(h) if h.is_ascii_hexdigit() => {
                                s.push(*h);
                                chars.next();
                            }
                            _ => break,
                        }
                    }
                    s
                };
                let fg = take_hex(&mut chars, 6);
                let mut spec = String::new();
                if fg.len() == 6 {
                    spec.push_str(&fg);
                    if chars.peek() == Some(&',') {
                        chars.next();
                        let bg = take_hex(&mut chars, 6);
                        if bg.len() == 6 {
                            spec.push(',');
                            spec.push_str(&bg);
                        }
                    }
                }
                push_text(&mut tokens, std::mem::take(&mut cur));
                tokens.push(Token::Ctrl(format!("\u{4}{spec}")));
            }
            _ => cur.push(c),
        }
    }
    push_text(&mut tokens, cur);
    tokens
}

/// Apply a control token to the state. Returns the new state.
fn apply_ctrl(state: &I2MState, ctrl: &str) -> I2MState {
    let mut s = state.clone();
    let bytes = ctrl.as_bytes();
    match bytes.first() {
        Some(0x0f) => I2MState::default(),
        Some(0x02) => {
            s.bold = !s.bold;
            s
        }
        Some(0x11) => {
            s.monospace = !s.monospace;
            s
        }
        Some(0x1d) => {
            s.italic = !s.italic;
            s
        }
        Some(0x1e) => {
            s.strike = !s.strike;
            s
        }
        Some(0x1f) => {
            s.underlined = !s.underlined;
            s
        }
        Some(0x03) => {
            let spec = &ctrl[1..];
            let (fgs, bgs) = spec.split_once(',').unwrap_or((spec, ""));
            let fg = fgs
                .parse::<usize>()
                .ok()
                .and_then(color2hex)
                .map(|h| h.to_owned());
            let bg = if bgs.is_empty() {
                None
            } else {
                bgs.parse::<usize>().ok().and_then(color2hex).map(|h| h.to_owned())
            };
            s.color = (fg, bg);
            s
        }
        Some(0x04) => {
            let spec = &ctrl[1..];
            let (fgs, bgs) = spec.split_once(',').unwrap_or((spec, ""));
            let fg = if fgs.len() == 6 { Some(format!("#{fgs}")) } else { None };
            let bg = if bgs.len() == 6 { Some(format!("#{bgs}")) } else { None };
            s.color = (fg, bg);
            s
        }
        _ => s,
    }
}

fn toggle_markers(prev: &I2MState, new: &I2MState) -> String {
    let mut out = String::new();
    if prev.bold != new.bold {
        out.push('*');
    }
    if prev.monospace != new.monospace {
        out.push('`');
    }
    if prev.italic != new.italic {
        out.push('/');
    }
    if prev.underlined != new.underlined {
        out.push('_');
    }
    if prev.strike != new.strike {
        out.push('~');
    }
    out
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn wrap_html(state: &I2MState, html: String) -> String {
    let html = if state.bold { format!("<b>{html}</b>") } else { html };
    let html = if state.monospace { format!("<code>{html}</code>") } else { html };
    let html = if state.italic { format!("<i>{html}</i>") } else { html };
    let html = if state.underlined { format!("<u>{html}</u>") } else { html };
    let html = if state.strike { format!("<strike>{html}</strike>") } else { html };
    match &state.color {
        (None, None) => html,
        (fg, bg) => {
            let mut attrs = String::new();
            if let Some(fg) = fg {
                attrs.push_str(&format!(" data-mx-color=\"{fg}\""));
            }
            if let Some(bg) = bg {
                attrs.push_str(&format!(" data-mx-bg-color=\"{bg}\""));
            }
            format!("<font{attrs}>{html}</font>")
        }
    }
}

fn linkified_html(text: &str, nicklist: &[String]) -> String {
    // strip remaining control chars, split on newlines into <br/>
    static URL_RE: OnceLock<regex::Regex> = OnceLock::new();
    static MXID_RE: OnceLock<regex::Regex> = OnceLock::new();
    let url_re = URL_RE.get_or_init(|| {
        regex::Regex::new(r"(mailto:|[a-z][a-z0-9]+://)\S+").expect("url regex")
    });
    let mxid_re = MXID_RE.get_or_init(|| {
        regex::Regex::new(r"@?[a-zA-Z0-9._=/-]+:[A-Za-z0-9.\-]+").expect("mxid regex")
    });

    let mut parts: Vec<String> = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            parts.push("<br/>".into());
        }
        let mut html = String::new();
        let mut last = 0;
        for m in url_re.find_iter(line) {
            html.push_str(&escape_html(&line[last..m.start()]));
            let url = m.as_str();
            let trimmed = url.trim_end_matches(['>', ')', '.', ',']);
            let suffix = &url[trimmed.len()..];
            html.push_str(&format!("<a href=\"{}\">{}</a>{suffix}", escape_html(trimmed), escape_html(trimmed)));
            last = m.end();
        }
        html.push_str(&escape_html(&line[last..]));
        // linkify full mxids that are room members
        let mut html2 = String::new();
        let mut last = 0;
        for m in mxid_re.find_iter(&html) {
            html2.push_str(&html[last..m.start()]);
            let mut userid = m.as_str().to_owned();
            if !userid.starts_with('@') {
                userid.insert(0, '@');
            }
            let (local, domain) = userid.split_once(':').unwrap_or((&userid, ""));
            let local = local.trim_start_matches('@');
            if nicklist.iter().any(|n| n == &userid) {
                html2.push_str(&format!(
                    "<a href=\"https://matrix.to/#/@{local}%3A{domain}\">{}</a>",
                    escape_html(local)
                ));
            } else {
                html2.push_str(m.as_str());
            }
            last = m.end();
        }
        html2.push_str(&html[last..]);
        parts.push(html2);
    }
    parts.join("")
}

/// Result of the IRC в†’ Matrix conversion.
pub struct IrcToMatrix {
    pub plain: String,
    /// `None` when the message had no formatting at all (send plain only).
    pub html: Option<String>,
}

/// Convert IRC-formatted text into a Matrix plain body + HTML body.
/// `nicklist` is the list of full Matrix user ids (`@user:server`) eligible
/// for mention links.
pub fn irc_to_matrix(text: &str, nicklist: &[String]) -> IrcToMatrix {
    // trailing \x0f makes sure toggle markers get emitted before the end
    let full = format!("{text}\u{f}");
    let tokens = tokenize_irc(&full);
    let mut state = I2MState::default();
    let mut plain = String::new();
    let mut html = String::new();
    let mut has_formatting = false;
    for tok in &tokens {
        let new_state = match tok {
            Token::Ctrl(c) => {
                let ns = apply_ctrl(&state, c);
                let markers = toggle_markers(&state, &ns);
                if !markers.is_empty() {
                    plain.push_str(&markers);
                    has_formatting = true;
                }
                if state != ns {
                    has_formatting = true;
                }
                ns
            }
            Token::Text(t) => {
                plain.push_str(t);
                if t.contains('\n') {
                    has_formatting = true; // <br/> needed
                }
                let frag = wrap_html(&state, linkified_html(t, nicklist));
                if !frag.is_empty() {
                    html.push_str(&frag);
                }
                state.clone()
            }
        };
        state = new_state;
    }
    let _ = has_formatting;
    // html equals escaped plain text when nothing was formatted: drop it
    let plain = plain.trim_end_matches('\u{f}').to_owned();
    let trivial = html == escape_html(&plain);
    IrcToMatrix { plain, html: if trivial { None } else { Some(html) } }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m2i_bold() {
        assert_eq!(matrix_to_irc("<b>foo</b>"), "\u{2}foo\u{2}");
    }

    #[test]
    fn m2i_link() {
        assert_eq!(
            matrix_to_irc("<a href=\"https://example.org\">foo</a>"),
            "foo <https://example.org>"
        );
    }

    #[test]
    fn m2i_link_same_text() {
        assert_eq!(
            matrix_to_irc("<a href=\"https://example.org\">https://example.org</a>"),
            "https://example.org"
        );
    }

    #[test]
    fn m2i_matrix_to_user() {
        // matrix2051 replaces the link text with the decoded user id
        assert_eq!(
            matrix_to_irc("<a href=\"https://matrix.to/#/@john%3Aexample.org\">Johnny</a>"),
            "@john:example.org"
        );
    }

    #[test]
    fn m2i_br() {
        assert_eq!(matrix_to_irc("foo<br/>bar"), "foo\nbar");
    }

    #[test]
    fn m2i_font_color() {
        assert_eq!(
            matrix_to_irc("foo <font data-mx-color=\"#FF0000\">bar</font> baz"),
            "foo \u{4}FF0000bar\u{3}99,99 baz"
        );
    }

    #[test]
    fn m2i_font_color_and_bg() {
        assert_eq!(
            matrix_to_irc("<font data-mx-color=\"#ff0000\" data-mx-bg-color=\"#00ff00\">x</font>"),
            "\u{4}FF0000,00FF00x\u{3}99,99"
        );
    }

    #[test]
    fn m2i_nested_color_restore() {
        assert_eq!(
            matrix_to_irc(
                "<font data-mx-color=\"#FF0000\">a<font data-mx-color=\"#00FF00\">b</font>c</font>"
            ),
            "\u{4}FF0000a\u{4}00FF00b\u{4}FF0000c\u{3}99,99"
        );
    }

    #[test]
    fn m2i_paragraphs() {
        assert_eq!(matrix_to_irc("<p>one</p><p>two</p>"), "one\ntwo");
    }

    #[test]
    fn m2i_list() {
        assert_eq!(
            matrix_to_irc("<ul><li>a</li><li>b</li></ul>").trim(),
            "\n* a\n* b\n".trim()
        );
    }

    #[test]
    fn m2i_mx_reply_dropped() {
        assert_eq!(matrix_to_irc("<mx-reply><blockquote>x</blockquote></mx-reply>hello"), "hello");
    }

    #[test]
    fn m2i_all_simple_tags() {
        assert_eq!(matrix_to_irc("<i>it</i>"), "\u{1d}it\u{1d}");
        assert_eq!(matrix_to_irc("<em>it</em>"), "\u{1d}it\u{1d}");
        assert_eq!(matrix_to_irc("<u>u</u>"), "\u{1f}u\u{1f}");
        assert_eq!(matrix_to_irc("<del>d</del>"), "\u{1e}d\u{1e}");
        assert_eq!(matrix_to_irc("<code>c</code>"), "\u{11}c\u{11}");
        assert_eq!(matrix_to_irc("<strong>s</strong>"), "\u{2}s\u{2}");
    }

    #[test]
    fn m2i_entities() {
        assert_eq!(matrix_to_irc("a &amp; b &lt;c&gt;"), "a & b <c>");
    }

    #[test]
    fn m2i_empty() {
        assert_eq!(matrix_to_irc(""), "");
    }

    #[test]
    fn i2m_bold() {
        let r = irc_to_matrix("\u{2}foo\u{2}", &[]);
        assert_eq!(r.plain, "*foo*");
        assert_eq!(r.html.as_deref(), Some("<b>foo</b>"));
    }

    #[test]
    fn i2m_plain_only() {
        let r = irc_to_matrix("hello world", &[]);
        assert_eq!(r.plain, "hello world");
        assert_eq!(r.html, None);
    }

    #[test]
    fn i2m_color() {
        let r = irc_to_matrix("foo \u{3}04bar", &[]);
        assert_eq!(r.plain, "foo bar");
        assert_eq!(
            r.html.as_deref(),
            Some("foo <font data-mx-color=\"#FF0000\">bar</font>")
        );
    }

    #[test]
    fn i2m_ext_color_16() {
        let r = irc_to_matrix("\u{3}16x", &[]);
        assert_eq!(r.html.as_deref(), Some("<font data-mx-color=\"#470000\">x</font>"));
    }

    #[test]
    fn i2m_color_reset() {
        let r = irc_to_matrix("\u{3}04a\u{3}99,99b", &[]);
        assert_eq!(
            r.html.as_deref(),
            Some("<font data-mx-color=\"#FF0000\">a</font>b")
        );
    }

    #[test]
    fn i2m_hex_color() {
        let r = irc_to_matrix("\u{4}FF0000x", &[]);
        assert_eq!(r.html.as_deref(), Some("<font data-mx-color=\"#FF0000\">x</font>"));
    }

    #[test]
    fn i2m_hex_color_bg() {
        let r = irc_to_matrix("\u{4}FF0000,00FF00x", &[]);
        assert_eq!(
            r.html.as_deref(),
            Some("<font data-mx-color=\"#FF0000\" data-mx-bg-color=\"#00FF00\">x</font>")
        );
    }

    #[test]
    fn i2m_one_digit_color() {
        let r = irc_to_matrix("\u{3}4x", &[]);
        assert_eq!(r.html.as_deref(), Some("<font data-mx-color=\"#FF0000\">x</font>"));
    }

    #[test]
    fn i2m_url() {
        let r = irc_to_matrix("foo https://example.org bar", &[]);
        assert_eq!(r.plain, "foo https://example.org bar");
        assert_eq!(
            r.html.as_deref(),
            Some("foo <a href=\"https://example.org\">https://example.org</a> bar")
        );
    }

    #[test]
    fn i2m_newline() {
        let r = irc_to_matrix("foo\nbar", &[]);
        assert_eq!(r.plain, "foo\nbar");
        assert_eq!(r.html.as_deref(), Some("foo<br/>bar"));
    }

    #[test]
    fn i2m_all_toggles() {
        let r = irc_to_matrix("\u{2}b\u{2}\u{1d}i\u{1d}\u{1f}u\u{1f}\u{1e}s\u{1e}\u{11}m\u{11}", &[]);
        assert_eq!(r.plain, "*b*/i/_u_~s~`m`");
        assert_eq!(
            r.html.as_deref(),
            Some("<b>b</b><i>i</i><u>u</u><strike>s</strike><code>m</code>")
        );
    }

    #[test]
    fn i2m_escape() {
        let r = irc_to_matrix("a <b> & c", &[]);
        assert_eq!(r.html, None); // escaped == plain, no formatting
        let r2 = irc_to_matrix("\u{2}a <b> & c\u{2}", &[]);
        assert_eq!(r2.html.as_deref(), Some("<b>a &lt;b&gt; &amp; c</b>"));
    }

    #[test]
    fn i2m_mxid_link() {
        let members = vec!["@john:example.org".to_owned()];
        let r = irc_to_matrix("hi @john:example.org !", &members);
        assert_eq!(
            r.html.as_deref(),
            Some("hi <a href=\"https://matrix.to/#/@john%3Aexample.org\">john</a> !")
        );
    }

    #[test]
    fn strip_fallback() {
        assert_eq!(
            strip_reply_fallback("> <@a:b> original\n\nreply body"),
            "\nreply body".trim_start_matches('\n')
        );
    }
}
