//! Claude's answers as HTML: the Markdown it writes (code blocks, lists,
//! tables, headings, quotes; inline code, bold, links). Everything is
//! escaped first; links only to http(s), opened apart from the hub's page.

use crate::map::esc;

pub fn to_html(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim_start();
        if let Some(fence) = fence_of(t) {
            let lang = t[fence.len()..].trim();
            let mut code = String::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with(fence) {
                code.push_str(lines[i]);
                code.push('\n');
                i += 1;
            }
            i += 1;
            out.push_str(&format!(
                "<pre class=\"code\"{}><code>{}</code></pre>",
                if lang.is_empty() {
                    String::new()
                } else {
                    format!(" data-lang=\"{}\"", esc(lang))
                },
                crate::highlight::highlight(lang, &code)
            ));
            continue;
        }
        if t.is_empty() {
            i += 1;
            continue;
        }
        if let Some((level, text)) = heading(t) {
            out.push_str(&format!("<h{level}>{}</h{level}>", inline(text)));
            i += 1;
            continue;
        }
        if t == "---" || t == "***" || t == "___" {
            out.push_str("<hr>");
            i += 1;
            continue;
        }
        if t.starts_with('|') {
            let start = i;
            while i < lines.len() && lines[i].trim_start().starts_with('|') {
                i += 1;
            }
            out.push_str(&table(&lines[start..i]));
            continue;
        }
        if t.starts_with('>') {
            let mut inner = String::new();
            while i < lines.len() && lines[i].trim_start().starts_with('>') {
                let q = lines[i].trim_start()[1..]
                    .strip_prefix(' ')
                    .unwrap_or(&lines[i].trim_start()[1..]);
                inner.push_str(q);
                inner.push('\n');
                i += 1;
            }
            out.push_str(&format!("<blockquote>{}</blockquote>", to_html(&inner)));
            continue;
        }
        if let Some((numbered, _)) = list_item(t) {
            let start = i;
            i += 1;
            // Items, and lines that continue one (indented).
            while i < lines.len() {
                let l = lines[i];
                let lt = l.trim_start();
                if lt.is_empty() {
                    // A blank line ends the list unless an item follows.
                    if i + 1 < lines.len()
                        && list_item(lines[i + 1].trim_start()).is_some_and(|(n, _)| n == numbered)
                    {
                        i += 1;
                        continue;
                    }
                    break;
                }
                if list_item(lt).is_some() || l.starts_with("  ") || l.starts_with('\t') {
                    i += 1;
                    continue;
                }
                break;
            }
            out.push_str(&list(&lines[start..i]));
            continue;
        }
        // A paragraph: lines up to a blank one or another kind of block.
        let mut para = Vec::new();
        while i < lines.len() {
            let lt = lines[i].trim_start();
            if lt.is_empty()
                || fence_of(lt).is_some()
                || heading(lt).is_some()
                || lt.starts_with('|')
                || lt.starts_with('>')
                || (list_item(lt).is_some() && !para.is_empty())
            {
                break;
            }
            para.push(inline(lt));
            i += 1;
        }
        out.push_str(&format!("<p>{}</p>", para.join("<br>")));
    }
    out
}

fn fence_of(t: &str) -> Option<&'static str> {
    if t.starts_with("```") {
        Some("```")
    } else if t.starts_with("~~~") {
        Some("~~~")
    } else {
        None
    }
}

fn heading(t: &str) -> Option<(usize, &str)> {
    let level = t.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&level) {
        let rest = &t[level..];
        if let Some(text) = rest.strip_prefix(' ') {
            return Some((level.min(4) + 1, text.trim().trim_end_matches('#').trim()));
        }
    }
    None
}

/// A list item: whether it is numbered, and its text.
fn list_item(t: &str) -> Option<(bool, &str)> {
    for b in ["- ", "* ", "+ "] {
        if let Some(rest) = t.strip_prefix(b) {
            return Some((false, rest));
        }
    }
    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
    if (1..=3).contains(&digits) {
        let rest = &t[digits..];
        if let Some(r) = rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")) {
            return Some((true, r));
        }
    }
    None
}

fn list(lines: &[&str]) -> String {
    let base = lines[0].len() - lines[0].trim_start().len();
    let numbered = list_item(lines[0].trim_start()).is_some_and(|(n, _)| n);
    let mut items: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        let indent = l.len() - l.trim_start().len();
        let lt = l.trim_start();
        match list_item(lt) {
            Some((_, text)) if indent <= base + 1 => {
                items.push(inline(text));
                i += 1;
            }
            _ if lt.is_empty() => i += 1,
            _ => {
                // Deeper: a list inside the last item, or its next line.
                let start = i;
                while i < lines.len() {
                    let l = lines[i];
                    let ind = l.len() - l.trim_start().len();
                    if !l.trim().is_empty()
                        && ind <= base + 1
                        && list_item(l.trim_start()).is_some()
                    {
                        break;
                    }
                    i += 1;
                }
                let inner: Vec<&str> = lines[start..i].to_vec();
                let first = inner
                    .iter()
                    .find(|l| !l.trim().is_empty())
                    .map(|l| l.trim_start());
                let html = if first.and_then(list_item).is_some() {
                    list(
                        &inner
                            .into_iter()
                            .filter(|l| !l.trim().is_empty())
                            .collect::<Vec<_>>(),
                    )
                } else {
                    inner
                        .iter()
                        .map(|l| inline(l.trim()))
                        .collect::<Vec<_>>()
                        .join("<br>")
                };
                match items.last_mut() {
                    Some(last) => {
                        if !html.starts_with('<') {
                            last.push_str("<br>");
                        }
                        last.push_str(&html);
                    }
                    None => items.push(html),
                }
            }
        }
    }
    let tag = if numbered { "ol" } else { "ul" };
    format!(
        "<{tag}>{}</{tag}>",
        items
            .iter()
            .map(|x| format!("<li>{x}</li>"))
            .collect::<String>()
    )
}

fn table(lines: &[&str]) -> String {
    let cells = |l: &str| -> Vec<String> {
        let t = l.trim();
        let t = t.strip_prefix('|').unwrap_or(t);
        let t = t.strip_suffix('|').unwrap_or(t);
        t.split('|').map(|c| c.trim().to_string()).collect()
    };
    let is_rule =
        |l: &str| l.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ' | '\t')) && l.contains('-');
    let mut out = String::from("<div class=\"table\"><table>");
    let mut head = lines.len() > 1 && is_rule(lines[1]);
    for l in lines {
        if is_rule(l) {
            continue;
        }
        let tag = if head { "th" } else { "td" };
        out.push_str("<tr>");
        for c in cells(l) {
            out.push_str(&format!("<{tag}>{}</{tag}>", inline(&c)));
        }
        out.push_str("</tr>");
        head = false;
    }
    out.push_str("</table></div>");
    out
}

/// Inline code, bold, and links, in escaped text.
pub fn inline(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(a) = rest.find('`') {
        let after = &rest[a + 1..];
        match after.find('`') {
            Some(b) => {
                out.push_str(&emphasis(&rest[..a]));
                out.push_str(&format!("<code>{}</code>", esc(&after[..b])));
                rest = &after[b + 1..];
            }
            None => break,
        }
    }
    out.push_str(&emphasis(rest));
    out
}

fn emphasis(s: &str) -> String {
    let e = links(s);
    // **bold**
    let mut out = String::new();
    let mut rest = e.as_str();
    while let Some(a) = rest.find("**") {
        let after = &rest[a + 2..];
        match after.find("**") {
            Some(b) if b > 0 => {
                out.push_str(&rest[..a]);
                out.push_str(&format!("<strong>{}</strong>", &after[..b]));
                rest = &after[b + 2..];
            }
            _ => break,
        }
    }
    out.push_str(rest);
    out
}

/// [text](http...) as a link; the rest escaped.
fn links(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(a) = rest.find('[') {
        let Some(close) = rest[a..].find("](").map(|i| a + i) else {
            break;
        };
        let Some(end) = rest[close + 2..].find(')').map(|i| close + 2 + i) else {
            break;
        };
        let text = &rest[a + 1..close];
        let url = &rest[close + 2..end];
        out.push_str(&esc(&rest[..a]));
        if (url.starts_with("https://") || url.starts_with("http://"))
            && !url.contains(char::is_whitespace)
        {
            out.push_str(&format!(
                "<a href=\"{}\" rel=\"noopener noreferrer\" target=\"_blank\">{}</a>",
                esc(url),
                esc(text)
            ));
        } else {
            out.push_str(&esc(&rest[a..=end]));
        }
        rest = &rest[end + 1..];
    }
    out.push_str(&esc(rest));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks() {
        let md = "# Title\n\nSome **bold** and `a < b`.\nNext line.\n\n```rust\nfn x() {}\n```\n\n- one\n- two\n  - deep\n\n1. first\n2. second\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n> quoted";
        let h = to_html(md);
        assert!(h.contains("<h2>Title</h2>"), "{h}");
        assert!(
            h.contains(
                "<p>Some <strong>bold</strong> and <code>a &lt; b</code>.<br>Next line.</p>"
            ),
            "{h}"
        );
        assert!(
            h.contains("<pre class=\"code\" data-lang=\"rust\"><code><span class=\"hl-k\">fn</span> <span class=\"hl-f\">x</span>() {}\n</code></pre>"),
            "{h}"
        );
        assert!(
            h.contains("<ul><li>one</li><li>two<ul><li>deep</li></ul></li></ul>"),
            "{h}"
        );
        assert!(h.contains("<ol><li>first</li><li>second</li></ol>"), "{h}");
        assert!(
            h.contains("<tr><th>a</th><th>b</th></tr><tr><td>1</td><td>2</td></tr>"),
            "{h}"
        );
        assert!(h.contains("<blockquote><p>quoted</p></blockquote>"), "{h}");
    }

    #[test]
    fn nothing_gets_through() {
        let h = to_html(
            "<script>alert(1)</script> [x](javascript:alert(1)) [ok](https://a.example/?q=\"x\")",
        );
        assert!(!h.contains("<script"), "{h}");
        assert!(!h.contains("href=\"javascript"), "{h}");
        assert!(h.contains("<a href=\"https://a.example/?q=&quot;x&quot;\" rel=\"noopener noreferrer\" target=\"_blank\">ok</a>"), "{h}");
        assert_eq!(inline("**<b>**"), "<strong>&lt;b&gt;</strong>");
        // An unclosed fence runs to the end.
        assert!(to_html("```\ncode").contains("<code>code\n</code>"));
    }
}
