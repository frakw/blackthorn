//! Code in chats, coloured: comments, strings, numbers, keywords and
//! called names, for the languages Claude writes most. A small tokenizer,
//! not a parser: good enough to read by. Its output is escaped HTML.

use crate::map::esc;

struct Lang {
    line: &'static [&'static str],
    block: Option<(&'static str, &'static str)>,
    quotes: &'static [char],
    keywords: &'static [&'static str],
    /// Words starting with $ are variables (shell, PHP).
    dollar: bool,
}

const PY: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield", "self", "print",
];
const JS: &[&str] = &[
    "async",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "default",
    "delete",
    "do",
    "else",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "from",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "interface",
    "let",
    "new",
    "null",
    "of",
    "return",
    "static",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "type",
    "typeof",
    "undefined",
    "var",
    "void",
    "while",
    "yield",
    "enum",
    "implements",
    "readonly",
    "as",
];
const RS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while", "Some", "None", "Ok", "Err",
];
const GO: &[&str] = &[
    "break",
    "case",
    "chan",
    "const",
    "continue",
    "default",
    "defer",
    "else",
    "fallthrough",
    "for",
    "func",
    "go",
    "goto",
    "if",
    "import",
    "interface",
    "map",
    "package",
    "range",
    "return",
    "select",
    "struct",
    "switch",
    "type",
    "var",
    "nil",
    "true",
    "false",
];
const SH: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "in", "function", "return", "exit", "export", "local", "readonly", "set", "unset", "echo",
    "cd", "sudo", "source", "true", "false",
];
const C: &[&str] = &[
    "auto",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "delete",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "false",
    "final",
    "float",
    "for",
    "goto",
    "if",
    "import",
    "include",
    "int",
    "long",
    "namespace",
    "new",
    "null",
    "nullptr",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "template",
    "this",
    "throw",
    "true",
    "try",
    "typedef",
    "union",
    "unsigned",
    "using",
    "var",
    "virtual",
    "void",
    "volatile",
    "while",
    "fun",
    "val",
    "let",
    "func",
    "override",
];
const SQL: &[&str] = &[
    "select", "from", "where", "and", "or", "not", "insert", "into", "values", "update", "set",
    "delete", "create", "table", "drop", "alter", "index", "join", "left", "right", "inner",
    "outer", "on", "as", "group", "by", "order", "limit", "having", "null", "is", "in", "primary",
    "key", "distinct", "union", "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "INSERT", "INTO",
    "VALUES", "UPDATE", "SET", "DELETE", "CREATE", "TABLE", "DROP", "ALTER", "INDEX", "JOIN",
    "LEFT", "RIGHT", "INNER", "OUTER", "ON", "AS", "GROUP", "BY", "ORDER", "LIMIT", "HAVING",
    "NULL", "IS", "IN", "PRIMARY", "KEY", "DISTINCT", "UNION",
];
const DATA: &[&str] = &["true", "false", "null", "yes", "no", "on", "off"];
const RB: &[&str] = &[
    "def", "end", "if", "elsif", "else", "unless", "while", "until", "for", "in", "do", "return",
    "class", "module", "require", "self", "nil", "true", "false", "and", "or", "not", "then",
    "yield", "begin", "rescue", "ensure", "local", "function",
];

fn lang(name: &str) -> Option<Lang> {
    let l = |line, block, quotes, keywords, dollar| {
        Some(Lang {
            line,
            block,
            quotes,
            keywords,
            dollar,
        })
    };
    match name.to_ascii_lowercase().as_str() {
        "python" | "py" | "python3" => l(&["#"], None, &['"', '\''], PY, false),
        "js" | "javascript" | "ts" | "typescript" | "jsx" | "tsx" | "mjs" | "cjs" => {
            l(&["//"], Some(("/*", "*/")), &['"', '\'', '`'], JS, false)
        }
        "rust" | "rs" => l(&["//"], Some(("/*", "*/")), &['"'], RS, false),
        "go" | "golang" => l(&["//"], Some(("/*", "*/")), &['"', '`', '\''], GO, false),
        "sh" | "bash" | "shell" | "zsh" | "console" | "shellsession" | "dockerfile"
        | "makefile" => l(&["#"], None, &['"', '\''], SH, true),
        "c" | "h" | "cpp" | "c++" | "cc" | "hpp" | "java" | "kotlin" | "kt" | "swift" | "cs"
        | "csharp" | "scala" | "dart" | "groovy" => {
            l(&["//"], Some(("/*", "*/")), &['"', '\''], C, false)
        }
        "php" => l(&["//", "#"], Some(("/*", "*/")), &['"', '\''], C, true),
        "sql" | "psql" | "mysql" | "sqlite" => {
            l(&["--"], Some(("/*", "*/")), &['"', '\''], SQL, false)
        }
        "json" | "jsonc" | "json5" => l(&["//"], None, &['"'], DATA, false),
        "yaml" | "yml" | "toml" | "ini" | "conf" | "env" | "properties" | "nginx" | "hcl"
        | "tf" => l(&["#", ";"], None, &['"', '\''], DATA, false),
        "ruby" | "rb" | "lua" | "perl" | "pl" | "r" => {
            l(&["#", "--"], None, &['"', '\''], RB, true)
        }
        _ => None,
    }
}

/// The language of a file, by its name.
pub fn lang_of_path(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name {
        "Dockerfile" | "Containerfile" => return "dockerfile",
        "Makefile" => return "makefile",
        _ => {}
    }
    name.rsplit_once('.').map(|(_, e)| e).unwrap_or("")
}

fn span(class: &str, text: &str) -> String {
    format!("<span class=\"hl-{class}\">{}</span>", esc(text))
}

/// `code` as escaped HTML, coloured if its language is known.
pub fn highlight(lang_name: &str, code: &str) -> String {
    let Some(l) = lang(lang_name) else {
        return esc(code);
    };
    let mut out = String::new();
    let mut plain = String::new();
    let flush = |plain: &mut String, out: &mut String| {
        out.push_str(&esc(plain));
        plain.clear();
    };
    let b = code;
    let mut i = 0;
    // The last thing seen was part of a word (so a digit continues it).
    let mut in_word = false;
    while i < b.len() {
        let rest = &b[i..];
        if let Some(c) = l.line.iter().find(|c| rest.starts_with(**c)) {
            // A shell # inside a word ($#, a#b) is not a comment.
            if !(*c == "#" && in_word) {
                flush(&mut plain, &mut out);
                let end = rest.find('\n').unwrap_or(rest.len());
                out.push_str(&span("c", &rest[..end]));
                i += end;
                in_word = false;
                continue;
            }
        }
        if let Some((open, close)) = l.block {
            if rest.starts_with(open) {
                flush(&mut plain, &mut out);
                let end = rest[open.len()..]
                    .find(close)
                    .map_or(rest.len(), |e| open.len() + e + close.len());
                out.push_str(&span("c", &rest[..end]));
                i += end;
                in_word = false;
                continue;
            }
        }
        let ch = rest.chars().next().expect("not empty");
        if l.quotes.contains(&ch) && !(ch == '\'' && in_word) {
            flush(&mut plain, &mut out);
            // Python's triple quotes.
            let triple: String = std::iter::repeat_n(ch, 3).collect();
            let end = if rest.starts_with(&triple) {
                rest[3..].find(&triple).map_or(rest.len(), |e| e + 6)
            } else {
                let mut esc_next = false;
                let mut end = rest.len();
                for (j, c) in rest.char_indices().skip(1) {
                    if esc_next {
                        esc_next = false;
                    } else if c == '\\' {
                        esc_next = true;
                    } else if c == ch {
                        end = j + c.len_utf8();
                        break;
                    } else if c == '\n' && ch != '`' {
                        end = j;
                        break;
                    }
                }
                end
            };
            out.push_str(&span("s", &rest[..end]));
            i += end;
            in_word = false;
            continue;
        }
        if ch.is_ascii_digit() && !in_word {
            flush(&mut plain, &mut out);
            let end = rest
                .char_indices()
                .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '.' || *c == '_'))
                .map_or(rest.len(), |(j, _)| j);
            out.push_str(&span("n", &rest[..end]));
            i += end;
            continue;
        }
        if (ch.is_alphabetic() || ch == '_' || (l.dollar && ch == '$')) && !in_word {
            let end = rest
                .char_indices()
                .skip(1)
                .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
                .map_or(rest.len(), |(j, _)| j);
            let word = &rest[..end];
            let next = rest[end..].chars().next();
            if word.starts_with('$') {
                flush(&mut plain, &mut out);
                out.push_str(&span("v", word));
            } else if l.keywords.contains(&word) {
                flush(&mut plain, &mut out);
                out.push_str(&span("k", word));
            } else if next == Some('(') {
                flush(&mut plain, &mut out);
                out.push_str(&span("f", word));
            } else {
                plain.push_str(word);
            }
            i += end;
            in_word = true;
            continue;
        }
        plain.push(ch);
        in_word = ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == '/';
        i += ch.len_utf8();
    }
    flush(&mut plain, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python() {
        let h = highlight(
            "python",
            "def f(n):  # note <b>\n    return \"a\\\"b\" + 'c' + 42\n",
        );
        assert!(
            h.contains("<span class=\"hl-k\">def</span> <span class=\"hl-f\">f</span>(n):"),
            "{h}"
        );
        assert!(
            h.contains("<span class=\"hl-c\"># note &lt;b&gt;</span>"),
            "{h}"
        );
        assert!(
            h.contains("<span class=\"hl-s\">&quot;a\\&quot;b&quot;</span>"),
            "{h}"
        );
        assert!(h.contains("<span class=\"hl-s\">&#39;c&#39;</span>"), "{h}");
        assert!(h.contains("<span class=\"hl-n\">42</span>"), "{h}");
    }

    #[test]
    fn others() {
        let h = highlight("rust", "let x = 1; /* a */ // b\nfn main() {}");
        assert!(h.contains("<span class=\"hl-k\">let</span>"), "{h}");
        assert!(h.contains("<span class=\"hl-c\">/* a */</span>"), "{h}");
        assert!(h.contains("<span class=\"hl-f\">main</span>"), "{h}");
        let h = highlight("bash", "echo \"$HOME\" $# x1 # done");
        assert!(h.contains("<span class=\"hl-k\">echo</span>"), "{h}");
        assert!(h.contains("<span class=\"hl-c\"># done</span>"), "{h}");
        assert!(!h.contains("hl-n\">1"), "{h}");
        // Unknown: escaped only.
        assert_eq!(highlight("brainfuck", "<+>"), "&lt;+&gt;");
        assert_eq!(lang_of_path("/a/b/main.rs"), "rs");
        assert_eq!(lang_of_path("Dockerfile"), "dockerfile");
        // Every character comes through, whatever it is.
        let odd = "x = '未完 \u{1F600}\n\"\\";
        let h = highlight("py", odd);
        let back = h
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .split('<')
            .map(|p| p.split_once('>').map_or(p, |(_, t)| t))
            .collect::<String>();
        assert_eq!(back, odd);
    }
}
