//! Recipe engine — committable, headless pipelines.
//!
//! A recipe is a plain-text file listing the operations to chain, one per line
//! (or several per line separated by whitespace or `|`). `#` begins a comment,
//! and blank lines are ignored. This turns an ad-hoc command line into a
//! version-controlled, shareable transform — the CyberChef "recipe" idea, but
//! headless and diff-able.
//!
//! Example recipe:
//! ```text
//! # Deobfuscate a captured config blob
//! from_base64          # layer 1: transport encoding
//! xor:0x5a             # layer 2: single-byte obfuscation
//! strings:6            # pull readable indicators
//! ```
//!
//! The parsed op specs feed the exact same builder the CLI uses, so every
//! operation and `op:arg` form is available inside a recipe.

/// Parse recipe text into an ordered list of operation specs (`op` or `op:arg`).
///
/// Comments (`#` to end of line) and blank lines are stripped. Each remaining
/// line may hold several ops separated by whitespace or `|`.
pub fn parse_recipe(text: &str) -> Vec<String> {
    let mut specs = Vec::new();
    for line in text.lines() {
        // Strip trailing comments. (Keeps it simple: `#` is never valid in an
        // op spec, so this is unambiguous.)
        let code = match line.split_once('#') {
            Some((before, _)) => before,
            None => line,
        };
        for tok in code.split(|c: char| c.is_whitespace() || c == '|') {
            if !tok.is_empty() {
                specs.push(tok.to_string());
            }
        }
    }
    specs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines_comments_and_blanks() {
        let recipe = "\
# header comment\n\
from_base64   # transport\n\
\n\
xor:0x5a\n\
strings:6\n";
        assert_eq!(
            parse_recipe(recipe),
            vec!["from_base64", "xor:0x5a", "strings:6"]
        );
    }

    #[test]
    fn multiple_ops_per_line() {
        assert_eq!(
            parse_recipe("to_hex | rot13   to_base64"),
            vec!["to_hex", "rot13", "to_base64"]
        );
    }

    #[test]
    fn empty_recipe_is_empty() {
        assert!(parse_recipe("# only comments\n\n   \n").is_empty());
    }
}
