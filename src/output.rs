//! Structured output layer.
//!
//! Every invocation can emit either raw bytes (the default, pipeline-native)
//! or a stable JSON report (`--json`) that downstream tooling can parse.
//!
//! The JSON is hand-serialized (no `serde` dependency) to keep NetForge's
//! supply chain minimal and auditable — a deliberate trade for a security
//! tool that may run on locked-down or air-gapped hosts.
//!
//! ## Schema (v1 — stable, semver-governed)
//!
//! Success:
//! ```json
//! {
//!   "tool": "netforge",
//!   "schema": 1,
//!   "version": "2.0.0",
//!   "ok": true,
//!   "input": { "bytes": 14, "source": "stdin" },
//!   "pipeline": ["xor:0x42", "to_hex"],
//!   "output": { "bytes": 28, "encoding": "utf8", "data": "..." },
//!   "sha256": "..."
//! }
//! ```
//!
//! Error:
//! ```json
//! {
//!   "tool": "netforge",
//!   "schema": 1,
//!   "version": "2.0.0",
//!   "ok": false,
//!   "pipeline": ["from_base64"],
//!   "error": { "code": "invalid_base64", "message": "invalid base64 input" }
//! }
//! ```

use crate::error::NetForgeError;
use crate::op::Operation;
use crate::ops::{HashSha256, ToBase64};

/// Stable schema version. Bump on any breaking change to the JSON shape.
pub const SCHEMA_VERSION: u32 = 1;

/// Escape a string for embedding in a JSON string literal (RFC 8259).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render a `["a","b"]` JSON array from string slices.
fn json_str_array(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("\"{}\"", json_escape(s))).collect();
    format!("[{}]", inner.join(","))
}

/// Build the success report as a JSON string.
///
/// `output` is encoded as a UTF-8 string when it is valid UTF-8, otherwise as
/// base64 with `"encoding": "base64"` so binary results stay machine-safe.
pub fn success_json(
    version: &str,
    input_len: usize,
    input_source: &str,
    pipeline: &[String],
    output: &[u8],
) -> String {
    let (encoding, data) = match std::str::from_utf8(output) {
        Ok(s) => ("utf8", json_escape(s)),
        Err(_) => {
            // Reuse the existing base64 encoder; it cannot fail on arbitrary bytes.
            let b64 = ToBase64.execute(output).unwrap_or_default();
            ("base64", String::from_utf8_lossy(&b64).into_owned())
        }
    };

    // SHA-256 of the output for integrity / correlation. Digest is ASCII hex.
    let sha = HashSha256
        .execute(output)
        .ok()
        .and_then(|h| String::from_utf8(h).ok())
        .unwrap_or_default();

    format!(
        "{{\"tool\":\"netforge\",\"schema\":{schema},\"version\":\"{version}\",\"ok\":true,\
         \"input\":{{\"bytes\":{input_len},\"source\":\"{source}\"}},\
         \"pipeline\":{pipeline},\
         \"output\":{{\"bytes\":{out_len},\"encoding\":\"{encoding}\",\"data\":\"{data}\"}},\
         \"sha256\":\"{sha}\"}}",
        schema = SCHEMA_VERSION,
        version = json_escape(version),
        input_len = input_len,
        source = json_escape(input_source),
        pipeline = json_str_array(pipeline),
        out_len = output.len(),
        encoding = encoding,
        data = data,
        sha = sha,
    )
}

/// Build the error report as a JSON string.
pub fn error_json(version: &str, pipeline: &[String], err: &NetForgeError) -> String {
    format!(
        "{{\"tool\":\"netforge\",\"schema\":{schema},\"version\":\"{version}\",\"ok\":false,\
         \"pipeline\":{pipeline},\
         \"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}}}}",
        schema = SCHEMA_VERSION,
        version = json_escape(version),
        pipeline = json_str_array(pipeline),
        code = err.code(),
        message = json_escape(&err.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_quotes() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
        assert_eq!(json_escape("\x01"), "\\u0001");
    }

    #[test]
    fn success_utf8_output_is_inline() {
        let j = success_json("2.0.0", 2, "stdin", &["to_hex".into()], b"4142");
        assert!(j.contains("\"ok\":true"));
        assert!(j.contains("\"encoding\":\"utf8\""));
        assert!(j.contains("\"data\":\"4142\""));
        assert!(j.contains("\"source\":\"stdin\""));
        assert!(j.contains("\"schema\":1"));
    }

    #[test]
    fn success_binary_output_is_base64() {
        let j = success_json("2.0.0", 1, "inline", &["xor:0xff".into()], &[0xff, 0x00, 0x80]);
        assert!(j.contains("\"encoding\":\"base64\""));
    }

    #[test]
    fn error_carries_stable_code() {
        let j = error_json("2.0.0", &["from_base64".into()], &NetForgeError::InvalidBase64);
        assert!(j.contains("\"ok\":false"));
        assert!(j.contains("\"code\":\"invalid_base64\""));
    }
}
