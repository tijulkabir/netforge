//! `magic` — recursive auto-decode.
//!
//! Breadth-first searches a tree of reversible decodings (base64, hex, URL,
//! ROT13) up to a bounded depth, scoring every node as candidate plaintext and
//! returning the best result together with the decode path that produced it.
//! Short-circuits the moment a CTF flag marker appears.
//!
//! This is the "what the heck is this string" button: paste an opaque blob and
//! let NetForge peel the layers.

use crate::error::NetForgeError;
use crate::op::Operation;
use crate::ops::score::{english_score, looks_like_flag, preview, printable_ratio};
use crate::ops::{FromBase64, FromHex, Rot13, UrlDecode};

/// Maximum decode depth (layers of nesting) explored by default.
const DEFAULT_DEPTH: usize = 6;
/// Hard cap on nodes expanded, so pathological inputs stay bounded.
const MAX_NODES: usize = 4096;

/// Recursive auto-decoder.
pub struct Magic {
    max_depth: usize,
}

impl Magic {
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth: max_depth.clamp(1, 12),
        }
    }
}

impl Default for Magic {
    fn default() -> Self {
        Self::new(DEFAULT_DEPTH)
    }
}

/// A decoder that may or may not apply to a given byte stream.
struct Decoder {
    name: &'static str,
    guard: fn(&[u8]) -> bool,
    apply: fn(&[u8]) -> Result<Vec<u8>, NetForgeError>,
}

fn decoders() -> Vec<Decoder> {
    vec![
        Decoder {
            name: "from_base64",
            guard: looks_base64,
            apply: |d| FromBase64.execute(d),
        },
        Decoder {
            name: "from_hex",
            guard: looks_hex,
            apply: |d| FromHex.execute(d),
        },
        Decoder {
            name: "url_decode",
            guard: |d| d.contains(&b'%'),
            apply: |d| UrlDecode.execute(d),
        },
        Decoder {
            name: "rot13",
            guard: looks_alpha,
            apply: |d| Rot13.execute(d),
        },
    ]
}

/// FNV-1a 64-bit hash, used to dedupe already-seen intermediate buffers.
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn looks_base64(d: &[u8]) -> bool {
    if d.len() < 8 {
        return false;
    }
    let (mut ok, mut total) = (0usize, 0usize);
    for &b in d {
        if b == b'\n' || b == b'\r' || b == b' ' {
            continue;
        }
        total += 1;
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=') {
            ok += 1;
        }
    }
    total >= 8 && ok == total
}

fn looks_hex(d: &[u8]) -> bool {
    let cleaned: Vec<u8> = d
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && !matches!(b, b':' | b',' | b' '))
        .collect();
    cleaned.len() >= 8
        && cleaned.len().is_multiple_of(2)
        && cleaned.iter().all(|b| b.is_ascii_hexdigit())
}

fn looks_alpha(d: &[u8]) -> bool {
    if d.is_empty() {
        return false;
    }
    let alpha = d.iter().filter(|b| b.is_ascii_alphabetic()).count();
    alpha as f64 / d.len() as f64 > 0.5
}

impl Operation for Magic {
    fn name(&self) -> &str {
        "magic"
    }

    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if input.is_empty() {
            return Err(NetForgeError::Custom("empty input".to_string()));
        }
        let decs = decoders();

        // BFS frontier of (data, path, depth).
        let mut queue: std::collections::VecDeque<(Vec<u8>, Vec<&'static str>, usize)> =
            std::collections::VecDeque::new();
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        seen.insert(fnv1a(input));
        queue.push_back((input.to_vec(), Vec::new(), 0));

        let mut best_score = english_score(input);
        let mut best_data = input.to_vec();
        let mut best_path: Vec<&'static str> = Vec::new();
        let flag_hit = false;

        let mut nodes = 0usize;
        while let Some((data, path, depth)) = queue.pop_front() {
            nodes += 1;
            if nodes > MAX_NODES {
                break;
            }
            if depth >= self.max_depth {
                continue;
            }
            for dec in &decs {
                if !(dec.guard)(&data) {
                    continue;
                }
                let Ok(out) = (dec.apply)(&data) else {
                    continue;
                };
                if out.is_empty() || out == data {
                    continue;
                }
                let h = fnv1a(&out);
                if !seen.insert(h) {
                    continue;
                }
                let mut child_path = path.clone();
                child_path.push(dec.name);

                let score = english_score(&out);
                if looks_like_flag(&out) {
                    // A flag beats everything — take it and stop.
                    return Ok(render(&out, &child_path, score, true));
                }
                if score > best_score {
                    best_score = score;
                    best_data = out.clone();
                    best_path = child_path.clone();
                }
                // Only keep descending through plausibly-textual layers.
                if printable_ratio(&out) >= 0.75 {
                    queue.push_back((out, child_path, depth + 1));
                }
            }
        }

        Ok(render(&best_data, &best_path, best_score, flag_hit))
    }
}

fn render(data: &[u8], path: &[&'static str], score: f64, flag: bool) -> Vec<u8> {
    let route = if path.is_empty() {
        "(input is already the best candidate — no decoding improved it)".to_string()
    } else {
        path.join(" -> ")
    };
    let mut out = String::new();
    out.push_str(&format!(
        "magic: best score {score:.3}{} via {route}\n",
        if flag { "  [FLAG DETECTED]" } else { "" }
    ));
    out.push_str(&format!("preview: {}\n", preview(data, 80)));
    out.push_str("---\n");
    out.extend(String::from_utf8_lossy(data).chars());
    out.push('\n');
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{Rot13, ToBase64, ToHex};

    #[test]
    fn peels_nested_base64_hex() {
        // flag{...} -> base64 -> hex. magic must unwind both layers.
        let secret = b"flag{nested_layers_peeled}";
        let b64 = ToBase64.execute(secret).unwrap();
        let hexed = ToHex.execute(&b64).unwrap();
        let report = Magic::default().execute(&hexed).unwrap();
        let text = String::from_utf8(report).unwrap();
        assert!(text.contains("FLAG DETECTED"), "no flag: {text}");
        assert!(
            text.contains("flag{nested_layers_peeled}"),
            "not decoded: {text}"
        );
    }

    #[test]
    fn single_layer_base64() {
        let b64 = ToBase64
            .execute(b"the quick brown fox jumps over it")
            .unwrap();
        let report = Magic::default().execute(&b64).unwrap();
        let text = String::from_utf8(report).unwrap();
        assert!(text.contains("from_base64"), "path wrong: {text}");
        assert!(text.contains("quick brown fox"), "not decoded: {text}");
    }

    #[test]
    fn rot13_recovered() {
        let r = Rot13
            .execute(b"attack at dawn the whole team moves")
            .unwrap();
        let report = Magic::default().execute(&r).unwrap();
        let text = String::from_utf8(report).unwrap();
        assert!(text.contains("attack at dawn"), "rot13 not undone: {text}");
    }

    #[test]
    fn empty_errors() {
        assert!(Magic::default().execute(b"").is_err());
    }
}
