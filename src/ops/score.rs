//! Plaintext-likelihood scoring.
//!
//! Shared heuristics used by the brute-force decoders (`xor_brute`, `xor_break`)
//! and the recursive `magic` engine to decide whether a candidate byte stream
//! looks like meaningful plaintext — and to rank competing candidates.

/// Relative English character frequencies (letters a–z then space), as weights.
/// Values are rough corpus frequencies; only their relative size matters.
const ENGLISH_FREQ: [f64; 27] = [
    8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7, 7.5, 1.9, 0.095, 6.0,
    6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074, 13.0,
];

/// Common CTF flag-wrapper prefixes checked by [`looks_like_flag`].
const FLAG_MARKERS: &[&[u8]] = &[
    b"flag{",
    b"ctf{",
    b"htb{",
    b"pico",
    b"flag-",
    b"key{",
    b"flag(",
    b"the flag",
];

/// Fraction of bytes that are printable ASCII (incl. common whitespace), 0.0–1.0.
pub fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    printable as f64 / data.len() as f64
}

/// Heuristic "is this English-ish plaintext?" score (higher is better).
///
/// Each byte contributes its English frequency weight when it is a letter or
/// space, a small positive weight for other printable characters, and a heavy
/// negative weight for non-printable bytes — so random binary scores far below
/// real text. The result is averaged over length so inputs of different sizes
/// are comparable.
pub fn english_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut score = 0.0;
    for &b in data {
        let c = b.to_ascii_lowercase();
        score += if c.is_ascii_lowercase() {
            ENGLISH_FREQ[(c - b'a') as usize]
        } else if c == b' ' {
            ENGLISH_FREQ[26]
        } else if matches!(c, b'\n' | b'\r' | b'\t') {
            0.5
        } else if (0x20..=0x7e).contains(&c) {
            0.3 // digits, punctuation
        } else {
            -15.0 // non-printable: strongly penalized
        };
    }
    score / data.len() as f64
}

/// True if the data contains a recognizable CTF flag marker (case-insensitive).
pub fn looks_like_flag(data: &[u8]) -> bool {
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    FLAG_MARKERS.iter().any(|m| window_contains(&lower, m))
}

/// Case-sensitive substring search (needle already lowercased by caller).
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A short, single-line printable preview of `data`, truncated to `max` chars.
/// Non-printable bytes are rendered as `.` so the preview is terminal-safe.
pub fn preview(data: &[u8], max: usize) -> String {
    let mut s = String::with_capacity(max.min(data.len()));
    for &b in data.iter().take(max) {
        s.push(if (0x20..=0x7e).contains(&b) {
            b as char
        } else {
            '.'
        });
    }
    if data.len() > max {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_beats_random() {
        let text = b"the quick brown fox jumps over the lazy dog";
        let random = [0x00u8, 0xff, 0x13, 0x9a, 0x7f, 0x01, 0xc4, 0x80];
        assert!(english_score(text) > english_score(&random));
    }

    #[test]
    fn printable_ratio_bounds() {
        assert_eq!(printable_ratio(b"hello"), 1.0);
        assert_eq!(printable_ratio(&[0u8, 0, 0, 0]), 0.0);
    }

    #[test]
    fn flag_detection() {
        assert!(looks_like_flag(b"here is flag{w1n}"));
        assert!(looks_like_flag(b"HTB{pwn}"));
        assert!(!looks_like_flag(b"just some ordinary text"));
    }

    #[test]
    fn preview_truncates_and_sanitizes() {
        assert_eq!(preview(b"ab\x00cd", 10), "ab.cd");
        assert_eq!(preview(b"abcdef", 3), "abc…");
    }
}
