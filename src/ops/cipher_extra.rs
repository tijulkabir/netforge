//! Classic ciphers and analysis helpers (`rc4`, `vigenere`, `atbash`,
//! `caesar_brute`, `to_morse`, `from_morse`, `badchars`).
//!
//! CTF- and analysis-oriented: decode obfuscated strings and malware/C2 config
//! blobs (RC4), work classic cipher challenges, and vet data for forbidden
//! bytes. Everything here is reversible analysis, hand-rolled and zero-dependency.

use crate::error::NetForgeError;
use crate::op::Operation;
use crate::ops::score::{english_score, preview};

// ──────────────────────────── RC4 ────────────────────────────

/// RC4 stream cipher (symmetric: the same op both encrypts and decrypts).
///
/// Widely used to obfuscate malware strings and C2 configuration; recovering
/// the plaintext during analysis is the point here.
pub struct Rc4 {
    key: Vec<u8>,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl Operation for Rc4 {
    fn name(&self) -> &str {
        "rc4"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if self.key.is_empty() {
            return Err(NetForgeError::Custom("RC4 key cannot be empty".to_string()));
        }
        // Key-scheduling algorithm (KSA).
        let mut s: [u8; 256] = [0; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j
                .wrapping_add(s[i])
                .wrapping_add(self.key[i % self.key.len()]);
            s.swap(i, j as usize);
        }
        // Pseudo-random generation algorithm (PRGA).
        let mut out = Vec::with_capacity(input.len());
        let (mut i, mut j) = (0u8, 0u8);
        for &b in input {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            out.push(b ^ k);
        }
        Ok(out)
    }
}

// ────────────────────────── Vigenère ─────────────────────────

/// Vigenère cipher. `decrypt = false` enciphers, `true` deciphers. Only ASCII
/// letters are shifted; case is preserved and all other bytes pass through.
pub struct Vigenere {
    key: Vec<u8>,
    decrypt: bool,
}

impl Vigenere {
    pub fn new(key: &[u8], decrypt: bool) -> Self {
        Self {
            key: key
                .iter()
                .filter(|b| b.is_ascii_alphabetic())
                .copied()
                .collect(),
            decrypt,
        }
    }
}

impl Operation for Vigenere {
    fn name(&self) -> &str {
        "vigenere"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if self.key.is_empty() {
            return Err(NetForgeError::Custom(
                "Vigenère key must contain letters".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(input.len());
        let mut ki = 0usize;
        for &b in input {
            if b.is_ascii_alphabetic() {
                let base = if b.is_ascii_uppercase() { b'A' } else { b'a' };
                let k = (self.key[ki % self.key.len()].to_ascii_lowercase() - b'a') as i16;
                let shift = if self.decrypt { 26 - k } else { k };
                let c = (b - base) as i16;
                out.push(base + ((c + shift) % 26) as u8);
                ki += 1;
            } else {
                out.push(b);
            }
        }
        Ok(out)
    }
}

// ─────────────────────────── Atbash ──────────────────────────

/// Atbash substitution (a↔z, b↔y, …). Self-inverse.
pub struct Atbash;

impl Operation for Atbash {
    fn name(&self) -> &str {
        "atbash"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let out = input
            .iter()
            .map(|&b| match b {
                b'a'..=b'z' => b'z' - (b - b'a'),
                b'A'..=b'Z' => b'Z' - (b - b'A'),
                other => other,
            })
            .collect();
        Ok(out)
    }
}

// ──────────────────────── Caesar brute ───────────────────────

/// Try all 25 Caesar shifts and rank them by English-likeness.
pub struct CaesarBrute;

impl Operation for CaesarBrute {
    fn name(&self) -> &str {
        "caesar_brute"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut scored: Vec<(f64, u8, Vec<u8>)> = (1u8..26)
            .map(|shift| {
                let dec: Vec<u8> = input
                    .iter()
                    .map(|&b| match b {
                        b'a'..=b'z' => b'a' + (b - b'a' + (26 - shift)) % 26,
                        b'A'..=b'Z' => b'A' + (b - b'A' + (26 - shift)) % 26,
                        o => o,
                    })
                    .collect();
                (english_score(&dec), shift, dec)
            })
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let mut out = String::new();
        out.push_str("shift  score    preview\n");
        for (score, shift, dec) in scored.iter().take(5) {
            out.push_str(&format!(
                "{shift:>3}   {score:>7.3}  {}\n",
                preview(dec, 60)
            ));
        }
        Ok(out.into_bytes())
    }
}

// ─────────────────────────── Morse ───────────────────────────

const MORSE: &[(char, &str)] = &[
    ('a', ".-"),
    ('b', "-..."),
    ('c', "-.-."),
    ('d', "-.."),
    ('e', "."),
    ('f', "..-."),
    ('g', "--."),
    ('h', "...."),
    ('i', ".."),
    ('j', ".---"),
    ('k', "-.-"),
    ('l', ".-.."),
    ('m', "--"),
    ('n', "-."),
    ('o', "---"),
    ('p', ".--."),
    ('q', "--.-"),
    ('r', ".-."),
    ('s', "..."),
    ('t', "-"),
    ('u', "..-"),
    ('v', "...-"),
    ('w', ".--"),
    ('x', "-..-"),
    ('y', "-.--"),
    ('z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
];

/// Encode ASCII text to Morse (letters space-separated, words by `/`).
pub struct ToMorse;

impl Operation for ToMorse {
    fn name(&self) -> &str {
        "to_morse"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut parts: Vec<String> = Vec::new();
        for &b in input {
            let c = (b as char).to_ascii_lowercase();
            if c == ' ' {
                parts.push("/".to_string());
            } else if let Some((_, code)) = MORSE.iter().find(|(ch, _)| *ch == c) {
                parts.push((*code).to_string());
            }
        }
        Ok(parts.join(" ").into_bytes())
    }
}

/// Decode Morse (letters space-separated, words by `/`) back to text.
pub struct FromMorse;

impl Operation for FromMorse {
    fn name(&self) -> &str {
        "from_morse"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let text = String::from_utf8_lossy(input);
        let mut out = String::new();
        for token in text.split_whitespace() {
            if token == "/" {
                out.push(' ');
            } else if let Some((ch, _)) = MORSE.iter().find(|(_, code)| *code == token) {
                out.push(*ch);
            }
        }
        Ok(out.into_bytes())
    }
}

// ───────────────────────── Bad chars ─────────────────────────

/// Report which forbidden bytes occur in the input and at what offsets.
///
/// Purely an analysis read-out: use it to vet whether data is safe for a
/// byte-restricted sink (e.g. a parser that chokes on NUL or newline).
pub struct BadChars {
    bad: Vec<u8>,
}

impl BadChars {
    pub fn new(bad: &[u8]) -> Self {
        Self { bad: bad.to_vec() }
    }
}

impl Operation for BadChars {
    fn name(&self) -> &str {
        "badchars"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if self.bad.is_empty() {
            return Err(NetForgeError::Custom(
                "no bad bytes specified (e.g. badchars:00,0a,0d)".to_string(),
            ));
        }
        let mut out = String::new();
        let mut any = false;
        for &bad in &self.bad {
            let offsets: Vec<usize> = input
                .iter()
                .enumerate()
                .filter(|&(_, &b)| b == bad)
                .map(|(i, _)| i)
                .collect();
            if !offsets.is_empty() {
                any = true;
                let shown: Vec<String> = offsets
                    .iter()
                    .take(16)
                    .map(|o| format!("0x{o:x}"))
                    .collect();
                let more = if offsets.len() > 16 {
                    format!(" (+{} more)", offsets.len() - 16)
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "0x{bad:02x} : {} occurrence(s) at {}{}\n",
                    offsets.len(),
                    shown.join(", "),
                    more
                ));
            }
        }
        if !any {
            out.push_str("clean: none of the specified bad bytes are present\n");
        }
        Ok(out.into_bytes())
    }
}

/// Parse a byte list like `00,0a,0d` or `0x00 0a` into bytes.
pub fn parse_byte_list(s: &str) -> Vec<u8> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .filter_map(|t| {
            let t = t
                .strip_prefix("0x")
                .or_else(|| t.strip_prefix("0X"))
                .unwrap_or(t);
            u8::from_str_radix(t, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_roundtrip_and_vector() {
        // RC4("Key", "Plaintext") = BBF316E8D940AF0AD3 (known test vector).
        let ct = Rc4::new(b"Key").execute(b"Plaintext").unwrap();
        let hex: String = ct.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(hex, "BBF316E8D940AF0AD3");
        // Symmetric roundtrip.
        let back = Rc4::new(b"Key").execute(&ct).unwrap();
        assert_eq!(back, b"Plaintext");
    }

    #[test]
    fn vigenere_roundtrip() {
        let enc = Vigenere::new(b"LEMON", false)
            .execute(b"Attack At Dawn")
            .unwrap();
        let dec = Vigenere::new(b"LEMON", true).execute(&enc).unwrap();
        assert_eq!(dec, b"Attack At Dawn");
    }

    #[test]
    fn atbash_involution() {
        let enc = Atbash.execute(b"Hello, World").unwrap();
        assert_eq!(Atbash.execute(&enc).unwrap(), b"Hello, World");
        assert_eq!(enc, b"Svool, Dliow");
    }

    #[test]
    fn caesar_brute_finds_plaintext() {
        // "hello world" shifted by 3 → "khoor zruog"
        let report = String::from_utf8(CaesarBrute.execute(b"khoor zruog").unwrap()).unwrap();
        assert!(report.contains("hello world"), "{report}");
    }

    #[test]
    fn morse_roundtrip() {
        let m = ToMorse.execute(b"sos help").unwrap();
        assert_eq!(FromMorse.execute(&m).unwrap(), b"sos help");
    }

    #[test]
    fn badchars_detects_and_clears() {
        let bad = parse_byte_list("00,0a");
        let r = String::from_utf8(BadChars::new(&bad).execute(b"ok\x00no\x0a").unwrap()).unwrap();
        assert!(r.contains("0x00"), "{r}");
        assert!(r.contains("0x0a"), "{r}");
        let clean =
            String::from_utf8(BadChars::new(&bad).execute(b"all good here").unwrap()).unwrap();
        assert!(clean.contains("clean"), "{clean}");
    }
}
