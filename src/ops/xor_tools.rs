//! XOR key-recovery tools.
//!
//! * [`XorBrute`]  — single-byte XOR brute force (all 256 keys, ranked).
//! * [`XorBreak`]  — repeating-key XOR recovery (keysize via Hamming distance,
//!   then per-column single-byte solve), the classic "break repeating-key XOR".

use crate::error::NetForgeError;
use crate::op::Operation;
use crate::ops::score::{english_score, preview};

/// Number of ranked candidates [`XorBrute`] reports.
const BRUTE_TOP_N: usize = 5;

/// Single-byte XOR brute force.
///
/// Tries every key in `0..=255`, scores each decoding as English plaintext, and
/// reports the best candidates — the fastest way to crack single-byte XOR
/// obfuscation of strings and small payloads.
pub struct XorBrute;

impl Operation for XorBrute {
    fn name(&self) -> &str {
        "xor_brute"
    }

    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if input.is_empty() {
            return Err(NetForgeError::Custom("empty input".to_string()));
        }
        let mut scored: Vec<(f64, u8, Vec<u8>)> = (0u16..=255)
            .map(|k| {
                let key = k as u8;
                let dec: Vec<u8> = input.iter().map(|&b| b ^ key).collect();
                (english_score(&dec), key, dec)
            })
            .collect();
        // Sort by score descending.
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let mut out = String::new();
        out.push_str("rank  key   score    preview\n");
        for (i, (score, key, dec)) in scored.iter().take(BRUTE_TOP_N).enumerate() {
            out.push_str(&format!(
                "{:>2}.   0x{:02x}  {:>7.3}  {}\n",
                i + 1,
                key,
                score,
                preview(dec, 60)
            ));
        }
        Ok(out.into_bytes())
    }
}

/// Index of Coincidence of a byte column.
///
/// XOR with a constant is a permutation of the byte alphabet, so a column that
/// is a single-byte-XOR of English text has the *same* IoC as English (≈0.066),
/// while a column that mixes several key bytes trends toward uniform (≈0.004).
/// This makes IoC a length-normalized, overfitting-proof keysize signal.
fn column_ioc(col: &[u8]) -> f64 {
    let n = col.len();
    if n < 2 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in col {
        freq[b as usize] += 1;
    }
    let sum: f64 = freq.iter().map(|&f| f as f64 * (f as f64 - 1.0)).sum();
    sum / (n as f64 * (n as f64 - 1.0))
}

/// Recover the best single-byte key for one column of bytes.
fn best_byte(col: &[u8]) -> u8 {
    let mut best_key = 0u8;
    let mut best_score = f64::NEG_INFINITY;
    for k in 0u16..=255 {
        let key = k as u8;
        let dec: Vec<u8> = col.iter().map(|&b| b ^ key).collect();
        let s = english_score(&dec);
        if s > best_score {
            best_score = s;
            best_key = key;
        }
    }
    best_key
}

/// Repeating-key XOR break.
///
/// Estimates the key length by the normalized Hamming distance between adjacent
/// blocks, then solves each key position independently with single-byte brute
/// force and reconstructs the full key and plaintext.
pub struct XorBreak {
    max_keysize: usize,
}

impl XorBreak {
    pub fn new(max_keysize: usize) -> Self {
        Self {
            max_keysize: max_keysize.clamp(2, 64),
        }
    }
}

impl Default for XorBreak {
    fn default() -> Self {
        Self::new(40)
    }
}

impl Operation for XorBreak {
    fn name(&self) -> &str {
        "xor_break"
    }

    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        // Need enough data for the Hamming estimate (>= 4 blocks of the key).
        if input.len() < 8 {
            return Err(NetForgeError::Custom(
                "input too short to recover a repeating key (need >= 8 bytes)".to_string(),
            ));
        }
        // Keysize detection by Index of Coincidence needs enough bytes per
        // column to be statistically meaningful; IoC over a handful of bytes is
        // pure noise (and spuriously high). We only consider keysizes that leave
        // at least MIN_COL samples per column, relaxing the floor for short
        // inputs so we still return a best effort.
        const MIN_COL: usize = 20;
        let mut min_col = MIN_COL;
        while min_col > 2 && input.len() / min_col < 2 {
            min_col /= 2;
        }
        let max_ks = self.max_keysize.min(input.len() / min_col).max(2);

        // ── Detect keysize via Index of Coincidence. ──
        // For each candidate keysize we average the IoC of its columns. The true
        // keysize (and its multiples) produce high-IoC columns; wrong sizes trend
        // toward uniform. We take the SMALLEST keysize whose average IoC is within
        // 10% of the maximum observed — that lands on the true key length rather
        // than a multiple, and is immune to the overfitting that fools a
        // plaintext-score search (a longer key can always fit a sample better).
        let mut best_ks = 2usize;
        let mut best_ioc = 0.0f64;
        let mut iocs: Vec<(usize, f64)> = Vec::new();
        for ks in 2..=max_ks {
            if input.len() / ks < min_col {
                continue;
            }
            let avg: f64 = (0..ks)
                .map(|c| {
                    let col: Vec<u8> = input.iter().skip(c).step_by(ks).copied().collect();
                    column_ioc(&col)
                })
                .sum::<f64>()
                / ks as f64;
            if avg > best_ioc {
                best_ioc = avg;
            }
            iocs.push((ks, avg));
        }
        let threshold = best_ioc * 0.90;
        if let Some(&(ks, _)) = iocs.iter().find(|&&(_, v)| v >= threshold) {
            best_ks = ks; // iocs is in ascending ks order → smallest qualifier
        }

        // ── Solve each column of the chosen keysize by single-byte brute. ──
        let mut key = Vec::with_capacity(best_ks);
        for col_idx in 0..best_ks {
            let col: Vec<u8> = input
                .iter()
                .skip(col_idx)
                .step_by(best_ks)
                .copied()
                .collect();
            key.push(best_byte(&col));
        }

        // ── Decrypt the full input with the recovered key. ──
        let plain: Vec<u8> = input
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % best_ks])
            .collect();
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let key_ascii = preview(&key, best_ks);

        let mut out = String::new();
        out.push_str(&format!("keysize    : {best_ks}\n"));
        out.push_str(&format!("key (hex)  : {key_hex}\n"));
        out.push_str(&format!("key (ascii): {key_ascii}\n"));
        out.push_str("plaintext  :\n");
        out.extend(String::from_utf8_lossy(&plain).chars());
        out.push('\n');
        Ok(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_brute_recovers_key() {
        let plain = b"Attack the server at dawn, bring the exploit kit.";
        let key = 0x5au8;
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let report = XorBrute.execute(&cipher).unwrap();
        let text = String::from_utf8(report).unwrap();
        // The correct key must appear as the top-ranked (line " 1.").
        assert!(text.contains("0x5a"), "report: {text}");
        let first_line = text.lines().nth(1).unwrap();
        assert!(
            first_line.contains("0x5a"),
            "top candidate wrong: {first_line}"
        );
    }

    #[test]
    fn repeating_key_break_recovers_plaintext() {
        // Breaking repeating-key XOR is statistical: it needs enough ciphertext
        // for the per-column analysis (~20+ samples per key position). This is a
        // realistic amount of captured traffic for a 7-byte key.
        let plain = b"When you break repeating key XOR you first recover the key length \
                      using per-column index of coincidence, and then you solve each \
                      column independently as a single byte XOR against expected letter \
                      frequencies. With enough ciphertext the recovery is reliable and the \
                      original plaintext falls right out of the analysis cleanly every time.";
        let key = b"REDTEAM";
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let report = XorBreak::default().execute(&cipher).unwrap();
        let text = String::from_utf8(report).unwrap();
        // Correct decryption is what matters; the detected keysize may be the
        // true length (7) or an exact multiple of it (both decrypt correctly).
        assert!(
            text.contains("repeating key XOR"),
            "plaintext not recovered: {text}"
        );
    }

    #[test]
    fn short_input_errors() {
        assert!(XorBreak::default().execute(b"abc").is_err());
        assert!(XorBrute.execute(b"").is_err());
    }
}
