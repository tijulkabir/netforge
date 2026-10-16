use crate::error::NetForgeError;
use crate::op::Operation;

use rayon::prelude::*;

// ──────────────────── Shannon Entropy ─────────────────────────

/// Shannon entropy of the input byte stream (bits per byte).
///
/// **Red team usage:**
/// - Entropy > 7.0 → likely encrypted or compressed (packed malware)
/// - Entropy ~ 4.5–5.5 → typical English text
/// - Entropy ~ 0 → repetitive / null-padded regions
///
/// Returns the entropy value as a human-readable UTF-8 string
/// (e.g., `"7.982341"`).
pub struct Entropy;

impl Operation for Entropy {
    fn name(&self) -> &str {
        "entropy"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if input.is_empty() {
            return Ok(b"0.000000".to_vec());
        }
        let freq = compute_byte_frequencies(input);
        let len = input.len() as f64;
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum();
        Ok(format!("{entropy:.6}").into_bytes())
    }
}

// ──────────────────── Byte Frequency ──────────────────────────

/// Print a histogram of byte frequencies.
///
/// Output format: one line per non-zero byte value:
/// `0x41 'A' : 12 (4.21%)`
///
/// Useful for identifying XOR keys (single-byte XOR against
/// English text will spike at the key byte XOR'd with 0x20/0x65).
pub struct ByteFrequency;

impl Operation for ByteFrequency {
    fn name(&self) -> &str {
        "byte_freq"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let freq = compute_byte_frequencies(input);
        let len = input.len() as f64;
        let mut out = String::new();
        for (i, &count) in freq.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let pct = (count as f64 / len) * 100.0;
            let ch = if (i as u8).is_ascii_graphic() {
                format!("'{}'", i as u8 as char)
            } else {
                "   ".to_string()
            };
            out.push_str(&format!("0x{i:02x} {ch:>3} : {count:>6} ({pct:>6.2}%)\n"));
        }
        Ok(out.into_bytes())
    }
}

// ──────────────────── Strings Extraction ──────────────────────

/// Extract printable ASCII strings of minimum length from binary data.
///
/// Mimics the Unix `strings` command — the first thing you run
/// on an unknown binary during triage.
pub struct ExtractStrings {
    min_len: usize,
}

impl ExtractStrings {
    pub fn new(min_len: usize) -> Self {
        Self { min_len }
    }
}

impl Default for ExtractStrings {
    fn default() -> Self {
        Self { min_len: 4 }
    }
}

impl Operation for ExtractStrings {
    fn name(&self) -> &str {
        "strings"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::new();
        let mut current = Vec::new();
        for &b in input {
            if b.is_ascii_graphic() || b == b' ' {
                current.push(b);
            } else {
                if current.len() >= self.min_len {
                    out.extend_from_slice(&current);
                    out.push(b'\n');
                }
                current.clear();
            }
        }
        // Flush remaining
        if current.len() >= self.min_len {
            out.extend_from_slice(&current);
            out.push(b'\n');
        }
        Ok(out)
    }
}

// ─────────────────── Length / Stats ───────────────────────────

/// Output the byte length of the input as a decimal string.
pub struct ByteLength;

impl Operation for ByteLength {
    fn name(&self) -> &str {
        "length"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        Ok(format!("{}", input.len()).into_bytes())
    }
}

/// Compute 256-bin byte frequency histogram.
///
/// Automatically parallelizes with Rayon across CPU cores for buffers
/// larger than 64KB, with zero lock contention via map-reduce.
pub fn compute_byte_frequencies(input: &[u8]) -> [u64; 256] {
    if input.len() > 64 * 1024 {
        input
            .par_chunks(32 * 1024)
            .fold(
                || [0u64; 256],
                |mut acc, chunk| {
                    for &b in chunk {
                        acc[b as usize] += 1;
                    }
                    acc
                },
            )
            .reduce(
                || [0u64; 256],
                |mut a, b| {
                    for i in 0..256 {
                        a[i] += b[i];
                    }
                    a
                },
            )
    } else {
        let mut freq = [0u64; 256];
        for &b in input {
            freq[b as usize] += 1;
        }
        freq
    }
}
