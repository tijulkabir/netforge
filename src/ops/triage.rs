//! `triage` — one-shot unified binary recon.
//!
//! Replaces the first five commands an operator runs on an unknown file
//! (`file`, `wc -c`, `md5sum`/`sha256sum`, `ent`, `checksec`) with a single
//! report: type, size, hashes, Shannon entropy (with a packed/encrypted flag),
//! embedded-file signatures, and — for ELF targets — exploit mitigations.

use crate::error::NetForgeError;
use crate::op::Operation;
use crate::ops::elf::Checksec;
use crate::ops::fileid::{identify, Carve};
use crate::ops::{Entropy, HashMd5, HashSha256};

/// Unified triage report.
pub struct Triage;

impl Operation for Triage {
    fn name(&self) -> &str {
        "triage"
    }

    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let kind = identify(input);
        let md5 = String::from_utf8(HashMd5.execute(input)?).unwrap_or_default();
        let sha = String::from_utf8(HashSha256.execute(input)?).unwrap_or_default();
        let entropy = String::from_utf8(Entropy.execute(input)?).unwrap_or_default();
        let ent_val: f64 = entropy.parse().unwrap_or(0.0);
        let packed = if ent_val >= 7.2 {
            "  <- high: likely packed/encrypted/compressed"
        } else {
            ""
        };

        let mut out = String::new();
        out.push_str("══ NetForge triage ══════════════════\n");
        out.push_str(&format!("type       : {kind}\n"));
        out.push_str(&format!("size       : {} bytes\n", input.len()));
        out.push_str(&format!("md5        : {md5}\n"));
        out.push_str(&format!("sha256     : {sha}\n"));
        out.push_str(&format!("entropy    : {entropy} bits/byte{packed}\n"));

        // ELF-specific mitigation block (best effort; ignored for non-ELF).
        if input.starts_with(b"\x7fELF") {
            if let Ok(cs) = Checksec.execute(input) {
                out.push('\n');
                out.push_str(&String::from_utf8_lossy(&cs));
            }
        }

        // Embedded signatures (skip the trailing newline noise if none).
        if let Ok(carve) = Carve.execute(input) {
            let text = String::from_utf8_lossy(&carve);
            if !text.starts_with("no embedded") {
                out.push_str("\n── embedded signatures ──────────────\n");
                out.push_str(&text);
            }
        }

        Ok(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triage_reports_core_fields() {
        let data = b"the quick brown fox";
        let report = String::from_utf8(Triage.execute(data).unwrap()).unwrap();
        assert!(report.contains("type       : ASCII"), "{report}");
        assert!(report.contains("size       : 19 bytes"), "{report}");
        assert!(report.contains("md5        :"), "{report}");
        assert!(report.contains("sha256     :"), "{report}");
        assert!(report.contains("entropy    :"), "{report}");
    }

    #[test]
    fn triage_flags_high_entropy() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let report = String::from_utf8(Triage.execute(&data).unwrap()).unwrap();
        assert!(report.contains("likely packed"), "{report}");
    }
}
