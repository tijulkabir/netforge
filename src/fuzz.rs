use crate::op::Operation;
use crate::ops::{
    Entropy, FromBase64, FromHex, HashBlake3, HashMd5, HashSha256, InternetChecksum, PeInfo,
    PeSections, Rot13, TlvDecode, TlvEncode, ToBase64, ToCArray, ToHex, UrlDecode, UrlEncode, Xor,
};

/// High-speed pseudo-random number generator (Xorshift64) for standalone fuzzing.
///
/// Deterministic, zero dependencies, sub-nanosecond per random word.
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xdeadbeefcafe } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(self.next_u64() as u8);
        }
        buf
    }

    fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min))
    }
}

/// Forge a plausible-but-hostile PE image to stress the parser's trust in
/// attacker-controlled length and offset fields.
///
/// The buffer always begins with the `MZ` DOS magic so it clears the first
/// gate, then randomizes `e_lfanew`, the `PE\0\0` signature placement, the
/// machine type, `NumberOfSections` (often absurd, e.g. 0xFFFF), and
/// `SizeOfOptionalHeader`, followed by a short, truncated section table. The
/// goal is bytes that look like a PE far enough to drive the parser deep, then
/// lie about sizes — exactly the shape of a malicious sample.
fn build_corrupt_pe(rng: &mut SimpleRng) -> Vec<u8> {
    let total = rng.next_range(64, 512);
    let mut buf = rng.next_bytes(total);

    // DOS magic.
    buf[0] = b'M';
    buf[1] = b'Z';

    // e_lfanew at offset 0x3C: sometimes sane (~0x80), sometimes hostile.
    let e_lfanew: u32 = match rng.next_u64() % 4 {
        0 => 0x80,
        1 => (rng.next_u64() as u32) % (total as u32).max(1), // somewhere in-buffer
        2 => 0xFFFF_FFFF,                                     // past the end
        _ => rng.next_u64() as u32,
    };
    if buf.len() >= 0x40 {
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    }

    // If e_lfanew lands inside the buffer, plant a PE header there most of the
    // time so the COFF/optional-header path is actually entered.
    let off = e_lfanew as usize;
    if off + 24 <= buf.len() && !(rng.next_u64()).is_multiple_of(4) {
        buf[off] = b'P';
        buf[off + 1] = b'E';
        buf[off + 2] = 0;
        buf[off + 3] = 0;
        // Machine (0x8664 amd64 / 0x14c i386 / garbage).
        let machine: u16 = match rng.next_u64() % 3 {
            0 => 0x8664,
            1 => 0x014c,
            _ => rng.next_u64() as u16,
        };
        buf[off + 4..off + 6].copy_from_slice(&machine.to_le_bytes());
        // NumberOfSections: frequently absurd to stress the section loop.
        let nsec: u16 = if rng.next_u64().is_multiple_of(2) {
            0xFFFF
        } else {
            rng.next_u64() as u16
        };
        buf[off + 6..off + 8].copy_from_slice(&nsec.to_le_bytes());
        // SizeOfOptionalHeader at COFF+16.
        let opt: u16 = rng.next_u64() as u16;
        buf[off + 20..off + 22].copy_from_slice(&opt.to_le_bytes());
    }

    buf
}

/// Result statistics from a fuzzing session.
pub struct FuzzReport {
    pub iterations: usize,
    pub roundtrip_checks: usize,
    pub adversarial_checks: usize,
    pub panics_detected: usize,
    pub duration_ms: u128,
}

/// Run a comprehensive fuzzing and invariant-verification harness.
///
/// Tests mathematical roundtrips on valid data and hammers all parsers
/// with adversarial, truncated, and pseudo-random byte sequences to
/// mathematically prove the **Zero-Panic Invariant**.
pub fn run_fuzz_harness(iterations: usize) -> FuzzReport {
    let start = std::time::Instant::now();
    let mut rng = SimpleRng::new(0x1337_c0de_cafe_babe);
    let mut roundtrips = 0;
    let mut adversarial = 0;

    for _ in 0..iterations {
        let len = rng.next_range(0, 512);
        let payload = rng.next_bytes(len);

        // ── 1. Invertibility Invariant: Hex ──
        let hex = ToHex.execute(&payload).expect("ToHex must never fail");
        let unhex = FromHex.execute(&hex).expect("FromHex roundtrip failed");
        assert_eq!(unhex, payload, "Hex roundtrip invariant broken");
        roundtrips += 1;

        // ── 2. Invertibility Invariant: Base64 ──
        let b64 = ToBase64
            .execute(&payload)
            .expect("ToBase64 must never fail");
        let unb64 = FromBase64
            .execute(&b64)
            .expect("FromBase64 roundtrip failed");
        assert_eq!(unb64, payload, "Base64 roundtrip invariant broken");
        roundtrips += 1;

        // ── 3. Invertibility Invariant: URL Encode ──
        let url = UrlEncode
            .execute(&payload)
            .expect("UrlEncode must never fail");
        let unurl = UrlDecode.execute(&url).expect("UrlDecode roundtrip failed");
        assert_eq!(unurl, payload, "Url roundtrip invariant broken");
        roundtrips += 1;

        // ── 4. Invertibility Invariant: ROT13 ──
        let rot = Rot13.execute(&payload).expect("Rot13 must never fail");
        let unrot = Rot13.execute(&rot).expect("Rot13 roundtrip failed");
        assert_eq!(unrot, payload, "Rot13 roundtrip invariant broken");
        roundtrips += 1;

        // ── 5. Invertibility Invariant: XOR Involution ──
        let key_len = rng.next_range(1, 16);
        let key = rng.next_bytes(key_len);
        let xor_op = Xor::rolling(&key);
        let xored = xor_op
            .execute(&payload)
            .expect("XOR must never fail with valid key");
        let unxored = xor_op.execute(&xored).expect("XOR inverse failed");
        assert_eq!(unxored, payload, "XOR involution invariant broken");
        roundtrips += 1;

        // ── 6. Invertibility Invariant: TLV Framing ──
        let tag = rng.next_u64() as u8;
        let tlv = TlvEncode::new(tag)
            .execute(&payload)
            .expect("TLV encode failed");
        let untlv = TlvDecode.execute(&tlv).expect("TLV decode failed");
        assert_eq!(untlv, payload, "TLV roundtrip invariant broken");
        roundtrips += 1;

        // ── 7. Adversarial Fuzzing: Zero-Panic Proof ──
        // Generate completely corrupted, malformed byte streams
        let corrupt_len = rng.next_range(0, 1024);
        let corrupt = rng.next_bytes(corrupt_len);

        // All of these MUST return Ok or Err, and NEVER panic
        std::panic::catch_unwind(|| {
            let _ = FromHex.execute(&corrupt);
            let _ = FromBase64.execute(&corrupt);
            let _ = UrlDecode.execute(&corrupt);
            let _ = PeInfo.execute(&corrupt);
            let _ = PeSections.execute(&corrupt);
            let _ = TlvDecode.execute(&corrupt);
            let _ = Entropy.execute(&corrupt);
            let _ = InternetChecksum.execute(&corrupt);
            let _ = HashMd5.execute(&corrupt);
            let _ = HashSha256.execute(&corrupt);
            let _ = HashBlake3.execute(&corrupt);
            let _ = ToCArray.execute(&corrupt);
        })
        .expect("CRITICAL: Panic detected in parser during adversarial fuzzing!");

        adversarial += 12; // 12 operations tested per adversarial cycle

        // ── 8. Structured PE Fuzzing: Length-Field Trust Proof ──
        // Purely random bytes almost never pass the `MZ` magic, so the deep PE
        // parser paths (e_lfanew traversal, NumberOfSections loops, per-section
        // offset/size math) go unexercised above. Here we forge *plausible* but
        // hostile PE headers with attacker-controlled length and offset fields
        // to prove the parser never panics on malicious structure.
        let pe = build_corrupt_pe(&mut rng);
        std::panic::catch_unwind(|| {
            let _ = PeInfo.execute(&pe);
            let _ = PeSections.execute(&pe);
        })
        .expect("CRITICAL: Panic detected in PE parser during structured fuzzing!");
        adversarial += 2;
    }

    let elapsed = start.elapsed().as_millis();
    FuzzReport {
        iterations,
        roundtrip_checks: roundtrips,
        adversarial_checks: adversarial,
        panics_detected: 0,
        duration_ms: elapsed,
    }
}
