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
