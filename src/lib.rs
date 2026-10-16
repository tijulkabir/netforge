pub mod error;
pub mod fuzz;
pub mod input;
pub mod op;
pub mod ops;
pub mod pipeline;
pub mod registry;

// Root-level re-exports for ergonomic usage.
pub use error::NetForgeError;
pub use fuzz::{run_fuzz_harness, FuzzReport};
pub use input::InputData;
pub use op::Operation;
pub use ops::*;
pub use pipeline::Pipeline;
pub use registry::{build_operation, list_operations};

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────── Encoding ────────────────────

    #[test]
    fn hex_roundtrip() {
        let data = b"NetForge v2";
        let encoded = ToHex.execute(data).unwrap();
        let decoded = FromHex.execute(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn rot13_involution() {
        let data = b"Attack at dawn!";
        let enc = Rot13.execute(data).unwrap();
        let dec = Rot13.execute(&enc).unwrap();
        assert_eq!(dec, data);
        assert_ne!(enc, data.to_vec()); // actually changed
    }

    #[test]
    fn base64_roundtrip() {
        for input in &[
            b"".to_vec(),
            b"f".to_vec(),
            b"fo".to_vec(),
            b"foo".to_vec(),
            b"foobar".to_vec(),
        ] {
            let enc = ToBase64.execute(input).unwrap();
            let dec = FromBase64.execute(&enc).unwrap();
            assert_eq!(&dec, input, "Base64 roundtrip failed for {:?}", input);
        }
    }

    #[test]
    fn base64_known_vectors() {
        // RFC 4648 test vectors
        assert_eq!(ToBase64.execute(b"").unwrap(), b"");
        assert_eq!(ToBase64.execute(b"f").unwrap(), b"Zg==");
        assert_eq!(ToBase64.execute(b"fo").unwrap(), b"Zm8=");
        assert_eq!(ToBase64.execute(b"foo").unwrap(), b"Zm9v");
        assert_eq!(ToBase64.execute(b"foob").unwrap(), b"Zm9vYg==");
        assert_eq!(ToBase64.execute(b"fooba").unwrap(), b"Zm9vYmE=");
        assert_eq!(ToBase64.execute(b"foobar").unwrap(), b"Zm9vYmFy");
    }

    #[test]
    fn url_encode_roundtrip() {
        let input = b"hello world! foo@bar.com/path?q=1&b=2";
        let enc = UrlEncode.execute(input).unwrap();
        let dec = UrlDecode.execute(&enc).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn from_hex_sanitizes_dumps() {
        // Wireshark / IDA Pro / Python hex dump formats
        assert_eq!(FromHex.execute(b"\\x41\\x42\\x43").unwrap(), b"ABC");
        assert_eq!(FromHex.execute(b"0x41, 0x42, 0x43").unwrap(), b"ABC");
        assert_eq!(FromHex.execute(b"41 42 43").unwrap(), b"ABC");
        assert_eq!(FromHex.execute(b"41:42:43").unwrap(), b"ABC");
        assert_eq!(FromHex.execute(b"41\r\n42\n43").unwrap(), b"ABC");
    }

    #[test]
    fn base64_rejects_padding_smuggling() {
        // Middle-of-stream padding must fail
        assert_eq!(
            FromBase64.execute(b"A=AA"),
            Err(NetForgeError::InvalidBase64)
        );
        assert_eq!(
            FromBase64.execute(b"==AA"),
            Err(NetForgeError::InvalidBase64)
        );
        assert_eq!(
            FromBase64.execute(b"A==="),
            Err(NetForgeError::InvalidBase64)
        );
        assert_eq!(
            FromBase64.execute(b"Zm9v=YmFy"),
            Err(NetForgeError::InvalidBase64)
        );
    }

    #[test]
    fn base64_supports_url_safe_and_unpadded() {
        // URL-safe characters '-' and '_'
        let dec = FromBase64.execute(b"-__-").unwrap();
        assert_eq!(dec.len(), 3);

        // Unpadded Base64 (JWT token style: 'Zm9v' is 4 chars, 'Zg' is 2 chars = 'f')
        assert_eq!(FromBase64.execute(b"Zg").unwrap(), b"f");
        assert_eq!(FromBase64.execute(b"Zm8").unwrap(), b"fo");
    }

    // ─────────────────── Crypto ──────────────────────

    #[test]
    fn xor_empty_key_does_not_panic() {
        let xor = Xor::rolling(&[]);
        assert!(xor.execute(b"test data").is_err());
        assert!(build_operation("xor", Some("")).is_none());
        assert!(build_operation("xor", Some("0x")).is_none());
    }

    #[test]
    fn xor_roundtrip() {
        let data = b"secret payload";
        let key = Xor::single(0x42);
        let enc = key.execute(data).unwrap();
        let dec = key.execute(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn xor_rolling_key() {
        let data = b"AAAA";
        let key = Xor::rolling(b"\x01\x02");
        let enc = key.execute(data).unwrap();
        assert_eq!(enc, vec![b'A' ^ 1, b'A' ^ 2, b'A' ^ 1, b'A' ^ 2]);
    }

    // ─────────────────── Hashing ─────────────────────

    #[test]
    fn md5_known_hash() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let hash = HashMd5.execute(b"").unwrap();
        assert_eq!(
            std::str::from_utf8(&hash).unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn sha256_known_hash() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = HashSha256.execute(b"").unwrap();
        assert_eq!(
            std::str::from_utf8(&hash).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        let hash = HashSha256.execute(b"hello").unwrap();
        assert_eq!(
            std::str::from_utf8(&hash).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn blake3_deterministic() {
        let h1 = HashBlake3.execute(b"test").unwrap();
        let h2 = HashBlake3.execute(b"test").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 256-bit = 64 hex chars
    }

    #[test]
    fn ntlm_known_hash() {
        // NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
        let hash = HashNtlm.execute(b"password").unwrap();
        assert_eq!(
            std::str::from_utf8(&hash).unwrap(),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
    }

    // ─────────────────── Analysis ────────────────────

    #[test]
    fn entropy_of_uniform_bytes() {
        // 256 distinct bytes → max entropy = 8.0
        let data: Vec<u8> = (0..=255).collect();
        let result = Entropy.execute(&data).unwrap();
        let val: f64 = std::str::from_utf8(&result).unwrap().parse().unwrap();
        assert!((val - 8.0).abs() < 0.001, "Expected ~8.0, got {val}");
    }

    #[test]
    fn entropy_of_zeros() {
        let data = vec![0u8; 100];
        let result = Entropy.execute(&data).unwrap();
        let val: f64 = std::str::from_utf8(&result).unwrap().parse().unwrap();
        assert!(val.abs() < 0.001, "Expected ~0.0, got {val}");
    }

    #[test]
    fn strings_extraction() {
        let mut data = vec![0u8; 10];
        data.extend_from_slice(b"HelloWorld");
        data.extend_from_slice(&[0, 0, 0]);
        data.extend_from_slice(b"ab"); // too short
        data.extend_from_slice(&[0]);
        data.extend_from_slice(b"LongEnoughString");
        let result = ExtractStrings::default().execute(&data).unwrap();
        let text = std::str::from_utf8(&result).unwrap();
        assert!(text.contains("HelloWorld"));
        assert!(text.contains("LongEnoughString"));
        assert!(!text.contains("ab\n")); // below min length
    }

    #[test]
    fn byte_length() {
        let data = b"twelve bytes";
        let result = ByteLength.execute(data).unwrap();
        assert_eq!(std::str::from_utf8(&result).unwrap(), "12");
    }

    // ─────────────────── Network ─────────────────────

    #[test]
    fn defang_refang_ip() {
        let ip = b"192.168.1.1";
        let defanged = DefangIp.execute(ip).unwrap();
        assert_eq!(defanged, b"192[.]168[.]1[.]1");
        let refanged = RefangIp.execute(&defanged).unwrap();
        assert_eq!(refanged, ip);
    }

    #[test]
    fn defang_refang_url() {
        let url = b"https://evil.example.com/payload";
        let defanged = DefangUrl.execute(url).unwrap();
        assert_eq!(defanged, b"https[://]evil[.]example[.]com/payload");
        let refanged = RefangUrl.execute(&defanged).unwrap();
        assert_eq!(refanged, url);
    }

    // ─────────────────── Pipeline ────────────────────

    #[test]
    fn pipeline_chain() {
        let mut pipe = Pipeline::new();
        pipe.push(Box::new(Xor::single(0xFF)));
        pipe.push(Box::new(ToHex));
        let result = pipe.execute(b"AB").unwrap();
        // 'A' ^ 0xFF = 0xBE, 'B' ^ 0xFF = 0xBD
        assert_eq!(result, b"bebd");
    }

    #[test]
    fn pipeline_scratch_buffer_ping_pong_multistage() {
        let original = b"NetForge v2.0 Production Pipeline Buffer Reuse Test";
        let mut pipe = Pipeline::new();
        pipe.push(Box::new(Xor::rolling(b"VANGUARD")));
        pipe.push(Box::new(ToBase64));
        pipe.push(Box::new(FromBase64));
        pipe.push(Box::new(ToHex));
        pipe.push(Box::new(FromHex));
        pipe.push(Box::new(Rot13));
        pipe.push(Box::new(Rot13));
        pipe.push(Box::new(Xor::rolling(b"VANGUARD")));

        let result = pipe.execute(original).unwrap();
        assert_eq!(result, original);

        // Test empty pipeline
        let empty_pipe = Pipeline::new();
        assert_eq!(empty_pipe.execute(original).unwrap(), original);

        // Test single op
        let mut single_pipe = Pipeline::new();
        single_pipe.push(Box::new(Rot13));
        let r13 = single_pipe.execute(b"hello").unwrap();
        assert_eq!(r13, b"uryyb");
    }

    // ─────────────────── Registry ────────────────────

    #[test]
    fn registry_builds_all() {
        let names = list_operations();
        for (name, _) in &names {
            if *name == "xor" || *name == "strings" {
                continue;
            } // need args
            assert!(
                build_operation(name, None).is_some(),
                "Registry failed to build '{name}'"
            );
        }
        // XOR with arg
        assert!(build_operation("xor", Some("42")).is_some());
        assert!(build_operation("xor", Some("0xDEAD")).is_some());
        // Strings with arg
        assert!(build_operation("strings", Some("6")).is_some());
    }

    // ─────────────────── High-Throughput / Phase 1 ─────────

    #[test]
    fn parallel_entropy_large_buffer() {
        // 128 KB buffer (triggers Rayon par_chunks)
        let chunk: Vec<u8> = (0..=255).collect();
        let large: Vec<u8> = chunk.repeat(512); // 256 * 512 = 131,072 bytes (128 KB)
        assert_eq!(large.len(), 131072);

        let result = Entropy.execute(&large).unwrap();
        let val: f64 = std::str::from_utf8(&result).unwrap().parse().unwrap();
        // Since each byte occurs with exact equal probability, entropy must be 8.0
        assert!((val - 8.0).abs() < 0.0001, "Expected ~8.0, got {val}");
    }

    #[test]
    fn input_data_mmap_reads_file() {
        let input = InputData::from_file("Cargo.toml").unwrap();
        assert!(!input.is_empty());
        assert!(input.contains(&b"[package]"[0]));
    }

    #[test]
    fn input_data_owned_bytes() {
        let input = InputData::from_bytes(b"hello world".to_vec());
        assert_eq!(&*input, b"hello world");
    }

    // ─────────────────── Binary & Protocol / Phase 2 ───────

    #[test]
    fn tlv_encode_decode_roundtrip() {
        let payload = b"secret_c2_telemetry";
        let frame = TlvEncode::new(0x07).execute(payload).unwrap();
        assert_eq!(frame[0], 0x07); // Type tag
        assert_eq!(&frame[1..5], &(payload.len() as u32).to_be_bytes()); // BE length

        let extracted = TlvDecode.execute(&frame).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn tlv_truncated_frame_fails() {
        assert!(TlvDecode.execute(b"\x01\x00\x00").is_err());
        assert!(TlvDecode.execute(b"\x01\x00\x00\x00\x10short").is_err());
    }

    #[test]
    fn internet_checksum_calculation() {
        // Known IP header without checksum
        let ip_hdr =
            b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c";
        let csum = InternetChecksum.execute(ip_hdr).unwrap();
        assert_eq!(csum.len(), 4); // 4-char hex
        assert_eq!(std::str::from_utf8(&csum).unwrap(), "b1e6");
    }

    #[test]
    fn to_c_array_formatting() {
        let data = b"XYZ";
        let out = ToCArray.execute(data).unwrap();
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("const unsigned char payload[3]"));
        assert!(text.contains("0x58, 0x59, 0x5a"));
    }

    #[test]
    fn pe_info_invalid_dos_fails() {
        assert!(PeInfo.execute(b"NOT_A_PE_FILE").is_err());
        assert!(PeSections.execute(b"MZ_TOO_SHORT").is_err());
    }

    #[test]
    fn fuzz_harness_smoke_test() {
        let report = run_fuzz_harness(100);
        assert_eq!(report.iterations, 100);
        assert_eq!(report.panics_detected, 0);
        assert!(report.roundtrip_checks >= 600);
        assert!(report.adversarial_checks >= 1200);
    }
}
