use netforge::*;
use proptest::prelude::*;

proptest! {
    // ── 1. Hex Invertibility Property ──
    #[test]
    fn prop_hex_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let hex = ToHex.execute(&data).unwrap();
        let unhex = FromHex.execute(&hex).unwrap();
        prop_assert_eq!(unhex, data);
    }

    // ── 2. Base64 Invertibility Property ──
    #[test]
    fn prop_base64_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let b64 = ToBase64.execute(&data).unwrap();
        let unb64 = FromBase64.execute(&b64).unwrap();
        prop_assert_eq!(unb64, data);
    }

    // ── 3. URL Encoding Invertibility Property ──
    #[test]
    fn prop_url_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let enc = UrlEncode.execute(&data).unwrap();
        let dec = UrlDecode.execute(&enc).unwrap();
        prop_assert_eq!(dec, data);
    }

    // ── 4. XOR Involution Property ──
    #[test]
    fn prop_xor_involution(
        data in proptest::collection::vec(any::<u8>(), 0..1024),
        key in proptest::collection::vec(any::<u8>(), 1..64) // Non-empty key
    ) {
        let xor_op = Xor::rolling(&key);
        let enc = xor_op.execute(&data).unwrap();
        let dec = xor_op.execute(&enc).unwrap();
        prop_assert_eq!(dec, data);
    }

    // ── 5. TLV Framing Roundtrip ──
    #[test]
    fn prop_tlv_roundtrip(
        data in proptest::collection::vec(any::<u8>(), 0..1024),
        tag in any::<u8>()
    ) {
        let framed = TlvEncode::new(tag).execute(&data).unwrap();
        let extracted = TlvDecode.execute(&framed).unwrap();
        prop_assert_eq!(extracted, data);
    }

    // ── 6. Zero-Panic Invariant on Arbitrary Malformed Data ──
    #[test]
    fn prop_no_panics_on_adversarial_bytes(corrupt in proptest::collection::vec(any::<u8>(), 0..1024)) {
        // These parsers must handle ANY byte slice without panicking
        let _ = FromHex.execute(&corrupt);
        let _ = FromBase64.execute(&corrupt);
        let _ = UrlDecode.execute(&corrupt);
        let _ = PeInfo.execute(&corrupt);
        let _ = PeSections.execute(&corrupt);
        let _ = TlvDecode.execute(&corrupt);
        let _ = InternetChecksum.execute(&corrupt);
        let _ = Entropy.execute(&corrupt);
    }
}
