use crate::op::Operation;
use crate::ops;

/// Build a boxed operation from its CLI name.
///
/// This is the dynamic dispatch table that maps string identifiers
/// to concrete operation structs.  Adding a new operation?  Just
/// add a match arm here and in [`list_operations`].
pub fn build_operation(name: &str, arg: Option<&str>) -> Option<Box<dyn Operation>> {
    match name {
        // Encoding
        "to_hex" | "hex" => Some(Box::new(ops::ToHex)),
        "from_hex" | "unhex" => Some(Box::new(ops::FromHex)),
        "rot13" => Some(Box::new(ops::Rot13)),
        "to_base64" | "b64" => Some(Box::new(ops::ToBase64)),
        "from_base64" | "unb64" => Some(Box::new(ops::FromBase64)),
        "url_encode" => Some(Box::new(ops::UrlEncode)),
        "url_decode" => Some(Box::new(ops::UrlDecode)),

        // Crypto
        "xor" => {
            let key_str = arg.unwrap_or("0");
            if key_str.is_empty() {
                return None;
            }
            if let Some(hex) = key_str
                .strip_prefix("0x")
                .or_else(|| key_str.strip_prefix("0X"))
            {
                let clean_hex =
                    hex.replace(|c: char| c.is_whitespace() || c == ',' || c == ':', "");
                if clean_hex.is_empty() || clean_hex.len() % 2 != 0 {
                    return None;
                }
                let mut key_bytes = Vec::new();
                for pair in clean_hex.as_bytes().chunks_exact(2) {
                    let s = std::str::from_utf8(pair).ok()?;
                    let byte = u8::from_str_radix(s, 16).ok()?;
                    key_bytes.push(byte);
                }
                if key_bytes.is_empty() {
                    return None;
                }
                Some(Box::new(ops::Xor::rolling(&key_bytes)))
            } else if let Ok(byte) = key_str.parse::<u8>() {
                Some(Box::new(ops::Xor::single(byte)))
            } else {
                let bytes = key_str.as_bytes();
                if bytes.is_empty() {
                    return None;
                }
                Some(Box::new(ops::Xor::rolling(bytes)))
            }
        }

        // Hashing
        "md5" => Some(Box::new(ops::HashMd5)),
        "sha256" => Some(Box::new(ops::HashSha256)),
        "sha512" => Some(Box::new(ops::HashSha512)),
        "blake3" => Some(Box::new(ops::HashBlake3)),
        "ntlm" => Some(Box::new(ops::HashNtlm)),

        // Analysis
        "entropy" => Some(Box::new(ops::Entropy)),
        "byte_freq" => Some(Box::new(ops::ByteFrequency)),
        "strings" => {
            let min_len = arg.and_then(|a| a.parse().ok()).unwrap_or(4);
            Some(Box::new(ops::ExtractStrings::new(min_len)))
        }
        "length" => Some(Box::new(ops::ByteLength)),

        // Network
        "defang_ip" => Some(Box::new(ops::DefangIp)),
        "refang_ip" => Some(Box::new(ops::RefangIp)),
        "defang_url" => Some(Box::new(ops::DefangUrl)),
        "refang_url" => Some(Box::new(ops::RefangUrl)),

        // Binary Analysis (Phase 2)
        "pe_info" => Some(Box::new(ops::PeInfo)),
        "pe_sections" => Some(Box::new(ops::PeSections)),

        // Protocol & Framing (Phase 2)
        "tlv_encode" => {
            let tag = arg.and_then(|a| a.parse::<u8>().ok()).unwrap_or(1);
            Some(Box::new(ops::TlvEncode::new(tag)))
        }
        "tlv_decode" => Some(Box::new(ops::TlvDecode)),
        "checksum" => Some(Box::new(ops::InternetChecksum)),
        "to_c_array" => Some(Box::new(ops::ToCArray)),

        _ => None,
    }
}

/// All registered operation names for `--list`.
pub fn list_operations() -> Vec<(&'static str, &'static str)> {
    vec![
        // (name, description)
        ("to_hex", "Encode bytes → hex string"),
        ("from_hex", "Decode hex string → bytes"),
        ("rot13", "ROT13 Caesar cipher (self-inverse)"),
        ("to_base64", "Base64 encode (RFC 4648)"),
        ("from_base64", "Base64 decode"),
        ("url_encode", "Percent-encode (RFC 3986)"),
        ("url_decode", "Percent-decode"),
        (
            "xor",
            "XOR cipher (single or rolling key via --arg or inline :key)",
        ),
        ("md5", "MD5 hash (32-char hex)"),
        ("sha256", "SHA-256 hash (64-char hex)"),
        ("sha512", "SHA-512 hash (128-char hex)"),
        ("blake3", "BLAKE3 multi-threaded tree hash (64-char hex)"),
        ("ntlm", "NTLM hash (MD4 of UTF-16LE)"),
        (
            "entropy",
            "Shannon entropy (multi-threaded Rayon bits/byte)",
        ),
        ("byte_freq", "Byte frequency histogram"),
        (
            "strings",
            "Extract printable strings (min len via --arg or :len)",
        ),
        ("length", "Byte length of input"),
        ("defang_ip", "Defang IP: 1.2.3.4 → 1[.]2[.]3[.]4"),
        ("refang_ip", "Refang IP: 1[.]2[.]3[.]4 → 1.2.3.4"),
        ("defang_url", "Defang URL for safe sharing"),
        ("refang_url", "Refang URL back to clickable"),
        (
            "pe_info",
            "PE header triage (arch, entry point, subsystem, timestamp)",
        ),
        (
            "pe_sections",
            "PE section table with RWX detection & per-section entropy",
        ),
        (
            "tlv_encode",
            "Frame payload with Type-Length-Value header (type via :type)",
        ),
        ("tlv_decode", "Extract payload from TLV packet frame"),
        ("checksum", "RFC 1071 16-bit Internet Checksum (IP/TCP/UDP)"),
        ("to_c_array", "Format bytes as C/C++ byte array declaration"),
    ]
}
