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

        // Auto-decode & XOR recovery (Phase 1)
        "magic" => {
            let depth = arg.and_then(|a| a.parse::<usize>().ok()).unwrap_or(6);
            Some(Box::new(ops::Magic::new(depth)))
        }
        "xor_brute" => Some(Box::new(ops::XorBrute)),
        "rc4" => {
            let key = arg.unwrap_or("");
            if key.is_empty() {
                return None;
            }
            let key_bytes = if let Some(hex) =
                key.strip_prefix("0x").or_else(|| key.strip_prefix("0X"))
            {
                let clean = hex.replace(|c: char| c.is_whitespace() || c == ',' || c == ':', "");
                if clean.is_empty() || !clean.len().is_multiple_of(2) {
                    return None;
                }
                let mut b = Vec::new();
                for pair in clean.as_bytes().chunks_exact(2) {
                    b.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
                }
                b
            } else {
                key.as_bytes().to_vec()
            };
            Some(Box::new(ops::Rc4::new(&key_bytes)))
        }
        "vigenere" => arg
            .filter(|a| !a.is_empty())
            .map(|a| Box::new(ops::Vigenere::new(a.as_bytes(), false)) as Box<dyn Operation>),
        "vigenere_decrypt" => arg
            .filter(|a| !a.is_empty())
            .map(|a| Box::new(ops::Vigenere::new(a.as_bytes(), true)) as Box<dyn Operation>),
        "atbash" => Some(Box::new(ops::Atbash)),
        "caesar_brute" => Some(Box::new(ops::CaesarBrute)),
        "to_morse" => Some(Box::new(ops::ToMorse)),
        "from_morse" => Some(Box::new(ops::FromMorse)),
        "badchars" => {
            let bytes = ops::parse_byte_list(arg.unwrap_or("00"));
            Some(Box::new(ops::BadChars::new(&bytes)))
        }
        "xor_break" => {
            let max_ks = arg.and_then(|a| a.parse::<usize>().ok()).unwrap_or(40);
            Some(Box::new(ops::XorBreak::new(max_ks)))
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
        "elf_info" => Some(Box::new(ops::ElfInfo)),
        "checksec" => Some(Box::new(ops::Checksec)),
        "file_type" => Some(Box::new(ops::FileType)),
        "carve" => Some(Box::new(ops::Carve)),
        "triage" => Some(Box::new(ops::Triage)),

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
        (
            "magic",
            "Recursive auto-decode (base64/hex/url/rot13); depth via :N",
        ),
        (
            "xor_brute",
            "Single-byte XOR brute force, ranked by plaintext score",
        ),
        (
            "rc4",
            "RC4 stream cipher (symmetric); key via :key or :0xHEX",
        ),
        ("vigenere", "Vigenère encrypt (key via :key)"),
        ("vigenere_decrypt", "Vigenère decrypt (key via :key)"),
        ("atbash", "Atbash substitution (self-inverse)"),
        ("caesar_brute", "Brute-force all 25 Caesar shifts, ranked"),
        ("to_morse", "Encode ASCII text to Morse code"),
        ("from_morse", "Decode Morse code to ASCII text"),
        (
            "badchars",
            "Report forbidden bytes & offsets (e.g. badchars:00,0a,0d)",
        ),
        (
            "xor_break",
            "Break repeating-key XOR (Hamming keysize + per-column solve)",
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
            "elf_info",
            "ELF header triage (class, machine, type, entry)",
        ),
        (
            "checksec",
            "ELF exploit mitigations (NX, PIE, RELRO, canary, Fortify)",
        ),
        ("file_type", "Identify file type by magic bytes"),
        ("carve", "Scan for embedded file signatures & offsets"),
        (
            "triage",
            "One-shot recon: type, hashes, entropy, mitigations, embedded files",
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
