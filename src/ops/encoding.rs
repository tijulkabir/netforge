use crate::error::NetForgeError;
use crate::op::Operation;

// ───────────────────────────── Hex ─────────────────────────────

/// Encode raw bytes to lowercase hexadecimal ASCII.
pub struct ToHex;

impl Operation for ToHex {
    fn name(&self) -> &str {
        "to_hex"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(input.len() * 2);
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        output.clear();
        output.reserve(input.len() * 2);
        for &b in input {
            output.push(HEX_LOWER[(b >> 4) as usize]);
            output.push(HEX_LOWER[(b & 0x0f) as usize]);
        }
        Ok(())
    }
}

/// Decode hexadecimal ASCII back to raw bytes.
///
/// Automatically sanitizes common delimiters and prefixes from IDA Pro,
/// Ghidra, Wireshark, and Python hex strings (e.g., `\x41\x42`, `0x41, 0x42`, `41 42 43`).
pub struct FromHex;

impl Operation for FromHex {
    fn name(&self) -> &str {
        "from_hex"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::new();
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let clean = sanitize_hex(input);
        if clean.is_empty() {
            output.clear();
            return Ok(());
        }
        if !clean.len().is_multiple_of(2) {
            return Err(NetForgeError::InvalidHexLength);
        }
        output.clear();
        output.reserve(clean.len() / 2);
        for pair in clean.chunks_exact(2) {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            output.push((hi << 4) | lo);
        }
        Ok(())
    }
}

fn sanitize_hex(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        // Skip whitespace, commas, colons, semicolons
        if input[i].is_ascii_whitespace()
            || input[i] == b','
            || input[i] == b':'
            || input[i] == b';'
        {
            i += 1;
            continue;
        }
        // Skip \x or \X prefix
        if input[i] == b'\\'
            && i + 1 < input.len()
            && (input[i + 1] == b'x' || input[i + 1] == b'X')
        {
            i += 2;
            continue;
        }
        // Skip 0x or 0X prefix
        if input[i] == b'0' && i + 1 < input.len() && (input[i + 1] == b'x' || input[i + 1] == b'X')
        {
            i += 2;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_val(byte: u8) -> Result<u8, NetForgeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(NetForgeError::InvalidHexCharacter(byte as char)),
    }
}

// ───────────────────────────── ROT13 ──────────────────────────

/// Classic ROT13 — its own inverse.
pub struct Rot13;

impl Operation for Rot13 {
    fn name(&self) -> &str {
        "rot13"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(input.len());
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        output.clear();
        output.reserve(input.len());
        for &b in input {
            output.push(match b {
                b'a'..=b'm' | b'A'..=b'M' => b + 13,
                b'n'..=b'z' | b'N'..=b'Z' => b - 13,
                _ => b,
            });
        }
        Ok(())
    }
}

// ───────────────────────────── Base64 ─────────────────────────

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// RFC 4648 Base64 encoding — implemented from scratch, no crate.
pub struct ToBase64;

impl Operation for ToBase64 {
    fn name(&self) -> &str {
        "to_base64"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        output.clear();
        output.reserve(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let (b0, b1, b2) = match chunk.len() {
                3 => (chunk[0], chunk[1], chunk[2]),
                2 => (chunk[0], chunk[1], 0),
                1 => (chunk[0], 0, 0),
                _ => unreachable!(),
            };
            let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
            output.push(B64_ALPHABET[((triple >> 18) & 0x3F) as usize]);
            output.push(B64_ALPHABET[((triple >> 12) & 0x3F) as usize]);
            if chunk.len() > 1 {
                output.push(B64_ALPHABET[((triple >> 6) & 0x3F) as usize]);
            } else {
                output.push(b'=');
            }
            if chunk.len() > 2 {
                output.push(B64_ALPHABET[(triple & 0x3F) as usize]);
            } else {
                output.push(b'=');
            }
        }
        Ok(())
    }
}

/// RFC 4648 Base64 decoding with URL-safe and unpadded token support.
/// Rejects middle-stream padding smuggling.
pub struct FromBase64;

impl Operation for FromBase64 {
    fn name(&self) -> &str {
        "from_base64"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::new();
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let mut clean: Vec<u8> = input
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if clean.is_empty() {
            output.clear();
            return Ok(());
        }

        // Support unpadded Base64 (JWTs, URL-safe tokens)
        match clean.len() % 4 {
            0 => {}
            2 => {
                clean.push(b'=');
                clean.push(b'=');
            }
            3 => {
                clean.push(b'=');
            }
            _ => return Err(NetForgeError::InvalidBase64),
        }

        // Validate padding position: '=' is only allowed in the last 1 or 2 bytes
        let total = clean.len();
        if let Some(first_pad) = clean.iter().position(|&b| b == b'=') {
            if first_pad < total - 2 {
                return Err(NetForgeError::InvalidBase64);
            }
            if first_pad == total - 2 && clean[total - 1] != b'=' {
                return Err(NetForgeError::InvalidBase64);
            }
        }

        let num_quads = total / 4;
        output.clear();
        output.reserve(num_quads * 3);

        for (quad_idx, quad) in clean.chunks_exact(4).enumerate() {
            let is_last = quad_idx == num_quads - 1;
            if !is_last {
                let v0 = b64_val(quad[0])? as u32;
                let v1 = b64_val(quad[1])? as u32;
                let v2 = b64_val(quad[2])? as u32;
                let v3 = b64_val(quad[3])? as u32;
                let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
                output.push((triple >> 16) as u8);
                output.push((triple >> 8) as u8);
                output.push(triple as u8);
            } else {
                let v0 = b64_val(quad[0])? as u32;
                let v1 = b64_val(quad[1])? as u32;
                if quad[2] == b'=' {
                    if quad[3] != b'=' {
                        return Err(NetForgeError::InvalidBase64);
                    }
                    output.push(((v0 << 2) | (v1 >> 4)) as u8);
                } else if quad[3] == b'=' {
                    let v2 = b64_val(quad[2])? as u32;
                    let triple = (v0 << 18) | (v1 << 12) | (v2 << 6);
                    output.push((triple >> 16) as u8);
                    output.push((triple >> 8) as u8);
                } else {
                    let v2 = b64_val(quad[2])? as u32;
                    let v3 = b64_val(quad[3])? as u32;
                    let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
                    output.push((triple >> 16) as u8);
                    output.push((triple >> 8) as u8);
                    output.push(triple as u8);
                }
            }
        }
        Ok(())
    }
}

fn b64_val(b: u8) -> Result<u8, NetForgeError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' | b'-' => Ok(62),
        b'/' | b'_' => Ok(63),
        _ => Err(NetForgeError::InvalidBase64),
    }
}

// ──────────────────────── URL Percent Encoding ────────────────

/// Percent-encode non-URL-safe bytes (RFC 3986 unreserved set).
pub struct UrlEncode;

impl Operation for UrlEncode {
    fn name(&self) -> &str {
        "url_encode"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(input.len());
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        output.clear();
        output.reserve(input.len());
        for &b in input {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                output.push(b);
            } else {
                output.push(b'%');
                output.push(HEX_LOWER[(b >> 4) as usize]);
                output.push(HEX_LOWER[(b & 0x0f) as usize]);
            }
        }
        Ok(())
    }
}

/// Decode percent-encoded bytes back to raw form.
pub struct UrlDecode;

impl Operation for UrlDecode {
    fn name(&self) -> &str {
        "url_decode"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(input.len());
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        output.clear();
        output.reserve(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] == b'%' {
                if i + 2 >= input.len() {
                    return Err(NetForgeError::InvalidUrlEncoding);
                }
                let hi = hex_val(input[i + 1]).map_err(|_| NetForgeError::InvalidUrlEncoding)?;
                let lo = hex_val(input[i + 2]).map_err(|_| NetForgeError::InvalidUrlEncoding)?;
                output.push((hi << 4) | lo);
                i += 3;
            } else if input[i] == b'+' {
                output.push(b' '); // form-data convention
                i += 1;
            } else {
                output.push(input[i]);
                i += 1;
            }
        }
        Ok(())
    }
}
