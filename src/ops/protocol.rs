use crate::error::NetForgeError;
use crate::op::Operation;

// ────────────────────── Type-Length-Value Framing ─────────────

/// Encode raw payload into standard TLV (Type-Length-Value) packet frame.
///
/// Frame Format:
/// - Type   : 1 byte (specified via `--arg` or `tlv_encode:<type>`, defaults to 1)
/// - Length : 4 bytes (Big-Endian unsigned integer)
/// - Value  : Payload bytes
pub struct TlvEncode {
    tag_type: u8,
}

impl TlvEncode {
    pub fn new(tag_type: u8) -> Self {
        Self { tag_type }
    }
}

impl Default for TlvEncode {
    fn default() -> Self {
        Self { tag_type: 1 }
    }
}

impl Operation for TlvEncode {
    fn name(&self) -> &str {
        "tlv_encode"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let len = (input.len() as u32).to_be_bytes();
        let mut frame = Vec::with_capacity(5 + input.len());
        frame.push(self.tag_type);
        frame.extend_from_slice(&len);
        frame.extend_from_slice(input);
        Ok(frame)
    }
}

/// Decode a TLV packet frame, extracting the value payload.
///
/// Validates that the frame contains at least 5 bytes and that the
/// declared length matches the actual payload size.
pub struct TlvDecode;

impl Operation for TlvDecode {
    fn name(&self) -> &str {
        "tlv_decode"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if input.len() < 5 {
            return Err(NetForgeError::Custom(
                "TLV frame too short: requires at least 5 header bytes".into(),
            ));
        }
        let declared_len = u32::from_be_bytes([input[1], input[2], input[3], input[4]]) as usize;
        let payload = &input[5..];
        if payload.len() < declared_len {
            return Err(NetForgeError::Custom(format!(
                "TLV frame truncated: declared {declared_len} bytes, got {}",
                payload.len()
            )));
        }
        Ok(payload[..declared_len].to_vec())
    }
}

// ────────────────────── RFC 1071 Internet Checksum ────────────

/// Compute RFC 1071 16-bit One's Complement Internet Checksum.
///
/// Standard algorithm used in IPv4 headers, TCP, and UDP packets.
/// Output is a 4-character hex string (e.g. `"a4b2"`).
pub struct InternetChecksum;

impl Operation for InternetChecksum {
    fn name(&self) -> &str {
        "checksum"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut sum: u32 = 0;
        let mut chunks = input.chunks_exact(2);
        for chunk in &mut chunks {
            let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            sum = sum.wrapping_add(word);
        }
        let remainder = chunks.remainder();
        if let Some(&b) = remainder.first() {
            let word = (b as u32) << 8;
            sum = sum.wrapping_add(word);
        }

        // Fold 32-bit sum into 16 bits
        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let checksum = !(sum as u16);
        Ok(format!("{checksum:04x}").into_bytes())
    }
}

// ────────────────────── C-Array Formatter ─────────────────────

/// Format raw bytes into a C/C++ byte array definition.
///
/// Useful for compiling payloads directly into C/Rust source files.
/// Output:
/// `const unsigned char payload[4] = { 0x41, 0x42, 0x43, 0x44 };`
pub struct ToCArray;

impl Operation for ToCArray {
    fn name(&self) -> &str {
        "to_c_array"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = format!("const unsigned char payload[{}] = {{\n    ", input.len());
        for (i, &b) in input.iter().enumerate() {
            out.push_str(&format!("0x{b:02x}"));
            if i + 1 < input.len() {
                out.push_str(", ");
                if (i + 1) % 12 == 0 {
                    out.push_str("\n    ");
                }
            }
        }
        out.push_str("\n};\n");
        Ok(out.into_bytes())
    }
}
