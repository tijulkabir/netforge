use crate::error::NetForgeError;
use crate::op::Operation;
use std::io::{Read, Write};

/// Single-byte or rolling-key XOR cipher.
///
/// Rolling XOR repeats the key cyclically across the input —
/// the bread-and-butter of malware string deobfuscation.
pub struct Xor {
    key: Vec<u8>,
}

impl Xor {
    /// Single-byte XOR key.
    pub fn single(byte: u8) -> Self {
        Self { key: vec![byte] }
    }

    /// Multi-byte rolling key.
    pub fn rolling(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl Operation for Xor {
    fn name(&self) -> &str {
        "xor"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(input.len());
        self.execute_into(input, &mut out)?;
        Ok(out)
    }

    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        if self.key.is_empty() {
            return Err(NetForgeError::Custom("XOR key cannot be empty".to_string()));
        }
        output.clear();
        output.reserve(input.len());
        for (i, &b) in input.iter().enumerate() {
            output.push(b ^ self.key[i % self.key.len()]);
        }
        Ok(())
    }

    /// Constant-memory streaming XOR.
    ///
    /// Processes the input in 64 KiB chunks while tracking the absolute key
    /// position, so the rolling key stays aligned across chunk boundaries and
    /// a file far larger than RAM can be XORed through a pipe.
    fn transform_stream(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), NetForgeError> {
        if self.key.is_empty() {
            return Err(NetForgeError::Custom("XOR key cannot be empty".to_string()));
        }
        let klen = self.key.len();
        let mut buf = [0u8; 65536];
        let mut pos: usize = 0;
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| NetForgeError::Io(format!("stream read failed: {e}")))?;
            if n == 0 {
                break;
            }
            for b in &mut buf[..n] {
                *b ^= self.key[pos % klen];
                pos += 1;
            }
            writer
                .write_all(&buf[..n])
                .map_err(|e| NetForgeError::Io(format!("stream write failed: {e}")))?;
        }
        Ok(())
    }
}
