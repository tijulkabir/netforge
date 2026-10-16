use crate::error::NetForgeError;
use crate::op::Operation;

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
}
