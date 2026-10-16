use crate::error::NetForgeError;
use crate::op::Operation;

use md5::Md5;
use sha2::{Digest, Sha256, Sha512};

// ───────────────────────────── MD5 ────────────────────────────

/// MD5 digest — outputs 32-char lowercase hex.
///
/// Used in CTFs, NTLM chains, and legacy file-integrity checks.
/// **Never** use for security-sensitive hashing in production.
pub struct HashMd5;

impl Operation for HashMd5 {
    fn name(&self) -> &str {
        "md5"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(32);
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let digest = Md5::digest(input);
        hex_encode_into(&digest, output);
        Ok(())
    }
}

// ──────────────────────────── SHA-256 ─────────────────────────

/// SHA-256 digest — 64-char lowercase hex output.
///
/// The workhorse for file hashing, IoC correlation, and
/// malware sample identification.
pub struct HashSha256;

impl Operation for HashSha256 {
    fn name(&self) -> &str {
        "sha256"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(64);
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let digest = Sha256::digest(input);
        hex_encode_into(&digest, output);
        Ok(())
    }
}

// ──────────────────────────── SHA-512 ─────────────────────────

/// SHA-512 digest — 128-char lowercase hex output.
pub struct HashSha512;

impl Operation for HashSha512 {
    fn name(&self) -> &str {
        "sha512"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(128);
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let digest = Sha512::digest(input);
        hex_encode_into(&digest, output);
        Ok(())
    }
}

// ──────────────────────────── BLAKE3 ──────────────────────────

/// BLAKE3 — blazing-fast cryptographic hash (256-bit output, hex).
///
/// Ideal for high-throughput file scanning where SHA-256 is too slow.
pub struct HashBlake3;

impl Operation for HashBlake3 {
    fn name(&self) -> &str {
        "blake3"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(64);
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update_rayon(input);
        let hash = hasher.finalize();
        output.clear();
        output.extend_from_slice(hash.to_hex().as_bytes());
        Ok(())
    }
}

/// NTLM hash — used in Windows credential attacks (pass-the-hash).
///
/// Algorithm: MD4(UTF-16LE(password)).
pub struct HashNtlm;

impl Operation for HashNtlm {
    fn name(&self) -> &str {
        "ntlm"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut out = Vec::with_capacity(32);
        self.execute_into(input, &mut out)?;
        Ok(out)
    }
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        use md4::Digest;
        let text = std::str::from_utf8(input).map_err(|_| NetForgeError::InvalidUtf8)?;
        let utf16le: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let digest = md4::Md4::digest(&utf16le);
        hex_encode_into(&digest, output);
        Ok(())
    }
}

// ─────────────────────── helpers ──────────────────────────────

fn hex_encode_into(bytes: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.clear();
    out.reserve(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
}
