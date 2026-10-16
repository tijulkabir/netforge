use crate::error::NetForgeError;
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;

/// Zero-copy, high-throughput input buffer.
///
/// Wraps either a memory-mapped file (`Mmap`) or owned bytes in memory.
/// Implements `Deref<Target = [u8]>` so it can be passed directly as a
/// borrowed byte slice to any pipeline or operation.
pub enum InputData {
    /// Zero-copy memory-mapped file buffer (OS kernel page cache).
    Mmap(Mmap),
    /// In-memory owned byte buffer (stdin / inline CLI string).
    Owned(Vec<u8>),
}

impl Deref for InputData {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            InputData::Mmap(m) => m,
            InputData::Owned(v) => v,
        }
    }
}

impl AsRef<[u8]> for InputData {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl InputData {
    /// Open and memory-map a file from disk.
    ///
    /// For non-empty files, creates an OS virtual memory mapping (`Mmap`)
    /// with zero user-space heap allocation.  For 0-byte files, returns
    /// an empty owned buffer without erroring.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, NetForgeError> {
        let file = File::open(path.as_ref())
            .map_err(|e| NetForgeError::Custom(format!("cannot open file: {e}")))?;
        let meta = file
            .metadata()
            .map_err(|e| NetForgeError::Custom(format!("cannot read metadata: {e}")))?;

        if meta.len() == 0 {
            return Ok(InputData::Owned(Vec::new()));
        }

        // Safety: We map the file in read-only mode for analysis/transformation.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| NetForgeError::Custom(format!("mmap failed: {e}")))?;

        Ok(InputData::Mmap(mmap))
    }

    /// Construct from owned in-memory bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        InputData::Owned(bytes)
    }

    /// Read all bytes from a `Read` stream (e.g. `stdin`).
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self, NetForgeError> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| NetForgeError::Custom(format!("failed to read stream: {e}")))?;
        Ok(InputData::Owned(buf))
    }
}
