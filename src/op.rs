use crate::error::NetForgeError;

/// The fundamental contract every transformation implements.
///
/// Every operation in NetForge is a stateless, deterministic function
/// from raw bytes to raw bytes.  The `&[u8]` input is zero-copy;
/// the `Vec<u8>` output is an owned allocation the caller controls.
///
/// Operations **must** be `Send + Sync` so the pipeline can be
/// dispatched across threads for batch / stream processing.
pub trait Operation: Send + Sync {
    /// Human-readable name used in CLI output and logs.
    fn name(&self) -> &str;

    /// Execute the transformation on `input`.
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError>;

    /// In-place transformation writing into a reusable output scratch buffer.
    ///
    /// The caller provides a pre-allocated `&mut Vec<u8>` capacity pool.
    /// Implementations override this to achieve zero heap allocations
    /// during pipeline traversal.
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let res = self.execute(input)?;
        output.clear();
        output.extend_from_slice(&res);
        Ok(())
    }
}
