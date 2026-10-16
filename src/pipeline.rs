use crate::error::NetForgeError;
use crate::op::Operation;

/// Ordered chain of operations executed sequentially.
///
/// Data flows left → right: the output of operation *n* becomes the
/// input of operation *n + 1*.  The pipeline owns all its operations
/// through `Box<dyn Operation>` (trait-object / dynamic dispatch).
pub struct Pipeline {
    ops: Vec<Box<dyn Operation>>,
}

impl Pipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Append an operation to the end of the chain.
    pub fn push(&mut self, op: Box<dyn Operation>) -> &mut Self {
        self.ops.push(op);
        self
    }

    /// Execute the full chain using reusable ping-pong capacity pools.
    ///
    /// Eliminates intermediate heap allocations: pre-allocates dual scratch
    /// buffers (`buf_a` and `buf_b`) that ping-pong back and forth across
    /// all transformations.
    pub fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        if self.ops.is_empty() {
            return Ok(input.to_vec());
        }

        let mut buf_a = Vec::with_capacity(input.len());
        let mut buf_b = Vec::with_capacity(input.len());

        // First step reads from `input` into `buf_a`
        self.ops[0].execute_into(input, &mut buf_a)?;

        // Subsequent steps ping-pong between buf_a and buf_b
        for op in &self.ops[1..] {
            buf_b.clear();
            op.execute_into(&buf_a, &mut buf_b)?;
            std::mem::swap(&mut buf_a, &mut buf_b);
        }

        Ok(buf_a)
    }

    /// How many operations are loaded.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the pipeline has zero operations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}
