# Contributing to NetForge

Thanks for your interest in improving NetForge. This guide covers the project's
scope, how the code is organized, and exactly how to add an operation that will
pass review and CI.

---

## Scope & ethics (read first)

NetForge is a **triage, analysis, decoding, and classic-cryptanalysis** tool for
**authorized** security work, research, and CTFs. Contributions that forge the
blade are welcome. Contributions that are payload **delivery** are not.

**In scope:** parsers and triage, decoders and cryptanalysis, hashing, analysis
read-outs, format identification, recipe/workflow tooling, performance, tests,
and docs.

**Out of scope (will be declined):** shellcode/loader-stub *generators*,
C2/implant functionality, exploitation primitives, and detection-evasion
tooling. Legitimate byte embedding is already covered by `to_c_array`.

If you are unsure, open an issue describing the use case before writing code.

---

## Development setup

Requires a recent stable Rust toolchain (MSRV 1.80+).

```bash
git clone https://github.com/tijulkabir/netforge.git
cd netforge
cargo build
cargo test
```

Before every commit, run the same gates CI runs:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings -A unknown-lints \
    -A clippy::chunks_exact_to_as_chunks -A clippy::manual_checked_ops
cargo test --all-targets
```

A pull request must be `fmt`-clean, `clippy`-clean under `-D warnings`, and have
all tests passing on Linux, Windows, and macOS (CI checks all three).

---

## Dependency policy

The **core is zero-dependency on purpose** — NetForge runs on locked-down and
air-gapped hosts, and a small supply chain is a feature. Current dependencies are
limited to well-known crates (`clap`, `sha2`/`md-5`/`md4`/`blake3` for hashing,
`memmap2`, `rayon`). Adding a dependency needs justification in the PR and must
pass the `cargo-deny` CI job (advisories, bans, licenses, sources). Prefer
hand-rolling small, well-understood algorithms over pulling a crate.

---

## Architecture

```
src/
├── main.rs        CLI: arg parsing, input resolution, pipeline execution, generators
├── lib.rs         crate root + the unit-test suite
├── op.rs          the Operation trait (the core seam)
├── pipeline.rs    chains ops with ping-pong scratch buffers
├── registry.rs    string name -> boxed Operation (add new ops here)
├── input.rs       InputData: mmap files / stdin / inline bytes
├── output.rs      --json structured report (stable schema v1)
├── error.rs       NetForgeError: codes + sysexits exit codes
├── recipe.rs      --recipe file parser
├── fuzz.rs        built-in zero-panic invariant fuzzer
└── ops/           one module per operation family
    ├── encoding.rs  analysis.rs  hashing.rs  crypto.rs  network.rs
    ├── protocol.rs  binary.rs (PE)  elf.rs  fileid.rs  triage.rs
    ├── magic.rs  xor_tools.rs  cipher_extra.rs  score.rs
```

Every transformation implements one trait (`src/op.rs`):

```rust
pub trait Operation: Send + Sync {
    fn name(&self) -> &str;
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError>;

    // Default buffers then calls execute; override for zero-allocation reuse.
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> { /* ... */ }

    // Default buffers the whole stream; override for constant-memory streaming.
    fn transform_stream(&self, r: &mut dyn Read, w: &mut dyn Write) -> Result<(), NetForgeError> { /* ... */ }
}
```

Ops must be `Send + Sync` and deterministic.

---

## Adding an operation — step by step

Say you want to add `base32` decoding.

1. **Implement the op** in the right `src/ops/*.rs` module (here, `encoding.rs`):

   ```rust
   pub struct FromBase32;

   impl Operation for FromBase32 {
       fn name(&self) -> &str { "from_base32" }
       fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
           // ... return decoded bytes or a NetForgeError
       }
   }
   ```

2. **Register it** in `src/registry.rs` — add a match arm in `build_operation`
   and a row in `list_operations`:

   ```rust
   "from_base32" => Some(Box::new(ops::FromBase32)),
   // ...
   ("from_base32", "Base32 decode (RFC 4648)"),
   ```

   If the op takes an argument, parse it in the match arm (see `xor`, `rc4`,
   `strings` for patterns) and return `None` for invalid/missing arguments.

3. **Add it to `--list` display** in `src/main.rs` (the category table).

4. **Write tests** in the same module under `#[cfg(test)]`: a round-trip or a
   known test vector, plus an error case. For anything that parses untrusted
   bytes, add an adversarial/truncated case.

5. **If the op parses attacker-controlled binary**, also wire it into the fuzz
   harness in `src/fuzz.rs` so it is proven panic-free.

6. Run the three gates above. Done.

---

## Coding conventions

- **Never trust length or offset fields** in parsed input. Bounds-check every
  multi-byte read (see `src/ops/elf.rs` for the pattern: `rd_u32`/`rd_u64`
  return `Option`, counts are clamped to what the file can hold). Parsers must
  return `Err`, never panic, on malformed input.
- **Errors** go through `NetForgeError`. Use `Io` for I/O failures, the specific
  variants for known cases, and `Custom(String)` otherwise. If you add a variant,
  give it a stable slug in `code()` and the right `exit_code()`.
- **Keep ops deterministic and side-effect-free** — same input, same output, no
  network, no clock, no filesystem.
- **Prefer streaming** for byte-wise ops by overriding `transform_stream`
  (see `Xor`) so large files stay out of RAM.
- **Document** each public op with a short doc comment saying what it does and,
  for security ops, the operator use case.

---

## Tests & fuzzing

- Unit and property tests run with `cargo test` (proptest suites live in
  `tests/fuzz_properties.rs`).
- The live invariant fuzzer runs from the CLI: `netforge --fuzz --fuzz-iters N`.
  It proves a zero-panic guarantee across adversarial inputs, including a
  structured PE fuzzer that forges hostile headers.
- New parsing code should not reduce fuzz coverage — add your op to `fuzz.rs`.

---

## Commit & PR conventions

- Use clear, conventional-style messages: `feat(scope): …`, `fix(ci): …`,
  `docs: …`, `test: …`.
- One logical change per PR where practical; keep diffs reviewable.
- Describe *what* and *why*, and note test results.
- Make sure CI is green before requesting review.

---

## Roadmap

Planned work and its rationale live in **[docs/ROADMAP.md](docs/ROADMAP.md)**.
Good first contributions include new decoders (base32/58/85), classic ciphers
(bacon, substitution), additional file-type signatures, and crack-ready hash
formatting. Pick an unchecked item, or open an issue to propose your own.
