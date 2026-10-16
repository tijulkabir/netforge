# NetForge

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

**NetForge** is a high-performance cyber transformation engine engineered for red team operators, malware analysts, and CTF competitors. Written in pure systems Rust with zero runtime garbage collection, it provides deterministic, sub-millisecond pipeline execution over arbitrary binary payloads.

> [!NOTE]
> **Evolution Note:** NetForge v1.0 was an experimental web-based tool. NetForge v2.0 is a complete ground-up rewrite in systems-level Rust focused on zero-copy binary triage, high-throughput multi-core analysis, and red-team workflow automation. The legacy v1 codebase is permanently archived on branch [`archive/v1-js`](https://github.com/tijulkabir/netforge/tree/archive/v1-js) and tagged as `v1.0.0-legacy`.

---

## Key Capabilities

| Domain | Operations | Description |
|---|---|---|
| **Encoding** | `to_hex`, `from_hex`, `rot13`, `to_base64`, `from_base64`, `url_encode`, `url_decode` | RFC-compliant data representation encodings with zero heap fragmentation. |
| **Crypto** | `xor` | Single-byte and cyclic rolling-key XOR cipher for string deobfuscation. |
| **Hashing** | `md5`, `sha256`, `sha512`, `blake3`, `ntlm` | Fast threat-intel correlation digests & pass-the-hash NTLM generation. |
| **Analysis** | `entropy`, `byte_freq`, `strings`, `length` | Shannon entropy calculation (detecting packed/encrypted samples) & binary triage. |
| **Binary** | `pe_info`, `pe_sections` | Zero-dependency PE32/PE32+ triage, entry point RVA, RWX permission alerts, and per-section entropy scanning. |
| **Protocol** | `tlv_encode`, `tlv_decode`, `checksum`, `to_c_array` | Type-Length-Value packet framing, RFC 1071 IP/TCP checksums, and C-array formatting. |
| **Network** | `defang_ip`, `refang_ip`, `defang_url`, `refang_url` | Safe threat-sharing transformations for IoCs and C2 domains. |

---

## Installation & Build

Ensure you have Rust (MSRV 1.80+) installed:

```bash
git clone https://github.com/tijulkabir/netforge.git
cd netforge
cargo build --release
```

The optimized binary will be located at `target/release/netforge` (or `netforge.exe` on Windows).

---

## CLI Usage & Pipeline Examples

### 1. NTLM Hash Generation (Pass-the-Hash)
Compute the NTLM hash of a password directly via RFC 1320 MD4:
```bash
netforge --input "password" ntlm
# Output: 8846f7eaee8fb117ad06bdd830b7586c
```

### 2. Payload Obfuscation & Chaining
Chain operations left-to-right with inline arguments (`xor:0xDEAD` $\to$ Base64 $\to$ URL encode):
```bash
netforge --input "admin_session_token" xor:0xDEAD to_base64 url_encode
# Output: v8mzxLDyrcit3rfCsPKqwrXIsA%3d%3d
```

Reverse pipeline (URL decode $\to$ Base64 decode $\to$ XOR rolling key):
```bash
netforge --input "v8mzxLDyrcit3rfCsPKqwrXIsA%3d%3d" url_decode from_base64 xor:0xDEAD
# Output: admin_session_token
```

### 3. Hex Dump Sanitization (IDA / Wireshark / Python)
`from_hex` automatically strips `\x`, `0x`, spaces, newlines, and commas:
```bash
netforge --input "\x41\x42\x43" from_hex
netforge --input "0x41, 0x42, 0x43" from_hex
# Both Output: ABC
```

### 4. Malware Analysis: Shannon Entropy & Strings Extraction
Detect packed or encrypted sections of an unknown binary:
```bash
netforge --file suspicious_binary.bin entropy
# Entropy > 7.2 indicates packed / encrypted payload

netforge --file suspicious_binary.bin strings:6
# Extracts printable ASCII strings of length >= 6
```

### 4. Threat Intel: Defang Network IoCs
```bash
netforge --input "http://malicious-c2.corp/payload.exe" defang_url
# Output: http[://]malicious-c2[.]corp/payload[.]exe
```

### 5. Stdin Unix Pipe Workflow
```bash
echo -n "flag{crypto_is_fun}" | netforge to_hex rot13
```

---

## Architecture

```
                      ┌──────────────────────┐
                      │    Pipeline Runner   │
                      └──────────┬───────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 ▼               ▼               ▼
          ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
          │   ToHex     │ │  HashNtlm   │ │   Entropy   │
          └─────────────┘ └─────────────┘ └─────────────┘
                 │               │               │
                 └───────────────┴───────────────┘
                                 │
                   impl Operation for Dynamic Dispatch
                   trait Operation: Send + Sync
```

Every transformation implements the `Operation` trait:
```rust
pub trait Operation: Send + Sync {
    fn name(&self) -> &str;
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError>;

    /// In-place transformation writing into a reusable output scratch buffer.
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> {
        let res = self.execute(input)?;
        output.clear();
        output.extend_from_slice(&res);
        Ok(())
    }
}
```

- **Ping-Pong Buffer Reuse:** [`Pipeline`](file:///src/pipeline.rs) allocates dual reusable capacity pools (`buf_a` and `buf_b`) that ping-pong back and forth via `std::mem::swap`. Intermediate heap allocations across chained transformations drop from $O(N)$ to $O(1)$.
- **Zero-Copy Ingestion:** [`InputData`](file:///src/input.rs) memory-maps files via `memmap2`. A 10GB disk dump is mapped directly into virtual memory with zero user-space RAM allocations.
- **Multi-Core Data Parallelism:** Large analysis workloads (Shannon entropy and BLAKE3 tree hashing) leverage `rayon` map-reduce chunking to saturate all CPU cores.
- **Zero-Copy Input:** Operations consume `&[u8]` borrowed byte slices.
- **Dynamic Registry:** Easily register new operations by adding an arm to `src/registry.rs`.
- **Thread-safe:** All operations enforce `Send + Sync` for parallel bulk processing.

---

## Testing & Invariant Fuzzing

### 1. Unit & Property-Based Test Suite
Runs 34 unit tests and 6 `proptest` property suites (40 total automated verifications):
```bash
cargo test
```

### 2. Standalone Live Invariant Fuzzer
Run the built-in stress fuzzer directly from the CLI to mathematically verify the **Zero-Panic Guarantee** over thousands of adversarial byte streams:
```bash
netforge --fuzz --fuzz-iters 10000
```
```
╔═══════════════════════════════════════════════════════╗
║          NetForge — Live Invariant Fuzzer             ║
╠═══════════════════════════════════════════════════════╣
║ Executing 10000 adversarial stress cycles...
║ Proving mathematical roundtrips & zero-panic safety...
╠═══════════════════════════════════════════════════════╣
║ Completed Iterations :    10000
║ Invertibility Checks :    60000 (100% verified)
║ Adversarial Probes   :   120000 (100% survived)
║ Total Invariant Ops  :   180000
║ Uncaught Panics      :        0 (Zero-Panic Proof)
║ Execution Wall Time  :      505 ms
║ Throughput           :   356435 checks/sec
╚═══════════════════════════════════════════════════════╝
```

## License
MIT License. Crafted for security researchers and builders.
