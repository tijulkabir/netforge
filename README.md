# NetForge

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

**NetForge** is a high-performance, offline **cyber transformation and triage engine** for red teamers, penetration testers, malware analysts, and CTF competitors. It is a single static binary with **zero runtime dependencies** — the multitool you keep on a jump box, an analyst VM, or an air-gapped host where you cannot install anything or open a browser.

Think of it as a fast, scriptable, offline CyberChef fused with `file`, `strings`, `checksec`, and a cryptanalysis kit — all pipeline-native and emitting structured JSON for your own tooling.

> **Scope & ethics.** NetForge is built for **authorized** engagements, research, and CTFs. It forges the blade — triage, analysis, decoding, and classic cryptanalysis — and deliberately does **not** ship payload delivery, C2, or detection-evasion capability. See [the roadmap's scope note](docs/ROADMAP.md).

New here? Start with the **[User Manual](docs/MANUAL.md)**. Want to add an operation? See **[CONTRIBUTING](CONTRIBUTING.md)**. The full plan lives in **[docs/ROADMAP.md](docs/ROADMAP.md)**.

---

## Three pillars

| Pillar | What it does | Headline ops |
|---|---|---|
| **DECODE** | Recursive auto-decode and key recovery | `magic`, `xor_brute`, `xor_break` |
| **TRIAGE** | Identify, inspect, and assess a binary in one shot | `triage`, `file_type`, `elf_info`, `checksec`, `carve` |
| **FORGE / ANALYZE** | Classic cryptanalysis and payload vetting | `rc4`, `vigenere`, `caesar_brute`, `badchars` |

---

## Capabilities

| Domain | Operations |
|---|---|
| **Encoding** | `to_hex`, `from_hex`, `rot13`, `to_base64`, `from_base64`, `url_encode`, `url_decode` |
| **Auto-decode** | `magic` (recursive, flag-aware) |
| **Crypto / cipher** | `xor`, `xor_brute`, `xor_break`, `rc4`, `vigenere`, `vigenere_decrypt`, `atbash`, `caesar_brute`, `to_morse`, `from_morse` |
| **Hashing** | `md5`, `sha256`, `sha512`, `blake3`, `ntlm` |
| **Analysis** | `entropy`, `byte_freq`, `strings`, `length`, `badchars` |
| **Binary triage** | `pe_info`, `pe_sections`, `elf_info`, `checksec`, `file_type`, `carve`, `triage` |
| **Protocol** | `tlv_encode`, `tlv_decode`, `checksum`, `to_c_array` |
| **Network IoC** | `defang_ip`, `refang_ip`, `defang_url`, `refang_url` |

Run `netforge --list` for the authoritative, self-documenting list.

---

## Install & build

Requires Rust (MSRV 1.80+):

```bash
git clone https://github.com/tijulkabir/netforge.git
cd netforge
cargo build --release
```

The optimized binary lands at `target/release/netforge` (`netforge.exe` on Windows).

Generate shell completions and a man page:

```bash
netforge --completions bash > netforge.bash
netforge --man > netforge.1
```

---

## Quick start

**Auto-decode an opaque blob** (peels nested encodings, detects flags):

```bash
echo -n 'flag{demo}' | netforge to_base64 to_hex | netforge magic
# magic: best score ...  [FLAG DETECTED] via from_hex -> from_base64
# flag{demo}
```

**Triage an unknown file** — type, size, hashes, entropy, ELF mitigations, embedded files, in one command:

```bash
netforge --file ./suspicious.bin triage
```

**Check exploit mitigations** on an ELF (checksec-equivalent):

```bash
netforge --file ./target_binary checksec
# RELRO / Stack Canary / NX / PIE / Fortify
```

**Crack single-byte XOR** and **break repeating-key XOR**:

```bash
cat ciphertext | netforge xor_brute      # ranks all 256 keys
cat ciphertext | netforge xor_break      # recovers the repeating key + plaintext
```

**Decode an RC4-obfuscated config** (symmetric):

```bash
cat blob | netforge rc4:S3cretKey
```

**Chain a pipeline** (left to right, inline args with `op:arg`):

```bash
netforge --input 'admin_token' xor:0xDEAD to_base64 url_encode
```

**Structured JSON** for your own tooling (stable schema v1):

```bash
echo -n 'AB' | netforge xor:0x42 to_hex --json
# {"tool":"netforge","schema":1,...,"output":{"bytes":4,"encoding":"utf8","data":"0300"},"sha256":"..."}
```

**Committable recipes** — version-controlled, shareable pipelines:

```bash
# deobf.nfr
#   from_base64      # transport layer
#   xor:0x5a         # single-byte obfuscation
#   strings:6        # pull indicators
cat capture.b64 | netforge --recipe deobf.nfr
```

See the **[User Manual](docs/MANUAL.md)** for a full tour with examples for every operation.

---

## Why NetForge

- **Offline, single static binary** — no interpreter, no browser, no network. Runs where `pip install` can't.
- **Pipeline-native & scriptable** — compose ops through pipes; `--json` on every run makes it callable from other tooling.
- **Fast** — memory-mapped input (`memmap2`), multi-core analysis (`rayon`), constant-memory streaming XOR for files larger than RAM.
- **Trustworthy** — zero-dependency core, a fuzzed parser suite proving a zero-panic guarantee, `cargo-deny` supply-chain gating in CI, and bounds-checked binary parsers that never trust attacker-controlled length fields.

---

## Architecture (in brief)

Every transformation implements one trait:

```rust
pub trait Operation: Send + Sync {
    fn name(&self) -> &str;
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError>;
    fn execute_into(&self, input: &[u8], output: &mut Vec<u8>) -> Result<(), NetForgeError> { /* ... */ }
    fn transform_stream(&self, r: &mut dyn Read, w: &mut dyn Write) -> Result<(), NetForgeError> { /* ... */ }
}
```

- **Pipeline** chains ops with ping-pong scratch buffers, dropping intermediate allocations from O(N) to O(1).
- **InputData** memory-maps files for zero-copy ingestion.
- **Streaming** — `transform_stream` buffers by default; byte-wise ops (XOR) override it for constant-memory processing of huge files.
- **Registry** — add an operation by implementing the trait and adding one arm to `src/registry.rs`.

Full details and a "how to add an operation" walkthrough are in **[CONTRIBUTING](CONTRIBUTING.md)**.

---

## Testing & fuzzing

```bash
cargo test                       # 75 tests: unit + property (proptest)
cargo clippy --all-targets       # lints clean under -D warnings
cargo fmt --check                # formatting
netforge --fuzz --fuzz-iters 10000   # live zero-panic invariant fuzzer
```

The fuzzer hammers every parser — including a structured PE fuzzer that forges hostile headers — and asserts zero panics across hundreds of thousands of adversarial operations.

---

## Documentation

- **[User Manual](docs/MANUAL.md)** — install, concepts, and worked examples for every operation.
- **[Contributing Guide](CONTRIBUTING.md)** — architecture, adding operations, testing, and conventions.
- **[Roadmap](docs/ROADMAP.md)** — the multi-phase plan, what's done, and what's next.

---

## License

MIT License. Crafted for security researchers and builders. Use it only against systems you are authorized to test.
