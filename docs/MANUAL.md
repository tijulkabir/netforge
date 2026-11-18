# NetForge User Manual

A practical, example-driven guide to every part of NetForge. If you have never
used it before, read the **Concepts** section once, then jump to whatever task
you have in front of you.

> NetForge is for **authorized** security work, research, and CTFs only.

---

## Table of contents

1. [Install](#1-install)
2. [Concepts](#2-concepts)
3. [Input, output, and pipelines](#3-input-output-and-pipelines)
4. [Operation reference](#4-operation-reference)
   - [Encoding](#encoding)
   - [Auto-decode: `magic`](#auto-decode-magic)
   - [XOR tooling](#xor-tooling)
   - [Classic ciphers](#classic-ciphers)
   - [Hashing](#hashing)
   - [Analysis](#analysis)
   - [Binary triage](#binary-triage)
   - [Protocol & framing](#protocol--framing)
   - [Network IoCs](#network-iocs)
5. [Recipes](#5-recipes)
6. [JSON output](#6-json-output)
7. [Exit codes](#7-exit-codes)
8. [Common workflows](#8-common-workflows)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Install

```bash
git clone https://github.com/tijulkabir/netforge.git
cd netforge
cargo build --release
```

Binary: `target/release/netforge` (`.exe` on Windows). Put it on your `PATH`.

Optional shell integration:

```bash
netforge --completions bash > /etc/bash_completion.d/netforge   # or zsh/fish/powershell
netforge --man > /usr/share/man/man1/netforge.1
```

List everything the build supports:

```bash
netforge --list
```

---

## 2. Concepts

**Operations** are small, deterministic byte-to-byte transforms (`to_base64`,
`xor`, `sha256`, `checksec`, …). You name one or more and NetForge runs them.

**Pipelines** chain operations left to right: the output of each feeds the next.

```bash
netforge --input 'hello' to_base64 to_hex
#                        └─ op 1 ──┘ └─ op 2 ┘
```

**Arguments** are passed to parameterized ops two ways:

- Inline, per op: `xor:0x42`, `strings:6`, `rc4:mykey`
- With `--arg`, applied to ops that take one on the command line.

Inline `op:arg` is preferred — it is unambiguous and composes cleanly.

---

## 3. Input, output, and pipelines

NetForge reads input from exactly one source, in this precedence:

| Flag | Source |
|---|---|
| `--input "<text>"` / `-i` | an inline string |
| `--file <path>` / `-f` | a file (memory-mapped; `-` means stdin) |
| *(none)* | standard input |

Output goes to stdout as raw bytes (a trailing newline is added unless you pass
`--no-newline`/`-n`). Diagnostics go to stderr.

```bash
echo -n 'data' | netforge to_hex          # stdin
netforge --input 'data' to_hex            # inline
netforge --file payload.bin entropy       # file (mmap)
```

Because output is raw bytes, NetForge composes with itself and with other Unix
tools:

```bash
cat capture.bin | netforge xor:0x5a | netforge strings:6 | sort -u
```

---

## 4. Operation reference

### Encoding

| Op | Description |
|---|---|
| `to_hex` / `from_hex` | Hex encode/decode. `from_hex` tolerates `\x41`, `0x41`, `41 42`, `41:42`, newlines. |
| `to_base64` / `from_base64` | Base64 (RFC 4648); decoder accepts URL-safe and unpadded. |
| `url_encode` / `url_decode` | Percent-encoding (RFC 3986). |
| `rot13` | ROT13 (self-inverse). |

```bash
netforge --input 'ABC' to_hex            # 414243
netforge --input '0x41,0x42,0x43' from_hex   # ABC
```

### Auto-decode: `magic`

Recursively tries nested decodings (base64, hex, URL, ROT13), scores each result
as plaintext, prints the winning **decode path**, and stops early on a detected
flag (`flag{`, `HTB{`, `ctf{`, …).

```bash
echo -n 'flag{demo}' | netforge to_base64 to_hex | netforge magic
# magic: best score 4.89  [FLAG DETECTED] via from_hex -> from_base64
# flag{demo}

netforge --input '<blob>' magic:8        # :N sets max decode depth (default 6)
```

### XOR tooling

| Op | Description |
|---|---|
| `xor:<key>` | XOR with a key: decimal byte (`xor:66`), hex (`xor:0xDEAD`), or ASCII (`xor:mykey`). |
| `xor_brute` | Single-byte brute force — ranks all 256 keys by plaintext score. |
| `xor_break` | Repeating-key XOR recovery — detects key length via Index of Coincidence, solves each column, returns the key and plaintext. |

```bash
cat cipher | netforge xor_brute          # top 5 candidate keys with previews
cat cipher | netforge xor_break          # keysize, key (hex/ascii), plaintext
```

> `xor_break` is statistical: it needs enough ciphertext (~20+ bytes per key
> position). A 7-byte key wants a few hundred bytes of ciphertext to be reliable.

### Classic ciphers

| Op | Description |
|---|---|
| `rc4:<key>` | RC4 stream cipher (symmetric); key as ASCII or `0xHEX`. |
| `vigenere:<key>` / `vigenere_decrypt:<key>` | Vigenère encipher / decipher. |
| `atbash` | Atbash substitution (self-inverse). |
| `caesar_brute` | Try all 25 Caesar shifts, ranked by English-likeness. |
| `to_morse` / `from_morse` | Morse encode/decode (`/` separates words). |

```bash
cat blob | netforge rc4:S3cret           # decode an RC4 config
echo -n 'khoor' | netforge caesar_brute  # finds 'hello' at shift 3
```

### Hashing

`md5`, `sha256`, `sha512`, `blake3`, `ntlm` — each returns a hex digest.

```bash
netforge --input 'password' ntlm         # 8846f7eaee8fb117ad06bdd830b7586c
netforge --file big.iso blake3           # multi-threaded tree hash
```

### Analysis

| Op | Description |
|---|---|
| `entropy` | Shannon entropy (bits/byte). >7.2 suggests packed/encrypted. |
| `byte_freq` | Byte-frequency histogram. |
| `strings:<n>` | Printable strings of min length n (default 4). |
| `length` | Byte count. |
| `badchars:<list>` | Report forbidden bytes and their offsets, e.g. `badchars:00,0a,0d`. |

```bash
netforge --file sample.bin entropy
cat shellcode.bin | netforge badchars:00,0a,0d   # vet for restricted bytes
```

### Binary triage

| Op | Description |
|---|---|
| `file_type` | Identify a buffer by magic bytes (20+ formats). |
| `carve` | Scan for embedded file signatures and report their offsets (binwalk-lite). |
| `pe_info` / `pe_sections` | PE32/PE32+ header and section triage (RWX alerts, per-section entropy). |
| `elf_info` | ELF header: class, endianness, machine, type, entry, linkage. |
| `checksec` | ELF exploit mitigations: NX, PIE, RELRO, stack canary, Fortify. |
| `triage` | One-shot: type, size, md5/sha256, entropy (+packed flag), ELF mitigations, embedded signatures. |

```bash
netforge --file unknown.bin triage       # the "what is this?" button
netforge --file ./a.out checksec         # exploit-mitigation report
netforge --file firmware.bin carve       # find embedded ZIP/PNG/ELF/...
```

### Protocol & framing

| Op | Description |
|---|---|
| `tlv_encode:<type>` / `tlv_decode` | Type-Length-Value packet framing. |
| `checksum` | RFC 1071 16-bit Internet checksum. |
| `to_c_array` | Format bytes as a C/C++ byte-array declaration (legitimate embedding). |

### Network IoCs

`defang_ip`, `refang_ip`, `defang_url`, `refang_url` — make indicators safe to
share, or restore them.

```bash
netforge --input 'http://evil.example/c2' defang_url
# http[://]evil[.]example/c2
```

---

## 5. Recipes

A **recipe** is a committable, shareable pipeline in a plain-text file — one
operation per line (or several separated by whitespace/`|`), `#` for comments.

```text
# deobf.nfr — peel a captured config blob
from_base64        # transport encoding
xor:0x5a           # single-byte obfuscation
strings:6          # pull readable indicators
```

Run it:

```bash
cat capture.b64 | netforge --recipe deobf.nfr
```

Every operation and `op:arg` form available on the command line works inside a
recipe. Combine with `--json` and the report shows the resolved pipeline.

---

## 6. JSON output

Add `--json` to any run for a stable, machine-readable report (schema v1):

```bash
echo -n 'AB' | netforge xor:0x42 to_hex --json
```

```json
{
  "tool": "netforge",
  "schema": 1,
  "version": "2.0.0",
  "ok": true,
  "input": { "bytes": 2, "source": "stdin" },
  "pipeline": ["xor:0x42", "to_hex"],
  "output": { "bytes": 4, "encoding": "utf8", "data": "0300" },
  "sha256": "cf3c..."
}
```

Binary output is base64-encoded with `"encoding": "base64"`. Errors produce
`"ok": false` with a stable `error.code` you can match on.

---

## 7. Exit codes

NetForge follows the BSD `sysexits.h` convention so it behaves well in scripts:

| Code | Meaning |
|---|---|
| `0` | success |
| `64` | usage error (unknown op, no ops, bad recipe path) |
| `65` | data error (input malformed for the operation) |
| `74` | I/O error (cannot read file/stdin) |

```bash
if ! cat x | netforge from_base64 >/dev/null; then echo "not valid base64"; fi
```

---

## 8. Common workflows

**Unknown dropped file:**

```bash
netforge --file dropped.bin triage
netforge --file dropped.bin strings:6 | less
```

**CTF mystery string:**

```bash
echo -n '<blob>' | netforge magic          # try auto-decode first
echo -n '<blob>' | netforge xor_brute      # if it looks single-byte XORed
echo -n '<blob>' | netforge caesar_brute   # if it looks like a shift cipher
```

**Pwn target recon:**

```bash
netforge --file ./chall elf_info
netforge --file ./chall checksec
```

**Decode a malware config:**

```bash
cat config.bin | netforge rc4:<key>        # or xor:<key>, or xor_break
```

---

## 9. Troubleshooting

- **"no operations specified"** — you ran NetForge with no ops and no `--recipe`. Add an op or a recipe; see `--list`.
- **"unknown or invalid operation"** — typo or a parameterized op missing its argument (e.g. `rc4` needs `rc4:<key>`).
- **`xor_break` returns garbage** — not enough ciphertext for the key length; capture more data.
- **A file won't open** — check the path; `-` reads stdin in the `--file` position.
- **Want structured errors** — add `--json`; the `error.code` field is stable.

More questions, or want to extend NetForge? See **[CONTRIBUTING](../CONTRIBUTING.md)**.
