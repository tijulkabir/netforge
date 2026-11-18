# NetForge — Transformation Roadmap

**Goal:** turn NetForge from a byte-transform CLI into a production-grade offline
operator's multitool — the binary a red teamer or pentester keeps on their jump
box, analyst VM, or USB and reaches for every day. One static executable, zero
runtime dependencies, scriptable, fast, trustworthy.

> **Scope & ethics.** NetForge is a *triage, analysis, and payload-forging* tool
> for authorized engagements, CTFs, and research. It forges the blade — it does
> not ship delivery, C2, or EDR-evasion capability. That line keeps the project
> publishable, auditable, and credible.

---

## 1. The thesis

"Fast offline CyberChef in Rust" is already taken (rsbkb, Ares, Chepy). NetForge
only earns a place on an operator's box if it does something none of them unify:

> **The single offline binary that fuses auto-decode + binary triage + payload
> forging, with structured output, scriptable recipes, and sub-second speed on
> real-world files.**

Three pillars, each must beat the incumbents on its own axis:

1. **DECODE** — recursive auto-decode that understands *binary structure*, not
   just text ciphers (beats Ares/Ciphey).
2. **TRIAGE** — `file` + `strings` + `checksec` + `binwalk` + `entropy` in one
   command with JSON output (replaces five tools in one invocation).
3. **FORGE** — payload encoding, shellcode formatting, bad-char analysis, real
   crypto (the part CyberChef/rsbkb do weakly).

---

## 2. Target UX — what "daily driver" looks like

```
netforge magic <file|->                 # recursive auto-decode, shows decode path
netforge triage <file>                  # full binary recon report (--json)
netforge forge shellcode <file> --fmt csharp --badchars '00,0a'
netforge run recipe.yaml                # headless, committable pipeline
netforge xor <file> --brute             # key recovery
netforge <op> ... | netforge <op> ...   # pipeline-native, everything streams
```

Design rules (these are what separate a tool from a toy):

- **Everything supports `--json`.** Structured output is the difference between
  "I ran it" and "my tooling calls it."
- **Everything streams.** Operate on files larger than RAM; never require loading
  the whole input.
- **Proper Unix citizenship.** Clean exit codes, `stderr` for diagnostics,
  `--quiet`/`--raw`, reads `-` as stdin, pipes compose.
- **Deterministic.** Same input → same output, always. No network by default.
- **One binary.** Static, cross-compiled, signed, SBOM-published.

---

## 3. Phased roadmap

### Phase 0 — Foundation (make it trustworthy before adding features)

The current code is clean but not yet "production shaped." Do this first so every
later feature inherits it.

- [x] `--json` structured output layer (stable schema v1, hand-rolled, zero-dep).
      Done — `src/output.rs`.
- [x] Streaming foundation: `Operation::transform_stream(reader, writer)` with a
      buffering default; constant-memory chunked override for XOR. Keep mmap for
      random-access parsers (PE/ELF). Done — `src/op.rs`, `src/ops/crypto.rs`.
      *Remaining:* opt more byte-wise ops into streaming + a CLI streaming fast-path.
- [x] Error model: typed errors, stable `code()` slugs, sysexits `exit_code()`,
      human + `--json` error output. Done — `src/error.rs`.
- [x] CLI polish: `-` = stdin, shell completions (`--completions`), man page
      (`--man`). Done — `src/main.rs`. *Remaining:* `--raw`, `--quiet`, `--output`.
- [x] Testing: structured PE-parser fuzzer (length-field-trust proof) added to the
      harness; streaming cross-chunk tests. Done — `src/fuzz.rs`, `src/lib.rs`.
      *Remaining:* golden-file tests, coverage gate.
- [x] Supply chain: `cargo deny` config + CI job (advisories, bans, licenses,
      sources). Done — `deny.toml`, `.github/workflows/ci.yml`. *Remaining:*
      `cargo-dist` multi-target release, signed binaries, SBOM, build provenance.
- [x] Docs: man page generator. *Remaining:* `--help` examples, README quickstart.

**Exit criteria:** a stranger can `cargo install`/download, pipe data through it in
a script, parse the JSON, and trust the release artifact.

### Phase 1 — DECODE (the hook that gets people to try it)

- [x] `magic`: recursive auto-decode with a scoring engine. Done — `src/ops/magic.rs`.
  - Decoders: base64, hex, url, rot13 (BFS, depth-limited, deduped, bounded).
  - Scoring: English-frequency + printable ratio + flag-marker short-circuit
    (`src/ops/score.rs`); prints the winning decode path (`from_hex -> from_base64`).
  - *Remaining:* base32/58/85, gzip/zlib (needs a dep decision), and branching into
    binary triage (magic bytes → PE/ELF/ZIP) once Phase 2 parsers land.
- [x] XOR key recovery: `xor_brute` (single-byte, ranked) and `xor_break`
      (repeating-key: Index-of-Coincidence keysize + per-column single-byte solve).
      Done — `src/ops/xor_tools.rs`. *Remaining:* known-plaintext crib drag.
- [x] Classic ciphers: Vigenère, Atbash, Caesar brute, Morse — delivered in
      Phase 3 (`src/ops/cipher_extra.rs`). *Remaining:* bacon, substitution.

### Phase 2 — TRIAGE (the capability that replaces a toolbox)

- [x] ELF parser + `checksec`-equivalent (NX, PIE, RELRO, canary, Fortify).
      Done — `src/ops/elf.rs` (`elf_info`, `checksec`), bounds-checked ELF32/64.
- [x] File-type detection by magic bytes + embedded-file carving (binwalk-lite:
      find appended ZIP/PNG/ELF/gzip/…). Done — `src/ops/fileid.rs`
      (`file_type`, `carve`). *Remaining:* actual extraction/dumping of carved files.
- [x] `triage <file>`: one command → unified report (type, size, hashes, entropy
      with packed flag, ELF mitigations, embedded signatures). Done —
      `src/ops/triage.rs`. *Remaining:* `--json` report shape, entropy map.
- [ ] PE depth: import table with suspicious-API flagging (VirtualAlloc,
      WriteProcessMemory, etc.), exports, imphash, rich header, Authenticode presence,
      TLS callbacks, overlay detection.
- [ ] Mach-O basics (load commands, segments, signature presence).
- [ ] YARA-lite: simple byte/string pattern rules for tagging known stagers/configs.

### Phase 3 — FORGE / CRYPTO & ANALYSIS

> **Scope decision:** this phase is deliberately kept to reversible analysis and
> classic cryptanalysis. Multi-language shellcode/loader-stub *generators*
> (C#/PowerShell byte-array emitters, etc.) are intentionally **out of scope** —
> they are payload-delivery code, which the project's ethics note excludes. Byte
> embedding for legitimate uses is already covered by `to_c_array`.

- [x] Bad-char *analysis*: `badchars` reports forbidden bytes and their offsets
      (a vetting read-out, not a payload generator). Done — `src/ops/cipher_extra.rs`.
- [x] RC4 encrypt/decrypt for decoding malware/C2 config blobs and CTF crypto.
      Done — `src/ops/cipher_extra.rs` (verified against the RC4("Key","Plaintext")
      test vector).
- [x] Classic ciphers (carried from Phase 1): Vigenère (+decrypt), Atbash,
      Caesar brute-force, Morse encode/decode. Done — `src/ops/cipher_extra.rs`.
- [ ] AES-CBC/GCM, ChaCha20 decrypt for config analysis (needs a vetted,
      audited crypto dependency — deferred pending that supply-chain decision).
- [ ] Hash tooling: output in hashcat/john formats; NetNTLMv2, LM.
- [ ] Shellcode source formatters — **excluded** (see scope decision above).

### Phase 4 — PLATFORM (become infrastructure, not a command)

- [x] Recipe engine: `netforge --recipe file` — committable, shareable, headless
      pipelines (one op per line, `#` comments; the CyberChef recipe idea, but
      diff-able and in version control). Works with `--json`, which reports the
      resolved pipeline. Done — `src/recipe.rs`. *Remaining:* a `run` subcommand
      alias and a named recipe library.
- [ ] Named recipe library shipped with the binary + user recipe dir.
- [ ] `--server`: local HTTP/JSON API so other tooling (Burp, custom scripts,
      notebooks) can call NetForge ops without reimplementing them (needs an HTTP
      dependency — deferred pending that supply-chain decision).
- [ ] Plugin/op SDK: stable trait so the community can add ops without forking.
      (The `Operation` trait is already the seam; this is about publishing it.)
- [ ] Optional TUI for interactive triage sessions.

---

## 4. Architecture changes required

The current `Op` trait + registry is a good base. To support the above:

- **Streaming op trait:** ops should expose `transform(reader, writer, ctx)` so
  they compose without buffering. Keep a `transform_bytes` convenience for parsers
  that genuinely need random access.
- **Typed output model:** an `Output` enum (`Bytes`, `Text`, `Report(serde_json::Value)`)
  so one op can emit raw bytes to a pipe *or* a JSON report to tooling.
- **Context object:** carries `--json`, verbosity, badchars, flag-formats, recipe
  state — threaded through every op instead of globals.
- **Parser isolation:** PE/ELF/Mach-O parsers in their own fuzzed modules with
  hard bounds; never trust length fields (they are attacker-controlled input).
- **Feature flags:** gate `server`, `tui`, heavy crypto behind cargo features so
  the core binary stays small for air-gapped use.

---

## 5. Competitive scorecard (what "done" beats)

| Capability | CyberChef | rsbkb | Ares | pwntools | **NetForge target** |
|---|---|---|---|---|---|
| Offline single static binary | no | yes | yes | no | **yes** |
| Recursive auto-decode | weak | no | **yes** | no | **yes + binary-aware** |
| Binary triage (PE/ELF/checksec) | no | no | no | partial | **yes** |
| Shellcode forge + badchars | weak | no | no | **yes** | **yes** |
| JSON/scriptable output | no | partial | partial | n/a (lib) | **yes everywhere** |
| Committable recipes | no | no | no | code | **yes** |
| Speed on large files | poor | good | good | n/a | **best (streaming+rayon)** |

NetForge wins by being the *only* column that is yes across triage **and** forge
**and** auto-decode **and** scriptable — the unified knife.

---

## 6. Suggested execution order

1. **Phase 0** (foundation) — non-negotiable, do it first.
2. **`magic` + XOR brute** (Phase 1 core) — the hook, reuses existing ops, biggest
   visible payoff per effort.
3. **ELF + checksec** (Phase 2 core) — pulls in the CTF/pwn crowd.
4. **PE depth + carving** (Phase 2) — pulls in malware triage crowd.
5. **Forge: shellcode + crypto** (Phase 3).
6. **Recipe engine** (Phase 4) — turns users into dependents.

Each phase ships independently and leaves the tool more useful than before.

---

## 7. Metrics that mean "production-grade"

- Release cadence + signed artifacts for 3 OSes / 2 arches.
- Fuzzed parsers with no known crashers; CI coverage gate.
- `--json` schema stability guarantee (semver on the schema).
- Real-world benchmark published (throughput MB/s vs CyberChef/Chepy).
- External users scripting it (issues/PRs from non-authors), recipes shared.
