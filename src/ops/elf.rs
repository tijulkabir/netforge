//! ELF triage and exploit-mitigation detection (`elf_info`, `checksec`).
//!
//! Zero-dependency ELF32/ELF64 parser for the two questions an operator asks of
//! a Linux target first: *what is it?* (`elf_info` — class, endianness, machine,
//! type, entry, interpreter) and *how hard is it to exploit?* (`checksec` — NX,
//! PIE, RELRO, stack canary, Fortify), the same signals as the classic
//! `checksec` tool.
//!
//! Every multi-byte read is bounds-checked; length and offset fields in the file
//! are attacker-controlled and are never trusted.

use crate::error::NetForgeError;
use crate::op::Operation;

const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;

/// Parsed ELF facts shared by both operations.
struct Elf<'a> {
    data: &'a [u8],
    is64: bool,
    le: bool,
    e_type: u16,
    e_machine: u16,
    e_entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

/// Little/big-endian bounded integer readers.
fn rd_u16(d: &[u8], off: usize, le: bool) -> Option<u16> {
    let b = d.get(off..off + 2)?;
    Some(if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}
fn rd_u32(d: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = d.get(off..off + 4)?;
    let a = [b[0], b[1], b[2], b[3]];
    Some(if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    })
}
fn rd_u64(d: &[u8], off: usize, le: bool) -> Option<u64> {
    let b = d.get(off..off + 8)?;
    let a = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
    Some(if le {
        u64::from_le_bytes(a)
    } else {
        u64::from_be_bytes(a)
    })
}

impl<'a> Elf<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, NetForgeError> {
        if data.len() < 0x40 || &data[..4] != b"\x7fELF" {
            return Err(NetForgeError::Custom("not an ELF file".to_string()));
        }
        let is64 = match data[4] {
            1 => false,
            2 => true,
            _ => return Err(NetForgeError::Custom("invalid ELF class".to_string())),
        };
        let le = match data[5] {
            1 => true,
            2 => false,
            _ => return Err(NetForgeError::Custom("invalid ELF endianness".to_string())),
        };
        let e_type = rd_u16(data, 16, le).ok_or(bad())?;
        let e_machine = rd_u16(data, 18, le).ok_or(bad())?;
        let (e_entry, phoff, phentsize, phnum) = if is64 {
            (
                rd_u64(data, 24, le).ok_or(bad())?,
                rd_u64(data, 32, le).ok_or(bad())?,
                rd_u16(data, 54, le).ok_or(bad())?,
                rd_u16(data, 56, le).ok_or(bad())?,
            )
        } else {
            (
                rd_u32(data, 24, le).ok_or(bad())? as u64,
                rd_u32(data, 28, le).ok_or(bad())? as u64,
                rd_u16(data, 42, le).ok_or(bad())?,
                rd_u16(data, 44, le).ok_or(bad())?,
            )
        };
        Ok(Elf {
            data,
            is64,
            le,
            e_type,
            e_machine,
            e_entry,
            phoff,
            phentsize,
            phnum,
        })
    }

    /// Iterate program-header (p_type, p_flags) pairs, bounds-checked.
    fn segments(&self) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        let entsize = self.phentsize as usize;
        if entsize == 0 {
            return out;
        }
        // Cap the count to what the file can actually hold — never trust phnum.
        let max_by_file = self
            .data
            .len()
            .saturating_sub(self.phoff as usize)
            .checked_div(entsize)
            .unwrap_or(0);
        let n = (self.phnum as usize).min(max_by_file);
        for i in 0..n {
            let base = self.phoff as usize + i * entsize;
            let p_type = match rd_u32(self.data, base, self.le) {
                Some(v) => v,
                None => break,
            };
            // p_flags sits at +4 (64-bit) or +24 (32-bit).
            let flags_off = if self.is64 { base + 4 } else { base + 24 };
            let p_flags = rd_u32(self.data, flags_off, self.le).unwrap_or(0);
            // p_offset for DYNAMIC scanning.
            out.push((p_type, p_flags));
        }
        out
    }

    /// Locate the dynamic segment's file range, if present.
    fn dynamic_range(&self) -> Option<(usize, usize)> {
        let entsize = self.phentsize as usize;
        let n = self.phnum as usize;
        for i in 0..n {
            let base = self.phoff as usize + i * entsize;
            if rd_u32(self.data, base, self.le)? == PT_DYNAMIC {
                let (off, sz) = if self.is64 {
                    (
                        rd_u64(self.data, base + 8, self.le)? as usize,
                        rd_u64(self.data, base + 32, self.le)? as usize,
                    )
                } else {
                    (
                        rd_u32(self.data, base + 4, self.le)? as usize,
                        rd_u32(self.data, base + 16, self.le)? as usize,
                    )
                };
                let end = off.checked_add(sz)?;
                if end <= self.data.len() {
                    return Some((off, end));
                }
            }
        }
        None
    }

    /// Full RELRO requires BIND_NOW; scan the dynamic table's (tag,val) entries.
    fn has_bind_now(&self) -> bool {
        let Some((start, end)) = self.dynamic_range() else {
            return false;
        };
        let step = if self.is64 { 16 } else { 8 };
        let mut off = start;
        while off + step <= end {
            let (tag, val) = if self.is64 {
                (
                    rd_u64(self.data, off, self.le).unwrap_or(0),
                    rd_u64(self.data, off + 8, self.le).unwrap_or(0),
                )
            } else {
                (
                    rd_u32(self.data, off, self.le).unwrap_or(0) as u64,
                    rd_u32(self.data, off + 4, self.le).unwrap_or(0) as u64,
                )
            };
            if tag == DT_BIND_NOW
                || (tag == DT_FLAGS && val & DF_BIND_NOW != 0)
                || (tag == DT_FLAGS_1 && val & DF_1_NOW != 0)
            {
                return true;
            }
            if tag == 0 {
                break; // DT_NULL terminator
            }
            off += step;
        }
        false
    }

    fn machine_name(&self) -> &'static str {
        match self.e_machine {
            0x03 => "x86",
            0x3e => "x86-64",
            0x28 => "ARM",
            0xb7 => "AArch64",
            0xf3 => "RISC-V",
            0x08 => "MIPS",
            _ => "unknown",
        }
    }

    fn type_name(&self) -> &'static str {
        match self.e_type {
            1 => "REL (object)",
            2 => "EXEC (executable)",
            3 => "DYN (shared/PIE)",
            4 => "CORE",
            _ => "unknown",
        }
    }
}

fn bad() -> NetForgeError {
    NetForgeError::Custom("truncated ELF header".to_string())
}

/// Case-sensitive byte-substring search over the whole file.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

/// ELF header triage: class, endianness, machine, type, entry, interpreter.
pub struct ElfInfo;

impl Operation for ElfInfo {
    fn name(&self) -> &str {
        "elf_info"
    }

    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let elf = Elf::parse(input)?;
        let has_interp = elf.segments().iter().any(|&(t, _)| t == PT_INTERP);
        let mut out = String::new();
        out.push_str("── ELF ──────────────────────────────\n");
        out.push_str(&format!(
            "class      : ELF{}\n",
            if elf.is64 { "64" } else { "32" }
        ));
        out.push_str(&format!(
            "endianness : {}\n",
            if elf.le { "little" } else { "big" }
        ));
        out.push_str(&format!("machine    : {}\n", elf.machine_name()));
        out.push_str(&format!("type       : {}\n", elf.type_name()));
        out.push_str(&format!("entry      : 0x{:x}\n", elf.e_entry));
        out.push_str(&format!("segments   : {}\n", elf.segments().len()));
        out.push_str(&format!(
            "dynamic    : {}\n",
            if has_interp {
                "yes (dynamically linked)"
            } else {
                "no / static"
            }
        ));
        Ok(out.into_bytes())
    }
}

/// `checksec`-equivalent exploit-mitigation report.
pub struct Checksec;

impl Operation for Checksec {
    fn name(&self) -> &str {
        "checksec"
    }

    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let elf = Elf::parse(input)?;
        let segs = elf.segments();

        // NX: executable stack is signalled by the X flag on PT_GNU_STACK.
        // No GNU_STACK segment at all → the old default of an executable stack.
        let nx = match segs.iter().find(|&&(t, _)| t == PT_GNU_STACK) {
            Some(&(_, flags)) => flags & 0x1 == 0, // X bit clear → NX on
            None => false,
        };

        // PIE: ET_DYN with an interpreter (a shared object is ET_DYN but has no
        // PT_INTERP). ET_EXEC is never PIE.
        let has_interp = segs.iter().any(|&(t, _)| t == PT_INTERP);
        let pie = elf.e_type == ET_DYN && has_interp;
        let is_exec = elf.e_type == ET_EXEC;

        // RELRO: PT_GNU_RELRO present → partial; + BIND_NOW → full.
        let has_relro = segs.iter().any(|&(t, _)| t == PT_GNU_RELRO);
        let relro = if has_relro {
            if elf.has_bind_now() {
                "Full"
            } else {
                "Partial"
            }
        } else {
            "None"
        };

        // Canary / Fortify: detected by the presence of their guard symbols,
        // the same heuristic the checksec tool uses.
        let canary = contains(input, b"__stack_chk_fail");
        let fortify = contains(input, b"_chk\0") || contains(input, b"__memcpy_chk");

        let yn = |b: bool| if b { "yes" } else { "NO" };
        let mut out = String::new();
        out.push_str("── checksec ─────────────────────────\n");
        out.push_str(&format!("RELRO      : {relro}\n"));
        out.push_str(&format!("Stack Canary: {}\n", yn(canary)));
        out.push_str(&format!("NX         : {}\n", yn(nx)));
        out.push_str(&format!(
            "PIE        : {}\n",
            if pie {
                "yes"
            } else if is_exec {
                "NO (no PIE)"
            } else {
                "N/A (shared object)"
            }
        ));
        out.push_str(&format!("Fortify    : {}\n", yn(fortify)));
        Ok(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal synthetic ELF64 header + one PT_GNU_STACK (non-exec) segment.
    fn synth_elf64(e_type: u16, stack_flags: u32) -> Vec<u8> {
        let mut d = vec![0u8; 0x40 + 56];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2; // 64-bit
        d[5] = 1; // little-endian
        d[16..18].copy_from_slice(&e_type.to_le_bytes());
        d[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86-64
        d[24..32].copy_from_slice(&0x1040u64.to_le_bytes()); // entry
        d[32..40].copy_from_slice(&0x40u64.to_le_bytes()); // phoff = 0x40
        d[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        d[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum = 1
                                                        // Program header at 0x40: PT_GNU_STACK with given flags.
        let ph = 0x40;
        d[ph..ph + 4].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        d[ph + 4..ph + 8].copy_from_slice(&stack_flags.to_le_bytes());
        d
    }

    #[test]
    fn rejects_non_elf() {
        assert!(ElfInfo.execute(b"MZ not elf").is_err());
        assert!(Checksec.execute(b"\x7fELFxx").is_err());
    }

    #[test]
    fn parses_header() {
        let d = synth_elf64(ET_EXEC, 0x6); // RW stack → NX on
        let report = String::from_utf8(ElfInfo.execute(&d).unwrap()).unwrap();
        assert!(report.contains("ELF64"), "{report}");
        assert!(report.contains("x86-64"), "{report}");
        assert!(report.contains("EXEC"), "{report}");
        assert!(report.contains("0x1040"), "{report}");
    }

    #[test]
    fn checksec_nx_and_pie() {
        // Non-exec stack (RW) → NX enabled; ET_EXEC → no PIE.
        let d = synth_elf64(ET_EXEC, 0x6);
        let r = String::from_utf8(Checksec.execute(&d).unwrap()).unwrap();
        assert!(r.contains("NX         : yes"), "{r}");
        assert!(r.contains("PIE        : NO"), "{r}");

        // Executable stack (RWX) → NX disabled.
        let d2 = synth_elf64(ET_EXEC, 0x7);
        let r2 = String::from_utf8(Checksec.execute(&d2).unwrap()).unwrap();
        assert!(r2.contains("NX         : NO"), "{r2}");
    }

    #[test]
    fn checksec_detects_canary_symbol() {
        let mut d = synth_elf64(ET_EXEC, 0x6);
        d.extend_from_slice(b"__stack_chk_fail\0");
        let r = String::from_utf8(Checksec.execute(&d).unwrap()).unwrap();
        assert!(r.contains("Stack Canary: yes"), "{r}");
    }
}
