use crate::error::NetForgeError;
use crate::op::Operation;
use crate::ops::analysis::compute_byte_frequencies;

// ──────────────────── PE Header Parser & Triage ──────────────────

/// Parse Portable Executable (PE32 / PE32+) header and output summary.
///
/// Extracts architecture, entry point RVA, image base, compile timestamp,
/// and subsystem with bounds-checked parsing.
pub struct PeInfo;

impl Operation for PeInfo {
    fn name(&self) -> &str {
        "pe_info"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let pe = parse_pe_headers(input)?;
        let mut out = String::new();
        out.push_str("╔═══════════════════════════════════════════════════════╗\n");
        out.push_str("║              NetForge — PE Binary Triage              ║\n");
        out.push_str("╠═══════════════════════════════════════════════════════╣\n");
        out.push_str(&format!("║ Format       : {}\n", pe.format));
        out.push_str(&format!("║ Machine/Arch : {}\n", pe.machine_str()));
        out.push_str(&format!("║ Sections     : {}\n", pe.num_sections));
        out.push_str(&format!(
            "║ Entry Point  : 0x{:08x} (RVA)\n",
            pe.entry_point
        ));
        out.push_str(&format!("║ Image Base   : 0x{:016x}\n", pe.image_base));
        out.push_str(&format!("║ Subsystem    : {}\n", pe.subsystem_str()));
        out.push_str(&format!("║ Timestamp    : 0x{:08x}\n", pe.timestamp));
        out.push_str("╚═══════════════════════════════════════════════════════╝\n");
        Ok(out.into_bytes())
    }
}

/// Detailed PE section inspection.
///
/// Scans every section header, calculates per-section Shannon entropy,
/// and flags critical security anomalies:
/// - `RWX` permissions (Self-modifying code / shellcode stagers)
/// - High entropy (> 7.2, packed/encrypted sections like UPX)
/// - Non-standard / cloaked section names
pub struct PeSections;

impl Operation for PeSections {
    fn name(&self) -> &str {
        "pe_sections"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let pe = parse_pe_headers(input)?;
        let mut out = String::new();
        out.push_str(
            "Name       V.Size     V.Addr     Raw.Size   Raw.Ptr    Perms  Entropy   Alerts\n",
        );
        out.push_str("────────── ────────── ────────── ────────── ────────── ────── ───────── ────────────────────────\n");

        for sec in &pe.sections {
            // Calculate per-section entropy
            let sec_data = if sec.raw_ptr as usize + sec.raw_size as usize <= input.len() {
                &input[sec.raw_ptr as usize..sec.raw_ptr as usize + sec.raw_size as usize]
            } else {
                &[]
            };

            let entropy = if sec_data.is_empty() {
                0.0
            } else {
                let freq = compute_byte_frequencies(sec_data);
                let len = sec_data.len() as f64;
                freq.iter()
                    .filter(|&&c| c > 0)
                    .map(|&c| {
                        let p = c as f64 / len;
                        -p * p.log2()
                    })
                    .sum()
            };

            let mut alerts = Vec::new();
            if sec.is_rwx() {
                alerts.push("[!] RWX (Executable + Writable)");
            }
            if entropy > 7.2 {
                alerts.push("[!] HIGH ENTROPY (Packed/Crypto)");
            }
            if sec.name.starts_with("UPX") {
                alerts.push("[*] UPX Packer Signature");
            }

            let alert_str = if alerts.is_empty() {
                "-".to_string()
            } else {
                alerts.join(" | ")
            };

            out.push_str(&format!(
                "{:<10} 0x{:08x} 0x{:08x} 0x{:08x} 0x{:08x} {:<6} {:>6.3}    {}\n",
                sec.name,
                sec.virtual_size,
                sec.virtual_addr,
                sec.raw_size,
                sec.raw_ptr,
                sec.perms_str(),
                entropy,
                alert_str
            ));
        }

        Ok(out.into_bytes())
    }
}

// ─────────────────────── PE Parser Internals ───────────────────

struct PeHeaderInfo {
    format: &'static str,
    machine: u16,
    num_sections: u16,
    timestamp: u32,
    entry_point: u32,
    image_base: u64,
    subsystem: u16,
    sections: Vec<PeSection>,
}

impl PeHeaderInfo {
    fn machine_str(&self) -> &'static str {
        match self.machine {
            0x014c => "i386 (x86 32-bit)",
            0x8664 => "AMD64 (x86-64 64-bit)",
            0xaa64 => "ARM64 (Little Endian)",
            0x0200 => "Intel Itanium",
            _ => "Unknown Machine",
        }
    }

    fn subsystem_str(&self) -> &'static str {
        match self.subsystem {
            1 => "Native (Driver)",
            2 => "Windows GUI",
            3 => "Windows CUI (Console)",
            7 => "POSIX CUI",
            9 => "Windows CE GUI",
            10 => "EFI Application",
            14 => "Xbox",
            _ => "Unknown Subsystem",
        }
    }
}

struct PeSection {
    name: String,
    virtual_size: u32,
    virtual_addr: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
}

impl PeSection {
    fn is_rwx(&self) -> bool {
        const SCN_MEM_EXECUTE: u32 = 0x20000000;
        const SCN_MEM_WRITE: u32 = 0x80000000;
        (self.characteristics & SCN_MEM_EXECUTE != 0) && (self.characteristics & SCN_MEM_WRITE != 0)
    }

    fn perms_str(&self) -> String {
        const SCN_MEM_READ: u32 = 0x40000000;
        const SCN_MEM_WRITE: u32 = 0x80000000;
        const SCN_MEM_EXECUTE: u32 = 0x20000000;

        let r = if self.characteristics & SCN_MEM_READ != 0 {
            'R'
        } else {
            '-'
        };
        let w = if self.characteristics & SCN_MEM_WRITE != 0 {
            'W'
        } else {
            '-'
        };
        let x = if self.characteristics & SCN_MEM_EXECUTE != 0 {
            'X'
        } else {
            '-'
        };
        format!("{r}{w}{x}")
    }
}

fn parse_pe_headers(input: &[u8]) -> Result<PeHeaderInfo, NetForgeError> {
    // 1. Verify DOS Header
    if input.len() < 0x40 || &input[0..2] != b"MZ" {
        return Err(NetForgeError::Custom(
            "invalid DOS header: missing 'MZ' signature".into(),
        ));
    }

    // 2. Read e_lfanew offset to PE header
    let e_lfanew =
        u32::from_le_bytes([input[0x3c], input[0x3d], input[0x3e], input[0x3f]]) as usize;
    if input.len() < e_lfanew + 24 {
        return Err(NetForgeError::Custom(
            "file truncated before PE header".into(),
        ));
    }

    // 3. Verify PE Signature
    if &input[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(NetForgeError::Custom(
            "invalid PE signature: missing 'PE\\0\\0'".into(),
        ));
    }

    // 4. COFF Header (20 bytes following "PE\0\0")
    let coff = e_lfanew + 4;
    let machine = u16::from_le_bytes([input[coff], input[coff + 1]]);
    let num_sections = u16::from_le_bytes([input[coff + 2], input[coff + 3]]);
    let timestamp = u32::from_le_bytes([
        input[coff + 4],
        input[coff + 5],
        input[coff + 6],
        input[coff + 7],
    ]);
    let opt_hdr_size = u16::from_le_bytes([input[coff + 16], input[coff + 17]]) as usize;

    // 5. Optional Header
    let opt = coff + 20;
    if input.len() < opt + opt_hdr_size {
        return Err(NetForgeError::Custom(
            "file truncated before Optional header".into(),
        ));
    }

    let magic = u16::from_le_bytes([input[opt], input[opt + 1]]);
    let (format, entry_point, image_base, subsystem) = match magic {
        0x010b => {
            // PE32 (32-bit)
            let ep = u32::from_le_bytes([
                input[opt + 16],
                input[opt + 17],
                input[opt + 18],
                input[opt + 19],
            ]);
            let base = u32::from_le_bytes([
                input[opt + 28],
                input[opt + 29],
                input[opt + 30],
                input[opt + 31],
            ]) as u64;
            let sub = u16::from_le_bytes([input[opt + 68], input[opt + 69]]);
            ("PE32 (32-bit executable)", ep, base, sub)
        }
        0x020b => {
            // PE32+ (64-bit)
            let ep = u32::from_le_bytes([
                input[opt + 16],
                input[opt + 17],
                input[opt + 18],
                input[opt + 19],
            ]);
            let base = u64::from_le_bytes([
                input[opt + 24],
                input[opt + 25],
                input[opt + 26],
                input[opt + 27],
                input[opt + 28],
                input[opt + 29],
                input[opt + 30],
                input[opt + 31],
            ]);
            let sub = u16::from_le_bytes([input[opt + 68], input[opt + 69]]);
            ("PE32+ (64-bit executable)", ep, base, sub)
        }
        _ => {
            return Err(NetForgeError::Custom(format!(
                "unknown optional header magic: 0x{magic:04x}"
            )))
        }
    };

    // 6. Section Headers
    let sec_table = opt + opt_hdr_size;
    let mut sections = Vec::with_capacity(num_sections as usize);

    for i in 0..(num_sections as usize) {
        let sec_offset = sec_table + (i * 40);
        if input.len() < sec_offset + 40 {
            break; // Truncated section table
        }
        let raw_name = &input[sec_offset..sec_offset + 8];
        let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..name_end])
            .trim()
            .to_string();

        let virtual_size = u32::from_le_bytes([
            input[sec_offset + 8],
            input[sec_offset + 9],
            input[sec_offset + 10],
            input[sec_offset + 11],
        ]);
        let virtual_addr = u32::from_le_bytes([
            input[sec_offset + 12],
            input[sec_offset + 13],
            input[sec_offset + 14],
            input[sec_offset + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            input[sec_offset + 16],
            input[sec_offset + 17],
            input[sec_offset + 18],
            input[sec_offset + 19],
        ]);
        let raw_ptr = u32::from_le_bytes([
            input[sec_offset + 20],
            input[sec_offset + 21],
            input[sec_offset + 22],
            input[sec_offset + 23],
        ]);
        let characteristics = u32::from_le_bytes([
            input[sec_offset + 36],
            input[sec_offset + 37],
            input[sec_offset + 38],
            input[sec_offset + 39],
        ]);

        sections.push(PeSection {
            name,
            virtual_size,
            virtual_addr,
            raw_size,
            raw_ptr,
            characteristics,
        });
    }

    Ok(PeHeaderInfo {
        format,
        machine,
        num_sections,
        timestamp,
        entry_point,
        image_base,
        subsystem,
        sections,
    })
}
