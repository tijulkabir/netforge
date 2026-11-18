//! File-type identification and embedded-file carving (`file_type`, `carve`).
//!
//! * [`FileType`] — identify a buffer by its magic bytes (the `file` command's
//!   core trick), the first question of any triage.
//! * [`Carve`]    — scan the whole buffer for embedded file signatures and report
//!   their offsets (binwalk-lite), for pulling payloads out of blobs and images.

use crate::error::NetForgeError;
use crate::op::Operation;

/// A magic-byte signature: offset into the file, the bytes, and a label.
struct Sig {
    offset: usize,
    magic: &'static [u8],
    label: &'static str,
}

/// Signature table, ordered so that more specific matches are listed first.
const SIGS: &[Sig] = &[
    Sig {
        offset: 0,
        magic: b"\x7fELF",
        label: "ELF executable",
    },
    Sig {
        offset: 0,
        magic: b"MZ",
        label: "PE/DOS executable",
    },
    Sig {
        offset: 0,
        magic: b"\xca\xfe\xba\xbe",
        label: "Mach-O universal / Java class",
    },
    Sig {
        offset: 0,
        magic: b"\xcf\xfa\xed\xfe",
        label: "Mach-O 64-bit",
    },
    Sig {
        offset: 0,
        magic: b"\xfe\xed\xfa\xce",
        label: "Mach-O 32-bit",
    },
    Sig {
        offset: 0,
        magic: b"PK\x03\x04",
        label: "ZIP / JAR / APK / OOXML",
    },
    Sig {
        offset: 0,
        magic: b"PK\x05\x06",
        label: "ZIP (empty archive)",
    },
    Sig {
        offset: 0,
        magic: b"\x89PNG\r\n\x1a\n",
        label: "PNG image",
    },
    Sig {
        offset: 0,
        magic: b"\xff\xd8\xff",
        label: "JPEG image",
    },
    Sig {
        offset: 0,
        magic: b"GIF87a",
        label: "GIF image",
    },
    Sig {
        offset: 0,
        magic: b"GIF89a",
        label: "GIF image",
    },
    Sig {
        offset: 0,
        magic: b"\x1f\x8b",
        label: "gzip stream",
    },
    Sig {
        offset: 0,
        magic: b"BZh",
        label: "bzip2 stream",
    },
    Sig {
        offset: 0,
        magic: b"\xfd7zXZ\x00",
        label: "xz stream",
    },
    Sig {
        offset: 0,
        magic: b"7z\xbc\xaf\x27\x1c",
        label: "7-Zip archive",
    },
    Sig {
        offset: 0,
        magic: b"Rar!\x1a\x07",
        label: "RAR archive",
    },
    Sig {
        offset: 0,
        magic: b"%PDF-",
        label: "PDF document",
    },
    Sig {
        offset: 0,
        magic: b"\xd0\xcf\x11\xe0",
        label: "MS Office (legacy OLE)",
    },
    Sig {
        offset: 0,
        magic: b"SQLite format 3\x00",
        label: "SQLite database",
    },
    Sig {
        offset: 0,
        magic: b"OggS",
        label: "Ogg media",
    },
    Sig {
        offset: 0,
        magic: b"ID3",
        label: "MP3 (ID3)",
    },
    Sig {
        offset: 0,
        magic: b"\x25\x21PS",
        label: "PostScript",
    },
    Sig {
        offset: 0,
        magic: b"#!",
        label: "script (shebang)",
    },
];

/// Signatures scanned for throughout the buffer by [`Carve`] (offset ignored).
const CARVE_SIGS: &[(&[u8], &str)] = &[
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/DOS"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"%PDF-", "PDF"),
    (b"RIFF", "RIFF (WAV/AVI/WEBP)"),
    (b"SQLite format 3\x00", "SQLite"),
];

/// Identify a buffer by magic bytes. Returns a label, or an entropy-based guess.
pub fn identify(data: &[u8]) -> &'static str {
    for sig in SIGS {
        let end = sig.offset + sig.magic.len();
        if data.len() >= end && &data[sig.offset..end] == sig.magic {
            return sig.label;
        }
    }
    // Fallback: printable-heavy → text, else unknown binary.
    if data.is_empty() {
        return "empty";
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    if printable as f64 / data.len() as f64 > 0.95 {
        "ASCII/UTF-8 text"
    } else {
        "unknown binary data"
    }
}

/// `file_type` — report the identified type.
pub struct FileType;

impl Operation for FileType {
    fn name(&self) -> &str {
        "file_type"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        Ok(identify(input).as_bytes().to_vec())
    }
}

/// `carve` — list embedded file signatures and their offsets.
pub struct Carve;

impl Operation for Carve {
    fn name(&self) -> &str {
        "carve"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let mut hits: Vec<(usize, &str)> = Vec::new();
        for (magic, label) in CARVE_SIGS {
            if input.len() < magic.len() {
                continue;
            }
            // Report every occurrence; cheap windowed scan.
            let mut i = 0;
            while i + magic.len() <= input.len() {
                if &input[i..i + magic.len()] == *magic {
                    hits.push((i, label));
                    i += magic.len();
                } else {
                    i += 1;
                }
            }
        }
        hits.sort_by_key(|&(off, _)| off);

        let mut out = String::new();
        if hits.is_empty() {
            out.push_str("no embedded file signatures found\n");
        } else {
            out.push_str("offset       type\n");
            for (off, label) in hits {
                out.push_str(&format!("0x{off:08x}   {label}\n"));
            }
        }
        Ok(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_common_types() {
        assert_eq!(identify(b"\x7fELF\x02\x01\x01"), "ELF executable");
        assert_eq!(identify(b"MZ\x90\x00"), "PE/DOS executable");
        assert_eq!(identify(b"\x89PNG\r\n\x1a\nxxxx"), "PNG image");
        assert_eq!(identify(b"%PDF-1.7"), "PDF document");
        assert_eq!(identify(b"hello world, plain text!"), "ASCII/UTF-8 text");
        assert_eq!(identify(&[0u8, 1, 2, 3, 0xff, 0x80]), "unknown binary data");
    }

    #[test]
    fn carve_finds_embedded_png_and_zip() {
        let mut blob = vec![0u8; 16];
        blob.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(b"PK\x03\x04");
        let report = String::from_utf8(Carve.execute(&blob).unwrap()).unwrap();
        assert!(report.contains("PNG"), "{report}");
        assert!(report.contains("ZIP"), "{report}");
        assert!(report.contains("0x00000010"), "offset wrong: {report}");
    }

    #[test]
    fn carve_empty_when_nothing() {
        let r = String::from_utf8(Carve.execute(b"just text here").unwrap()).unwrap();
        assert!(r.contains("no embedded"), "{r}");
    }
}
