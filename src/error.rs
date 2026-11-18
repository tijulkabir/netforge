use std::fmt;

/// All errors produced by NetForge operations.
#[derive(Debug, PartialEq, Eq)]
pub enum NetForgeError {
    /// A non-hex character was encountered during hex decoding.
    InvalidHexCharacter(char),
    /// Hex input has an odd number of characters.
    InvalidHexLength,
    /// Input bytes are not valid UTF-8.
    InvalidUtf8,
    /// Base64 input is malformed.
    InvalidBase64,
    /// A URL-encoded sequence is malformed (e.g., `%ZZ`).
    InvalidUrlEncoding,
    /// An I/O failure (file open, stdin read, write).
    Io(String),
    /// Generic error with a human-readable message.
    Custom(String),
}

impl NetForgeError {
    /// Stable machine-readable error slug (for `--json` output and tooling).
    ///
    /// These strings are part of the public contract: downstream scripts
    /// match on them, so they must not change without a semver bump.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidHexCharacter(_) => "invalid_hex_character",
            Self::InvalidHexLength => "invalid_hex_length",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::InvalidBase64 => "invalid_base64",
            Self::InvalidUrlEncoding => "invalid_url_encoding",
            Self::Io(_) => "io_error",
            Self::Custom(_) => "operation_error",
        }
    }

    /// Process exit code, following the BSD `sysexits.h` convention so the
    /// tool behaves predictably in scripts and CI.
    ///
    /// * `65` EX_DATAERR  — input data was malformed for the operation.
    /// * `74` EX_IOERR    — an I/O operation failed.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 74,
            _ => 65,
        }
    }
}

impl fmt::Display for NetForgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHexCharacter(c) => write!(f, "invalid hex character: '{c}'"),
            Self::InvalidHexLength => write!(f, "hex string must have even length"),
            Self::InvalidUtf8 => write!(f, "data is not valid UTF-8"),
            Self::InvalidBase64 => write!(f, "invalid base64 input"),
            Self::InvalidUrlEncoding => write!(f, "malformed percent-encoded sequence"),
            Self::Io(msg) => write!(f, "{msg}"),
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for NetForgeError {}
