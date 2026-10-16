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
    /// Generic error with a human-readable message.
    Custom(String),
}

impl fmt::Display for NetForgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHexCharacter(c) => write!(f, "invalid hex character: '{c}'"),
            Self::InvalidHexLength => write!(f, "hex string must have even length"),
            Self::InvalidUtf8 => write!(f, "data is not valid UTF-8"),
            Self::InvalidBase64 => write!(f, "invalid base64 input"),
            Self::InvalidUrlEncoding => write!(f, "malformed percent-encoded sequence"),
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for NetForgeError {}
