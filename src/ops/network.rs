use crate::error::NetForgeError;
use crate::op::Operation;

/// Replace dots in IPv4 addresses with `[.]` for safe sharing.
///
/// Standard practice in threat intel reports and IoC feeds to
/// prevent accidental hyperlink resolution.
pub struct DefangIp;

impl Operation for DefangIp {
    fn name(&self) -> &str {
        "defang_ip"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let text = std::str::from_utf8(input).map_err(|_| NetForgeError::InvalidUtf8)?;
        Ok(text.replace('.', "[.]").into_bytes())
    }
}

/// Reverse defanging — restore `[.]` back to `.`.
pub struct RefangIp;

impl Operation for RefangIp {
    fn name(&self) -> &str {
        "refang_ip"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let text = std::str::from_utf8(input).map_err(|_| NetForgeError::InvalidUtf8)?;
        Ok(text.replace("[.]", ".").into_bytes())
    }
}

/// Defang URLs by replacing `://` with `[://]` and `.` with `[.]`.
pub struct DefangUrl;

impl Operation for DefangUrl {
    fn name(&self) -> &str {
        "defang_url"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let text = std::str::from_utf8(input).map_err(|_| NetForgeError::InvalidUtf8)?;
        let result = text.replace("://", "[://]").replace('.', "[.]");
        Ok(result.into_bytes())
    }
}

/// Refang URLs — restore defanged URL to original form.
pub struct RefangUrl;

impl Operation for RefangUrl {
    fn name(&self) -> &str {
        "refang_url"
    }
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, NetForgeError> {
        let text = std::str::from_utf8(input).map_err(|_| NetForgeError::InvalidUtf8)?;
        let result = text.replace("[://]", "://").replace("[.]", ".");
        Ok(result.into_bytes())
    }
}
