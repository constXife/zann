use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32;
use serde::Serialize;
use thiserror::Error;
use totp_rs::{Algorithm, TOTP};

const DEFAULT_ALGORITHM: &str = "SHA1";
const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u32 = 30;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("unsupported otp algorithm")]
    Algorithm,
    #[error("unsupported otp digits")]
    Digits,
    #[error("invalid otp period")]
    Period,
    #[error("invalid otp secret")]
    Secret,
    #[error("invalid system time")]
    SystemTime,
    #[error("{0}")]
    Generate(String),
}

/// TOTP parameters as they come out of an item payload; `None` means "use the
/// RFC 6238 default".
#[derive(Debug, Clone, Default)]
pub struct TotpParams {
    pub secret: String,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
}

impl TotpParams {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TotpCode {
    pub code: String,
    /// Seconds until the current code rolls over.
    pub remaining_seconds: u32,
    pub period: u32,
}

pub fn generate_totp(params: &TotpParams) -> Result<TotpCode, TotpError> {
    let algorithm = parse_algorithm(params.algorithm.as_deref())?;
    let digits = parse_digits(params.digits)?;
    let period = parse_period(params.period)?;
    let secret = decode_secret(&params.secret)?;

    // `TOTP::new` rejects secrets shorter than 128 bits since totp-rs 5.7.1.
    // Plenty of services still hand out 80-bit secrets, and refusing to show a
    // code for a secret the user already holds helps nobody, so the length
    // check is skipped deliberately.
    let totp = TOTP::new_unchecked(algorithm, digits as usize, 1, period as u64, secret);
    let code = totp
        .generate_current()
        .map_err(|err| TotpError::Generate(err.to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TotpError::SystemTime)?
        .as_secs();
    let remaining_seconds = period as u64 - (now % period as u64);

    Ok(TotpCode {
        code,
        remaining_seconds: remaining_seconds as u32,
        period,
    })
}

fn parse_algorithm(value: Option<&str>) -> Result<Algorithm, TotpError> {
    let value = value.unwrap_or(DEFAULT_ALGORITHM).trim();
    let normalized = if value.is_empty() {
        DEFAULT_ALGORITHM.to_string()
    } else {
        value.to_uppercase()
    };
    match normalized.as_str() {
        "SHA1" => Ok(Algorithm::SHA1),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        _ => Err(TotpError::Algorithm),
    }
}

fn parse_digits(value: Option<u32>) -> Result<u32, TotpError> {
    match value.unwrap_or(DEFAULT_DIGITS) {
        digits @ (6 | 8) => Ok(digits),
        _ => Err(TotpError::Digits),
    }
}

fn parse_period(value: Option<u32>) -> Result<u32, TotpError> {
    match value.unwrap_or(DEFAULT_PERIOD) {
        0 => Err(TotpError::Period),
        period => Ok(period),
    }
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, TotpError> {
    let cleaned: String = secret
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .collect::<String>()
        .to_uppercase();
    BASE32
        .decode(cleaned.as_bytes())
        .map_err(|_| TotpError::Secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    #[test]
    fn generates_code_with_defaults() {
        let code = generate_totp(&TotpParams::new(SECRET)).expect("totp");
        assert_eq!(code.code.len(), 6);
        assert_eq!(code.period, DEFAULT_PERIOD);
        assert!(code.remaining_seconds > 0);
        assert!(code.remaining_seconds <= code.period);
    }

    #[test]
    fn accepts_formatted_secrets() {
        let code = generate_totp(&TotpParams::new("jbsw y3dp-ehpk 3pxp")).expect("totp");
        let reference = generate_totp(&TotpParams::new(SECRET)).expect("totp");
        assert_eq!(code.code, reference.code);
    }

    #[test]
    fn empty_algorithm_falls_back_to_sha1() {
        let params = TotpParams {
            algorithm: Some(String::new()),
            ..TotpParams::new(SECRET)
        };
        assert!(generate_totp(&params).is_ok());
    }

    #[test]
    fn rejects_unsupported_parameters() {
        let bad_algorithm = TotpParams {
            algorithm: Some("MD5".to_string()),
            ..TotpParams::new(SECRET)
        };
        assert_eq!(generate_totp(&bad_algorithm), Err(TotpError::Algorithm));

        let bad_digits = TotpParams {
            digits: Some(7),
            ..TotpParams::new(SECRET)
        };
        assert_eq!(generate_totp(&bad_digits), Err(TotpError::Digits));

        let bad_period = TotpParams {
            period: Some(0),
            ..TotpParams::new(SECRET)
        };
        assert_eq!(generate_totp(&bad_period), Err(TotpError::Period));

        let bad_secret = TotpParams::new("not base32!");
        assert_eq!(generate_totp(&bad_secret), Err(TotpError::Secret));
    }

    #[test]
    fn honours_eight_digit_codes() {
        let params = TotpParams {
            digits: Some(8),
            period: Some(60),
            ..TotpParams::new(SECRET)
        };
        let code = generate_totp(&params).expect("totp");
        assert_eq!(code.code.len(), 8);
        assert_eq!(code.period, 60);
    }
}
