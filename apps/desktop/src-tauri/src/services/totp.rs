use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32;
use totp_rs::{Algorithm, TOTP};

use crate::types::TotpCodeResponse;

#[derive(Debug)]
pub struct TotpParams {
    pub secret: String,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
}

fn parse_algorithm(value: Option<&str>) -> Result<Algorithm, String> {
    let normalized = value.unwrap_or("SHA1").trim().to_uppercase();
    match normalized.as_str() {
        "SHA1" => Ok(Algorithm::SHA1),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        _ => Err("unsupported otp algorithm".to_string()),
    }
}

fn parse_digits(value: Option<u32>) -> Result<u32, String> {
    let digits = value.unwrap_or(6);
    match digits {
        6 | 8 => Ok(digits),
        _ => Err("unsupported otp digits".to_string()),
    }
}

fn parse_period(value: Option<u32>) -> Result<u32, String> {
    let period = value.unwrap_or(30);
    if period == 0 {
        return Err("invalid otp period".to_string());
    }
    Ok(period)
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = secret
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .collect::<String>()
        .to_uppercase();
    BASE32
        .decode(cleaned.as_bytes())
        .map_err(|_| "invalid otp secret".to_string())
}

pub fn generate_totp(params: TotpParams) -> Result<TotpCodeResponse, String> {
    let algorithm = parse_algorithm(params.algorithm.as_deref())?;
    let digits = parse_digits(params.digits)?;
    let period = parse_period(params.period)?;
    let secret_bytes = decode_secret(params.secret.trim())?;
    let totp = TOTP::new(
        algorithm,
        digits as usize,
        1,
        period as u64,
        secret_bytes,
    )
    .map_err(|err| err.to_string())?;
    let code = totp.generate_current().map_err(|err| err.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid system time".to_string())?
        .as_secs();
    let remaining = period as u64 - (now % period as u64);
    Ok(TotpCodeResponse {
        code,
        remaining_seconds: remaining as u32,
        period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_code_with_defaults() {
        let params = TotpParams {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: None,
            digits: None,
            period: None,
        };
        let response = generate_totp(params).expect("totp");
        assert_eq!(response.code.len(), 6);
        assert!(response.remaining_seconds <= response.period);
        assert!(response.remaining_seconds > 0);
    }
}
