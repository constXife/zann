use crate::types::TotpCodeResponse;

/// Re-exported so command handlers keep their existing import path.
pub use zann_ui_core::TotpParams;

pub fn generate_totp(params: TotpParams) -> Result<TotpCodeResponse, String> {
    let code = zann_ui_core::generate_totp(&params).map_err(|err| err.to_string())?;
    Ok(TotpCodeResponse {
        code: code.code,
        remaining_seconds: code.remaining_seconds,
        period: code.period,
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
