use super::*;

pub struct TotpMeta {
    pub secret: String,
    pub otp_type: Option<String>,
    pub issuer: Option<String>,
    pub label: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<String>,
    pub period: Option<String>,
}

pub fn extract_totp_meta(value: &str) -> Option<TotpMeta> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let url = Url::parse(trimmed).ok()?;
    if url.scheme() != "otpauth" {
        return None;
    }
    let otp_type = url.host_str().map(|value| value.to_string());
    let mut secret = None;
    let mut issuer = None;
    let mut label = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    let raw_path = url.path().trim_matches('/');
    if !raw_path.is_empty() {
        let decoded = percent_decode_str(raw_path).decode_utf8_lossy();
        if let Some((path_issuer, path_label)) = decoded.split_once(':') {
            let path_issuer = path_issuer.trim();
            let path_label = path_label.trim();
            if !path_issuer.is_empty() && issuer.is_none() {
                issuer = Some(path_issuer.to_string());
            }
            if !path_label.is_empty() {
                label = Some(path_label.to_string());
            }
        } else {
            let path_label = decoded.trim();
            if !path_label.is_empty() {
                label = Some(path_label.to_string());
            }
        }
    }
    for (key, val) in url.query_pairs() {
        if key.eq_ignore_ascii_case("secret") {
            let value = val.trim();
            if !value.is_empty() {
                secret = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("issuer") {
            let value = val.trim();
            if !value.is_empty() {
                issuer = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("algorithm") {
            let value = val.trim();
            if !value.is_empty() {
                algorithm = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("digits") {
            let value = val.trim();
            if !value.is_empty() {
                digits = Some(value.to_string());
            }
        } else if key.eq_ignore_ascii_case("period") {
            let value = val.trim();
            if !value.is_empty() {
                period = Some(value.to_string());
            }
        }
    }
    let secret = secret?;
    Some(TotpMeta {
        secret,
        otp_type,
        issuer,
        label,
        algorithm,
        digits,
        period,
    })
}

#[derive(serde::Deserialize)]
pub struct ApplePasswordsRow {
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "Username")]
    pub username: Option<String>,
    #[serde(rename = "Password")]
    pub password: Option<String>,
    #[serde(rename = "Notes")]
    pub notes: Option<String>,
    #[serde(rename = "OTPAuth")]
    pub otp_auth: Option<String>,
}
