/// Turn what the user typed in the "connect to server" field into a URL.
///
/// Blank input stays blank so callers can report "server URL is required";
/// anything without a scheme is assumed to be HTTPS.
pub fn normalize_server_url(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    format!("https://{trimmed}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_input_stays_blank() {
        assert_eq!(normalize_server_url(""), "");
        assert_eq!(normalize_server_url("   "), "");
    }

    #[test]
    fn keeps_an_explicit_scheme() {
        assert_eq!(
            normalize_server_url("http://localhost:8080"),
            "http://localhost:8080"
        );
        assert_eq!(
            normalize_server_url(" https://zann.example "),
            "https://zann.example"
        );
    }

    #[test]
    fn defaults_to_https() {
        assert_eq!(normalize_server_url("zann.example"), "https://zann.example");
        assert_eq!(
            normalize_server_url("zann.example:8443/path"),
            "https://zann.example:8443/path"
        );
    }
}
