//! TLS policy shared by every production HTTP transport in the client.

pub(crate) fn client_builder() -> reqwest::ClientBuilder {
    // Native TLS permits older protocols by default. Keep the same TLS 1.2
    // floor as Rustls when selecting the iOS system trust implementation.
    let builder = reqwest::Client::builder().min_tls_version(reqwest::tls::Version::TLS_1_2);
    // Select explicitly: Cargo feature unification must not choose our backend.
    #[cfg(target_os = "ios")]
    {
        builder.use_native_tls()
    }
    #[cfg(not(target_os = "ios"))]
    {
        builder.use_rustls_tls()
    }
}
