#![cfg(feature = "browser-ipc")]
use zann_client::browser_ipc::*;
fn context() -> BrowserContext {
    BrowserContext {
        top_level_url: "https://login.example.com:443/path?secret=ignored".into(),
        frame_url: "https://login.example.com/path".into(),
    }
}
fn create() -> serde_json::Value {
    serde_json::json!({"challenge":"AQID","rp":{"name":"Example"},"user":{"id":"AQ","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]})
}
#[test]
fn webauthn_defaults_come_from_observed_origin_and_client_data_is_canonical() {
    let request = passkey_request(context(), "create", &create().to_string()).unwrap();
    assert_eq!(request.rp_id, "login.example.com");
    let client: serde_json::Value =
        serde_json::from_slice(&request.client_data().unwrap()).unwrap();
    assert_eq!(
        client,
        serde_json::json!({"type":"webauthn.create","challenge":"AQID","origin":"https://login.example.com","crossOrigin":false})
    );
    assert_eq!(request.client_data_hash().unwrap().len(), 32);
    let mut request_json = create();
    request_json["rp"]["id"] = "example.com".into();
    assert!(passkey_request(context(), "create", &request_json.to_string()).is_ok());
}
#[test]
fn unsupported_claims_bounds_and_browser_unsafe_origins_are_refused_in_rust() {
    for patch in [
        serde_json::json!({"challenge":"AQ=="}),
        serde_json::json!({"authenticatorSelection":{"userVerification":"required"}}),
        serde_json::json!({"extensions":{"prf":{}}}),
        serde_json::json!({"attestation":"direct"}),
        serde_json::json!({"rp":{"id":"other.com","name":"Other"}}),
        serde_json::json!({"rp":{"id":"com","name":"PSL"}}),
        serde_json::json!({"timeout":0}),
        serde_json::json!({"unknown":"field"}),
        serde_json::json!({"challenge":"a".repeat(2000)}),
    ] {
        let mut options = create();
        for (key, value) in patch.as_object().unwrap() {
            options[key] = value.clone();
        }
        assert!(passkey_request(context(), "create", &options.to_string()).is_err());
    }
    let mut cross = context();
    cross.frame_url = "https://other.example.com".into();
    assert!(passkey_request(cross, "create", &create().to_string()).is_err());
    let mut insecure = context();
    insecure.top_level_url = "http://login.example.com".into();
    insecure.frame_url = insecure.top_level_url.clone();
    assert!(passkey_request(insecure, "create", &create().to_string()).is_err());
    let mut options = create();
    options["excludeCredentials"] =
        serde_json::json!(vec![serde_json::json!({"type":"public-key","id":"AQ"}); 65]);
    assert!(passkey_request(context(), "create", &options.to_string()).is_err());
    assert!(passkey_request(context(), "get", &create().to_string()).is_err());
}
