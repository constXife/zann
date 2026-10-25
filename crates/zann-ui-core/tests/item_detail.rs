use serde_json::{json, Value};
use zann_ui_core::{project_item_fields, ItemDetailField};

fn project(fields: Value, extra: Value) -> Vec<ItemDetailField> {
    project_item_fields(
        &json!({"v": 1, "typeId": "login", "fields": fields, "extra": extra}).to_string(),
    )
    .expect("project canonical payload")
}

#[test]
fn orders_known_fields_before_alphabetical_custom_fields() {
    let keys = [
        "z_custom", "notes", "value", "key", "url", "totp", "otp", "password", "email", "username",
        "a_custom",
    ];
    let fields = keys
        .into_iter()
        .map(|key| (key.to_string(), json!({"kind": "text", "value": key})))
        .collect::<serde_json::Map<_, _>>();
    let projected = project(fields.into(), Value::Null);
    assert_eq!(
        projected
            .iter()
            .map(|field| field.key.as_str())
            .collect::<Vec<_>>(),
        [
            "username", "email", "password", "otp", "totp", "url", "key", "value", "notes",
            "a_custom", "z_custom",
        ]
    );
}

#[test]
fn kinds_supply_policy_and_explicit_metadata_overrides_it() {
    let fields = project(
        json!({
            "password": {"kind": "password", "value": "secret"},
            "otp": {"kind": "otp", "value": "JBSWY3DPEHPK3PXP"},
            "notes": {"kind": "note", "value": "line one\nline two"},
            "url": {"kind": "url", "value": "https://example.com"},
            "custom": {"kind": "text", "value": "private", "meta": {
                "masked": true, "multiline": true
            }},
            "unmasked": {"kind": "password", "value": "visible", "meta": {
                "masked": false, "multiline": true
            }},
            "single_line": {"kind": "note", "value": "note", "meta": {
                "masked": true, "multiline": false
            }}
        }),
        Value::Null,
    );
    let field = |key: &str| fields.iter().find(|field| field.key == key).expect("field");
    assert!(field("password").masked);
    assert!(!field("password").multiline);
    assert!(field("otp").masked);
    assert!(field("otp").totp.is_some());
    assert!(!field("notes").masked);
    assert!(field("notes").multiline);
    assert_eq!(field("notes").value, "line one\nline two");
    assert!(!field("url").masked);
    assert!(!field("url").multiline);
    assert!(field("custom").masked && field("custom").multiline);
    assert!(!field("unmasked").masked && field("unmasked").multiline);
    assert!(field("single_line").masked && !field("single_line").multiline);
}

#[test]
fn bare_otp_reads_canonical_payload_parameters() {
    let fields = project(
        json!({"otp": {"kind": "otp", "value": "JBSWY3DPEHPK3PXP"}}),
        json!({"otp_algorithm": "SHA512", "otp_digits": "8", "otp_period": "60"}),
    );
    let params = fields[0].totp.as_ref().expect("otp parameters");
    assert_eq!(params.secret, "JBSWY3DPEHPK3PXP");
    assert_eq!(params.algorithm.as_deref(), Some("SHA512"));
    assert_eq!(params.digits, Some(8));
    assert_eq!(params.period, Some(60));
}

#[test]
fn absent_otp_parameters_are_left_to_the_totp_owner() {
    let fields = project(
        json!({"otp": {"kind": "otp", "value": "JBSWY3DPEHPK3PXP"}}),
        Value::Null,
    );
    let params = fields[0].totp.as_ref().expect("otp parameters");
    assert!(params.algorithm.is_none());
    assert!(params.digits.is_none());
    assert!(params.period.is_none());
}

#[test]
fn uri_parameters_override_extra_without_changing_the_stored_value() {
    let uri = "otpauth://totp/zann:demo?secret=NBSWY3DP&algorithm=SHA256&digits=8&period=60";
    let fields = project(
        json!({"custom_otp": {"kind": "otp", "value": uri}}),
        json!({"otp_algorithm": "SHA1", "otp_digits": "6", "otp_period": "30"}),
    );
    let params = fields[0].totp.as_ref().expect("otp parameters");
    assert_eq!(fields[0].value, uri);
    assert_eq!(params.secret, "NBSWY3DP");
    assert_eq!(params.algorithm.as_deref(), Some("SHA256"));
    assert_eq!(params.digits, Some(8));
    assert_eq!(params.period, Some(60));
}

#[test]
fn otp_policy_uses_kind_rather_than_field_name() {
    let fields = project(
        json!({"otp": {"kind": "text", "value": "ordinary text"}}),
        Value::Null,
    );
    assert!(!fields[0].masked);
    assert!(fields[0].totp.is_none());
}

#[test]
fn empty_fields_and_canonical_optional_fields_are_supported() {
    assert!(project_item_fields(r#"{"v":1,"typeId":"login"}"#)
        .expect("canonical empty payload")
        .is_empty());
}

#[test]
fn projection_and_parse_errors_redact_secrets() {
    let sentinel = "sentinel-private-value";
    let fields = project(
        json!({sentinel: {"kind": "otp", "value": sentinel}}),
        json!({"otp_algorithm": sentinel}),
    );
    assert!(!format!("{fields:?}").contains(sentinel));

    for payload in [
        json!({"v": 1, "typeId": "login", "fields": {
            "otp": {"kind": sentinel, "value": sentinel}
        }}),
        json!({"v": 1, "typeId": "login", sentinel: sentinel}),
        json!({"v": 1, "typeId": "login", "fields": {
            "otp": {"kind": "otp", "value": sentinel, "meta": {sentinel: true}}
        }}),
    ] {
        let error = project_item_fields(&payload.to_string()).expect_err("invalid schema");
        assert!(!format!("{error:?} {error}").contains(sentinel));
        // The canonical error retains the original serde diagnostic for callers.
        let zann_core::secrets::PayloadError::InvalidJson(source) = error;
        assert!(source.column() > 0);
    }
    assert!(project_item_fields("{").is_err());
}
