mod client_workflow_support;
mod support;

use axum::http::{Method, StatusCode};
use serde_json::json;

use client_workflow_support::{encrypt_vault_key, TestApp};
use zann_crypto::crypto::SecretKey;

async fn personal_status(app: &TestApp, token: &str) -> serde_json::Value {
    let (status, json) = app
        .send_json(
            Method::GET,
            "/v1/vaults/personal/status",
            Some(token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "personal status failed: {:?}", json);
    json
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_status_reports_missing_envelope() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("preflight-personal@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");

    let status = personal_status(&app, token).await;
    assert_eq!(status["personal_vaults_present"], true);
    assert_eq!(status["personal_key_envelopes_present"], false);
    assert!(status["personal_vault_id"].as_str().is_some());
}

#[tokio::test]
#[cfg_attr(not(feature = "postgres-tests"), ignore = "requires TEST_DATABASE_URL")]
async fn personal_status_reports_envelope_present() {
    let app = TestApp::new_with_smk().await;
    let user = app
        .register("preflight-envelope@example.com", "password")
        .await;
    let token = user["access_token"].as_str().expect("token");
    let vault_id = app
        .personal_vault_id("preflight-envelope@example.com")
        .await;
    let vault_key = SecretKey::generate();
    let vault_key_enc = encrypt_vault_key(&SecretKey::generate(), vault_id, &vault_key);
    app.update_vault_key(token, vault_id, vault_key_enc).await;

    let status = personal_status(&app, token).await;
    assert_eq!(status["personal_vaults_present"], true);
    assert_eq!(status["personal_key_envelopes_present"], true);
    assert!(status["personal_vault_id"].as_str().is_some());
}
