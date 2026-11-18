#![allow(dead_code)]
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zann_core::api::{account_access::*, auth::LoginResponse};
use zann_crypto::{account_access::*, SecretKey};
use zann_db::PgPool;
use zann_server::{
    app::{build_router, AppState},
    config::{InternalRegistration, PasskeyConfig, ServerConfig},
};
pub mod token;
pub const ORIGIN: &str = "https://zann.example";
pub struct TestApp {
    pub app: axum::Router,
    pub state: AppState,
    pub pool: PgPool,
}
impl TestApp {
    pub async fn new() -> Self {
        let pool = crate::support::setup_db().await;
        let mut config = ServerConfig::default();
        crate::support::tune_test_kdf(&mut config);
        config.auth.internal.registration = InternalRegistration::Open;
        config.auth.passkey = Some(PasskeyConfig {
            rp_id: "zann.example".into(),
            rp_name: "Zann".into(),
            origins: vec![
                ORIGIN.into(),
                "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ],
        });
        let (secret_policies, secret_default_policy) = crate::support::default_secret_policies();
        let state = AppState {
            db: pool.clone(),
            db_tx_isolation: zann_server::settings::DbTxIsolation::ReadCommitted,
            started_at: std::time::Instant::now(),
            password_pepper: "test-pepper".into(),
            token_pepper: "test-token-pepper".into(),
            server_master_key: Some(Arc::new(SecretKey::generate())),
            identity_key: crate::support::test_identity_key(),
            access_token_ttl_seconds: 3600,
            refresh_token_ttl_seconds: 3600,
            argon2_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            account_access: Default::default(),
            oidc_jwks_cache: zann_server::oidc::OidcJwksCache::new(),
            config,
            policy_store: zann_server::domains::access_control::policy_store::PolicyStore::new(
                zann_server::domains::access_control::policies::PolicySet::from_rules(
                    crate::support::load_policy_rules(),
                ),
            ),
            usage_tracker: Arc::new(zann_server::infra::usage::UsageTracker::new(
                pool.clone(),
                100,
            )),
            security_profiles: zann_server::infra::security_profiles::load_security_profiles(),
            secret_policies,
            secret_default_policy,
        };
        Self {
            app: build_router(state.clone()),
            state,
            pool,
        }
    }
    pub async fn request<T: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        input: &T,
    ) -> (StatusCode, Vec<u8>) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(
                request
                    .body(Body::from(serde_json::to_vec(input).expect("input")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .map(|s| s.to_str().expect("cache-control")),
            Some("no-store")
        );
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 128 * 1024)
            .await
            .expect("bounded response");
        (status, bytes.to_vec())
    }
    pub async fn ok<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        input: &T,
    ) -> R {
        let (status, bytes) = self.request(Method::POST, path, token, input).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        serde_json::from_slice(&bytes).expect("typed reply")
    }
    pub async fn register_user(&self) -> LoginResponse {
        // Legacy registration is outside the new no-store router.
        let request=Request::builder().method(Method::POST).uri("/v1/auth/register").header("content-type","application/json")
            .body(Body::from(serde_json::to_vec(&serde_json::json!({"email":"person@example.test","password":"server-login-password"})).expect("registration"))).expect("request");
        let response = self.app.clone().oneshot(request).await.expect("register");
        assert_eq!(response.status(), StatusCode::CREATED);
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.expect("body"))
            .expect("tokens")
    }
    pub async fn security(&self, token: &str) -> AccountSecurity {
        let (status, bytes) = self
            .request(Method::GET, "/v1/users/me/security", Some(token), &())
            .await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_slice(&bytes).expect("security")
    }
    pub async fn descriptor(&self, token: &str) -> (SecretKey, AccountDescriptor, AccountSecurity) {
        let snapshot = self.security(token).await;
        let key = SecretKey::from_bytes([27; 32]);
        let id = zann_server::infra::server_identity::server_id(
            &self.state.identity_key.verifying_key(),
        );
        let descriptor = AccountCustody::derive(&key, &id, snapshot.user_id, 1)
            .expect("custody")
            .descriptor(&id, snapshot.user_id, 1);
        let input = DescriptorBootstrap {
            operation_id: Uuid::new_v4(),
            expected_revision: snapshot.security_revision,
            descriptor: descriptor.clone(),
            proof: ManagementProof::InitialPassword {
                server_password: "server-login-password".into(),
            },
        };
        let security = self
            .ok("/v1/users/me/security/descriptor", Some(token), &input)
            .await;
        (key, descriptor, security)
    }
    pub async fn proof(
        &self,
        token: &str,
        key: &SecretKey,
        descriptor: &AccountDescriptor,
        revision: i64,
        purpose: MutationPurpose,
        digest: [u8; 32],
    ) -> CustodyProof {
        let options = MutationOptions {
            purpose,
            body_digest: encode(&digest),
            expected_revision: revision,
        };
        let context: MutationContext = self
            .ok(
                "/v1/users/me/security/custody/options",
                Some(token),
                &options,
            )
            .await;
        let custody = AccountCustody::derive(
            key,
            &descriptor.server_id,
            descriptor.user_id,
            descriptor.key_epoch,
        )
        .expect("custody");
        CustodyProof {
            signature: custody
                .sign_mutation(descriptor, &context)
                .expect("signature"),
            context,
        }
    }
    pub fn device() -> DeviceDescriptor {
        DeviceDescriptor {
            name: "test-device".into(),
            platform: "linux".into(),
            fingerprint: Some("test".into()),
            os: Some("linux".into()),
            os_version: None,
            app_version: None,
        }
    }
}
impl TestApp {
    pub async fn enroll_auth_only(
        &self,
        token: &str,
        key: &SecretKey,
        descriptor: &AccountDescriptor,
    ) -> (token::Token, PasskeySummary) {
        let snapshot = self.security(token).await;
        let enrollment = EnrollmentRequest {
            operation_id: Uuid::new_v4(),
            expected_revision: snapshot.security_revision,
            name: "spare token".into(),
            mode: PasskeyMode::AuthOnly,
        };
        let options: CeremonyOptions = self
            .ok("/v1/users/me/passkeys/options", Some(token), &enrollment)
            .await;
        let (hardware, response) = token::Token::register(&options, ORIGIN, true);
        let options: CeremonyOptions = self
            .ok(
                "/v1/users/me/passkeys/register",
                Some(token),
                &CeremonyFinish {
                    operation_id: enrollment.operation_id,
                    response,
                },
            )
            .await;
        let receipt: CandidateReceipt = self
            .ok(
                "/v1/users/me/passkeys/test",
                Some(token),
                &CeremonyFinish {
                    operation_id: enrollment.operation_id,
                    response: hardware.assert(&options, ORIGIN, true, false),
                },
            )
            .await;
        let proof = self
            .proof(
                token,
                key,
                descriptor,
                snapshot.security_revision,
                MutationPurpose::CredentialAdd,
                receipt.activation_digest().expect("digest"),
            )
            .await;
        let _: SecurityReceipt = self
            .ok(
                "/v1/users/me/passkeys/activate",
                Some(token),
                &ActivateCredential {
                    operation_id: enrollment.operation_id,
                    expected_revision: snapshot.security_revision,
                    proof: ManagementProof::Custody { proof },
                },
            )
            .await;
        (
            hardware,
            self.security(token)
                .await
                .credentials
                .into_iter()
                .find(|k| k.credential_id == receipt.credential_id)
                .expect("activated"),
        )
    }
    pub async fn login_with(&self, token: &token::Token) -> PasskeyLogin {
        let options: CeremonyOptions = self
            .ok(
                "/v1/auth/passkeys/login/options",
                None,
                &PasskeyLoginOptions {
                    operation_id: Uuid::new_v4(),
                    device: Self::device(),
                },
            )
            .await;
        self.ok(
            "/v1/auth/passkeys/login/finish",
            None,
            &CeremonyFinish {
                operation_id: options.operation_id,
                response: token.assert(&options, ORIGIN, true, false),
            },
        )
        .await
    }
}
impl TestApp {
    pub async fn activate_recovery_code(
        &self,
        token: &str,
        key: &SecretKey,
        descriptor: &AccountDescriptor,
    ) -> zeroize::Zeroizing<String> {
        let snapshot = self.security(token).await;
        let code = zann_crypto::recovery::generate_server_recovery_key();
        let mut input = ActivateRecoveryCode {
            candidate_id: Uuid::new_v4(),
            expected_revision: snapshot.security_revision,
            recovery_key: code.to_string(),
            disable_password: true,
            proof: ManagementProof::InitialPassword {
                server_password: String::new(),
            },
        };
        let proof = self
            .proof(
                token,
                key,
                descriptor,
                snapshot.security_revision,
                MutationPurpose::CodeRotate,
                input.digest().expect("digest"),
            )
            .await;
        input.proof = ManagementProof::Custody { proof };
        let _: SecurityReceipt = self
            .ok(
                "/v1/users/me/security/recovery-code/activate",
                Some(token),
                &input,
            )
            .await;
        code
    }
    pub async fn recovery_request<T: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        id: Uuid,
        secrets: &zann_crypto::recovery::RecoverySecrets,
        input: &T,
    ) -> (StatusCode, Vec<u8>) {
        let header = zeroize::Zeroizing::new(format!("Recovery {id}.{}", secrets.resume_token()));
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", header.as_str())
            .body(Body::from(serde_json::to_vec(input).expect("input")))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        assert_eq!(
            response.headers().get("cache-control").expect("no-store"),
            "no-store"
        );
        let status = response.status();
        let body = to_bytes(response.into_body(), 128 * 1024)
            .await
            .expect("body");
        (status, body.to_vec())
    }
    pub async fn recovery<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        id: Uuid,
        secrets: &zann_crypto::recovery::RecoverySecrets,
        input: &T,
    ) -> R {
        let (status, body) = self
            .recovery_request(method, path, id, secrets, input)
            .await;
        assert_eq!(status, StatusCode::OK, "{path}");
        serde_json::from_slice(&body).expect("recovery reply")
    }
}
