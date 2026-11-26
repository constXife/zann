//! Real HTTP/Postgres/native core with synthetic UV+PRF: no hardware claim.
use super::*;
use zann_client::account_access::*;
use zann_client::app::{
    LoginPassword, PasskeyEnrollmentAuthorization, PasskeyVaultRequirement,
    PrepareConnectionOutcome,
};
use zann_core::api::account_access::{CeremonyPhase, PasskeyMode, RecoveryStepResult};
use zann_core::recovery::RecoveryState;
use zeroize::Zeroizing;
#[path = "../../zann-server/tests/account_access_support/token.rs"]
mod token;
#[derive(Default)]
struct Provider(Mutex<Option<token::Token>>, std::sync::atomic::AtomicUsize);
impl AccountCeremonyProvider for Provider {
    fn perform(&self, prompt: AccountCeremonyPrompt) -> AccountCeremonyFuture<'_> {
        Box::pin(async move {
            validate_account_prompt(&prompt)?;
            let response = match prompt.options.phase {
                CeremonyPhase::Register => {
                    self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let (token, response) =
                        token::Token::register(&prompt.options, "https://zann.example", true);
                    *self.0.lock().unwrap() = Some(token);
                    response
                }
                _ => self
                    .0
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("registered synthetic key")
                    .assert(&prompt.options, "https://zann.example", true, false),
            };
            Ok(AccountCeremonyResult {
                response,
                prf: if prompt.require_prf || prompt.options.phase == CeremonyPhase::Login {
                    Some(PrfOutput::new([9; 32]))
                } else {
                    None
                },
            })
        })
    }
}
// Faults occur after the server commits, so the client must resolve ambiguity
// using the exact immutable receipt rather than repeating registration/consume.
#[derive(Default)]
struct LostReplies(Mutex<std::collections::VecDeque<&'static str>>);
async fn lose_replies(
    axum::extract::State(faults): axum::extract::State<Arc<LostReplies>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    const ACTIVATE: &str = "/v1/users/me/security/recovery-code/activate";
    if !(path.starts_with("/v1/auth/recover") || path == ACTIVATE)
        || !response.status().is_success()
    {
        return response;
    }
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    let kind = if path == ACTIVATE {
        Some("activate")
    } else if path == "/v1/auth/recover" {
        Some("consume")
    } else if path.ends_with("/credential/finish") {
        let reply: zann_core::api::account_access::RecoveryStepReply =
            serde_json::from_slice(&bytes).unwrap();
        match reply.result {
            RecoveryStepResult::Ceremony { .. } => Some("register"),
            RecoveryStepResult::GrantReady { .. } => Some("grant"),
            _ => None,
        }
    } else if path.ends_with("/complete") {
        Some("complete")
    } else {
        None
    };
    let mut queue = faults.0.lock().unwrap();
    if kind.is_some() && queue.front().copied() == kind {
        queue.pop_front();
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    axum::response::Response::from_parts(parts, axum::body::Body::from(bytes))
}
fn has_note(core: &LocalVault) {
    let page = core
        .items_list(
            zann_client::app::local::ItemsFilter {
                updated: None,
                query: None,
                include_deleted: false,
            },
            zann_client::app::local::Page {
                limit: 100,
                cursor: None,
            },
        )
        .unwrap();
    assert!(page
        .items
        .iter()
        .any(|item| item.title == "passkey-account-sentinel"));
}
fn failure(error: zann_client::app::SessionError) -> ! {
    use std::error::Error;
    panic!("account flow: {error}; source={:?}", error.source())
}
fn local_failure(error: zann_client::app::local::LocalError) -> ! {
    use std::error::Error;
    let mut causes = Vec::new();
    let mut source = error.source();
    while let Some(error) = source {
        causes.push(error.to_string());
        source = error.source();
    }
    panic!("local account flow: {error}; causes={causes:?}")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_native_account_flow_enrolls_opens_clean_device_and_recovers_without_server_e2ee_keys()
{
    let app = server_app::TestApp::new_with_smk().await;
    let login = app
        .register("passkey@example.test", "Test password 123!")
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let faults = Arc::new(LostReplies::default());
    let router = app
        .router_with_account_passkeys()
        .layer(axum::middleware::from_fn_with_state(
            faults.clone(),
            lose_replies,
        ));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let source_root = tempdir();
        let source_credentials = Arc::new(Credentials::default());
        let source = open_with_credentials(source_root.path(), source_credentials.clone());
        connect(&source, &url, &login);
        account_replicas::create_note(&source, "passkey-account-sentinel");
        source.remote_sync(None, None).unwrap();
        let original = Arc::new(Provider::default());
        source
            .enroll_account_passkey(
                "external UV key".into(),
                PasskeyMode::VaultUnlock,
                PasskeyEnrollmentAuthorization::ServerPassword(
                    LoginPassword::new("Test password 123!").unwrap(),
                ),
                original.clone(),
            )
            .unwrap_or_else(|error| panic!("enroll: {error:?}"));
        let candidate = source.prepare_server_recovery_code().unwrap();
        let code = Zeroizing::new(candidate.code().to_owned());
        faults.0.lock().unwrap().push_back("activate");
        // The server commits but the reply is lost: staged code and saved proof survive.
        source
            .activate_server_recovery_code(&candidate, code.to_string(), true, original.clone())
            .unwrap_err();
        // Same saved candidate is replayable after its security revision advanced.
        source
            .activate_server_recovery_code(&candidate, code.to_string(), true, original.clone())
            .unwrap();
        // Confirmed activation removed the staged code from the OS store: spent.
        source
            .activate_server_recovery_code(&candidate, code.to_string(), true, original.clone())
            .unwrap_err();
        let source_client = account_replicas::client(source_root.path(), source_credentials);
        let source_target = source_client.configured_target(None).unwrap();
        let signed_in = runtime
            .block_on(source_client.passkey_login(
                source_target,
                original.clone(),
                account_replicas::operation(),
            ))
            .unwrap_or_else(|e| failure(e));
        drop(signed_in.vault);
        assert!(source.activate_connected_account().unwrap());
        source.remote_sync(None, None).unwrap();
        has_note(&source);
        let auth_only = Arc::new(Provider::default());
        source
            .enroll_account_passkey(
                "explicit auth-only key".into(),
                PasskeyMode::AuthOnly,
                PasskeyEnrollmentAuthorization::EstablishedCustody,
                auth_only.clone(),
            )
            .unwrap();
        let auth_root = tempdir();
        let auth_credentials = Arc::new(Credentials::default());
        let auth_core = open_with_credentials(auth_root.path(), auth_credentials.clone());
        let auth_client = account_replicas::client(auth_root.path(), auth_credentials);
        let PrepareConnectionOutcome::Ready(auth_prepared) = runtime
            .block_on(auth_client.prepare_account_connection(&url, "Auth-only test", None))
            .unwrap()
        else {
            panic!("trust changed")
        };
        let auth = runtime
            .block_on(auth_client.passkey_login(
                auth_prepared.target().clone(),
                auth_only,
                account_replicas::operation(),
            ))
            .unwrap_or_else(|e| failure(e));
        assert_eq!(
            auth.vault.requirement(),
            PasskeyVaultRequirement::EncryptionPassword
        );
        drop(auth.vault);
        auth_core
            .initialize_master_password("independent auth-only device".into())
            .unwrap();
        assert!(!auth_core.activate_connected_account().unwrap());
        auth_core
            .enroll_account_key("test master password".into())
            .unwrap();
        auth_core.remote_sync(None, None).unwrap();
        has_note(&auth_core);
        let clean_root = tempdir();
        let credentials = Arc::new(Credentials::default());
        let clean = open_with_credentials(clean_root.path(), credentials.clone());
        let client = account_replicas::client(clean_root.path(), credentials);
        let PrepareConnectionOutcome::Ready(prepared) = runtime
            .block_on(client.prepare_account_connection(&url, "Passkey test", None))
            .unwrap()
        else {
            panic!("trust changed")
        };
        let clean_target = prepared.target().clone();
        let outcome = runtime
            .block_on(client.passkey_login(
                prepared.target().clone(),
                original.clone(),
                account_replicas::operation(),
            ))
            .unwrap_or_else(|e| failure(e));
        assert_eq!(outcome.vault.requirement(), PasskeyVaultRequirement::Ready);
        assert!(
            !clean.app_status().unwrap().initialized,
            "server passkey never initializes/opens DeviceUnlock"
        );
        clean
            .initialize_master_password("independent second device password".into())
            .unwrap();
        clean
            .complete_account_passkey_login(outcome.vault)
            .unwrap_or_else(|error| local_failure(error));
        clean.remote_sync(None, None).unwrap();
        has_note(&clean);
        clean.lock().unwrap();
        clean
            .unlock("independent second device password".into())
            .unwrap();
        has_note(&clean);
        let recovery_root = tempdir();
        let credentials = Arc::new(Credentials::default());
        let recovered = open_with_credentials(recovery_root.path(), credentials.clone());
        let recovering = account_replicas::client(recovery_root.path(), credentials.clone());
        let PrepareConnectionOutcome::Ready(prepared) = runtime
            .block_on(recovering.prepare_account_connection(&url, "Recovery test", None))
            .unwrap()
        else {
            panic!("trust changed")
        };
        let plan = runtime
            .block_on(recovering.prepare_account_recovery(
                prepared.target().clone(),
                "passkey@example.test".into(),
                account_replicas::operation(),
            ))
            .unwrap();
        let successor = Zeroizing::new(plan.successor_code().to_owned());
        faults
            .0
            .lock()
            .unwrap()
            .extend(["consume", "register", "grant", "complete"]);
        let (_, result) = runtime
            .block_on(recovering.arm_and_consume_account_recovery(
                plan,
                successor.clone(),
                code,
                account_replicas::operation(),
            ))
            .unwrap_or_else(|e| failure(e));
        assert_eq!(result.expect_err("lost consume reply").status(), Some(503));
        // Restart the facade and resume from the persisted keystore bundle.
        drop(recovering);
        let recovering = account_replicas::client(recovery_root.path(), credentials);
        let handle = runtime
            .block_on(
                recovering
                    .pending_account_recoveries(prepared.target(), &account_replicas::operation()),
            )
            .unwrap()
            .pop()
            .expect("durable recovery handle");
        let view = runtime
            .block_on(recovering.resume_account_recovery(&handle, account_replicas::operation()))
            .unwrap_or_else(|e| failure(e));
        assert_eq!(view.status.state, RecoveryState::Consumed);
        let replacement = Arc::new(Provider::default());
        for expected in ["register", "grant", "complete"] {
            let lost = runtime
                .block_on(recovering.enroll_recovery_passkey(
                    &handle,
                    "replacement UV key".into(),
                    PasskeyMode::VaultUnlock,
                    Some(LoginPassword::new("test master password").unwrap()),
                    replacement.clone(),
                    account_replicas::operation(),
                ))
                .err()
                .unwrap_or_else(|| panic!("expected lost {expected} reply"));
            assert_eq!(lost.status(), Some(503));
            let resumed = runtime
                .block_on(
                    recovering.resume_account_recovery(&handle, account_replicas::operation()),
                )
                .unwrap_or_else(|e| failure(e));
            match expected {
                "register" => assert!(resumed
                    .candidate
                    .as_ref()
                    .unwrap()
                    .registered_credential_id
                    .is_some()),
                "grant" => assert!(resumed.grant.is_some()),
                "complete" => assert_eq!(resumed.status.state, RecoveryState::Completed),
                _ => unreachable!(),
            }
        }
        assert!(faults.0.lock().unwrap().is_empty());
        assert_eq!(
            replacement.1.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "resume never registers another key"
        );
        assert!(!recovered.app_status().unwrap().initialized);
        let outcome = runtime
            .block_on(recovering.passkey_login(
                prepared.target().clone(),
                replacement,
                account_replicas::operation(),
            ))
            .unwrap_or_else(|e| failure(e));
        recovered
            .initialize_master_password("independent recovered device password".into())
            .unwrap();
        recovered
            .complete_account_passkey_login(outcome.vault)
            .unwrap();
        recovered.remote_sync(None, None).unwrap();
        has_note(&recovered);
        recovered.acknowledge_account_recovery().unwrap();
        assert!(runtime
            .block_on(
                recovering
                    .pending_account_recoveries(prepared.target(), &account_replicas::operation())
            )
            .unwrap()
            .is_empty());
        let revoked = runtime
            .block_on(client.passkey_login(clean_target, original, account_replicas::operation()))
            .err()
            .expect("lost key revoked");
        assert_eq!(revoked.status(), Some(401));
        for root in [source_root.path(), clean_root.path(), recovery_root.path()] {
            for name in [
                "client-config.json",
                "client-auth.account-requests.json",
                "client-auth.recovery-intents.json",
            ] {
                if let Ok(text) = std::fs::read_to_string(root.join(name)) {
                    assert!(!text.contains("Test password 123!"));
                    assert!(!text.contains("test master password"));
                    assert!(!text.contains(successor.as_str()));
                    assert!(!text.contains(&zann_crypto::account_access::encode(&[9; 32])));
                }
            }
        }
    })
    .await
    .unwrap();
    server.abort();
}
