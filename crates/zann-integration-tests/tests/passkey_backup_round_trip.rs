//! Synthetic passkey corpus through both canonical server restore paths and clean pulls.
use super::*;
use zann_client::app::local::{BackupRecipient, ItemsFilter, Page};
use zann_client::passkey_exchange::{self as exchange, ExchangeFormat};
use zann_passkey::*;
fn phrase() -> BackupRecipient {
    BackupRecipient::Passphrase {
        passphrase: "synthetic corpus recovery phrase".into(),
    }
}
fn check(payload: &zann_core::EncryptedPayload) {
    let credential = Credential::from_payload(payload).unwrap();
    let site = SiteUrl::parse("https://login.example.com").unwrap();
    let rp = RpId::parse("example.com").unwrap();
    let request = GetAssertionRequest {
        client_data_hash: [42; 32],
        context: CeremonyContext {
            top_level: &site,
            frame: &site,
            cross_origin_permission: CrossOriginPermission::Denied,
            presence: UserPresence::Confirmed,
            verification: UserVerification::Verified,
        },
        rp_id: &rp,
        allow_credentials: &[],
        require_verification: true,
    };
    let response = get_assertion(&request, &credential).unwrap();
    let mut signed = response.authenticator_data;
    assert_eq!(signed[32], 0x1d);
    assert_eq!(&signed[33..], &[0; 4]);
    signed.extend([42; 32]);
    let public = include_str!("../../../tests/fixtures/passkey-exchange/es256-public.hex").trim();
    let expected = (0..public.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&public[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    zann_crypto::es256::verify(&expected, &signed, &response.signature).unwrap();
}
fn payloads(core: &LocalVault) -> Vec<zann_core::EncryptedPayload> {
    let mut items = core
        .items_list(
            ItemsFilter {
                query: None,
                include_deleted: false,
            },
            Page {
                limit: 100,
                cursor: None,
            },
        )
        .unwrap()
        .items;
    items.sort_by(|a, b| a.path.cmp(&b.path));
    items
        .into_iter()
        .map(|item| {
            assert_eq!(item.type_id, "passkey");
            zann_core::EncryptedPayload::from_bytes(
                core.item_get(item.id).unwrap().payload_json.as_bytes(),
            )
            .unwrap()
        })
        .collect()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passkey_corpus_restores_plain_and_encrypted_then_asserts_on_an_independent_device() {
    let app = server_app::TestApp::new_with_smk().await;
    let login = app
        .register("passkey-corpus@example.test", "Test password 123!")
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = app.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let pool = app.pool.clone();
    tokio::task::spawn_blocking(move || {
        let root = tempdir();
        let core = open(root.path());
        connect(&core, &url, &login);
        let fixtures: [(ExchangeFormat, &[u8]); 4] = [
            (
                ExchangeFormat::Cxf,
                include_bytes!("../../../tests/fixtures/passkey-exchange/cxf.json"),
            ),
            (
                ExchangeFormat::Bitwarden,
                include_bytes!("../../../tests/fixtures/passkey-exchange/bitwarden.json"),
            ),
            (
                ExchangeFormat::KeepassXcPasskey,
                include_bytes!("../../../tests/fixtures/passkey-exchange/keepassxc.passkey"),
            ),
            (
                ExchangeFormat::KeepassXml,
                include_bytes!("../../../tests/fixtures/passkey-exchange/keepassxc.xml"),
            ),
        ];
        for (index, (format, bytes)) in fixtures.into_iter().enumerate() {
            let doc = exchange::import(bytes, format).unwrap();
            let mut payload = doc.entries[0].payload(0).unwrap();
            payload.fields.get_mut("credential_id").unwrap().value =
                ["Y29ycHVzLTA", "Y29ycHVzLTE", "Y29ycHVzLTI", "Y29ycHVzLTM"][index].into();
            core.item_create(ItemCreate {
                title: format!("Fixture {index}"),
                path: format!("Passkeys/Fixture {index}"),
                type_id: "passkey".into(),
                payload_json: serde_json::to_string(&payload).unwrap(),
            })
            .unwrap();
        }
        core.remote_sync(None, None).unwrap();
        let expected = payloads(&core);
        assert_eq!(expected.len(), 4);
        for payload in &expected {
            check(payload);
        }
        assert!(core.verify().unwrap().problems.is_empty());
        let plain = root.path().join("corpus.json");
        core.backup_export_file(plain.display().to_string(), export_authorization(&core))
            .unwrap();
        let source = core.current_storage_id().unwrap();
        let handle = core.backup_begin(account_replicas::operation()).unwrap();
        core.backup_add_recipient(handle.clone(), phrase()).unwrap();
        let encrypted = root.path().join("corpus.zann");
        core.backup_export_encrypted(encrypted.display().to_string(), handle)
            .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for encrypted_mode in [false, true] {
            runtime
                .block_on(
                    sqlx_core::query::query("TRUNCATE items, changes, item_history CASCADE")
                        .execute(&pool),
                )
                .unwrap();
            let restored = tempdir();
            let target = open(restored.path());
            connect(&target, &url, &login);
            let options = BackupImportOptions {
                target_storage_id: target.current_storage_id(),
            };
            let report = if encrypted_mode {
                let handle = target
                    .backup_open_encrypted(
                        encrypted.display().to_string(),
                        0,
                        phrase(),
                        account_replicas::operation(),
                    )
                    .unwrap();
                assert_eq!(
                    target
                        .backup_inspect_encrypted(handle.clone())
                        .unwrap()
                        .items_count,
                    4
                );
                target
                    .backup_import_encrypted(handle, source.clone(), options)
                    .unwrap()
            } else {
                target
                    .backup_import_file(plain.display().to_string(), source.clone(), options)
                    .unwrap()
            };
            assert_eq!(report.imported_items, 4);
            assert_eq!(payloads(&target), expected);
            assert!(target.verify().unwrap().problems.is_empty());
            let clean = tempdir();
            let pulled = open(clean.path());
            connect(&pulled, &url, &login);
            let actual = payloads(&pulled);
            assert_eq!(actual, expected);
            for payload in &actual {
                check(payload);
            }
            assert_eq!(
                pulled
                    .pending_change_count(pulled.current_storage_id().unwrap())
                    .unwrap(),
                0
            );
        }
        // Invalid passkeys fail during whole-file preflight, before any server publication.
        let mut invalid: Value = serde_json::from_slice(&std::fs::read(&plain).unwrap()).unwrap();
        invalid["items"][3]["payload"]["fields"]["private_key"]["value"] =
            json!("sentinel-invalid-private-key");
        let bad = root.path().join("invalid.json");
        std::fs::write(&bad, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let before = payloads(&core);
        let error = core
            .backup_import_file(
                bad.display().to_string(),
                source,
                BackupImportOptions {
                    target_storage_id: core.current_storage_id(),
                },
            )
            .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("sentinel"));
        assert_eq!(payloads(&core), before);
    })
    .await
    .unwrap();
    server.abort();
}
