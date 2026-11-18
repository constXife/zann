//! Opt-in process fixture for the real Chromium/WASM/host smoke test only.
mod support;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use support::*;
#[test]
#[ignore = "started by apps/extension/tests/browser with an explicit temporary readiness file"]
fn chromium_fixture() {
    let ready = std::path::PathBuf::from(
        std::env::var_os("ZANN_CHROMIUM_READY").expect("explicit fixture path"),
    );
    let fixture = Fixture::new();
    for n in 0..32 {
        fixture.login(&format!("Unrelated {n}"), "https://unrelated.test");
    }
    fixture.login("Example", "https://example.test");
    for n in 32..64 {
        fixture.login(&format!("Unrelated {n}"), "https://unrelated.test");
    }
    fixture.login("Second login", "https://example.test");
    let count: usize = std::env::var("ZANN_CHROMIUM_MATCHES")
        .expect("explicit fixture count")
        .parse()
        .unwrap();
    assert!((2..=1024).contains(&count));
    for n in 2..count {
        fixture.login_as(
            &format!("Account {n:04}"),
            "https://example.test",
            &format!("person-{n:04}@example.test"),
        );
    }
    let daemon = fixture.daemon();
    let code = daemon.control().begin_pairing().unwrap();
    let mut readiness = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&ready)
        .unwrap();
    readiness.write_all(&serde_json::to_vec(&serde_json::json!({"root":fixture.root,"server":daemon.server_key(), "code":code.value.as_str()})).unwrap()).unwrap();
    let start = std::time::Instant::now();
    let command_path = ready.with_extension("account-command.json");
    let reply_path = ready.with_extension("account-reply.json");
    let mut rounds = 0;
    while ready.exists() && start.elapsed() < std::time::Duration::from_secs(120) {
        if command_path.exists() {
            assert!(rounds < 16);
            rounds += 1;
            let input: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&command_path).unwrap()).unwrap();
            std::fs::remove_file(&command_path).unwrap();
            let phase = match input["phase"].as_str().unwrap() {
                "register" => zann_core::api::account_access::CeremonyPhase::Register,
                "test" => zann_core::api::account_access::CeremonyPhase::Test,
                "login" => zann_core::api::account_access::CeremonyPhase::Login,
                _ => panic!("invalid test phase"),
            };
            let server = "ceirceirceirceirceirceirceirceirceirceirceirceirceiq";
            let prompt = zann_client::account_access::AccountCeremonyPrompt {
                server_address: "https://example.test".into(),
                server_fingerprint: "synthetic-server-pin".into(),
                server_id: server.into(),
                require_prf: input["require_prf"].as_bool().unwrap(),
                options: zann_core::api::account_access::CeremonyOptions {
                    operation_id: uuid::Uuid::new_v4(),
                    phase,
                    challenge: zann_crypto::account_access::encode(&[rounds; 32]),
                    rp_id: "example.test".into(),
                    rp_name: "Zann test".into(),
                    user_id: Some(uuid::Uuid::from_bytes([1; 16])),
                    user_name: Some("fixture@example.test".into()),
                    credential_ids: Vec::new(),
                    prf_input: zann_crypto::account_access::encode(
                        &zann_crypto::account_access::prf_input(server, "example.test").unwrap(),
                    ),
                },
            };
            let pairing = daemon.control().settings().unwrap().paired[0]
                .public_key
                .clone();
            let wait = daemon
                .control()
                .begin_account_ceremony(&pairing, prompt)
                .unwrap();
            let output = match wait.wait().unwrap() {
                zann_client::account_access::AccountCeremonyCompletion::Completed { result } => {
                    serde_json::json!({"response":result.response,"has_prf":result.prf.is_some()})
                }
                zann_client::account_access::AccountCeremonyCompletion::Failed { reason } => {
                    serde_json::json!({"failure":reason})
                }
            };
            let temporary = reply_path.with_extension("tmp");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .unwrap();
            file.write_all(&serde_json::to_vec(&output).unwrap())
                .unwrap();
            file.sync_all().unwrap();
            std::fs::rename(temporary, &reply_path).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
