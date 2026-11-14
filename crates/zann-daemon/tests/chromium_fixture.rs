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
    while ready.exists() && start.elapsed() < std::time::Duration::from_secs(120) {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
