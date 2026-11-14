mod support;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use support::*;
use zann_client::app::ClientPaths;
use zann_daemon::Daemon;

#[test]
fn socket_state_and_singleton_lock_are_private_and_a_second_owner_cannot_replace_them() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon();
    for (name, mode) in [
        ("ipc", 0o700),
        ("ipc/browser.sock", 0o600),
        ("ipc/identity.json", 0o600),
        ("ipc/owner.lock", 0o600),
    ] {
        assert_eq!(
            fs::metadata(fixture.root.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }
    assert!(Daemon::start(ClientPaths::new(&fixture.root), fixture.vault.clone()).is_err());
    let mut client = Client::connect(&fixture, &daemon, 10);
    client.pair(&daemon);
    daemon.shutdown().unwrap();
    assert!(!fixture.root.join("ipc/browser.sock").exists());
}

#[test]
fn unsafe_identity_state_fails_closed_without_replacing_the_original() {
    for case in ["permissions", "symlink", "hardlink", "malformed", "future"] {
        let fixture = Fixture::new();
        fixture.daemon().shutdown().unwrap();
        let path = fixture.root.join("ipc/identity.json");
        match case {
            "permissions" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                let target = fixture.root.join("saved.json");
                fs::rename(&path, &target).unwrap();
                std::os::unix::fs::symlink(target, &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, fixture.root.join("other.json")).unwrap(),
            "malformed" => fs::write(&path, b"invalid-sentinel").unwrap(),
            "future" => {
                let mut state: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                state["version"] = serde_json::json!(2);
                fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            Daemon::start(ClientPaths::new(&fixture.root), fixture.vault.clone()).is_err(),
            "{case}"
        );
    }
}
