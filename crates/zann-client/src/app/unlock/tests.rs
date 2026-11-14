use super::*;

#[test]
fn password_rotation_preserves_independent_account_keys_and_root() {
    let (mut keyring, root) = DeviceUnlock::create("original unlock password").expect("create");
    let first = SecretKey::generate();
    let second = SecretKey::generate();
    keyring
        .insert_account(
            &root,
            "10000000-0000-4000-8000-000000000001".into(),
            "server-a".into(),
            "subject-a".into(),
            &first,
        )
        .expect("first");
    keyring
        .insert_account(
            &root,
            "10000000-0000-4000-8000-000000000002".into(),
            "server-b".into(),
            "subject-b".into(),
            &second,
        )
        .expect("second");
    let serialized = serde_json::to_vec(&keyring).expect("serialize");
    assert!(!serialized
        .windows(32)
        .any(|window| window == root.as_bytes()
            || window == first.as_bytes()
            || window == second.as_bytes()));
    let candidate = keyring
        .rewrap("original unlock password", "new unlock password")
        .expect("rewrap");
    assert_eq!(
        candidate.accounts, keyring.accounts,
        "account ciphertext must not be rewritten"
    );
    assert_ne!(candidate.identity.kdf_salt, keyring.identity.kdf_salt);
    assert!(candidate.open("original unlock password").is_err());
    let reopened: DeviceUnlock =
        serde_json::from_slice(&serde_json::to_vec(&candidate).expect("serialize")).expect("read");
    let new_root = reopened.open("new unlock password").expect("new password");
    assert!(root.as_bytes() == new_root.as_bytes());
    reopened
        .check_root(&root)
        .expect("remembered root remains usable");
    let keys = reopened.account_keys(&new_root).expect("open accounts");
    assert!(keys["10000000-0000-4000-8000-000000000001"].as_bytes() == first.as_bytes());
    assert!(keys["10000000-0000-4000-8000-000000000002"].as_bytes() == second.as_bytes());
    assert!(
        keys["10000000-0000-4000-8000-000000000001"].as_bytes()
            != keys["10000000-0000-4000-8000-000000000002"].as_bytes()
    );
}

#[test]
fn swapped_account_envelopes_and_changed_bindings_are_rejected() {
    let (mut keyring, root) = DeviceUnlock::create("original unlock password").expect("create");
    keyring
        .insert_account(
            &root,
            "10000000-0000-4000-8000-000000000001".into(),
            "server-a".into(),
            "subject-a".into(),
            &SecretKey::generate(),
        )
        .expect("first");
    let mut swapped = keyring.clone();
    let envelope = swapped
        .accounts
        .remove("10000000-0000-4000-8000-000000000001")
        .expect("envelope");
    swapped
        .accounts
        .insert("10000000-0000-4000-8000-000000000002".into(), envelope);
    assert!(swapped.account_keys(&root).is_err());
    keyring
        .accounts
        .get_mut("10000000-0000-4000-8000-000000000001")
        .expect("envelope")
        .account_subject = "another subject".into();
    assert!(keyring.account_keys(&root).is_err());
}

#[test]
fn whitespace_policy_preserves_internal_spaces_and_existing_password_bytes() {
    for password in [
        " leading password",
        "trailing password ",
        "\u{00a0}leading password",
        "trailing password\n",
        "short",
        "e\u{301}e\u{301}e\u{301}e\u{301}",
    ] {
        assert!(validate_unlock_password(password).is_err());
    }
    let (keyring, _) = DeviceUnlock::create("pass word inside").expect("internal spaces");
    assert!(keyring.open("pass word inside").is_ok());
    assert!(keyring.open("passwordinside").is_err());
    assert!(keyring
        .rewrap("incorrect old password", "replacement password")
        .is_err());
}

#[test]
fn frozen_device_keyring_opens_with_its_original_password_and_bindings() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        synthetic_only: bool,
        password: String,
        expected_root_base64: String,
        expected_account_base64: String,
        keyring: DeviceUnlock,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/crypto/v1_device_keyring.json"
    ))
    .expect("fixture");
    assert!(fixture.synthetic_only);
    let keyring = DeviceUnlock::decode(&serde_json::to_string(&fixture.keyring).expect("keyring"))
        .expect("admit persisted keyring");
    let root = keyring.open(&fixture.password).expect("frozen password");
    assert!(STANDARD.encode(root.as_bytes()) == fixture.expected_root_base64);
    let keys = keyring.account_keys(&root).expect("account AAD and key");
    assert!(
        STANDARD.encode(keys["10000000-0000-4000-8000-000000000001"].as_bytes())
            == fixture.expected_account_base64
    );
}
