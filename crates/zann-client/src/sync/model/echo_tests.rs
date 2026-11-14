use super::*;

#[test]
fn shared_echo_requires_identical_plaintext_and_metadata() {
    let key = VaultPayloadKey::from_bytes([7; 32]);
    let scope = SyncScope::new(Uuid::now_v7(), Uuid::now_v7()).unwrap();
    let id = Uuid::now_v7();
    let make = |value: &str| {
        let mut payload = zann_crypto::EncryptedPayload::new("note");
        payload.extra = Some(std::collections::HashMap::from([(
            "fixture".into(),
            value.into(),
        )]));
        let ciphertext =
            zann_crypto::encrypt_payload(key.expose(), scope.vault_id(), id, &payload).unwrap();
        let checksum = ContentChecksum::for_ciphertext(&ciphertext).unwrap();
        ItemProjection::validated(
            scope,
            id,
            "item".into(),
            "item".into(),
            "note".into(),
            ciphertext,
            checksum,
            key.cache_key_fingerprint().into(),
            SyncSeq::new(1).unwrap(),
            Utc::now(),
            None,
        )
    };
    let held = make("first");
    let mut echo = make("first");
    assert_ne!(echo.payload_enc(), held.payload_enc());
    echo.normalize_echo(&held, VaultPlane::SharedServer, &key)
        .unwrap();
    assert!(held.accepts_pulled(&echo));
    assert!(make("changed")
        .normalize_echo(&held, VaultPlane::SharedServer, &key)
        .is_err());
    let mut wrong_metadata = make("first");
    wrong_metadata.metadata.favorite = true;
    assert!(wrong_metadata
        .normalize_echo(&held, VaultPlane::SharedServer, &key)
        .is_err());
    let mut personal = make("first");
    personal
        .normalize_echo(&held, VaultPlane::PersonalClient, &key)
        .unwrap();
    assert!(
        !held.accepts_pulled(&personal),
        "personal ciphertext identity remains strict"
    );
}
