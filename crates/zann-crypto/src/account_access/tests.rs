use super::*;

fn fixture() -> (SecretKey, AccountDescriptor, AccountPrf, AccountGrant) {
    let key = SecretKey::from_bytes([23; 32]);
    let server = "ceirceirceirceirceirceirceirceirceirceirceirceirceiq";
    let user = Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("user");
    let descriptor = AccountCustody::derive(&key, server, user, 1)
        .expect("custody")
        .descriptor(server, user, 1);
    let prf = AccountPrf::from_bytes([91; 32]);
    let id = Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("grant");
    let grant = AccountGrant::create(
        &descriptor,
        "zann.example".into(),
        encode(b"credential"),
        id,
        &key,
        &prf,
    )
    .expect("verified grant");
    (key, descriptor, prf, grant)
}

#[test]
fn public_prf_normalization_matches_protocol_vector() {
    let server = "ceirceirceirceirceirceirceirceirceirceirceirceirceiq";
    assert_eq!(
        hex::encode(prf_input(server, "zann.example").expect("input")),
        "6bc12783bee367383f8a541268d121a645f34a169f7837445e5379688939effa"
    );
    assert_eq!(
        hex::encode(ctap_prf_salt(server, "zann.example").expect("salt")),
        "c874ec63cf93f6911bbd29a0cc25c0c1348f5db1a09d3e0a6ec5fbdb9f6920b6"
    );
}

#[test]
fn grant_trial_unwrap_and_all_context_bindings_are_enforced() {
    let (key, descriptor, prf, grant) = fixture();
    assert_eq!(
        grant.open(&descriptor, &prf).expect("unwrap").as_bytes(),
        key.as_bytes()
    );
    assert!(grant
        .open(&descriptor, &AccountPrf::from_bytes([92; 32]))
        .is_err());
    let mut variants = Vec::new();
    let mut changed = grant.clone();
    changed.user_id = Uuid::nil();
    variants.push(changed);
    let mut changed = grant.clone();
    changed.server_id = "a".repeat(52);
    variants.push(changed);
    let mut changed = grant.clone();
    changed.rp_id = "other.example".into();
    variants.push(changed);
    let mut changed = grant.clone();
    changed.credential_id = encode(b"other");
    variants.push(changed);
    let mut changed = grant.clone();
    changed.grant_id = grant.user_id;
    variants.push(changed);
    let mut changed = grant.clone();
    changed.key_epoch = 2;
    variants.push(changed);
    let mut changed = grant.clone();
    changed.proof_public_key = encode(&[1; 32]);
    variants.push(changed);
    let mut changed = grant.clone();
    changed.algorithm = "chacha20poly1305".into();
    variants.push(changed);
    let mut changed = grant.clone();
    changed.blob = encode(&[1; 128]);
    variants.push(changed);
    let mut changed = grant.clone();
    changed.signature = encode(&[1; 64]);
    variants.push(changed);
    for variant in variants {
        assert!(variant.open(&descriptor, &prf).is_err());
    }
    assert!(AccountGrant::create(
        &descriptor,
        grant.rp_id.clone(),
        grant.credential_id.clone(),
        grant.grant_id,
        &SecretKey::from_bytes([24; 32]),
        &prf
    )
    .is_err());
}

#[test]
fn mutation_proof_binds_authority_revision_nonce_purpose_and_body() {
    let (key, descriptor, _, grant) = fixture();
    let custody = AccountCustody::derive(&key, &descriptor.server_id, descriptor.user_id, 1)
        .expect("custody");
    let context = MutationContext {
        server_id: descriptor.server_id.clone(),
        user_id: descriptor.user_id,
        authority: Authority::Session,
        authority_id: grant.grant_id,
        security_revision: 3,
        nonce: encode(&[11; 32]),
        purpose: MutationPurpose::GrantAdd,
        body_digest: encode(&grant.body_digest().expect("digest")),
    };
    let signature = custody.sign_mutation(&descriptor, &context).expect("sign");
    context.verify(&descriptor, &signature).expect("verify");
    let mut variants = Vec::new();
    let mut changed = context.clone();
    changed.authority = Authority::Recovery;
    variants.push(changed);
    let mut changed = context.clone();
    changed.authority_id = descriptor.user_id;
    variants.push(changed);
    let mut changed = context.clone();
    changed.security_revision += 1;
    variants.push(changed);
    let mut changed = context.clone();
    changed.nonce = encode(&[12; 32]);
    variants.push(changed);
    let mut changed = context.clone();
    changed.purpose = MutationPurpose::CodeRotate;
    variants.push(changed);
    let mut changed = context.clone();
    changed.body_digest = encode(&[12; 32]);
    variants.push(changed);
    for variant in variants {
        assert!(variant.verify(&descriptor, &signature).is_err());
    }
}

#[test]
fn strict_wire_encoding_and_duplicates_are_rejected() {
    let (_, descriptor, _, grant) = fixture();
    let mut encoded = serde_json::to_string(&grant).expect("json");
    encoded.insert_str(1, "\"format\":1,");
    assert!(serde_json::from_str::<AccountGrant>(&encoded).is_err());
    assert!(decode("AA==", 32).is_err());
    assert!(array::<32>(&encode(&[1; 33])).is_err());
    let mut altered = descriptor;
    altered.key_epoch = 0;
    assert!(altered.validate().is_err());
}
