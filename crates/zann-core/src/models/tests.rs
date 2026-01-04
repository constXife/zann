use super::*;
use std::str::FromStr;

#[test]
fn enum_roundtrips() {
    assert_eq!(
        VaultKind::from_str("personal").expect("valid vault kind"),
        VaultKind::Personal
    );
    assert_eq!(VaultKind::Personal.as_str(), "personal");

    assert_eq!(
        VaultMemberRole::from_str("readonly").expect("valid vault member role"),
        VaultMemberRole::Readonly
    );
    assert_eq!(VaultMemberRole::Readonly.as_str(), "readonly");
    assert_eq!(
        VaultMemberRole::from_str("operator").expect("valid vault member role"),
        VaultMemberRole::Operator
    );
    assert_eq!(VaultMemberRole::Operator.as_str(), "operator");

    assert_eq!(
        VaultEncryptionType::from_str("client").expect("valid vault encryption type"),
        VaultEncryptionType::Client
    );
    assert_eq!(VaultEncryptionType::Server.as_str(), "server");

    assert_eq!(
        CachePolicy::from_str("metadata_only").expect("valid cache policy"),
        CachePolicy::MetadataOnly
    );
    assert_eq!(CachePolicy::MetadataOnly.as_str(), "metadata_only");

    assert_eq!(
        ChangeOp::from_str("update").expect("valid change op"),
        ChangeOp::Update
    );
    assert_eq!(ChangeOp::Update.as_str(), "update");

    assert_eq!(
        UserStatus::from_str("disabled").expect("valid user status"),
        UserStatus::Disabled
    );
    assert_eq!(UserStatus::Disabled.as_str(), "disabled");
    assert_eq!(
        UserStatus::from_str("system").expect("valid user status"),
        UserStatus::System
    );
    assert_eq!(UserStatus::System.as_str(), "system");
}

#[test]
fn enum_parse_invalid() {
    assert!(VaultKind::from_str("invalid").is_err());
    assert!(VaultMemberRole::from_str("invalid").is_err());
    assert!(VaultEncryptionType::from_str("invalid").is_err());
    assert!(CachePolicy::from_str("invalid").is_err());
    assert!(ChangeOp::from_str("invalid").is_err());
    assert!(UserStatus::from_str("invalid").is_err());
}
