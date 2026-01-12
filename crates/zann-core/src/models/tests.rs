use super::*;
#[test]
fn enum_roundtrips() {
    assert_eq!(
        VaultKind::try_from(1).expect("valid vault kind"),
        VaultKind::Personal
    );
    assert_eq!(VaultKind::Personal.as_i32(), 1);

    assert_eq!(
        VaultMemberRole::try_from(4).expect("valid vault member role"),
        VaultMemberRole::Readonly
    );
    assert_eq!(VaultMemberRole::Readonly.as_i32(), 4);
    assert_eq!(
        VaultMemberRole::try_from(2).expect("valid vault member role"),
        VaultMemberRole::Operator
    );
    assert_eq!(VaultMemberRole::Operator.as_i32(), 2);

    assert_eq!(
        VaultEncryptionType::try_from(1).expect("valid vault encryption type"),
        VaultEncryptionType::Client
    );
    assert_eq!(VaultEncryptionType::Server.as_i32(), 2);

    assert_eq!(
        CachePolicy::try_from(2).expect("valid cache policy"),
        CachePolicy::MetadataOnly
    );
    assert_eq!(CachePolicy::MetadataOnly.as_i32(), 2);

    assert_eq!(
        ChangeOp::try_from(2).expect("valid change op"),
        ChangeOp::Update
    );
    assert_eq!(ChangeOp::Update.as_i32(), 2);

    assert_eq!(
        UserStatus::try_from(2).expect("valid user status"),
        UserStatus::Disabled
    );
    assert_eq!(UserStatus::Disabled.as_i32(), 2);
    assert_eq!(
        UserStatus::try_from(3).expect("valid user status"),
        UserStatus::System
    );
    assert_eq!(UserStatus::System.as_i32(), 3);
}

#[test]
fn enum_parse_invalid() {
    assert!(VaultKind::try_from(99).is_err());
    assert!(VaultMemberRole::try_from(99).is_err());
    assert!(VaultEncryptionType::try_from(99).is_err());
    assert!(CachePolicy::try_from(99).is_err());
    assert!(ChangeOp::try_from(99).is_err());
    assert!(UserStatus::try_from(99).is_err());
}
