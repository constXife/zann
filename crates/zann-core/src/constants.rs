pub mod system_users {
    use uuid::Uuid;

    /// System user for automated operations (vacuum, migrations, etc.).
    pub const SYSTEM: Uuid = Uuid::from_u128(0);

    /// Anonymous user (should never appear in production).
    pub const ANONYMOUS: Uuid = Uuid::from_u128(1);
}
