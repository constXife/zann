pub mod system_users {
    use uuid::Uuid;

    /// System user for automated operations (vacuum, migrations, etc.).
    pub const SYSTEM: Uuid = Uuid::from_u128(0);

    /// Anonymous user (should never appear in production).
    pub const ANONYMOUS: Uuid = Uuid::from_u128(1);
}
/// Maximum decrypted login candidates examined by one browser query page.
pub const BROWSER_PAGE_LIMIT: u32 = 32;
/// Keeps worst-case JSON-escaped metadata pages below the IPC body bound.
pub const BROWSER_MAX_USERNAME_BYTES: usize = 256;

/// Browser supplies decoded RGBA8, never an image container or remote URL.
pub const SITE_ICON_RGBA_BYTES: usize = 16 * 16 * 4;
