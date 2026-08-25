pub(crate) const MAX_VAULT_SLUG_BYTES: usize = 128;
pub(crate) const MAX_VAULT_NAME_BYTES: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VaultMetadataError {
    InvalidSlug,
    InvalidName,
}

impl VaultMetadataError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidSlug => "invalid_slug",
            Self::InvalidName => "invalid_name",
        }
    }
}

pub(crate) fn validate_vault_metadata(slug: &str, name: &str) -> Result<(), VaultMetadataError> {
    if slug.is_empty()
        || slug.len() > MAX_VAULT_SLUG_BYTES
        || slug != slug.trim()
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(VaultMetadataError::InvalidSlug);
    }
    if name.is_empty() || name.len() > MAX_VAULT_NAME_BYTES || name != name.trim() {
        return Err(VaultMetadataError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_vault_metadata_enforces_wire_byte_bounds() {
        assert_eq!(validate_vault_metadata("alpha_1", "Alpha Vault"), Ok(()));
        assert_eq!(
            validate_vault_metadata(&"a".repeat(MAX_VAULT_SLUG_BYTES), "name"),
            Ok(())
        );
        assert_eq!(
            validate_vault_metadata(&"a".repeat(MAX_VAULT_SLUG_BYTES + 1), "name"),
            Err(VaultMetadataError::InvalidSlug)
        );
        assert_eq!(
            validate_vault_metadata("bad slug", "name"),
            Err(VaultMetadataError::InvalidSlug)
        );
        assert_eq!(
            validate_vault_metadata("slug", " name"),
            Err(VaultMetadataError::InvalidName)
        );
        assert_eq!(
            validate_vault_metadata("slug", "name\t"),
            Err(VaultMetadataError::InvalidName)
        );
        assert_eq!(
            validate_vault_metadata("slug", &"é".repeat(101)),
            Err(VaultMetadataError::InvalidName)
        );
    }
}
