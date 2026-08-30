//! Versioned, value-free runtime secret delivery profiles.
//!
//! This module owns profile parsing, normalization and collision policy. A
//! shell resolves the resulting exact secret references through the canonical
//! machine-secrets transport and hands values to a platform sink.

use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;

pub const DELIVERY_PROFILE_VERSION: u32 = 1;
pub const MAX_DELIVERY_PROFILE_BYTES: usize = 256 * 1024;
pub const MAX_DELIVERY_FILES: usize = 64;

const MAX_VAULT_REFERENCE_BYTES: usize = 255;
const MAX_SECRET_PATH_BYTES: usize = 500;
const MAX_PATH_SEGMENTS: usize = 32;
const MAX_PATH_SEGMENT_BYTES: usize = 200;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProfile {
    pub version: u32,
    pub vault: String,
    pub files: Vec<DeliveryFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryFile {
    pub secret: String,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryPlan {
    vault: String,
    files: Vec<PlannedDeliveryFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedDeliveryFile {
    secret: String,
    target: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryProfileErrorKind {
    TooLarge,
    InvalidYaml,
    UnsupportedVersion,
    InvalidVault,
    EmptyFiles,
    TooManyFiles,
    InvalidSecretPath,
    InvalidTargetPath,
    DuplicateSecret,
    DuplicateTarget,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeliveryProfileError {
    kind: DeliveryProfileErrorKind,
}

impl DeliveryProfileError {
    const fn new(kind: DeliveryProfileErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> DeliveryProfileErrorKind {
        self.kind
    }
}

impl fmt::Debug for DeliveryProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryProfileError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for DeliveryProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "delivery_profile:{:?}", self.kind)
    }
}

impl std::error::Error for DeliveryProfileError {}

impl DeliveryProfile {
    pub fn from_yaml(source: &str) -> Result<Self, DeliveryProfileError> {
        if source.len() > MAX_DELIVERY_PROFILE_BYTES {
            return Err(DeliveryProfileError::new(
                DeliveryProfileErrorKind::TooLarge,
            ));
        }
        serde_yaml::from_str(source)
            .map_err(|_| DeliveryProfileError::new(DeliveryProfileErrorKind::InvalidYaml))
    }
}

impl TryFrom<DeliveryProfile> for DeliveryPlan {
    type Error = DeliveryProfileError;

    fn try_from(profile: DeliveryProfile) -> Result<Self, Self::Error> {
        if profile.version != DELIVERY_PROFILE_VERSION {
            return Err(DeliveryProfileError::new(
                DeliveryProfileErrorKind::UnsupportedVersion,
            ));
        }
        let vault = profile.vault.trim();
        if vault.is_empty()
            || vault.len() > MAX_VAULT_REFERENCE_BYTES
            || vault.contains('/')
            || vault.chars().any(char::is_control)
        {
            return Err(DeliveryProfileError::new(
                DeliveryProfileErrorKind::InvalidVault,
            ));
        }
        if profile.files.is_empty() {
            return Err(DeliveryProfileError::new(
                DeliveryProfileErrorKind::EmptyFiles,
            ));
        }
        if profile.files.len() > MAX_DELIVERY_FILES {
            return Err(DeliveryProfileError::new(
                DeliveryProfileErrorKind::TooManyFiles,
            ));
        }

        let mut secrets = HashSet::with_capacity(profile.files.len());
        let mut targets = HashSet::with_capacity(profile.files.len());
        let mut files = Vec::with_capacity(profile.files.len());
        for file in profile.files {
            let secret = normalize_secret_path(&file.secret)?;
            let target = normalize_target_path(&file.target)?;
            if !secrets.insert(secret.clone()) {
                return Err(DeliveryProfileError::new(
                    DeliveryProfileErrorKind::DuplicateSecret,
                ));
            }
            if !targets.insert(target.clone()) {
                return Err(DeliveryProfileError::new(
                    DeliveryProfileErrorKind::DuplicateTarget,
                ));
            }
            files.push(PlannedDeliveryFile { secret, target });
        }

        Ok(Self {
            vault: vault.to_string(),
            files,
        })
    }
}

impl DeliveryPlan {
    pub fn from_yaml(source: &str) -> Result<Self, DeliveryProfileError> {
        DeliveryProfile::from_yaml(source)?.try_into()
    }

    #[must_use]
    pub fn vault(&self) -> &str {
        &self.vault
    }

    #[must_use]
    pub fn files(&self) -> &[PlannedDeliveryFile] {
        &self.files
    }

    #[must_use]
    pub fn secret_paths(&self) -> Vec<String> {
        self.files.iter().map(|file| file.secret.clone()).collect()
    }
}

impl PlannedDeliveryFile {
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

fn normalize_secret_path(path: &str) -> Result<String, DeliveryProfileError> {
    let trimmed = path.trim().trim_matches('/');
    validate_path(trimmed, true)
        .map_err(|()| DeliveryProfileError::new(DeliveryProfileErrorKind::InvalidSecretPath))?;
    Ok(trimmed.to_string())
}

fn normalize_target_path(path: &str) -> Result<String, DeliveryProfileError> {
    if path.starts_with('/') || path.ends_with('/') || path.contains('\\') || path.trim() != path {
        return Err(DeliveryProfileError::new(
            DeliveryProfileErrorKind::InvalidTargetPath,
        ));
    }
    validate_path(path, false)
        .map_err(|()| DeliveryProfileError::new(DeliveryProfileErrorKind::InvalidTargetPath))?;
    Ok(path.to_string())
}

fn validate_path(path: &str, allow_leading_dot: bool) -> Result<(), ()> {
    let segments = path.split('/').collect::<Vec<_>>();
    if path.is_empty()
        || path.len() > MAX_SECRET_PATH_BYTES
        || segments.len() > MAX_PATH_SEGMENTS
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > MAX_PATH_SEGMENT_BYTES
                || *segment == "."
                || *segment == ".."
                || (!allow_leading_dot && segment.starts_with('.'))
                || segment.trim() != *segment
                || segment.chars().any(char::is_control)
        })
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(source: &str) -> Result<DeliveryPlan, DeliveryProfileError> {
        DeliveryPlan::from_yaml(source)
    }

    #[test]
    fn parses_and_normalizes_exact_references() {
        let plan = profile(
            "version: 1\nvault: infra\nfiles:\n  - secret: /services/web/database\n    target: database-password\n",
        )
        .expect("valid profile");
        assert_eq!(plan.vault(), "infra");
        assert_eq!(plan.files()[0].secret(), "services/web/database");
        assert_eq!(plan.files()[0].target(), "database-password");
    }

    #[test]
    fn rejects_unknown_fields_and_unsupported_versions() {
        assert_eq!(
            DeliveryProfile::from_yaml("version: 1\nvault: infra\nfiles: []\nplaintext: true\n")
                .expect_err("unknown field")
                .kind(),
            DeliveryProfileErrorKind::InvalidYaml
        );
        assert_eq!(
            profile("version: 2\nvault: infra\nfiles:\n  - secret: a\n    target: b\n")
                .expect_err("version")
                .kind(),
            DeliveryProfileErrorKind::UnsupportedVersion
        );
    }

    #[test]
    fn rejects_traversal_and_collisions() {
        assert_eq!(
            profile("version: 1\nvault: infra\nfiles:\n  - secret: a\n    target: ../a\n")
                .expect_err("traversal")
                .kind(),
            DeliveryProfileErrorKind::InvalidTargetPath
        );
        assert_eq!(
            profile(
                "version: 1\nvault: infra\nfiles:\n  - secret: a\n    target: foo\\\\..\\\\bar\n"
            )
            .expect_err("portable traversal")
            .kind(),
            DeliveryProfileErrorKind::InvalidTargetPath
        );
        assert_eq!(
            profile(
                "version: 1\nvault: infra\nfiles:\n  - secret: a\n    target: one\n  - secret: b\n    target: one\n"
            )
            .expect_err("collision")
            .kind(),
            DeliveryProfileErrorKind::DuplicateTarget
        );
    }
}
