pub mod v2;

pub(crate) mod locking;
pub use v2::{
    ActiveCredentialAfterRemoval, AuthorizedTargetGeneration, CliNamespace, ClientConfig, ClientId,
    ClientNamespace, ClientPaths, ConfigError, ConfigIdentity, ConfigKdfParams, ConfigRepository,
    ConfigSnapshot, ConfigV2, ConnectionConfig, ConnectionId, ConnectionMetadata,
    CredentialActivation, CredentialBundle, CredentialId, CredentialKind, CredentialPortError,
    CredentialPortErrorKind, CredentialProfile, CredentialProfileAnchor, CredentialSecret,
    CredentialSecretError, CredentialStore, CredentialTransactionOutcome,
    CredentialTransactionWarning, DesktopBackupSettings, DesktopNamespace,
    LegacyCredentialAccountSemantics, LegacyCredentialLocator, LegacyCredentialSource,
    MasterKeyFingerprintBindingOutcome, MigrationStamp, SyncCommitLease, SYNC_COMMIT_LOCK_FILENAME,
};
#[cfg(feature = "session")]
pub(crate) use v2::{
    AuthOperationIntentPermit, AuthOperationKind, AuthOperationRecoveryDisposition,
    AuthenticatedConnectionTarget, AuthenticatedSessionCommit, IdentityCommit, PasswordLoginAnchor,
    PasswordLoginIntentPermit, StoredConnectionBinding, VerifiedEndpointBinding,
};
