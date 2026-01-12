export const StorageKind = {
  LocalOnly: 1,
  Remote: 2,
} as const;

export type StorageKind = (typeof StorageKind)[keyof typeof StorageKind];

export const AuthMethod = {
  Password: 1,
  Oidc: 2,
  ServiceAccount: 3,
} as const;

export type AuthMethod = (typeof AuthMethod)[keyof typeof AuthMethod];

export const VaultKind = {
  Personal: 1,
  Shared: 2,
} as const;

export type VaultKind = (typeof VaultKind)[keyof typeof VaultKind];

export const VaultEncryptionType = {
  Client: 1,
  Server: 2,
} as const;

export type VaultEncryptionType =
  (typeof VaultEncryptionType)[keyof typeof VaultEncryptionType];

export const CachePolicy = {
  Full: 1,
  MetadataOnly: 2,
  None: 3,
} as const;

export type CachePolicy = (typeof CachePolicy)[keyof typeof CachePolicy];

export const SyncStatus = {
  Active: 1,
  Tombstone: 2,
  Modified: 3,
  LocalDeleted: 4,
  Conflict: 5,
  Synced: 6,
} as const;

export type SyncStatus = (typeof SyncStatus)[keyof typeof SyncStatus];

export const ChangeType = {
  Create: 1,
  Update: 2,
  Delete: 3,
  Restore: 4,
} as const;

export type ChangeType = (typeof ChangeType)[keyof typeof ChangeType];
