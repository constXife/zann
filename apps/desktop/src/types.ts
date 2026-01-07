export type ApiResponse<T> = {
  ok: boolean;
  api_version: number;
  data?: T;
  error?: { kind: string; message: string };
};

export type Status = { unlocked: boolean; db_path: string };
export type AppStatus = {
  initialized: boolean;
  locked: boolean;
  storages_count: number;
  has_local_vault: boolean;
};
export type Settings = {
  remember_unlock: boolean;
  auto_unlock: boolean;
  language?: string | null;
  auto_lock_minutes: number;
  lock_on_focus_loss: boolean;
  lock_on_hidden: boolean;
  clipboard_clear_seconds: number;
  clipboard_clear_on_lock: boolean;
  clipboard_clear_on_exit: boolean;
  clipboard_clear_if_unchanged: boolean;
  auto_hide_reveal_seconds: number;
  require_os_auth: boolean;
  biometry_dwk_backup?: string | null;
  trash_auto_purge_days: number;
};
export type VaultSummary = {
  id: string;
  name: string;
  kind: string;
  is_default: boolean;
};
export type ItemSummary = {
  id: string;
  vault_id: string;
  path: string;
  name: string;
  type_id: string;
  sync_status?: string | null;
  updated_at: string;
  deleted_at?: string | null;
  deleted_by?: string | null;
};
export type FieldKind = "text" | "password" | "url" | "otp" | "note";

export type FieldMeta = {
  masked?: boolean;
  multiline?: boolean;
  copyable?: boolean;
  readonly?: boolean;
  placeholder?: string;
};

export type FieldValue = {
  kind: FieldKind;
  value: string;
  meta?: FieldMeta;
};

export type EncryptedPayload = {
  v: number;
  typeId: string;
  fields: Record<string, FieldValue>;
  extra?: Record<string, string>;
};

export type ItemDetail = {
  id: string;
  vault_id: string;
  path: string;
  name: string;
  type_id: string;
  payload: EncryptedPayload;
};
export type ItemHistorySummary = {
  version: number;
  checksum: string;
  change_type: string;
  changed_by_name?: string | null;
  changed_by_email: string;
  created_at: string;
  pending?: boolean;
};
export type ItemHistoryDetail = {
  version: number;
  payload: EncryptedPayload;
};
export type StorageKind = "local_only" | "remote";

export type StorageSummary = {
  id: string;
  name: string;
  kind: StorageKind;
  server_url?: string | null;
  server_name?: string | null;
  account_subject?: string | null;
  personal_vaults_enabled: boolean;
  auth_method?: "oidc" | "password" | null;
};
export type StorageInfo = {
  id: string;
  name: string;
  kind: StorageKind;
  file_path?: string | null;
  file_size?: number | null;
  last_modified?: string | null;
  server_url?: string | null;
  server_name?: string | null;
  account_subject?: string | null;
  last_synced?: string | null;
  fingerprint?: string | null;
};
export type FieldRow = {
  key: string;
  value: string;
  path: string;
  kind: FieldKind;
  masked: boolean;
  copyable: boolean;
  revealable: boolean;
};
export type DetailSection = {
  title: string;
  fields: FieldRow[];
};
export type UiProfile = {
  masked_by_default?: string[];
  copyable?: string[];
  revealable?: string[];
};
export type SecurityProfile = {
  version: number;
  ui?: UiProfile;
  never_log_fields?: string[];
  exposable_public_attrs?: string[];
};
export type KeystoreStatus = {
  supported: boolean;
  biometrics_available: boolean;
  reason?: string | null;
};
export type FolderNode = {
  name: string;
  path: string;
  children: FolderNode[];
  itemCount: number;
  totalCount: number;
};
