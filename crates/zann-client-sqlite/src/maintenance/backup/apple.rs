use super::*;

/// A read-only summary used by clients before they ask for confirmation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplePasswordsPreflight {
    pub total_rows: usize,
    pub importable_items: usize,
    pub duplicate_rows: usize,
    pub invalid_rows: usize,
}

/// What the Apple Passwords import changed.
///
/// Existing paths and repeated titles are never overwritten or dropped. A
/// numeric suffix is added instead and counted in `renamed_items`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplePasswordsImportReport {
    pub imported_items: usize,
    pub renamed_items: usize,
    pub skipped_invalid: usize,
}

pub(super) fn apple_passwords_reader(
    path: &Path,
) -> Result<csv::Reader<std::fs::File>, BackupError> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        BackupError::new(
            "apple_csv_open_failed",
            format!("could not open CSV: {err}"),
        )
    })?;
    if metadata.len() > APPLE_PASSWORDS_MAX_FILE_BYTES {
        return Err(BackupError::new(
            "apple_csv_too_large",
            "Apple Passwords CSV exceeds the 50 MiB limit",
        ));
    }

    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_path(path)
        .map_err(|err| BackupError::new("apple_csv_open_failed", err.to_string()))?;
    let headers = reader
        .headers()
        .map_err(|err| BackupError::new("apple_csv_invalid", err.to_string()))?
        .clone();
    let missing = APPLE_PASSWORDS_REQUIRED_HEADERS
        .iter()
        .filter(|required| !headers.iter().any(|header| header == **required))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(BackupError::new(
            "apple_csv_headers_invalid",
            format!("missing Apple Passwords columns: {}", missing.join(", ")),
        ));
    }
    Ok(reader)
}

/// Validate an Apple Passwords export without retaining any secret fields.
pub fn apple_passwords_preflight(path: &Path) -> Result<ApplePasswordsPreflight, BackupError> {
    let mut reader = apple_passwords_reader(path)?;
    let mut report = ApplePasswordsPreflight::default();
    let mut seen_titles = HashSet::new();

    for result in reader.deserialize::<ApplePasswordsRow>() {
        if report.total_rows >= APPLE_PASSWORDS_MAX_ROWS {
            return Err(BackupError::new(
                "apple_csv_too_many_rows",
                "Apple Passwords CSV exceeds the 100000-row limit",
            ));
        }
        let row = result.map_err(|err| BackupError::new("apple_csv_invalid", err.to_string()))?;
        report.total_rows += 1;
        let title = row.title.trim();
        if title.is_empty() {
            report.invalid_rows += 1;
            continue;
        }
        report.importable_items += 1;
        if !seen_titles.insert(title.to_string()) {
            report.duplicate_rows += 1;
        }
    }
    Ok(report)
}

pub(super) async fn apple_passwords_target(
    ctx: &BackupCtx,
    target_storage_id: Option<&str>,
) -> Result<(Uuid, Uuid), BackupError> {
    let services = LocalServices::new(&ctx.pool, ctx.master_key.as_ref());
    let Some(target_storage_id) = target_storage_id
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "local")
    else {
        let vault = services
            .ensure_default_local_personal()
            .await
            .map_err(|err| BackupError::new(err.kind, err.message))?;
        return Ok((Uuid::nil(), vault.id));
    };

    let storage_id = Uuid::parse_str(target_storage_id)
        .map_err(|_| BackupError::new("apple_import_target_invalid", "invalid storage id"))?;
    let storage_repo = LocalStorageRepo::new(&ctx.pool);
    let storage = storage_repo
        .get(storage_id)
        .await
        .map_err(|err| BackupError::new("storage_lookup_failed", err.to_string()))?
        .ok_or_else(|| BackupError::new("storage_not_found", "storage not found"))?;
    if storage.kind == StorageKind::LocalOnly {
        let vault = services
            .ensure_default_local_personal()
            .await
            .map_err(|err| BackupError::new(err.kind, err.message))?;
        return Ok((Uuid::nil(), vault.id));
    }
    if !storage.personal_vaults_enabled {
        return Err(BackupError::new(
            "personal_vaults_disabled",
            "personal vaults are disabled for this server",
        ));
    }

    let vault_repo = LocalVaultRepo::new(&ctx.pool);
    let vault = vault_repo
        .list_by_storage(storage.id)
        .await
        .map_err(|err| BackupError::new("vault_lookup_failed", err.to_string()))?
        .into_iter()
        .find(|vault| vault.kind == VaultKind::Personal)
        .ok_or_else(|| {
            BackupError::new(
                "personal_vault_missing",
                "sync this server before importing into its personal vault",
            )
        })?;
    Ok((storage.id, vault.id))
}

pub(super) fn apple_passwords_payload(row: &ApplePasswordsRow) -> EncryptedPayload {
    let mut payload = EncryptedPayload::new("login");
    insert_payload_field(
        &mut payload,
        "username",
        FieldKind::Text,
        row.username.as_deref(),
    );
    insert_payload_field(
        &mut payload,
        "password",
        FieldKind::Password,
        row.password.as_deref(),
    );
    insert_payload_field(&mut payload, "url", FieldKind::Url, row.url.as_deref());
    insert_payload_field(&mut payload, "notes", FieldKind::Note, row.notes.as_deref());
    if let Some(meta) = row.otp_auth.as_deref().and_then(extract_totp_meta) {
        insert_payload_field(
            &mut payload,
            "totp_secret",
            FieldKind::Otp,
            Some(meta.secret.as_str()),
        );
        let mut extra = payload.extra.take().unwrap_or_default();
        for (key, value) in [
            ("otp_type", meta.otp_type),
            ("otp_issuer", meta.issuer),
            ("otp_algorithm", meta.algorithm),
            ("otp_label", meta.label),
            ("otp_digits", meta.digits),
            ("otp_period", meta.period),
        ] {
            if let Some(value) = value {
                extra.insert(key.to_string(), value);
            }
        }
        if !extra.is_empty() {
            payload.extra = Some(extra);
        }
    }
    payload
}

pub(super) fn suffixed_import_path(base: &str, attempt: usize) -> String {
    let suffix = format!(" ({attempt})");
    let (folder, name) = base
        .rsplit_once('/')
        .map_or((None, base), |(folder, name)| (Some(folder), name));
    let available = MAX_ITEM_NAME_LEN.saturating_sub(suffix.len());
    let mut shortened = String::new();
    for character in name.chars() {
        if shortened.len() + character.len_utf8() > available {
            break;
        }
        shortened.push(character);
    }
    match folder {
        Some(folder) => format!("{folder}/{shortened}{suffix}"),
        None => format!("{shortened}{suffix}"),
    }
}

/// Import an Apple Passwords CSV into the selected personal vault.
///
/// The file is streamed. Duplicate titles and paths already present in the
/// vault receive ` (2)`, ` (3)`, ... suffixes so distinct credentials are not
/// silently discarded.
pub async fn apple_passwords_import(
    ctx: &BackupCtx,
    path: PathBuf,
    target_storage_id: Option<String>,
) -> Result<ApplePasswordsImportReport, BackupError> {
    // Parse the entire source before the first write. A malformed row near the
    // end therefore cannot produce a surprising partial import.
    let _ = apple_passwords_preflight(&path)?;
    let mut reader = apple_passwords_reader(&path)?;
    let (storage_id, vault_id) = apple_passwords_target(ctx, target_storage_id.as_deref()).await?;
    let services = LocalServices::new(&ctx.pool, ctx.master_key.as_ref());
    let mut report = ApplePasswordsImportReport::default();
    ctx.log(&format!("apple_import_start path={}", path.display()));

    for (index, result) in reader.deserialize::<ApplePasswordsRow>().enumerate() {
        if index >= APPLE_PASSWORDS_MAX_ROWS {
            return Err(BackupError::new(
                "apple_csv_too_many_rows",
                "Apple Passwords CSV exceeds the 100000-row limit",
            ));
        }
        let row = result.map_err(|err| BackupError::new("apple_csv_invalid", err.to_string()))?;
        let title = row.title.trim();
        if title.is_empty() {
            report.skipped_invalid += 1;
            continue;
        }

        let payload = apple_passwords_payload(&row);
        let mut attempt = 1usize;
        loop {
            let candidate = if attempt == 1 {
                title.to_string()
            } else {
                suffixed_import_path(title, attempt)
            };
            match services
                .put_item(
                    storage_id,
                    vault_id,
                    candidate,
                    "login".to_string(),
                    payload.clone(),
                )
                .await
            {
                Ok(_) => {
                    report.imported_items += 1;
                    if attempt > 1 {
                        report.renamed_items += 1;
                    }
                    break;
                }
                Err(err) if err.kind == "item_exists" && attempt < 10_000 => {
                    attempt += 1;
                }
                Err(err)
                    if matches!(
                        err.kind.as_str(),
                        "path_required"
                            | "path_invalid"
                            | "path_segment_invalid"
                            | "name_too_long"
                            | "path_too_long"
                            | "path_segments_limit"
                            | "payload_too_large"
                    ) =>
                {
                    report.skipped_invalid += 1;
                    break;
                }
                Err(err) => return Err(BackupError::new(err.kind, err.message)),
            }
        }
    }

    ctx.log(&format!(
        "apple_import_ok path={} imported={} renamed={} skipped_invalid={}",
        path.display(),
        report.imported_items,
        report.renamed_items,
        report.skipped_invalid
    ));
    Ok(report)
}

pub fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if next == '-' {
            if last_dash || out.is_empty() {
                continue;
            }
            last_dash = true;
            out.push('-');
        } else {
            last_dash = false;
            out.push(next);
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "imported-vault".to_string()
    } else {
        trimmed
    }
}
