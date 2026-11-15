//! Account-qualified Config generation projection for SQLite sync.
use super::*;

pub(super) fn target_binding_from_generation(
    target: &SessionTarget,
    generation: &AuthorizedTargetGeneration,
    master_key: &SecretKey,
) -> Result<TargetBinding, SyncStoreError> {
    if generation.connection_id() != target.connection_id()
        || generation.profile_name() != target.profile_name()
        || generation.display_name().is_empty()
        || generation.address().is_empty()
    {
        return Err(store_error(SyncStoreErrorKind::InvalidData));
    }
    let server_id = required(generation.server_id())?;
    let server_fingerprint = required(generation.server_fingerprint())?;
    let storage_id_text = required(generation.storage_id())?;
    let storage_id = canonical_uuid(storage_id_text)?;
    let account_subject = required(generation.account_subject())?;
    canonical_uuid(account_subject)?;
    let auth_method = generation
        .auth_method()
        .ok_or_else(|| store_error(SyncStoreErrorKind::InvalidData))?;
    let master_key = master_key_binding(generation.expected_master_key_fingerprint(), master_key)?;
    Ok(TargetBinding {
        connection_id: target.connection_id().clone(),
        profile_name: target.profile_name().to_string(),
        display_name: generation.display_name().to_string(),
        address: generation.address().to_string(),
        server_id: server_id.to_string(),
        server_fingerprint: server_fingerprint.to_string(),
        storage_id,
        master_key,
        account_subject: account_subject.to_string(),
        auth_method,
    })
}
