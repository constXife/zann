use zann_core::Identity;

pub fn secrets_event(
    identity: &Identity,
    action: &str,
    result: &str,
    vault_id: &str,
    path: &str,
    detail: Option<&str>,
) {
    tracing::info!(
        event = "audit",
        category = "secrets",
        action = action,
        result = result,
        vault_id = vault_id,
        path = path,
        user_id = %identity.user_id,
        device_id = ?identity.device_id,
        service_account_id = ?identity.service_account_id,
        auth_source = ?identity.source,
        detail = ?detail,
    );
}
