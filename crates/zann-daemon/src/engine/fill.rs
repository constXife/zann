//! Select only the explicitly requested login secrets; never a payload export.
use zann_client::app::local::{LocalError, LocalResult};
use zann_client::browser_ipc::Reply;
use zeroize::Zeroize;

pub(super) fn password_reply(
    payload: &zann_core::EncryptedPayload,
    include_totp: bool,
) -> LocalResult<Reply> {
    let password = payload
        .fields
        .get("password")
        .filter(|p| p.kind == zann_core::FieldKind::Password)
        .ok_or_else(|| LocalError::InvalidArgument("login has no typed password".into()))?;
    if password.value.len() > 16 * 1024 {
        return Err(LocalError::InvalidArgument(
            "browser secret size bound".into(),
        ));
    }
    let totp = if include_totp {
        let mut field = zann_ui_core::item_detail::payload_totp_params(payload, "totp_secret")
            .ok_or_else(|| LocalError::InvalidArgument("login has no TOTP".into()))?;
        let code = zann_ui_core::generate_totp(&field);
        field.secret.zeroize();
        Some(
            code.map_err(|e| LocalError::BrowserPolicy(Box::new(e)))?
                .code,
        )
    } else {
        None
    };
    Ok(Reply::Filled {
        value: password.value.clone(),
        totp,
    })
}
