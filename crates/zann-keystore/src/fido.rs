//! Device wrapping keys derived from a FIDO2 authenticator.
//!
//! Unlike the OS credential store, nothing is *stored* here: the key is
//! recomputed from the authenticator's `hmac-secret` extension on every unlock.
//! What lands on disk is only `credential_id` and `salt`, neither of which is
//! secret and neither of which is useful without the physical token.
//!
//! Credentials are non-discoverable and require user presence (a touch) but not
//! user verification (a PIN): this is an optional convenience over the master
//! password, so a PIN on every unlock is the wrong trade. The token's own
//! discoverable-credential slots stay free for other uses.

use ctap_hid_fido2::fidokey::{
    get_assertion::get_assertion_params::{Extension as Aext, GetAssertionArgsBuilder},
    make_credential::make_credential_params::{Extension as Mext, MakeCredentialArgsBuilder},
    FidoKeyHid,
};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use serde::{Deserialize, Serialize};

/// Relying party the credentials are scoped to. Changing this orphans every
/// enrolled key, so it is deliberately not configurable.
const RP_ID: &str = "zann.local";

/// Domain separation for the KDF applied to the authenticator's output.
const DWK_CONTEXT: &str = "zann 2026-08-08 fido2 device wrapping key";

/// The authenticator itself gives up after ~30s of waiting for a touch, so any
/// UI timeout has to be at least this generous.
pub const TOUCH_TIMEOUT_SECS: u64 = 30;

/// What has to be remembered to derive a DWK again. Not secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareCredential {
    pub credential_id: Vec<u8>,
    pub salt: [u8; 32],
}

#[derive(thiserror::Error, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FidoError {
    #[error("no authenticator connected")]
    NoDevice,
    #[error("the connected authenticator is not enrolled for this vault")]
    NotEnrolled,
    #[error("no touch received")]
    Timeout,
    #[error("the authenticator is in use by another application")]
    Busy,
    #[error("this authenticator does not support hmac-secret")]
    NoHmacSecret,
    #[error("the authenticator is connected but not accessible; check the udev rules")]
    NotAccessible,
    #[error("authenticator error: {message}")]
    Internal { message: String },
}

impl FidoError {
    /// Stable identifier for the UI to translate; the variants map one-to-one
    /// onto the states a user can actually act on.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NoDevice => "hardware_key_absent",
            Self::NotEnrolled => "hardware_key_not_enrolled",
            Self::Timeout => "hardware_key_timeout",
            Self::Busy => "hardware_key_busy",
            Self::NoHmacSecret => "hardware_key_unsupported",
            Self::NotAccessible => "hardware_key_not_accessible",
            Self::Internal { .. } => "hardware_key_error",
        }
    }
}

fn cfg() -> Cfg {
    let mut cfg = Cfg::init();
    // The crate otherwise prints "- Touch the sensor..." straight to stdout.
    // Prompting is the UI's job.
    cfg.keep_alive_msg = String::new();
    cfg.enable_log = false;
    cfg
}

fn open() -> Result<FidoKeyHid, FidoError> {
    FidoKeyHidFactory::create(&cfg()).map_err(|err| classify(&err.to_string()))
}

/// The crate surfaces CTAP status codes only inside formatted messages, so the
/// taxonomy has to be recovered from the text. Kept in one place, and covered
/// by tests, because it drives what the user is told to do.
fn classify(message: &str) -> FidoError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("0x2e") || lower.contains("no_credentials") {
        FidoError::NotEnrolled
    } else if lower.contains("0x27") || lower.contains("operation_denied") {
        // The authenticator reports a touch that never came the same way it
        // reports one the user actively declined.
        FidoError::Timeout
    } else if lower.contains("0x33") || lower.contains("unsupported_extension") {
        FidoError::NoHmacSecret
    } else if lower.contains("device not found") || lower.contains("no device") {
        FidoError::NoDevice
    } else if lower.contains("permission denied") || lower.contains("access denied") {
        FidoError::NotAccessible
    } else if lower.contains("busy") || lower.contains("in use") {
        FidoError::Busy
    } else {
        FidoError::Internal {
            message: message.to_string(),
        }
    }
}

/// Whether any authenticator is reachable at all. Distinguishes "nothing
/// plugged in" from "plugged in but the process cannot open it", which are
/// different problems with different fixes.
pub fn authenticator_status() -> Result<(), FidoError> {
    if ctap_hid_fido2::get_fidokey_devices().is_empty() {
        return Err(FidoError::NoDevice);
    }
    open().map(|_| ())
}

/// Create a credential on the connected authenticator and return it together
/// with the key it derives. Costs two touches: one to create, one to prove the
/// authenticator really honours `hmac-secret`, so a token that silently ignored
/// the extension fails here rather than at the first unlock.
pub fn enroll(salt: [u8; 32]) -> Result<(HardwareCredential, [u8; 32]), FidoError> {
    let device = open()?;
    let args = MakeCredentialArgsBuilder::new(RP_ID, &challenge())
        .without_pin_and_uv()
        .extensions(&[Mext::HmacSecret(Some(true))])
        .build();
    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|err| classify(&err.to_string()))?;

    let credential = HardwareCredential {
        credential_id: attestation.credential_descriptor.id.clone(),
        salt,
    };

    let dwk = derive_dwk_with(&device, &credential)?;
    Ok((credential, dwk))
}

/// Derive the device wrapping key. Requires a touch.
pub fn derive_dwk(credential: &HardwareCredential) -> Result<[u8; 32], FidoError> {
    let device = open()?;
    derive_dwk_with(&device, credential)
}

fn derive_dwk_with(
    device: &FidoKeyHid,
    credential: &HardwareCredential,
) -> Result<[u8; 32], FidoError> {
    let args = GetAssertionArgsBuilder::new(RP_ID, &challenge())
        .without_pin_and_uv()
        .credential_id(&credential.credential_id)
        .extensions(&[Aext::HmacSecret(Some(credential.salt))])
        .build();
    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|err| classify(&err.to_string()))?;

    let output = assertions
        .iter()
        .flat_map(|assertion| assertion.extensions.iter())
        .find_map(|extension| match extension {
            Aext::HmacSecret(Some(value)) => Some(*value),
            _ => None,
        })
        .ok_or(FidoError::NoHmacSecret)?;

    Ok(derive_key(&output))
}

/// Whether *this* credential's authenticator is connected, without asking the
/// user for anything. A silent assertion answers in ~170ms and, unlike probing
/// for any FIDO device, cannot be satisfied by some unrelated token.
#[must_use]
pub fn is_present(credential: &HardwareCredential) -> bool {
    let Ok(device) = open() else {
        return false;
    };
    let args = GetAssertionArgsBuilder::new(RP_ID, &challenge())
        .without_pin_and_uv()
        .without_up()
        .credential_id(&credential.credential_id)
        .build();
    device.get_assertion_with_args(&args).is_ok()
}

/// The authenticator signs this, and nobody verifies the signature: the secret
/// comes from the extension, not from the assertion. A constant keeps the
/// derivation reproducible.
fn challenge() -> [u8; 32] {
    [0u8; 32]
}

fn derive_key(hmac_output: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(DWK_CONTEXT, hmac_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctap_status_codes_map_to_actionable_errors() {
        assert_eq!(
            classify("response_status err = 0x2E CTAP2_ERR_NO_CREDENTIALS"),
            FidoError::NotEnrolled
        );
        assert_eq!(
            classify("response_status err = 0x27 CTAP2_ERR_OPERATION_DENIED"),
            FidoError::Timeout
        );
        assert_eq!(
            classify("response_status err = 0x33 CTAP2_ERR_UNSUPPORTED_EXTENSION"),
            FidoError::NoHmacSecret
        );
        assert!(matches!(
            classify("something we have never seen"),
            FidoError::Internal { .. }
        ));
    }

    #[test]
    fn derivation_is_deterministic_and_not_the_raw_authenticator_output() {
        let output = [9u8; 32];
        let key = derive_key(&output);
        assert_eq!(key, derive_key(&output));
        assert_ne!(
            key, output,
            "the raw hmac output must not be used as the DWK"
        );
        assert_ne!(key, derive_key(&[8u8; 32]));
    }
}
