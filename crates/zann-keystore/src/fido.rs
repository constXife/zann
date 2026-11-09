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

use crate::{AuthenticatorInfo, FidoError, HardwareAuthenticator, HardwareCredential};
use ctap_hid_fido2::fidokey::{
    get_assertion::get_assertion_params::{Extension as Aext, GetAssertionArgsBuilder},
    make_credential::make_credential_params::{Extension as Mext, MakeCredentialArgsBuilder},
    FidoKeyHid,
};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

/// Relying party the credentials are scoped to. Changing this orphans every
/// enrolled key, so it is deliberately not configurable.
const RP_ID: &str = "zann.local";

/// Domain separation for the KDF applied to the authenticator's output.
const DWK_CONTEXT: &str = "zann 2026-08-08 fido2 device wrapping key";

/// The authenticator itself gives up after ~30s of waiting for a touch, so any
/// UI timeout has to be at least this generous.
pub const TOUCH_TIMEOUT_SECS: u64 = 30;

fn cfg() -> Cfg {
    let mut cfg = Cfg::init();
    // The crate otherwise prints "- Touch the sensor..." straight to stdout.
    // Prompting is the UI's job.
    cfg.keep_alive_msg = String::new();
    cfg.enable_log = false;
    cfg
}

fn open() -> Result<FidoKeyHid, FidoError> {
    FidoKeyHidFactory::create(&cfg()).map_err(backend_error)
}

fn backend_error(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> FidoError {
    let source = error.into();
    FidoError::Backend {
        kind: classify(&source.to_string()).kind(),
        source,
    }
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

/// Raw HID adapter. The port and its DTOs are available on every platform.
pub struct CtapHidAuthenticator;

impl HardwareAuthenticator for CtapHidAuthenticator {
    fn supported(&self) -> bool {
        true
    }

    fn status(&self) -> Result<AuthenticatorInfo, FidoError> {
        let devices = ctap_hid_fido2::get_fidokey_devices();
        let device = match devices.as_slice() {
            [] => return Err(FidoError::NoDevice),
            [device] => device,
            _ => {
                return Err(FidoError::Internal {
                    message: "multiple authenticators connected".into(),
                })
            }
        };
        let key = FidoKeyHidFactory::create_by_params(std::slice::from_ref(&device.param), &cfg())
            .map_err(backend_error)?;
        let info = key.get_info().map_err(backend_error)?;
        Ok(AuthenticatorInfo {
            product_name: (!device.product_string.trim().is_empty())
                .then(|| device.product_string.clone()),
            hmac_secret: info
                .extensions
                .iter()
                .any(|extension| extension == "hmac-secret"),
        })
    }

    /// Touch 1: create a credential. Confirmation is a separate derivation.
    fn create_credential(&self, salt: [u8; 32]) -> Result<HardwareCredential, FidoError> {
        let device = open()?;
        let args = MakeCredentialArgsBuilder::new(RP_ID, &challenge())
            .without_pin_and_uv()
            .extensions(&[Mext::HmacSecret(Some(true))])
            .build();
        let attestation = device
            .make_credential_with_args(&args)
            .map_err(backend_error)?;

        let credential = HardwareCredential {
            credential_id: attestation.credential_descriptor.id.clone(),
            salt,
        };

        Ok(credential)
    }

    /// Derive the device wrapping key. Requires a touch.
    fn derive_dwk(&self, credential: &HardwareCredential) -> Result<[u8; 32], FidoError> {
        let device = open()?;
        derive_dwk_with(&device, credential)
    }

    /// Whether *this* credential's authenticator is connected, without asking the
    /// user for anything. A silent assertion answers in ~170ms and, unlike probing
    /// for any FIDO device, cannot be satisfied by some unrelated token.
    fn is_present(&self, credential: &HardwareCredential) -> bool {
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
        .map_err(backend_error)?;

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
            classify("response_status err = 0x2E CTAP2_ERR_NO_CREDENTIALS").kind(),
            FidoError::NotEnrolled.kind()
        );
        assert_eq!(
            classify("response_status err = 0x27 CTAP2_ERR_OPERATION_DENIED").kind(),
            FidoError::Timeout.kind()
        );
        assert_eq!(
            classify("response_status err = 0x33 CTAP2_ERR_UNSUPPORTED_EXTENSION").kind(),
            FidoError::NoHmacSecret.kind()
        );
        assert!(matches!(
            classify("something we have never seen"),
            FidoError::Internal { .. }
        ));
    }

    #[test]
    fn classified_backend_errors_keep_the_original_cause() {
        let error = backend_error(std::io::Error::other(
            "response_status err = 0x27 CTAP2_ERR_OPERATION_DENIED",
        ));
        assert_eq!(error.kind(), "hardware_key_timeout");
        let source = std::error::Error::source(&error).expect("original cause");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
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
