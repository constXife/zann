//! Only bounded, public response structures are encoded here. Private keys are
//! stored by the canonical Item payload codec, never in a ceremony response.
use crate::{PasskeyError, PASSKEY_ALGORITHM};
use ciborium::value::Value;

fn encode(value: Value) -> Result<Vec<u8>, PasskeyError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).map_err(PasskeyError::Cbor)?;
    Ok(bytes)
}

pub(crate) fn cose_public_key(sec1: &[u8; 65]) -> Result<Vec<u8>, PasskeyError> {
    encode(Value::Map(vec![
        (1.into(), 2.into()), // kty EC2
        (3.into(), PASSKEY_ALGORITHM.into()),
        ((-1).into(), 1.into()), // crv P-256
        ((-2).into(), Value::Bytes(sec1[1..33].to_vec())),
        ((-3).into(), Value::Bytes(sec1[33..65].to_vec())),
    ]))
}

pub(crate) fn none_attestation(auth_data: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    encode(Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn w3c_es256_cose_example_has_ctap_canonical_encoding() {
        // WebAuthn Level 3 §6.5.1.1, ES256 example. Public key test data.
        // https://www.w3.org/TR/webauthn-3/#sctn-encoded-credPubKey-examples
        let coordinates = concat!(
            "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
            "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"
        );
        let mut sec1 = [0; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&hex::decode(coordinates).unwrap());
        assert_eq!(
            hex::encode(cose_public_key(&sec1).unwrap()),
            format!(
                "a5010203262001215820{}225820{}",
                &coordinates[..64],
                &coordinates[64..]
            )
        );
    }
}
