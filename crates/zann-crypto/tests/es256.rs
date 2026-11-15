#![cfg(feature = "passkey")]
use zann_crypto::es256::{verify, Es256Key};

#[test]
fn rfc6979_p256_sha256_sample_is_byte_exact() {
    // RFC 6979 Appendix A.2.5: public, synthetic standard test vector.
    let scalar =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let key = Es256Key::from_scalar(&scalar).expect("RFC key");
    let signature = key.sign(b"sample").expect("sign");
    assert_eq!(
        hex::encode(&signature),
        concat!(
            "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        )
    );
    verify(&key.public_key(), b"sample", &signature).expect("valid signature");
    assert!(verify(&key.public_key(), b"tampered", &signature).is_err());
    assert!(verify(&[0; 65], b"sample", &signature).is_err());
    assert!(verify(&key.public_key(), b"sample", &[0; 64]).is_err());
}

#[test]
fn pkcs8_round_trip_and_invalid_scalars_fail_closed() {
    let key = Es256Key::generate().expect("entropy");
    let document = key.to_pkcs8_der().expect("PKCS8");
    let reopened = Es256Key::from_pkcs8_der(&document).expect("decode");
    assert_eq!(key.public_key(), reopened.public_key());
    let mut invalid_point = document.to_vec();
    let last = invalid_point.len() - 1;
    invalid_point[last] ^= 1;
    assert!(Es256Key::from_pkcs8_der(&invalid_point).is_err());
    for scalar in [&[0; 32][..], &[0xff; 32][..], &[1; 31][..]] {
        let error = Es256Key::from_scalar(scalar).err().expect("invalid scalar");
        assert_eq!(
            format!("{error:?} {error}"),
            "invalid ES256 private key invalid ES256 private key"
        );
        if scalar.len() == 32 {
            assert!(std::error::Error::source(&error).is_some());
        }
    }
    assert!(Es256Key::from_pkcs8_der(b"sentinel-private-key").is_err());
    fn zeroizes<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes::<p256::ecdsa::SigningKey>();
}
