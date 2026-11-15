use super::*;
use std::io::Cursor;
use std::sync::Arc;
fn keys() -> Vec<RecipientKey> {
    vec![
        RecipientKey::new(
            RecipientDescriptor::Argon2idPassphrase {
                salt: [1; 32],
                iterations: 1,
                memory_kb: 8,
                parallelism: 1,
            },
            SecretKey::from_bytes([7; 32]),
        ),
        RecipientKey::from_hardware(
            RecipientDescriptor::Fido2HmacSecret {
                credential_id: vec![1, 2, 3],
                salt: [2; 32],
            },
            &[8; 32],
        )
        .expect("hardware"),
        RecipientKey::new(
            RecipientDescriptor::DeviceBiometric { key_id: [3; 16] },
            SecretKey::from_bytes([9; 32]),
        ),
    ]
}
fn archive(data: &[u8], keys: &[RecipientKey]) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new(), keys).expect("writer");
    writer.write_all(data).expect("write");
    writer.finish().expect("finish")
}
fn open(bytes: &[u8], key: &RecipientKey) -> Result<Vec<u8>, ArchiveError> {
    let header = ArchiveHeader::read(&mut Cursor::new(bytes))?;
    let unlocked = Arc::new(header.unlock(key)?);
    let mut reader = unlocked.reader(Cursor::new(bytes))?;
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    Ok(data)
}
#[test]
fn streaming_boundaries_empty_and_multiple_recipients_round_trip() {
    for mask in [1, 2, 3, 5, 6, 7] {
        let keys = keys()
            .into_iter()
            .enumerate()
            .filter_map(|(i, key)| ((mask & (1 << i)) != 0).then_some(key))
            .collect::<Vec<_>>();
        for size in [
            0,
            1,
            CHUNK_BYTES - 1,
            CHUNK_BYTES,
            CHUNK_BYTES + 1,
            3 * CHUNK_BYTES + 17,
        ] {
            let data = (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let bytes = archive(&data, &keys);
            for key in &keys {
                assert_eq!(open(&bytes, key).expect("open"), data);
            }
            assert!(!bytes.windows(32).any(|w| w == [7; 32]));
        }
    }
}
#[test]
fn every_truncation_header_slot_and_payload_tamper_and_append_fails() {
    let keys = keys();
    let bytes = archive(b"synthetic secret sentinel", &keys);
    for end in 0..bytes.len() {
        assert!(
            open(&bytes[..end], &keys[0]).is_err(),
            "accepted truncation {end}"
        );
    }
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(open(&changed, &keys[0]).is_err(), "accepted tamper {index}");
    }
    let mut appended = bytes.clone();
    appended.push(0);
    assert!(open(&appended, &keys[0]).is_err());
    let mut other = super::tests::keys();
    other[0].key = SecretKey::from_bytes([66; 32]);
    assert!(open(&bytes, &other[0]).is_err());
}
#[test]
fn frame_reordering_duplication_and_missing_final_are_detected() {
    let keys = keys();
    let bytes = archive(&vec![4; CHUNK_BYTES * 2], &keys);
    let mut cursor = Cursor::new(&bytes);
    ArchiveHeader::read(&mut cursor).expect("header");
    let start = cursor.position() as usize;
    let frame = CHUNK_BYTES + TAG_BYTES + 5;
    let mut reordered = bytes.clone();
    reordered[start..start + frame].copy_from_slice(&bytes[start + frame..start + 2 * frame]);
    reordered[start + frame..start + 2 * frame].copy_from_slice(&bytes[start..start + frame]);
    assert!(open(&reordered, &keys[0]).is_err());
    let mut duplicated = bytes.clone();
    duplicated.splice(start..start, bytes[start..start + frame].iter().copied());
    assert!(open(&duplicated, &keys[0]).is_err());
    assert!(open(&bytes[..start + 2 * frame], &keys[0]).is_err());
}
#[test]
fn biometric_only_and_oversized_or_duplicate_recipients_are_refused_before_writing() {
    let mut bytes = Vec::new();
    let keys = keys();
    assert!(ArchiveWriter::new(&mut bytes, &keys[2..]).is_err());
    assert!(bytes.is_empty());
    let many = (0..=MAX_RECIPIENTS)
        .map(|_| RecipientKey::new(keys[0].descriptor.clone(), SecretKey::from_bytes([7; 32])))
        .collect::<Vec<_>>();
    assert!(ArchiveWriter::new(&mut bytes, &many).is_err());
    assert!(ArchiveWriter::new(&mut bytes, &many[..2]).is_err());
    assert!(bytes.is_empty());
    let mut huge = MAGIC.to_vec();
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(ArchiveHeader::read(&mut Cursor::new(huge)).is_err());
}
#[test]
fn passphrase_nfc_equivalence_bounds_and_secret_redaction() {
    let descriptor = RecipientDescriptor::Argon2idPassphrase {
        salt: [3; 32],
        iterations: 1,
        memory_kb: 8,
        parallelism: 1,
    };
    let key = descriptor.key_from_passphrase("café").expect("key");
    let bytes = archive(b"passkey private key", &[key]);
    let equivalent = descriptor.key_from_passphrase("cafe\u{301}").expect("NFC");
    assert_eq!(
        open(&bytes, &equivalent).expect("NFC unlock"),
        b"passkey private key"
    );
    assert!(descriptor.key_from_passphrase("").is_err());
    let invalid = RecipientDescriptor::Argon2idPassphrase {
        salt: [0; 32],
        iterations: u32::MAX,
        memory_kb: u32::MAX,
        parallelism: 1,
    };
    let error = invalid
        .key_from_passphrase("sentinel")
        .err()
        .expect("bounds");
    assert!(!format!("{error:?} {error}").contains("sentinel"));
}

#[test]
fn a_large_stream_writes_bounded_frames_without_accumulating_the_archive() {
    #[derive(Default)]
    struct Sink {
        maximum: usize,
        total: usize,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.maximum = self.maximum.max(bytes.len());
            self.total += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let keys = keys();
    let mut writer = ArchiveWriter::new(Sink::default(), &keys).expect("writer");
    for _ in 0..1000 {
        writer.write_all(&[4; 10_000]).expect("stream chunk");
    }
    let sink = writer.finish().expect("finish");
    assert!(sink.total > 10_000_000);
    assert!(sink.maximum <= CHUNK_BYTES + TAG_BYTES);
}
