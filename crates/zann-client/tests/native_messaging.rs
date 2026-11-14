#![cfg(feature = "native-messaging")]
use std::io::{Cursor, ErrorKind};
use zann_client::native_messaging::*;

#[test]
fn framing_distinguishes_clean_eof_truncation_and_oversized_messages() {
    assert!(read_frame(&mut Cursor::new([])).unwrap().is_none());
    for bytes in [vec![1], vec![1, 0], vec![1, 0, 0], vec![0, 0, 0, 0]] {
        assert!(read_frame(&mut Cursor::new(bytes)).is_err());
    }
    let mut frame = (MAX_MESSAGE_BYTES as u32 + 1).to_ne_bytes().to_vec();
    assert_eq!(
        read_frame(&mut Cursor::new(&frame)).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    frame = 4_u32.to_ne_bytes().to_vec();
    frame.extend_from_slice(b"abc");
    assert_eq!(
        read_frame(&mut Cursor::new(frame)).unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
    let payload = vec![42; MAX_MESSAGE_BYTES];
    let mut wire = Vec::new();
    write_frame(&mut wire, &payload).unwrap();
    assert_eq!(
        read_frame(&mut Cursor::new(wire)).unwrap().unwrap(),
        payload
    );
    assert!(write_frame(&mut Vec::new(), &[]).is_err());
    assert!(write_frame(&mut Vec::new(), &vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
}
