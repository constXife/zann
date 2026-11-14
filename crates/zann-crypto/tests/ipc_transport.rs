#![cfg(feature = "ipc-transport")]
use zann_crypto::ipc_transport::{IpcHandshake, IpcTransport, IpcTransportKey, MAX_PLAINTEXT};

fn connected() -> (IpcTransport, IpcTransport) {
    let key = IpcTransportKey::generate();
    let mut client = IpcHandshake::initiator(&key.public_key(), b"bound server hello").unwrap();
    let mut server = key.responder(b"bound server hello").unwrap();
    assert!(client.binding().is_err());
    server.read(&client.write().unwrap()).unwrap();
    client.read(&server.write().unwrap()).unwrap();
    assert_eq!(client.binding().unwrap(), server.binding().unwrap());
    (client.finish().unwrap(), server.finish().unwrap())
}

#[test]
fn noise_channel_hides_content_and_authenticates_chunk_length_order_and_replay() {
    let (mut client, mut server) = connected();
    let packets = client.seal(b"password-sentinel").unwrap();
    assert!(!packets
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>()
        .windows(17)
        .any(|w| w == b"password-sentinel"));
    assert_eq!(&*server.open(&packets).unwrap(), b"password-sentinel");
    assert!(server.open(&packets).is_err());
    for tamper in ["bit", "truncate", "reorder"] {
        let (mut client, mut server) = connected();
        let mut packets = client.seal(&vec![42; 100_000]).unwrap();
        match tamper {
            "bit" => packets[0][5] ^= 1,
            "truncate" => {
                packets.pop();
            }
            "reorder" => packets.swap(0, 1),
            _ => unreachable!(),
        }
        assert!(server.open(&packets).is_err(), "{tamper}");
    }
    let (mut client, mut server) = connected();
    let message = vec![91; MAX_PLAINTEXT];
    assert_eq!(
        &*server.open(&client.seal(&message).unwrap()).unwrap(),
        &message
    );
    assert!(client.seal(&vec![0; MAX_PLAINTEXT + 1]).is_err());
}

#[test]
fn different_server_key_or_prologue_cannot_complete_the_channel() {
    let key = IpcTransportKey::generate();
    let wrong = IpcTransportKey::generate();
    for (public, prologue) in [
        (wrong.public_key(), b"hello".as_slice()),
        (key.public_key(), b"modified".as_slice()),
    ] {
        let mut client = IpcHandshake::initiator(&public, prologue).unwrap();
        let mut server = key.responder(b"hello").unwrap();
        assert!(server.read(&client.write().unwrap()).is_err());
    }
}
