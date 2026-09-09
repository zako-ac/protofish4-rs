use protofish4_proto::codec::{decode_body, encode_body};
use protofish4_proto::crypto::{self, ReplayWindow, SessionKey};
use protofish4_proto::header::{Header, HEADER_LEN};
use protofish4_proto::types::{Direction, RequestId, TimestampMs, XferSeq};
use protofish4_proto::{Body, PacketKind};

fn key() -> SessionKey {
    SessionKey::from_bytes(&[7u8; 32]).unwrap()
}

fn data_packet(id: RequestId, seq: u32, payload: &[u8]) -> Vec<u8> {
    let body = Body::Data { ts: TimestampMs(seq as u64 * 20), payload: payload.to_vec() };
    let header = Header::new(PacketKind::Data, id, seq);
    crypto::seal(&key(), header, Direction::Send, &encode_body(&body).unwrap()).unwrap()
}

#[test]
fn round_trips_every_kind() {
    let id = RequestId::random();
    let cases = vec![
        (PacketKind::Data, 1u32, Body::Data { ts: TimestampMs(20), payload: vec![1, 2, 3] }),
        (PacketKind::End, 0, Body::End { final_seq: XferSeq(900) }),
        (PacketKind::EndAck, 1, Body::EndAck),
        (
            PacketKind::Ack,
            2,
            Body::Ack { contiguous: XferSeq(10), highest: XferSeq(14), buffered_ms: 9000 },
        ),
        (
            PacketKind::Nack,
            3,
            Body::Nack { missing: vec![XferSeq(11), XferSeq(12), XferSeq(13)] },
        ),
        (PacketKind::Keepalive, 4, Body::Keepalive { lost_below: XferSeq(5) }),
    ];

    for (kind, seq, body) in cases {
        let dir = kind.direction();
        let header = Header::new(kind, id, seq);
        let datagram =
            crypto::seal(&key(), header, dir, &encode_body(&body).unwrap()).unwrap();

        let (got_header, plaintext) = crypto::open(&key(), &datagram, dir).unwrap();
        assert_eq!(got_header, header, "{}", kind.name());
        assert_eq!(decode_body(kind, &plaintext).unwrap(), body, "{}", kind.name());
    }
}

/// A verbatim resend is a replay of one message, not two messages under one
/// nonce. It must reproduce the ciphertext exactly — that identity is what makes
/// retransmission safe without re-encrypting.
#[test]
fn retransmission_is_byte_identical() {
    let id = RequestId::random();
    let first = data_packet(id, 42, b"opus");
    let again = data_packet(id, 42, b"opus");
    assert_eq!(first, again);
}

/// The nonce must never repeat across kinds or directions for one key, because
/// two different plaintexts under one nonce leaks the Poly1305 key.
#[test]
fn nonce_space_does_not_collide_across_kinds() {
    let id = RequestId::random();
    let k = key();

    // Same counter value, different kinds and directions.
    let data = crypto::seal(
        &k,
        Header::new(PacketKind::Data, id, 5),
        Direction::Send,
        &encode_body(&Body::Data { ts: TimestampMs(100), payload: vec![0; 8] }).unwrap(),
    )
    .unwrap();
    let end = crypto::seal(
        &k,
        Header::new(PacketKind::End, id, 5),
        Direction::Send,
        &encode_body(&Body::End { final_seq: XferSeq(5) }).unwrap(),
    )
    .unwrap();
    let ack = crypto::seal(
        &k,
        Header::new(PacketKind::Ack, id, 5),
        Direction::Recv,
        &encode_body(&Body::Ack {
            contiguous: XferSeq(5),
            highest: XferSeq(5),
            buffered_ms: 0,
        })
        .unwrap(),
    )
    .unwrap();

    // Ciphertexts differ, and each opens only in its own direction.
    assert_ne!(&data[HEADER_LEN..], &end[HEADER_LEN..]);
    assert!(crypto::open(&k, &data, Direction::Send).is_ok());
    assert!(crypto::open(&k, &end, Direction::Send).is_ok());
    assert!(crypto::open(&k, &ack, Direction::Recv).is_ok());
}

#[test]
fn rejects_wrong_key() {
    let id = RequestId::random();
    let datagram = data_packet(id, 1, b"opus");
    let other = SessionKey::from_bytes(&[9u8; 32]).unwrap();
    assert!(crypto::open(&other, &datagram, Direction::Send).is_err());
}

/// The header is authenticated even though it is readable. An attacker who can
/// see `request_id` and `seq` still cannot move a packet to another request.
#[test]
fn rejects_tampered_header() {
    let id = RequestId::random();
    let mut datagram = data_packet(id, 1, b"opus");
    datagram[2] ^= 0xff; // flip a byte of the request id
    assert!(crypto::open(&key(), &datagram, Direction::Send).is_err());

    let mut datagram = data_packet(id, 1, b"opus");
    datagram[HEADER_LEN - 1] ^= 0x01; // flip the sequence number
    assert!(crypto::open(&key(), &datagram, Direction::Send).is_err());
}

#[test]
fn rejects_tampered_body() {
    let id = RequestId::random();
    let mut datagram = data_packet(id, 1, b"opus");
    let last = datagram.len() - 1;
    datagram[last] ^= 0x01;
    assert!(crypto::open(&key(), &datagram, Direction::Send).is_err());
}

/// A packet travelling the wrong way is rejected before its body is trusted.
#[test]
fn rejects_wrong_direction() {
    let id = RequestId::random();
    let datagram = data_packet(id, 1, b"opus");
    assert!(crypto::open(&key(), &datagram, Direction::Recv).is_err());
}

#[test]
fn proxy_can_route_without_the_key() {
    let id = RequestId::random();
    let datagram = data_packet(id, 1, b"opus");
    assert_eq!(crypto::request_id_of(&datagram).unwrap(), id);
}

#[test]
fn replay_window_accepts_in_order_and_rejects_repeats() {
    let mut w = ReplayWindow::new();
    for c in 0..2000u32 {
        assert!(w.accept(c).is_ok(), "counter {c} should be new");
    }
    assert!(w.accept(1999).is_err(), "exact repeat must be rejected");
    assert!(w.accept(1500).is_err(), "in-window repeat must be rejected");
}

#[test]
fn replay_window_tolerates_reordering_but_not_duplicates() {
    let mut w = ReplayWindow::new();
    assert!(w.accept(10).is_ok());
    assert!(w.accept(14).is_ok());
    // Late arrivals inside the window are fine exactly once.
    assert!(w.accept(11).is_ok());
    assert!(w.accept(11).is_err());
    assert!(w.accept(13).is_ok());
    assert!(w.accept(14).is_err());
}

#[test]
fn replay_window_drops_packets_older_than_the_window() {
    let mut w = ReplayWindow::new();
    assert!(w.accept(0).is_ok());
    assert!(w.accept(5000).is_ok());
    assert!(w.accept(1).is_err(), "far-past counter must not be accepted");
}
