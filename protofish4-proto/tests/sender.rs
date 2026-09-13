//! Sender-side pacing, retransmission and give-up behaviour.

use std::time::{Duration, Instant};

use protofish4_proto::config::SenderConfig;
use protofish4_proto::frame::Body;
use protofish4_proto::types::{TimestampMs, XferSeq};
use protofish4_proto::xfer::sender::SendFailure;
use protofish4_proto::xfer::{SendEvent, XferSender};

/// Emit a frame and immediately record a stand-in for its sealed bytes, which
/// is what the real caller does.
fn send_one(tx: &mut XferSender, now: Instant) -> Option<XferSeq> {
    let ev = tx.push_frame(TimestampMs(0), vec![0xAB; 40], now)?;
    let SendEvent::Emit { seq, .. } = ev else {
        panic!("expected Emit");
    };
    tx.record_sealed(seq, format!("sealed:{}", seq.0).into_bytes());
    Some(seq)
}

#[test]
fn frames_are_numbered_from_one() {
    let t0 = Instant::now();
    let mut tx = XferSender::new(SenderConfig::default());
    assert_eq!(send_one(&mut tx, t0), Some(XferSeq(1)));
    assert_eq!(send_one(&mut tx, t0), Some(XferSeq(2)));
}

/// A tap that ignores wall-clock pacing still cannot burst a whole track onto
/// the wire — the outstanding-frame window stops it.
#[test]
fn send_window_closes_without_acks() {
    let t0 = Instant::now();
    let cfg = SenderConfig { max_outstanding: 4, ..Default::default() };
    let mut tx = XferSender::new(cfg);

    for _ in 0..4 {
        assert!(send_one(&mut tx, t0).is_some());
    }
    assert!(!tx.can_send(), "window should be closed at max_outstanding");
    assert!(tx.push_frame(TimestampMs(0), vec![0; 10], t0).is_none());

    // An ack reopens it.
    tx.handle(
        Body::Ack { contiguous: XferSeq(4), highest: XferSeq(4), buffered_ms: 0 },
        t0,
    );
    assert!(tx.can_send());
    assert!(send_one(&mut tx, t0).is_some());
}

/// `highest` rather than `contiguous` drives the window, so one lost frame does
/// not stall the sender behind its own gap.
#[test]
fn loss_does_not_stall_the_window() {
    let t0 = Instant::now();
    let cfg = SenderConfig { max_outstanding: 4, ..Default::default() };
    let mut tx = XferSender::new(cfg);

    for _ in 0..4 {
        send_one(&mut tx, t0);
    }
    assert!(!tx.can_send());

    // Frame 2 is missing, but the receiver has seen up to 4.
    tx.handle(
        Body::Ack { contiguous: XferSeq(1), highest: XferSeq(4), buffered_ms: 0 },
        t0,
    );
    assert!(tx.can_send(), "the window follows highest, not contiguous");
}

/// The receiver's buffer occupancy pauses and resumes the sender, with
/// hysteresis so it does not thrash at the threshold.
#[test]
fn buffer_occupancy_pauses_and_resumes() {
    let t0 = Instant::now();
    let cfg = SenderConfig::default();
    let (high, low) = (cfg.buffer_high_water_ms, cfg.buffer_low_water_ms);
    let mut tx = XferSender::new(cfg);
    send_one(&mut tx, t0);

    tx.handle(Body::Ack { contiguous: XferSeq(1), highest: XferSeq(1), buffered_ms: high }, t0);
    assert!(!tx.can_send(), "should pause at the high-water mark");

    // Between the marks: still paused.
    let mid = (high + low) / 2;
    tx.handle(Body::Ack { contiguous: XferSeq(1), highest: XferSeq(1), buffered_ms: mid }, t0);
    assert!(!tx.can_send(), "hysteresis keeps it paused between the marks");

    tx.handle(Body::Ack { contiguous: XferSeq(1), highest: XferSeq(1), buffered_ms: low }, t0);
    assert!(tx.can_send(), "should resume at the low-water mark");
}

/// The core safety property: a NACK is answered with the *exact bytes already
/// sent*, never a fresh encryption.
#[test]
fn nack_resends_the_original_sealed_bytes() {
    let t0 = Instant::now();
    let mut tx = XferSender::new(SenderConfig::default());
    for _ in 0..3 {
        send_one(&mut tx, t0);
    }

    let events = tx.handle(Body::Nack { missing: vec![XferSeq(2)] }, t0);
    assert_eq!(
        events,
        vec![SendEvent::Resend { datagrams: vec![b"sealed:2".to_vec()] }]
    );

    // And again, byte-identical — retransmission is idempotent.
    let again = tx.handle(Body::Nack { missing: vec![XferSeq(2)] }, t0);
    assert_eq!(again, events);
}

#[test]
fn acked_frames_leave_the_retransmit_ring() {
    let t0 = Instant::now();
    let mut tx = XferSender::new(SenderConfig::default());
    for _ in 0..3 {
        send_one(&mut tx, t0);
    }

    tx.handle(Body::Ack { contiguous: XferSeq(2), highest: XferSeq(3), buffered_ms: 0 }, t0);

    // 1 and 2 are gone; only 3 can still be resent.
    let events = tx.handle(Body::Nack { missing: vec![XferSeq(1), XferSeq(3)] }, t0);
    assert_eq!(
        events,
        vec![SendEvent::Resend { datagrams: vec![b"sealed:3".to_vec()] }]
    );
}

#[test]
fn end_carries_the_final_sequence_number() {
    let t0 = Instant::now();
    let mut tx = XferSender::new(SenderConfig::default());
    for _ in 0..7 {
        send_one(&mut tx, t0);
    }

    let ev = tx.finish(t0).expect("finish emits End");
    let SendEvent::Emit { body: Body::End { final_seq }, .. } = ev else {
        panic!("expected End");
    };
    assert_eq!(final_seq, XferSeq(7));
}

/// Between `End` and `EndAck` the sender must keep the NAT mapping open, or the
/// receiver's NACKs for the tail never arrive.
#[test]
fn keepalives_flow_while_finalizing() {
    let t0 = Instant::now();
    let cfg = SenderConfig::default();
    let interval = cfg.tail_keepalive_interval;
    let mut tx = XferSender::new(cfg);
    send_one(&mut tx, t0);
    tx.handle(Body::Ack { contiguous: XferSeq(1), highest: XferSeq(1), buffered_ms: 0 }, t0);
    tx.finish(t0);

    let events = tx.tick(t0 + interval + Duration::from_millis(1));
    assert!(
        events.iter().any(|e| matches!(
            e,
            SendEvent::Emit { body: Body::Keepalive { .. }, .. }
        )),
        "expected a tail keepalive, got {events:?}"
    );
}

#[test]
fn end_ack_completes_the_transfer() {
    let t0 = Instant::now();
    let mut tx = XferSender::new(SenderConfig::default());
    send_one(&mut tx, t0);
    tx.finish(t0);

    let events = tx.handle(Body::EndAck, t0);
    assert_eq!(events, vec![SendEvent::Completed]);
    assert!(tx.is_done());
}

/// Path validation without a handshake: if nothing ever acknowledges the
/// stream, the sender gives up on its own.
#[test]
fn no_ack_at_all_fails_the_transfer() {
    let t0 = Instant::now();
    let cfg = SenderConfig::default();
    let timeout = cfg.first_ack_timeout;
    let mut tx = XferSender::new(cfg);
    send_one(&mut tx, t0);

    assert!(tx.tick(t0 + timeout / 2).is_empty(), "must not give up early");

    let events = tx.tick(t0 + timeout + Duration::from_millis(1));
    assert_eq!(events, vec![SendEvent::Failed(SendFailure::NoAck)]);
    assert!(tx.is_done());
}

/// A sender held back by the receiver's buffer report has nothing to say — and
/// silence is what the receiver's idle timeout reads as a dead tap, after which
/// it aborts the transfer and stops acknowledging, leaving the pause permanent.
/// The pause is therefore spoken for.
#[test]
fn a_paused_sender_keeps_the_transfer_alive() {
    let t0 = Instant::now();
    let cfg = SenderConfig {
        tail_keepalive_interval: Duration::from_secs(1),
        buffer_high_water_ms: 1_000,
        buffer_low_water_ms: 500,
        ..Default::default()
    };
    let mut tx = XferSender::new(cfg);
    assert!(send_one(&mut tx, t0).is_some());

    // The receiver says its buffer is full, so the sender stops.
    let acked = tx.handle(
        Body::Ack {
            contiguous: XferSeq(1),
            highest: XferSeq(1),
            buffered_ms: 60_000,
        },
        t0,
    );
    assert!(acked.is_empty());
    assert!(!tx.can_send(), "the brake should have engaged");

    // Nothing to send, but still alive.
    let events = tx.tick(t0 + Duration::from_secs(2));
    assert!(
        events.iter().any(|e| matches!(
            e,
            SendEvent::Emit { body: Body::Keepalive { .. }, .. }
        )),
        "a paused sender must say it is still here: {events:?}"
    );

    // And a later, lower report releases it.
    tx.handle(
        Body::Ack {
            contiguous: XferSeq(1),
            highest: XferSeq(1),
            buffered_ms: 0,
        },
        t0 + Duration::from_secs(2),
    );
    assert!(tx.can_send(), "the sender must resume once the buffer drains");
}

/// Overflowing the ring is not an error — it just means those frames can no
/// longer be recovered, and the receiver is told so it can stop asking.
#[test]
fn ring_overflow_reports_lost_frames_rather_than_failing() {
    let t0 = Instant::now();
    let cfg = SenderConfig {
        retrans_ring_frames: 4,
        max_outstanding: 1000,
        ..Default::default()
    };
    let mut tx = XferSender::new(cfg);

    for _ in 0..10 {
        send_one(&mut tx, t0);
    }

    // The oldest are gone and cannot be resent.
    let events = tx.handle(Body::Nack { missing: vec![XferSeq(1)] }, t0);
    assert!(events.is_empty(), "evicted frames produce no resend");

    // Still able to serve what it kept.
    let events = tx.handle(Body::Nack { missing: vec![XferSeq(10)] }, t0);
    assert_eq!(
        events,
        vec![SendEvent::Resend { datagrams: vec![b"sealed:10".to_vec()] }]
    );

    // And the keepalive tells the receiver where the floor is.
    tx.finish(t0);
    let events = tx.tick(t0 + Duration::from_secs(6));
    let lost = events.iter().find_map(|e| match e {
        SendEvent::Emit { body: Body::Keepalive { lost_below }, .. } => Some(lost_below.0),
        _ => None,
    });
    assert_eq!(lost, Some(6), "frames 1..=6 were evicted");
}
