//! Receiver-side transfer behaviour: what the two outputs promise under loss.

use std::time::{Duration, Instant};

use protofish4_proto::config::{ReceiverConfig, RecvMode};
use protofish4_proto::frame::Body;
use protofish4_proto::types::{RelAbortReason, RelOutcome, TimestampMs, XferSeq};
use protofish4_proto::xfer::{RecvEvent, XferReceiver};

fn data(seq: u32) -> (XferSeq, Body) {
    (
        XferSeq(seq),
        Body::Data {
            ts: TimestampMs(seq as u64 * 20),
            payload: vec![seq as u8; 40],
        },
    )
}

fn unrel(events: &[RecvEvent]) -> Vec<u32> {
    events
        .iter()
        .filter_map(|e| match e {
            RecvEvent::Unreliable(f) => Some(f.seq.0),
            _ => None,
        })
        .collect()
}

fn rel(events: &[RecvEvent]) -> Vec<u32> {
    events
        .iter()
        .filter_map(|e| match e {
            RecvEvent::Reliable(f) => Some(f.seq.0),
            _ => None,
        })
        .collect()
}

fn outcome(events: &[RecvEvent]) -> Option<RelOutcome> {
    events.iter().find_map(|e| match e {
        RecvEvent::RelFinished(o) => Some(o.clone()),
        _ => None,
    })
}

fn nacked(events: &[RecvEvent]) -> Vec<u32> {
    events
        .iter()
        .flat_map(|e| match e {
            RecvEvent::SendNack { missing } => missing.iter().map(|s| s.0).collect(),
            _ => Vec::new(),
        })
        .collect()
}

#[test]
fn clean_transfer_completes_both_streams() {
    let t0 = Instant::now();
    let mut rx = XferReceiver::new(ReceiverConfig::audio_engine(), t0);
    let mut all = Vec::new();

    for i in 1..=10u32 {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }
    all.extend(rx.handle(XferSeq(1), Body::End { final_seq: XferSeq(10) }, t0));

    assert_eq!(unrel(&all), (1..=10).collect::<Vec<_>>());
    assert_eq!(rel(&all), (1..=10).collect::<Vec<_>>());
    assert_eq!(outcome(&all), Some(RelOutcome::Complete { final_seq: XferSeq(10) }));
    assert!(all.contains(&RecvEvent::SendEndAck));
}

/// The unreliable side must hand playback everything that physically arrived,
/// gaps and all — that is the whole reason it exists.
#[test]
fn unreliable_yields_out_of_order_arrivals_immediately() {
    let t0 = Instant::now();
    let mut rx = XferReceiver::new(ReceiverConfig::audio_engine(), t0);
    let mut all = Vec::new();

    for i in [1u32, 2, 5, 3, 9] {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }

    assert_eq!(unrel(&all), vec![1, 2, 5, 3, 9]);
    // The reliable side only releases what is contiguous.
    assert_eq!(rel(&all), vec![1, 2, 3]);
}

#[test]
fn duplicates_are_delivered_once() {
    let t0 = Instant::now();
    let mut rx = XferReceiver::new(ReceiverConfig::audio_engine(), t0);
    let mut all = Vec::new();

    for i in [1u32, 2, 2, 1, 3] {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }

    assert_eq!(unrel(&all), vec![1, 2, 3]);
    assert_eq!(rel(&all), vec![1, 2, 3]);
}

/// A gap is asked for, the retransmission arrives, and the reliable stream
/// completes as if nothing happened.
#[test]
fn nack_recovers_a_gap_and_commits() {
    let t0 = Instant::now();
    let mut rx = XferReceiver::new(ReceiverConfig::audio_engine(), t0);
    let mut all = Vec::new();

    for i in [1u32, 2, 4, 5] {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }
    all.extend(rx.handle(XferSeq(1), Body::End { final_seq: XferSeq(5) }, t0));

    let t1 = t0 + Duration::from_millis(50);
    let ticked = rx.tick(t1);
    assert_eq!(nacked(&ticked), vec![3], "the missing frame should be requested");

    // The retransmission arrives.
    let (seq, body) = data(3);
    all.extend(rx.handle(seq, body, t1));

    assert_eq!(rel(&all), vec![1, 2, 3, 4, 5]);
    assert_eq!(outcome(&all), Some(RelOutcome::Complete { final_seq: XferSeq(5) }));
}

/// The headline guarantee: a tap that never answers a NACK costs the cache
/// entry, never the audio and never unbounded memory.
#[test]
fn unanswered_nacks_abort_rel_but_never_unrel() {
    let t0 = Instant::now();
    let cfg = ReceiverConfig::audio_engine();
    let backoff: Duration = cfg.nack_backoff.iter().sum();
    let mut rx = XferReceiver::new(cfg, t0);
    let mut all = Vec::new();

    for i in [1u32, 2, 4] {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }

    // Burn the retry budget.
    let mut t = t0;
    for _ in 0..8 {
        t += backoff;
        all.extend(rx.tick(t));
    }

    assert_eq!(
        outcome(&all),
        Some(RelOutcome::Aborted(RelAbortReason::UnrecoverableGap))
    );

    // Playback keeps working after the reliable stream has given up.
    let before = unrel(&all).len();
    let (seq, body) = data(5);
    let more = rx.handle(seq, body, t);
    assert_eq!(unrel(&more), vec![5]);
    assert!(unrel(&all).len() == before);
}

/// A sender that has evicted the frames says so, and the receiver gives up in
/// one round trip instead of spending its whole budget.
#[test]
fn sender_reporting_lost_frames_aborts_rel_immediately() {
    let t0 = Instant::now();
    let mut rx = XferReceiver::new(ReceiverConfig::audio_engine(), t0);
    let mut all = Vec::new();

    for i in [1u32, 2, 6] {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }
    assert!(outcome(&all).is_none());

    all.extend(rx.handle(
        XferSeq(1),
        Body::Keepalive { lost_below: XferSeq(5) },
        t0,
    ));

    assert_eq!(
        outcome(&all),
        Some(RelOutcome::Aborted(RelAbortReason::SenderDiscarded))
    );
}

/// Memory is bounded by the reorder window, not by how far ahead a sender runs.
#[test]
fn reorder_window_overflow_aborts_rel_and_frees_memory() {
    let t0 = Instant::now();
    let cfg = ReceiverConfig { reorder_window: 8, ..ReceiverConfig::audio_engine() };
    let mut rx = XferReceiver::new(cfg, t0);
    let mut all = Vec::new();

    // Frame 1 never arrives; everything else runs far ahead of it.
    for i in 2..=40u32 {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }

    assert_eq!(
        outcome(&all),
        Some(RelOutcome::Aborted(RelAbortReason::BufferExhausted))
    );
    // Every frame still reached playback.
    assert_eq!(unrel(&all), (2..=40).collect::<Vec<_>>());
}

#[test]
fn rel_only_mode_yields_no_unreliable_frames() {
    let t0 = Instant::now();
    let mut rx = XferReceiver::new(ReceiverConfig::cache_worker(), t0);
    let mut all = Vec::new();

    for i in [1u32, 3, 2] {
        let (seq, body) = data(i);
        all.extend(rx.handle(seq, body, t0));
    }
    all.extend(rx.handle(XferSeq(1), Body::End { final_seq: XferSeq(3) }, t0));

    assert!(unrel(&all).is_empty(), "cache worker allocates no playback path");
    assert_eq!(rel(&all), vec![1, 2, 3]);
    assert_eq!(outcome(&all), Some(RelOutcome::Complete { final_seq: XferSeq(3) }));
}

/// The cache worker is deliberately far more patient than the audio engine.
/// That asymmetry is the reason it gets its own receiver.
#[test]
fn cache_worker_outlasts_audio_engine_on_the_same_gap() {
    let ae = ReceiverConfig::audio_engine();
    let cache = ReceiverConfig::cache_worker();
    assert!(cache.max_nack_attempts > ae.max_nack_attempts);
    assert!(cache.rel_stall_timeout > ae.rel_stall_timeout);
    assert!(cache.reorder_window > ae.reorder_window);
    assert_eq!(ae.mode, RecvMode::Dual);
    assert_eq!(cache.mode, RecvMode::RelOnly);
}

#[test]
fn silence_closes_the_transfer() {
    let t0 = Instant::now();
    let cfg = ReceiverConfig::audio_engine();
    let idle = cfg.idle_timeout;
    let mut rx = XferReceiver::new(cfg, t0);

    let (seq, body) = data(1);
    let _ = rx.handle(seq, body, t0);

    let events = rx.tick(t0 + idle + Duration::from_secs(1));
    assert!(events.contains(&RecvEvent::Closed));
    assert_eq!(outcome(&events), Some(RelOutcome::Aborted(RelAbortReason::PeerGone)));
    assert!(rx.is_closed());
}

#[test]
fn acks_report_progress_for_the_send_window() {
    let t0 = Instant::now();
    let cfg = ReceiverConfig::audio_engine();
    let interval = cfg.ack_interval;
    let mut rx = XferReceiver::new(cfg, t0);

    for i in [1u32, 2, 5] {
        let (seq, body) = data(i);
        let _ = rx.handle(seq, body, t0);
    }
    rx.set_buffered_ms(1234);

    let events = rx.tick(t0 + interval + Duration::from_millis(1));
    let ack = events.iter().find_map(|e| match e {
        RecvEvent::SendAck { contiguous, highest, buffered_ms } => {
            Some((contiguous.0, highest.0, *buffered_ms))
        }
        _ => None,
    });
    // `highest` must exceed `contiguous`, so loss does not stall the sender.
    assert_eq!(ack, Some((2, 5, 1234)));
}
