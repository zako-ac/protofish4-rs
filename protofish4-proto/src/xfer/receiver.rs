use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::config::ReceiverConfig;
use crate::frame::Body;
use crate::types::{RelAbortReason, RelOutcome, TimestampMs, XferSeq};

use super::gap_tracker::GapTracker;

/// A payload frame handed up to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub seq: XferSeq,
    pub ts: TimestampMs,
    pub payload: Vec<u8>,
}

/// What the receiver wants done after a step. The caller owns all I/O and
/// timers; this type never touches either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecvEvent {
    /// Play this now. Out of order and with gaps — only emitted in
    /// [`crate::config::RecvMode::Dual`].
    Unreliable(Frame),
    /// In order and gap-free. Safe to write to the cache.
    Reliable(Frame),
    /// Ask the sender for these.
    SendNack { missing: Vec<XferSeq> },
    /// Report progress, drain the sender's ring and drive its send window.
    SendAck { contiguous: XferSeq, highest: XferSeq, buffered_ms: u16 },
    /// Confirm the tail arrived.
    SendEndAck,
    /// The reliable stream is finished, one way or the other. Commit on
    /// `Complete`, abort on `Aborted`.
    RelFinished(RelOutcome),
    /// The transfer is over; the caller may release everything.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelState {
    Streaming,
    /// Released or aborted; keep serving the unreliable side but stop tracking
    /// gaps and stop holding memory.
    Finished,
}

/// Receiving half of one transfer.
///
/// Sans-IO: it is fed decrypted bodies and a clock, and returns events. The
/// same type serves an audio engine and the cache worker; the difference is
/// entirely in [`ReceiverConfig`].
#[derive(Debug)]
pub struct XferReceiver {
    cfg: ReceiverConfig,
    gaps: GapTracker,
    /// Frames above the contiguous prefix, held until the gap below them fills.
    reorder: BTreeMap<u32, Frame>,
    reorder_bytes: usize,
    rel_state: RelState,
    rel_released: u32,

    final_seq: Option<XferSeq>,
    end_acked: bool,
    closed: bool,

    /// Per-gap NACK bookkeeping: how many times asked, and when last asked.
    nacks: BTreeMap<u32, (u8, Instant)>,
    /// Highest sequence the sender says it can no longer retransmit.
    sender_lost_below: u32,

    last_packet_at: Instant,
    last_ack_at: Instant,
    last_rel_progress_at: Instant,
    /// Milliseconds of audio currently held, reported back in `Ack`.
    buffered_ms: u64,
}

impl XferReceiver {
    pub fn new(cfg: ReceiverConfig, now: Instant) -> Self {
        Self {
            cfg,
            gaps: GapTracker::new(),
            reorder: BTreeMap::new(),
            reorder_bytes: 0,
            rel_state: RelState::Streaming,
            rel_released: 0,
            final_seq: None,
            end_acked: false,
            closed: false,
            nacks: BTreeMap::new(),
            sender_lost_below: 0,
            last_packet_at: now,
            last_ack_at: now,
            last_rel_progress_at: now,
            buffered_ms: 0,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Report how much audio is buffered, so `Ack.buffered_ms` can pace the
    /// sender. The audio engine passes its jitter-buffer occupancy; the cache
    /// worker passes staged bytes converted to a duration.
    pub fn set_buffered_ms(&mut self, ms: u64) {
        self.buffered_ms = ms;
    }

    /// Feed one authenticated packet body.
    pub fn handle(&mut self, seq: XferSeq, body: Body, now: Instant) -> Vec<RecvEvent> {
        self.last_packet_at = now;
        let mut out = Vec::new();

        match body {
            Body::Data { ts, payload } => {
                self.on_data(Frame { seq, ts, payload }, now, &mut out);
            }
            Body::End { final_seq } => {
                self.final_seq = Some(final_seq);
                self.check_finish(now, &mut out);
            }
            Body::Keepalive { lost_below } => {
                if lost_below.0 > self.sender_lost_below {
                    self.sender_lost_below = lost_below.0;
                    // The sender has told us these are gone; there is no point
                    // spending the rest of the NACK budget discovering that.
                    if self.rel_state == RelState::Streaming
                        && self.gaps.contiguous().0 < self.sender_lost_below
                    {
                        self.finish_rel(
                            RelOutcome::Aborted(RelAbortReason::SenderDiscarded),
                            &mut out,
                        );
                    }
                }
                self.check_finish(now, &mut out);
            }
            // A sink receives no acknowledgements; direction is enforced before
            // decryption, so reaching here means a peer sent something absurd.
            Body::Ack { .. } | Body::Nack { .. } | Body::EndAck => {}
        }

        self.maybe_ack(now, &mut out);
        out
    }

    /// Drive timers. Call periodically; it is what emits NACK retries and
    /// notices stalls.
    pub fn tick(&mut self, now: Instant) -> Vec<RecvEvent> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }

        if now.duration_since(self.last_packet_at) > self.cfg.idle_timeout {
            if self.rel_state == RelState::Streaming {
                self.finish_rel(RelOutcome::Aborted(RelAbortReason::PeerGone), &mut out);
            }
            self.closed = true;
            out.push(RecvEvent::Closed);
            return out;
        }

        if self.rel_state == RelState::Streaming {
            // A prefix that will not advance while packets keep arriving is a
            // gap that is never going to fill.
            if now.duration_since(self.last_rel_progress_at) > self.cfg.rel_stall_timeout {
                self.finish_rel(RelOutcome::Aborted(RelAbortReason::Stalled), &mut out);
            } else {
                self.emit_nacks(now, &mut out);
            }
        }

        self.maybe_ack(now, &mut out);
        out
    }

    fn on_data(&mut self, frame: Frame, now: Instant, out: &mut Vec<RecvEvent>) {
        let fresh = self.gaps.record(frame.seq);

        // Playback wants every frame the moment it lands, including ones the
        // reliable side has already given up on.
        if fresh && self.cfg.mode.wants_unrel() {
            out.push(RecvEvent::Unreliable(frame.clone()));
        }

        if self.rel_state != RelState::Streaming {
            return;
        }
        if !fresh {
            // A duplicate or a retransmission of something already released.
            return;
        }

        // Refusing to buffer beyond the window is what bounds memory. It is
        // safe because playback, if there is any, already has the frame.
        if self.gaps.window_span() > self.cfg.reorder_window {
            self.finish_rel(RelOutcome::Aborted(RelAbortReason::BufferExhausted), out);
            return;
        }

        self.reorder_bytes += frame.payload.len();
        self.reorder.insert(frame.seq.0, frame);

        if self.reorder_bytes > self.cfg.max_reorder_bytes {
            self.finish_rel(RelOutcome::Aborted(RelAbortReason::BufferExhausted), out);
            return;
        }

        self.release_contiguous(now, out);
        self.check_finish(now, out);
    }

    fn release_contiguous(&mut self, now: Instant, out: &mut Vec<RecvEvent>) {
        let contiguous = self.gaps.contiguous().0;
        let mut released = false;
        while self.rel_released < contiguous {
            let next = self.rel_released + 1;
            let Some(frame) = self.reorder.remove(&next) else {
                break;
            };
            self.reorder_bytes -= frame.payload.len();
            self.rel_released = next;
            self.nacks.remove(&next);
            out.push(RecvEvent::Reliable(frame));
            released = true;
        }
        if released {
            self.last_rel_progress_at = now;
        }
    }

    fn emit_nacks(&mut self, now: Instant, out: &mut Vec<RecvEvent>) {
        let missing = self.gaps.missing(crate::codec::MAX_NACK_ENTRIES);
        if missing.is_empty() {
            return;
        }

        let mut ask = Vec::new();
        let mut exhausted = false;

        for seq in missing {
            if seq.0 <= self.sender_lost_below {
                exhausted = true;
                break;
            }
            let entry = self.nacks.entry(seq.0).or_insert((0, now - Duration::from_secs(3600)));
            if entry.0 >= self.cfg.max_nack_attempts {
                exhausted = true;
                break;
            }
            if now.duration_since(entry.1) >= self.cfg.nack_delay(entry.0) {
                entry.0 += 1;
                entry.1 = now;
                ask.push(seq);
            }
        }

        if exhausted {
            self.finish_rel(RelOutcome::Aborted(RelAbortReason::UnrecoverableGap), out);
            return;
        }
        if !ask.is_empty() {
            out.push(RecvEvent::SendNack { missing: ask });
        }
    }

    fn check_finish(&mut self, now: Instant, out: &mut Vec<RecvEvent>) {
        let Some(final_seq) = self.final_seq else {
            return;
        };

        if self.rel_state == RelState::Streaming && self.gaps.is_complete(final_seq) {
            self.release_contiguous(now, out);
            self.finish_rel(RelOutcome::Complete { final_seq }, out);
        }

        // Acknowledge the tail whenever the whole transfer has landed, so the
        // sender can stop keepaliving and let go.
        if !self.end_acked && self.gaps.is_complete(final_seq) {
            self.end_acked = true;
            out.push(RecvEvent::SendEndAck);
        }

        if self.end_acked && !self.closed {
            self.closed = true;
            out.push(RecvEvent::Closed);
        }
    }

    fn finish_rel(&mut self, outcome: RelOutcome, out: &mut Vec<RecvEvent>) {
        if self.rel_state == RelState::Finished {
            return;
        }
        self.rel_state = RelState::Finished;
        // Releasing the buffer here is the point: an abandoned reliable stream
        // must cost nothing to keep around.
        self.reorder.clear();
        self.reorder_bytes = 0;
        self.nacks.clear();
        self.gaps.abandon();
        out.push(RecvEvent::RelFinished(outcome));
    }

    fn maybe_ack(&mut self, now: Instant, out: &mut Vec<RecvEvent>) {
        if self.closed {
            return;
        }
        if now.duration_since(self.last_ack_at) < self.cfg.ack_interval {
            return;
        }
        if self.gaps.highest().0 == 0 {
            return;
        }
        self.last_ack_at = now;
        out.push(RecvEvent::SendAck {
            contiguous: self.gaps.contiguous(),
            highest: self.gaps.highest(),
            buffered_ms: self.buffered_ms.min(u16::MAX as u64) as u16,
        });
    }
}
