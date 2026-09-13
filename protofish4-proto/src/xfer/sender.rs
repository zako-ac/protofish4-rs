use std::time::Instant;

use crate::config::SenderConfig;
use crate::frame::Body;
use crate::types::{TimestampMs, XferSeq};

use super::retrans::RetransRing;

/// What the sender wants done. The caller seals and transmits; this type owns
/// no socket and no clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendEvent {
    /// Seal this body under `seq` and send it. The caller must hand the sealed
    /// bytes straight back via [`XferSender::record_sealed`], because those
    /// exact bytes are what a retransmission resends.
    Emit { seq: XferSeq, body: Body },
    /// Resend these previously sealed datagrams verbatim. Never re-seal them.
    Resend { datagrams: Vec<Vec<u8>> },
    /// The receiver has everything; the transfer is done.
    Completed,
    /// Give up. Nothing further will be sent.
    Failed(SendFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    /// No `Ack` ever came back. Either nothing is listening or the return path
    /// is broken — the check that replaces an `Open`/`OpenAck` handshake.
    NoAck,
    /// `EndAck` never arrived.
    FinalizeTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Sending payload.
    Streaming,
    /// `End` sent, waiting for `EndAck` while still answering NACKs.
    Finalizing,
    Done,
}

/// Sending half of one transfer.
#[derive(Debug)]
pub struct XferSender {
    cfg: SenderConfig,
    ring: RetransRing,
    state: State,

    next_seq: XferSeq,
    /// Counter for control packets. Independent of `next_seq`: `class` in the
    /// nonce already separates the two spaces, so each just needs to be
    /// monotonic within itself.
    control_counter: u32,
    /// Highest sequence the receiver admits to having seen.
    acked_highest: u32,
    /// The receiver's reported buffer occupancy, in milliseconds.
    buffered_ms: u16,
    /// True while occupancy sits above the high-water mark. Hysteresis, so a
    /// receiver hovering at the threshold does not thrash.
    paused: bool,

    first_data_at: Option<Instant>,
    got_ack: bool,
    finalize_at: Option<Instant>,
    last_keepalive_at: Option<Instant>,
}

impl XferSender {
    pub fn new(cfg: SenderConfig) -> Self {
        let ring = RetransRing::new(cfg.retrans_ring_frames, cfg.retrans_ring_bytes);
        Self {
            cfg,
            ring,
            state: State::Streaming,
            next_seq: XferSeq::FIRST,
            control_counter: 0,
            acked_highest: 0,
            buffered_ms: 0,
            paused: false,
            first_data_at: None,
            got_ack: false,
            finalize_at: None,
            last_keepalive_at: None,
        }
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Whether another payload frame may be sent right now.
    ///
    /// Two independent brakes: the outstanding-frame window, which stops a tap
    /// that ignores wall-clock pacing from bursting a whole track onto the
    /// wire, and the receiver's reported buffer occupancy.
    pub fn can_send(&self) -> bool {
        if self.state != State::Streaming || self.paused {
            return false;
        }
        let outstanding = self.next_seq.0.saturating_sub(1).saturating_sub(self.acked_highest);
        outstanding < self.cfg.max_outstanding
    }

    /// Queue one Opus frame. Returns `None` if the window is closed — the
    /// caller should wait rather than buffer, since the whole point is to make
    /// the tap produce no faster than the receiver consumes.
    pub fn push_frame(&mut self, ts: TimestampMs, payload: Vec<u8>, now: Instant) -> Option<SendEvent> {
        if !self.can_send() {
            return None;
        }
        let seq = self.next_seq;
        self.next_seq = seq.next();
        if self.first_data_at.is_none() {
            self.first_data_at = Some(now);
        }
        Some(SendEvent::Emit { seq, body: Body::Data { ts, payload } })
    }

    /// Hand back the sealed bytes for a previously emitted frame.
    ///
    /// This is the only way into the retransmission ring, and it takes
    /// ciphertext rather than a frame precisely so that resending can never
    /// re-encrypt under an already-used nonce.
    pub fn record_sealed(&mut self, seq: XferSeq, datagram: Vec<u8>) {
        self.ring.push(seq, datagram);
    }

    /// Signal end of payload.
    pub fn finish(&mut self, now: Instant) -> Option<SendEvent> {
        if self.state != State::Streaming {
            return None;
        }
        self.state = State::Finalizing;
        self.finalize_at = Some(now);
        self.last_keepalive_at = Some(now);
        let final_seq = XferSeq(self.next_seq.0.saturating_sub(1));
        Some(SendEvent::Emit { seq: self.control_seq(), body: Body::End { final_seq } })
    }

    /// Feed an authenticated packet from the receiver.
    pub fn handle(&mut self, body: Body, _now: Instant) -> Vec<SendEvent> {
        let mut out = Vec::new();
        match body {
            Body::Ack { contiguous, highest, buffered_ms } => {
                self.got_ack = true;
                self.ring.ack_through(contiguous);
                if highest.0 > self.acked_highest {
                    self.acked_highest = highest.0;
                }
                self.buffered_ms = buffered_ms;
                if buffered_ms >= self.cfg.buffer_high_water_ms {
                    self.paused = true;
                } else if buffered_ms <= self.cfg.buffer_low_water_ms {
                    self.paused = false;
                }
            }
            Body::Nack { missing } => {
                self.got_ack = true;
                let datagrams: Vec<Vec<u8>> = missing
                    .iter()
                    .filter_map(|seq| self.ring.get(*seq).map(|d| d.to_vec()))
                    .collect();
                if !datagrams.is_empty() {
                    out.push(SendEvent::Resend { datagrams });
                }
            }
            Body::EndAck => {
                self.state = State::Done;
                out.push(SendEvent::Completed);
            }
            Body::Data { .. } | Body::End { .. } | Body::Keepalive { .. } => {}
        }
        out
    }

    /// Drive timers.
    pub fn tick(&mut self, now: Instant) -> Vec<SendEvent> {
        let mut out = Vec::new();
        if self.state == State::Done {
            return out;
        }

        // Nothing ever acknowledged us: the receiver is gone, or the return
        // path through the proxy and the tap's NAT is broken.
        if !self.got_ack
            && let Some(first) = self.first_data_at
            && now.duration_since(first) > self.cfg.first_ack_timeout
        {
            self.state = State::Done;
            out.push(SendEvent::Failed(SendFailure::NoAck));
            return out;
        }

        // A sender held back by the receiver's buffer report has nothing to
        // send either, and the receiver cannot tell that silence from a tap
        // that died: its idle timeout fires, the transfer aborts with
        // `PeerGone`, and from then on nothing acknowledges the tap — so the
        // pause becomes permanent. A keepalive says "still here, still
        // holding"; the receiver records it as liveness and nothing else.
        if self.state == State::Streaming && self.paused {
            let due = match self.last_keepalive_at {
                Some(last) => now.duration_since(last) >= self.cfg.tail_keepalive_interval,
                None => true,
            };
            if due {
                self.last_keepalive_at = Some(now);
                out.push(SendEvent::Emit {
                    seq: self.control_seq(),
                    body: Body::Keepalive { lost_below: self.ring.lost_below() },
                });
            }
        }

        if self.state == State::Finalizing {
            if let Some(started) = self.finalize_at
                && now.duration_since(started) > self.cfg.finalize_timeout
            {
                self.state = State::Done;
                out.push(SendEvent::Failed(SendFailure::FinalizeTimeout));
                return out;
            }
            // Between End and EndAck the sender has nothing to say, but going
            // quiet lets the NAT mapping lapse and the receiver's NACKs for the
            // tail would never arrive.
            if let Some(last) = self.last_keepalive_at
                && now.duration_since(last) >= self.cfg.tail_keepalive_interval
            {
                self.last_keepalive_at = Some(now);
                out.push(SendEvent::Emit {
                    seq: self.control_seq(),
                    body: Body::Keepalive { lost_below: self.ring.lost_below() },
                });
            }
        }

        out
    }

    fn control_seq(&mut self) -> XferSeq {
        self.control_counter = self.control_counter.wrapping_add(1);
        XferSeq(self.control_counter)
    }
}
