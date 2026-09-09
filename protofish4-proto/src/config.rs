//! Tunable limits.
//!
//! Every bound is a field rather than a constant because the two sinks want
//! very different numbers. An audio engine is racing a playback deadline and
//! must give up on the reliable stream quickly; the cache worker has nobody
//! waiting and should be patient, because for it a reliable-stream abort is not
//! a degradation but the whole request failing.

use std::time::Duration;

/// What a receiver wants out of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvMode {
    /// Both outputs: frames on arrival for playback, and a gap-free copy for
    /// the cache.
    Dual,
    /// Reliable only. Nothing is yielded until it is in order, and no jitter
    /// buffer is allocated. What the cache worker uses.
    RelOnly,
}

impl RecvMode {
    pub fn wants_unrel(self) -> bool {
        matches!(self, RecvMode::Dual)
    }
}

#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    pub mode: RecvMode,

    /// How far past the contiguous prefix a frame may sit before the reliable
    /// stream gives up. Frames beyond it are dropped, which is safe in
    /// [`RecvMode::Dual`] because playback already received them.
    pub reorder_window: u32,

    /// Byte ceiling on frames held for reordering.
    pub max_reorder_bytes: usize,

    /// How many times one gap is asked for before it is declared lost.
    pub max_nack_attempts: u8,

    /// Backoff between NACKs for the same gap. The last entry repeats if
    /// `max_nack_attempts` exceeds its length.
    pub nack_backoff: Vec<Duration>,

    /// Give up on the reliable stream if its contiguous prefix has not advanced
    /// in this long *while packets are still arriving*. Distinguishes "the peer
    /// is gone" (handled by `idle_timeout`) from "the peer is alive but the gap
    /// will never fill".
    pub rel_stall_timeout: Duration,

    /// Give up on the transfer entirely after this long with no packet at all.
    pub idle_timeout: Duration,

    /// Send an `Ack` at least this often while data is flowing, so the sender
    /// can drain its retransmission ring even across a quiet stretch.
    pub ack_interval: Duration,
}

impl ReceiverConfig {
    /// Bounds for a live playback sink: fail the reliable stream fast and keep
    /// the audio going.
    pub fn audio_engine() -> Self {
        Self {
            mode: RecvMode::Dual,
            reorder_window: 1024,
            max_reorder_bytes: 1024 * 1024,
            max_nack_attempts: 3,
            nack_backoff: vec![
                Duration::from_millis(30),
                Duration::from_millis(100),
                Duration::from_millis(300),
            ],
            rel_stall_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(15),
            ack_interval: Duration::from_millis(200),
        }
    }

    /// Bounds for a cache fill: nobody is listening, so trade latency for a
    /// materially higher chance of a complete copy.
    pub fn cache_worker() -> Self {
        Self {
            mode: RecvMode::RelOnly,
            reorder_window: 65_536,
            max_reorder_bytes: 32 * 1024 * 1024,
            max_nack_attempts: 12,
            nack_backoff: vec![
                Duration::from_millis(50),
                Duration::from_millis(200),
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
            ],
            rel_stall_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(30),
            ack_interval: Duration::from_millis(500),
        }
    }

    pub fn nack_delay(&self, attempt: u8) -> Duration {
        let i = (attempt as usize).min(self.nack_backoff.len().saturating_sub(1));
        self.nack_backoff.get(i).copied().unwrap_or(Duration::from_millis(100))
    }
}

#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Sealed datagrams kept for retransmission, dropped as `Ack.contiguous`
    /// advances.
    pub retrans_ring_frames: usize,

    /// Byte ceiling on the same ring.
    pub retrans_ring_bytes: usize,

    /// Frames that may be outstanding beyond `Ack.highest`. Enforces pacing on
    /// a tap that ignores the wall-clock pacing the SDK asks for.
    pub max_outstanding: u32,

    /// Stop sending when the receiver reports at least this much buffered.
    pub buffer_high_water_ms: u16,

    /// Resume once it drains below this.
    pub buffer_low_water_ms: u16,

    /// Give up if no `Ack` arrives this long after the first `Data`. Replaces
    /// the path validation an `Open`/`OpenAck` handshake would have done, at no
    /// latency cost.
    pub first_ack_timeout: Duration,

    /// Keepalive cadence between `End` and `EndAck`, while the sender has
    /// nothing to send but must keep its NAT mapping open for NACKs.
    pub tail_keepalive_interval: Duration,

    /// Give up waiting for `EndAck` after this.
    pub finalize_timeout: Duration,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            retrans_ring_frames: 1024,
            retrans_ring_bytes: 1024 * 1024,
            max_outstanding: 512,
            buffer_high_water_ms: 10_000,
            buffer_low_water_ms: 5_000,
            first_ack_timeout: Duration::from_secs(2),
            tail_keepalive_interval: Duration::from_secs(5),
            finalize_timeout: Duration::from_secs(30),
        }
    }
}
