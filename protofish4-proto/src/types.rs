pub use uuid::Uuid;

/// Identifies one transfer.
///
/// Travels in the clear so `ae_proxy` can route a datagram without holding key
/// material, which makes it three things at once: a routing key, the audio
/// engine's demultiplexing key, and the proxy's source-pinning key. All three
/// want it unguessable and collision-free across independent minters, so it is a
/// v4 UUID rather than a counter — 128 random bits are not sprayable, and any
/// number of HQ replicas can mint without coordinating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub Uuid);

impl RequestId {
    pub const LEN: usize = 16;

    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        *self.0.as_bytes()
    }

    pub fn from_bytes(b: [u8; Self::LEN]) -> Self {
        Self(Uuid::from_bytes(b))
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Position of a payload frame within a transfer. Starts at 1.
///
/// Unlike protofish3, this rides in the *cleartext* header: the receiver needs
/// it to derive the AEAD nonce before it can decrypt anything, so it cannot live
/// in the body. It is covered by the authentication tag as associated data, so
/// it still cannot be tampered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XferSeq(pub u32);

impl XferSeq {
    pub const FIRST: Self = Self(1);

    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Monotonic counter for control packets, kept per direction.
///
/// Control packets need their own counter space rather than borrowing
/// [`XferSeq`]: a `Data` packet and an `Ack` must never derive the same nonce.
/// It also drives the replay window, which is what stops a captured `Nack` from
/// being replayed later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlSeq(pub u32);

impl ControlSeq {
    pub const FIRST: Self = Self(0);

    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// Playback timestamp of a payload frame, in milliseconds from the start of the
/// transfer. protofish3 carried no timestamp and every caller hand-rolled an
/// 8-byte prefix; here it is part of the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampMs(pub u64);

/// Which end a packet came from.
///
/// Both directions share one key, so this byte goes into the nonce to keep their
/// counter spaces apart. It is a property of the role, never read off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Tap to audio engine: payload, plus `End` and `Keepalive`.
    Send,
    /// Audio engine to tap: `Ack`, `Nack`, `EndAck`.
    Recv,
}

impl Direction {
    pub fn to_u8(self) -> u8 {
        match self {
            Direction::Send => 0x00,
            Direction::Recv => 0x01,
        }
    }

    pub fn peer(self) -> Self {
        match self {
            Direction::Send => Direction::Recv,
            Direction::Recv => Direction::Send,
        }
    }
}

/// Nonce counter space. Separates payload from control within one direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeqClass {
    Data,
    Control,
}

impl SeqClass {
    pub fn to_u8(self) -> u8 {
        match self {
            SeqClass::Data => 0x00,
            SeqClass::Control => 0x01,
        }
    }
}

/// How a reliable (cache-bound) stream ended.
///
/// Made explicit rather than inferred from a signal that never arrives: today
/// `bridge_rel` distinguishes "clean end" from "tap vanished" only by whether a
/// oneshot fired, which is correct but easy to break silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelOutcome {
    /// Every frame up to `final_seq` arrived. Safe to commit to the cache.
    Complete { final_seq: XferSeq },
    /// Gave up. The cache entry must be aborted; playback is unaffected.
    Aborted(RelAbortReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelAbortReason {
    /// A gap outlived its NACK retry budget.
    UnrecoverableGap,
    /// The reorder buffer hit its byte or frame budget.
    BufferExhausted,
    /// The contiguous prefix stopped advancing while packets were still arriving.
    Stalled,
    /// The sender said the frames are gone from its retransmission ring.
    SenderDiscarded,
    /// The transfer ended before `End` arrived.
    PeerGone,
    /// The audio engine declined to buffer this stream at all.
    NotAttempted,
}
