pub mod tag;

pub use tag::PacketKind;

use crate::types::{TimestampMs, XferSeq};

/// The decrypted body of a packet.
///
/// The sequence number is *not* here — it rides in the cleartext header, because
/// the receiver needs it to derive the nonce before it can decrypt this. See
/// [`crate::header::Header`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// One Opus frame, to be played at `ts`.
    Data { ts: TimestampMs, payload: Vec<u8> },

    /// No more payload will be produced.
    End { final_seq: XferSeq },

    /// Everything up to the final sequence number arrived.
    EndAck,

    /// The receiver's view of the transfer, in one packet.
    ///
    /// Replaces protofish3's separate `Ack` and `XferCreditUpdate`. Reporting
    /// occupancy in milliseconds rather than opaque credits means the sender can
    /// actually reason about it: "the receiver holds 9 seconds of audio" is
    /// actionable in a way that "you have 47 credits" is not.
    Ack {
        /// Everything up to and including this arrived; the sender may drop that
        /// much of its retransmission ring.
        contiguous: XferSeq,
        /// The highest sequence number seen at all. Gates the send window, so
        /// loss on the unreliable path does not stall the sender.
        highest: XferSeq,
        /// How much audio the receiver is currently holding, in milliseconds.
        /// The sender pauses above a high-water mark and resumes below a low one.
        buffered_ms: u16,
    },

    /// These sequence numbers are missing.
    Nack { missing: Vec<XferSeq> },

    /// Nothing to say; keeps the NAT mapping alive.
    ///
    /// `lost_below` lets the sender volunteer that frames have already fallen
    /// out of its retransmission ring, so the receiver can give up on the
    /// reliable stream in one round trip instead of burning its whole NACK
    /// retry budget waiting for frames that will never come.
    Keepalive { lost_below: XferSeq },
}

impl Body {
    pub fn kind(&self) -> PacketKind {
        match self {
            Body::Data { .. } => PacketKind::Data,
            Body::End { .. } => PacketKind::End,
            Body::EndAck => PacketKind::EndAck,
            Body::Ack { .. } => PacketKind::Ack,
            Body::Nack { .. } => PacketKind::Nack,
            Body::Keepalive { .. } => PacketKind::Keepalive,
        }
    }
}
