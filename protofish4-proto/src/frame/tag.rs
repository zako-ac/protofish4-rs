use crate::error::{Error, Result};
use crate::types::{Direction, SeqClass};

/// Packet kind.
///
/// Six kinds, deliberately. protofish3 needed ten-plus because it multiplexed
/// many transfers over one long-lived connection; protofish4 carries exactly one
/// transfer per request id and can drop the machinery that went with that.
///
/// Three kinds that an earlier draft had are gone on purpose:
///
/// * `Open`/`OpenAck` — a handshake cannot fix the arm-before-first-packet race,
///   because a receiver that lacks the key cannot authenticate `Open` either. It
///   only bought an extra internet round trip before the first audio byte. The
///   receiver keeps a small orphan buffer instead.
/// * `Retrans` — a batched retransmission has to be re-encrypted, which is the
///   one way to reuse a nonce with different plaintext. Retransmission here is a
///   verbatim resend of the already-sealed `Data` datagram, so nonce safety is
///   structural rather than a rule someone has to remember.
/// * `CreditUpdate` — [`PacketKind::Ack`] carries the receiver's actual buffer
///   occupancy, which is strictly more useful than an opaque credit count.
/// * `Close` — the only forgeable-and-replayable primitive with real teeth.
///   Termination belongs on the WebSocket, which is already authenticated and
///   reliable. UDP ends via `End`/`EndAck` or a timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketKind {
    /// One Opus frame. `seq` in the header is its [`crate::types::XferSeq`].
    Data = 0x00,
    /// No more payload. Carries the final sequence number so the receiver knows
    /// the tail arrived instead of inferring it from a silent socket.
    End = 0x01,
    /// Every frame up to the declared final sequence number arrived.
    EndAck = 0x02,
    /// Delivery report: drains the retransmission ring, gates the send window,
    /// and reports buffer occupancy.
    Ack = 0x03,
    /// These sequence numbers are missing.
    Nack = 0x04,
    /// Keeps the tap's NAT mapping open while it has nothing to send. Needed
    /// after `End`, when the receiver may still be recovering the tail and the
    /// tap would otherwise go silent long enough for the mapping to lapse.
    Keepalive = 0x05,
}

impl PacketKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x00 => PacketKind::Data,
            0x01 => PacketKind::End,
            0x02 => PacketKind::EndAck,
            0x03 => PacketKind::Ack,
            0x04 => PacketKind::Nack,
            0x05 => PacketKind::Keepalive,
            other => return Err(Error::UnknownKind(other)),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            PacketKind::Data => "Data",
            PacketKind::End => "End",
            PacketKind::EndAck => "EndAck",
            PacketKind::Ack => "Ack",
            PacketKind::Nack => "Nack",
            PacketKind::Keepalive => "Keepalive",
        }
    }

    /// The direction this kind only ever travels in. Checked after decryption,
    /// never before.
    pub fn direction(self) -> Direction {
        match self {
            PacketKind::Data | PacketKind::End | PacketKind::Keepalive => Direction::Send,
            PacketKind::EndAck | PacketKind::Ack | PacketKind::Nack => Direction::Recv,
        }
    }

    /// Which nonce counter space this kind draws from.
    pub fn seq_class(self) -> SeqClass {
        match self {
            PacketKind::Data => SeqClass::Data,
            _ => SeqClass::Control,
        }
    }
}
