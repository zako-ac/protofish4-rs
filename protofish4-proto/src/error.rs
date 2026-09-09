use crate::types::{RequestId, XferSeq};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("datagram too short: need at least {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },

    #[error("unsupported protocol version {0:#04x}")]
    UnsupportedVersion(u8),

    #[error("unknown packet kind {0:#04x}")]
    UnknownKind(u8),

    #[error("packet body malformed for kind {kind}: {reason}")]
    MalformedBody { kind: &'static str, reason: &'static str },

    #[error("trailing bytes after packet body for kind {0}")]
    TrailingBytes(&'static str),

    #[error("authentication failed for request {0:?}")]
    DecryptFailed(RequestId),

    #[error("replayed or too-old packet seq {0}")]
    Replay(u32),

    #[error("encryption key must be 32 bytes, got {0}")]
    BadKeyLength(usize),

    #[error("payload of {got} bytes exceeds the {max}-byte limit")]
    PayloadTooLarge { got: usize, max: usize },

    #[error("retransmission buffer full at {0} frames")]
    RetransBufferFull(usize),

    #[error("reorder buffer budget exhausted at {bytes} bytes / {frames} frames")]
    ReorderBudgetExhausted { bytes: usize, frames: usize },

    #[error("no send credit available")]
    NoCredit,

    #[error("frame {0} is not valid in the current transfer state")]
    UnexpectedFrame(&'static str),

    #[error("received {0} travelling in the wrong direction")]
    WrongDirection(&'static str),

    #[error("sender declared final seq {declared:?} but had already sent {sent:?}")]
    BadFinalSeq { declared: XferSeq, sent: XferSeq },
}

pub type Result<T> = std::result::Result<T, Error>;
