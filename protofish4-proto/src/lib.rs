//! Sans-IO core of protofish4.
//!
//! protofish4 moves one audio transfer from a tap to an audio engine over plain
//! UDP, giving the receiver two views of it at once: an unreliable stream that
//! yields frames the moment they arrive, for playback, and a reliable stream
//! recovered by retransmission, for the cache. That dual tee is the only reason
//! this protocol exists; everything protofish3 did beyond it — QUIC, TLS,
//! connection and channel multiplexing, keepalive and reconnection — is gone,
//! because a WebSocket to HQ now carries the control plane.
//!
//! Nothing here touches a socket. The tokio binding lives in the `protofish4`
//! crate.

pub mod codec;
pub mod config;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod header;
pub mod types;
pub mod xfer;

pub use error::{Error, Result};
pub use frame::{Body, PacketKind};
pub use header::{Header, HEADER_LEN, VERSION};
pub use config::{RecvMode, ReceiverConfig, SenderConfig};
pub use types::{
    ControlSeq, Direction, RelAbortReason, RelOutcome, RequestId, SeqClass, TimestampMs, XferSeq,
};
pub use xfer::{Frame, RecvEvent, SendEvent, SendFailure, XferReceiver, XferSender};
