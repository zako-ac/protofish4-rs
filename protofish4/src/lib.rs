//! Tokio UDP binding for protofish4.
//!
//! [`Endpoint`] is the sink side: one socket serving many transfers, keyed by
//! request id. [`Sender`] is the tap side: one connected socket per transfer.
//!
//! The ordering that makes this work without a handshake is that a sink arms a
//! request *before* asking HQ to dispatch it, so a tap's first packet always
//! finds a receiver waiting.

pub mod error;
pub mod receiver;
pub mod sender;

pub use error::{Error, Result};
pub use receiver::{ArmedRequest, Endpoint, Frame, Streams};
pub use sender::{random_key, send_all, Sender};

pub use protofish4_proto as proto;
pub use protofish4_proto::config::{RecvMode, ReceiverConfig, SenderConfig};
pub use protofish4_proto::crypto::SessionKey;
pub use protofish4_proto::types::{RelAbortReason, RelOutcome, RequestId, TimestampMs, XferSeq};
