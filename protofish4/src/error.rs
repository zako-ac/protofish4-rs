use std::net::SocketAddr;

use protofish4_proto::types::RequestId;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Proto(#[from] protofish4_proto::Error),

    #[error("no address in deliver_to resolved: {0:?}")]
    NoRouteToSink(Vec<String>),

    #[error("request {0} is already registered on this endpoint")]
    DuplicateRequest(RequestId),

    #[error("the endpoint was shut down")]
    EndpointClosed,

    #[error("no acknowledgement from {0} within the first-packet deadline")]
    NoAck(SocketAddr),

    #[error("timed out waiting for the receiver to confirm the tail")]
    FinalizeTimeout,

    #[error("the peer stopped responding")]
    PeerGone,
}

pub type Result<T> = std::result::Result<T, Error>;
