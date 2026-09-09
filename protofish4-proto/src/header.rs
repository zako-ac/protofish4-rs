use crate::error::{Error, Result};
use crate::frame::PacketKind;
use crate::types::RequestId;

/// Wire version carried in every datagram.
pub const VERSION: u8 = 0x04;

/// Size of the cleartext header, in bytes.
///
/// ```text
/// 0       1       2                                   18            22
/// +-------+-------+-----------------------------------+-------------+
/// |version| kind  |        request_id (16 bytes)      | seq (u32 BE)|
/// +-------+-------+-----------------------------------+-------------+
/// ```
pub const HEADER_LEN: usize = 22;

const REQUEST_ID_OFF: usize = 2;
const SEQ_OFF: usize = 18;

/// The unencrypted prefix of a datagram.
///
/// Everything here is in the clear for a reason. `request_id` lets `ae_proxy`
/// route without holding key material. `seq` and `kind` are what the receiver
/// needs to reconstruct the AEAD nonce, and it cannot decrypt without the nonce
/// — the same chicken-and-egg that DTLS and SRTP resolve the same way.
///
/// The whole header is fed to the AEAD as associated data, so none of it can be
/// altered without failing the tag. The rule that makes that worth anything:
/// **no receiver state changes on any of these fields until the tag verifies.**
/// Before that they are an attacker-supplied routing hint and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: PacketKind,
    pub request_id: RequestId,
    /// For [`PacketKind::Data`] this is the transfer sequence number; for every
    /// other kind it is that direction's control counter.
    pub seq: u32,
}

impl Header {
    pub fn new(kind: PacketKind, request_id: RequestId, seq: u32) -> Self {
        Self { kind, request_id, seq }
    }

    /// Parse the header, returning it with the remaining (still sealed) bytes.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated { need: HEADER_LEN, got: buf.len() });
        }
        if buf[0] != VERSION {
            return Err(Error::UnsupportedVersion(buf[0]));
        }
        let kind = PacketKind::from_u8(buf[1])?;
        let mut id = [0u8; RequestId::LEN];
        id.copy_from_slice(&buf[REQUEST_ID_OFF..SEQ_OFF]);
        let seq = u32::from_be_bytes(buf[SEQ_OFF..HEADER_LEN].try_into().expect("len checked"));
        Ok((
            Self { kind, request_id: RequestId::from_bytes(id), seq },
            &buf[HEADER_LEN..],
        ))
    }

    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = VERSION;
        out[1] = self.kind as u8;
        out[REQUEST_ID_OFF..SEQ_OFF].copy_from_slice(&self.request_id.to_bytes());
        out[SEQ_OFF..HEADER_LEN].copy_from_slice(&self.seq.to_be_bytes());
        out
    }

    /// Read just the request id, for a relay that only needs to route.
    ///
    /// Tolerates kinds it does not recognise, so `ae_proxy` keeps forwarding
    /// correctly after new kinds are added and never needs redeploying in step
    /// with the endpoints.
    pub fn peek_request_id(buf: &[u8]) -> Result<RequestId> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated { need: HEADER_LEN, got: buf.len() });
        }
        if buf[0] != VERSION {
            return Err(Error::UnsupportedVersion(buf[0]));
        }
        let mut id = [0u8; RequestId::LEN];
        id.copy_from_slice(&buf[REQUEST_ID_OFF..SEQ_OFF]);
        Ok(RequestId::from_bytes(id))
    }
}
