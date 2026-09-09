//! Serialisation of packet bodies.
//!
//! Bodies are fixed-layout big-endian, with no length prefix on the trailing
//! payload: a datagram is self-delimiting, so the Opus frame is simply "the
//! rest". protofish3 spent a `VarInt` on that length for no gain.

use crate::error::{Error, Result};
use crate::frame::{Body, PacketKind};
use crate::types::{TimestampMs, XferSeq};

/// Largest Opus payload accepted in one `Data` packet.
///
/// A 20 ms stereo frame is 240-320 bytes; this leaves generous headroom while
/// keeping a sealed datagram inside a 1200-byte safe MTU.
pub const MAX_PAYLOAD: usize = 1024;

/// Most sequence numbers one `Nack` may carry, so a single packet stays inside
/// the MTU.
pub const MAX_NACK_ENTRIES: usize = 128;

pub fn encode_body(body: &Body) -> Result<Vec<u8>> {
    Ok(match body {
        Body::Data { ts, payload } => {
            if payload.len() > MAX_PAYLOAD {
                return Err(Error::PayloadTooLarge { got: payload.len(), max: MAX_PAYLOAD });
            }
            let mut out = Vec::with_capacity(8 + payload.len());
            out.extend_from_slice(&ts.0.to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        Body::End { final_seq } => final_seq.0.to_be_bytes().to_vec(),
        Body::EndAck => Vec::new(),
        Body::Ack { contiguous, highest, buffered_ms } => {
            let mut out = Vec::with_capacity(10);
            out.extend_from_slice(&contiguous.0.to_be_bytes());
            out.extend_from_slice(&highest.0.to_be_bytes());
            out.extend_from_slice(&buffered_ms.to_be_bytes());
            out
        }
        Body::Nack { missing } => {
            if missing.len() > MAX_NACK_ENTRIES {
                return Err(Error::PayloadTooLarge {
                    got: missing.len(),
                    max: MAX_NACK_ENTRIES,
                });
            }
            let mut out = Vec::with_capacity(2 + missing.len() * 4);
            out.extend_from_slice(&(missing.len() as u16).to_be_bytes());
            for seq in missing {
                out.extend_from_slice(&seq.0.to_be_bytes());
            }
            out
        }
        Body::Keepalive { lost_below } => lost_below.0.to_be_bytes().to_vec(),
    })
}

pub fn decode_body(kind: PacketKind, buf: &[u8]) -> Result<Body> {
    let name = kind.name();
    Ok(match kind {
        PacketKind::Data => {
            let ts = TimestampMs(take_u64(buf, 0, name)?);
            let payload = &buf[8..];
            if payload.len() > MAX_PAYLOAD {
                return Err(Error::PayloadTooLarge { got: payload.len(), max: MAX_PAYLOAD });
            }
            Body::Data { ts, payload: payload.to_vec() }
        }
        PacketKind::End => {
            expect_len(buf, 4, name)?;
            Body::End { final_seq: XferSeq(take_u32(buf, 0, name)?) }
        }
        PacketKind::EndAck => {
            expect_len(buf, 0, name)?;
            Body::EndAck
        }
        PacketKind::Ack => {
            expect_len(buf, 10, name)?;
            Body::Ack {
                contiguous: XferSeq(take_u32(buf, 0, name)?),
                highest: XferSeq(take_u32(buf, 4, name)?),
                buffered_ms: take_u16(buf, 8, name)?,
            }
        }
        PacketKind::Nack => {
            let count = take_u16(buf, 0, name)? as usize;
            if count > MAX_NACK_ENTRIES {
                return Err(Error::PayloadTooLarge { got: count, max: MAX_NACK_ENTRIES });
            }
            expect_len(buf, 2 + count * 4, name)?;
            let missing = (0..count)
                .map(|i| Ok(XferSeq(take_u32(buf, 2 + i * 4, name)?)))
                .collect::<Result<Vec<_>>>()?;
            Body::Nack { missing }
        }
        PacketKind::Keepalive => {
            expect_len(buf, 4, name)?;
            Body::Keepalive { lost_below: XferSeq(take_u32(buf, 0, name)?) }
        }
    })
}

fn expect_len(buf: &[u8], want: usize, kind: &'static str) -> Result<()> {
    match buf.len().cmp(&want) {
        std::cmp::Ordering::Less => {
            Err(Error::MalformedBody { kind, reason: "body shorter than the fixed layout" })
        }
        std::cmp::Ordering::Greater => Err(Error::TrailingBytes(kind)),
        std::cmp::Ordering::Equal => Ok(()),
    }
}

fn take_u16(buf: &[u8], at: usize, kind: &'static str) -> Result<u16> {
    buf.get(at..at + 2)
        .map(|b| u16::from_be_bytes(b.try_into().expect("len checked")))
        .ok_or(Error::MalformedBody { kind, reason: "truncated u16" })
}

fn take_u32(buf: &[u8], at: usize, kind: &'static str) -> Result<u32> {
    buf.get(at..at + 4)
        .map(|b| u32::from_be_bytes(b.try_into().expect("len checked")))
        .ok_or(Error::MalformedBody { kind, reason: "truncated u32" })
}

fn take_u64(buf: &[u8], at: usize, kind: &'static str) -> Result<u64> {
    buf.get(at..at + 8)
        .map(|b| u64::from_be_bytes(b.try_into().expect("len checked")))
        .ok_or(Error::MalformedBody { kind, reason: "truncated u64" })
}
