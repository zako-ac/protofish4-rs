//! Sending endpoint: the tap side of one transfer.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use protofish4_proto::codec::{decode_body, encode_body};
use protofish4_proto::config::SenderConfig;
use protofish4_proto::crypto::{self, SessionKey};
use protofish4_proto::frame::Body;
use protofish4_proto::header::Header;
use protofish4_proto::types::{Direction, RequestId, TimestampMs, XferSeq};
use protofish4_proto::xfer::{SendEvent, SendFailure, XferSender};
use tokio::net::{lookup_host, UdpSocket};

use crate::error::{Error, Result};

const TICK: Duration = Duration::from_millis(20);

/// One outbound transfer.
///
/// The socket is connected to the sink, so the tap keeps a single 5-tuple for
/// the life of the transfer. That is what holds its NAT mapping open for the
/// receiver's NACKs — the return path only works because the tap spoke first.
pub struct Sender {
    socket: UdpSocket,
    key: SessionKey,
    request_id: RequestId,
    state: XferSender,
    peer: SocketAddr,
}

impl Sender {
    /// Connect to the first address in `deliver_to` that resolves.
    ///
    /// The list is ordered by preference: during IP transit HQ sends the proxy
    /// address, and afterwards the sink's own, so a tap needs no code change to
    /// follow the cutover.
    pub async fn connect(
        deliver_to: &[String],
        request_id: RequestId,
        key: SessionKey,
        cfg: SenderConfig,
    ) -> Result<Self> {
        for authority in deliver_to {
            let Ok(mut addrs) = lookup_host(authority.as_str()).await else {
                continue;
            };
            let Some(peer) = addrs.next() else { continue };
            let bind: SocketAddr = if peer.is_ipv4() {
                "0.0.0.0:0".parse().expect("valid literal")
            } else {
                "[::]:0".parse().expect("valid literal")
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(peer).await?;
            return Ok(Self {
                socket,
                key,
                request_id,
                state: XferSender::new(cfg),
                peer,
            });
        }
        Err(Error::NoRouteToSink(deliver_to.to_vec()))
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Send one Opus frame, waiting if the send window or the receiver's buffer
    /// says to slow down.
    ///
    /// Blocking here rather than buffering is deliberate: a tap decoding faster
    /// than realtime should be made to wait, not allowed to push a whole track
    /// onto a residential uplink at once.
    pub async fn send_frame(&mut self, ts: TimestampMs, payload: Vec<u8>) -> Result<()> {
        loop {
            if let Some(ev) = self.state.push_frame(ts, payload.clone(), Instant::now()) {
                self.dispatch(vec![ev]).await?;
                return Ok(());
            }
            self.pump_once().await?;
        }
    }

    /// Declare the end of the payload and wait for the receiver to confirm the
    /// tail, answering NACKs throughout.
    pub async fn finish(&mut self) -> Result<()> {
        if let Some(ev) = self.state.finish(Instant::now()) {
            self.dispatch(vec![ev]).await?;
        }
        while !self.state.is_done() {
            self.pump_once().await?;
        }
        Ok(())
    }

    /// One step of the receive-and-tick loop.
    async fn pump_once(&mut self) -> Result<()> {
        let mut buf = [0u8; 2048];
        match tokio::time::timeout(TICK, self.socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                if let Ok((header, plaintext)) =
                    crypto::open(&self.key, &buf[..len], Direction::Recv)
                    && let Ok(body) = decode_body(header.kind, &plaintext)
                {
                    let events = self.state.handle(body, Instant::now());
                    self.dispatch(events).await?;
                }
            }
            Ok(Err(e)) => return Err(Error::Io(e)),
            Err(_) => {}
        }
        let events = self.state.tick(Instant::now());
        self.dispatch(events).await
    }

    async fn dispatch(&mut self, events: Vec<SendEvent>) -> Result<()> {
        for ev in events {
            match ev {
                SendEvent::Emit { seq, body } => {
                    let is_data = matches!(body, Body::Data { .. });
                    let header = Header::new(body.kind(), self.request_id, seq.0);
                    let plaintext = encode_body(&body)?;
                    let sealed =
                        crypto::seal(&self.key, header, Direction::Send, &plaintext)?;
                    self.socket.send(&sealed).await?;
                    // Only payload is retained, and only as the exact bytes
                    // that went out — a retransmission resends these verbatim
                    // rather than encrypting again.
                    if is_data {
                        self.state.record_sealed(seq, sealed);
                    }
                }
                SendEvent::Resend { datagrams } => {
                    for d in datagrams {
                        self.socket.send(&d).await?;
                    }
                }
                SendEvent::Completed => {}
                SendEvent::Failed(SendFailure::NoAck) => return Err(Error::NoAck(self.peer)),
                SendEvent::Failed(SendFailure::FinalizeTimeout) => {
                    return Err(Error::FinalizeTimeout);
                }
            }
        }
        Ok(())
    }
}

/// Convenience for a caller that already has every frame ready.
pub async fn send_all(
    deliver_to: Vec<String>,
    request_id: RequestId,
    key: SessionKey,
    cfg: SenderConfig,
    frames: impl IntoIterator<Item = (TimestampMs, Vec<u8>)>,
) -> Result<()> {
    let mut sender = Sender::connect(&deliver_to, request_id, key, cfg).await?;
    for (ts, payload) in frames {
        sender.send_frame(ts, payload).await?;
    }
    sender.finish().await
}

/// Mint a fresh 32-byte key. Sinks call this; HQ never does.
pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::fill(&mut k);
    k
}

/// The first sequence number a transfer uses.
pub const FIRST_SEQ: XferSeq = XferSeq::FIRST;
