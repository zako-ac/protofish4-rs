//! Receiving endpoint: one UDP socket, many concurrent transfers.
//!
//! A sink — an audio engine or the cache worker — binds one of these and then
//! [`arms`](Endpoint::arm) a request *before* it asks HQ to dispatch anything.
//! That ordering is the whole reason there is no handshake: by the time a tap
//! could possibly send a packet, the entry it demultiplexes to already exists.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use protofish4_proto::codec::{decode_body, encode_body};
use protofish4_proto::config::ReceiverConfig;
use protofish4_proto::crypto::{self, SessionKey};
use protofish4_proto::frame::Body;
use protofish4_proto::header::Header;
use protofish4_proto::types::{
    ControlSeq, Direction, RelOutcome, RequestId, TimestampMs, XferSeq,
};
use protofish4_proto::xfer::{RecvEvent, XferReceiver};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::error::{Error, Result};

/// A payload frame delivered to the application.
#[derive(Debug, Clone)]
pub struct Frame {
    pub seq: XferSeq,
    pub ts: TimestampMs,
    pub payload: Vec<u8>,
}

/// The two views of one transfer.
///
/// `unrel` is empty in [`protofish4_proto::config::RecvMode::RelOnly`]. `rel`
/// ends with an explicit [`RelOutcome`] rather than by simply stopping, so a
/// truncated stream can never be mistaken for a complete one.
pub struct Streams {
    pub unrel: mpsc::Receiver<Frame>,
    pub rel: mpsc::Receiver<Frame>,
    pub outcome: tokio::sync::oneshot::Receiver<RelOutcome>,
}

struct Entry {
    key: SessionKey,
    state: XferReceiver,
    /// Learned from the first datagram and then fixed, so a later packet
    /// claiming the same request id cannot redirect our replies.
    peer: Option<SocketAddr>,
    control_seq: ControlSeq,
    unrel_tx: mpsc::Sender<Frame>,
    rel_tx: mpsc::Sender<Frame>,
    outcome_tx: Option<tokio::sync::oneshot::Sender<RelOutcome>>,
}

/// A bound UDP socket serving any number of transfers.
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    entries: Arc<Mutex<HashMap<RequestId, Entry>>>,
}

impl Endpoint {
    pub async fn bind(addr: SocketAddr) -> Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        Ok(Arc::new(Self {
            socket,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Register a request and start collecting for it.
    ///
    /// Call this *before* handing the ticket to HQ. The returned
    /// [`ArmedRequest`] disarms on drop, so a dispatch that fails cannot leak a
    /// demultiplexing slot.
    pub async fn arm(
        self: &Arc<Self>,
        request_id: RequestId,
        key: SessionKey,
        cfg: ReceiverConfig,
    ) -> Result<(ArmedRequest, Streams)> {
        let (unrel_tx, unrel) = mpsc::channel(256);
        let (rel_tx, rel) = mpsc::channel(256);
        let (outcome_tx, outcome) = tokio::sync::oneshot::channel();

        let mut entries = self.entries.lock().await;
        if entries.contains_key(&request_id) {
            return Err(Error::DuplicateRequest(request_id));
        }
        entries.insert(
            request_id,
            Entry {
                key,
                state: XferReceiver::new(cfg, Instant::now()),
                peer: None,
                control_seq: ControlSeq::FIRST,
                unrel_tx,
                rel_tx,
                outcome_tx: Some(outcome_tx),
            },
        );
        drop(entries);

        Ok((
            ArmedRequest { endpoint: Arc::clone(self), request_id },
            Streams { unrel, rel, outcome },
        ))
    }

    async fn disarm(&self, request_id: RequestId) {
        self.entries.lock().await.remove(&request_id);
    }

    /// Read datagrams until the socket fails. Spawn this once per endpoint.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut buf = vec![0u8; 2048];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            self.on_datagram(&buf[..len], from).await;
        }
    }

    async fn on_datagram(&self, datagram: &[u8], from: SocketAddr) {
        // Routing only. Nothing here is trusted until the tag verifies.
        let Ok(request_id) = crypto::request_id_of(datagram) else {
            return;
        };

        let mut entries = self.entries.lock().await;
        let Some(entry) = entries.get_mut(&request_id) else {
            // An unknown request id is the expected shape of a stray or
            // spoofed packet, so it is dropped without ceremony.
            return;
        };

        let Ok((header, plaintext)) = crypto::open(&entry.key, datagram, Direction::Send) else {
            return;
        };
        let Ok(body) = decode_body(header.kind, &plaintext) else {
            return;
        };

        // Only now, past the tag, is the source address worth believing.
        if entry.peer.is_none() {
            entry.peer = Some(from);
        }

        let now = Instant::now();
        let events = entry.state.handle(XferSeq(header.seq), body, now);
        let replies = Self::apply(entry, request_id, events).await;
        let peer = entry.peer;
        let finished = entry.state.is_closed();
        drop(entries);

        if let Some(peer) = peer {
            for reply in replies {
                let _ = self.socket.send_to(&reply, peer).await;
            }
        }
        if finished {
            self.disarm(request_id).await;
        }
    }

    /// Drive timers for every live transfer. Call on an interval.
    pub async fn tick(&self) {
        let now = Instant::now();
        let mut outbound: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
        let mut done: Vec<RequestId> = Vec::new();

        let mut entries = self.entries.lock().await;
        let ids: Vec<RequestId> = entries.keys().copied().collect();
        for id in ids {
            let Some(entry) = entries.get_mut(&id) else { continue };
            let events = entry.state.tick(now);
            let replies = Self::apply(entry, id, events).await;
            if let Some(peer) = entry.peer {
                outbound.extend(replies.into_iter().map(|r| (r, peer)));
            }
            if entry.state.is_closed() {
                done.push(id);
            }
        }
        for id in &done {
            entries.remove(id);
        }
        drop(entries);

        for (datagram, peer) in outbound {
            let _ = self.socket.send_to(&datagram, peer).await;
        }
    }

    /// Turn state-machine events into datagrams and channel sends.
    async fn apply(entry: &mut Entry, id: RequestId, events: Vec<RecvEvent>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for ev in events {
            match ev {
                RecvEvent::Unreliable(f) => {
                    // Playback must never be held up by a slow consumer; a full
                    // channel means the listener is behind and the frame is
                    // already stale.
                    let _ = entry.unrel_tx.try_send(Frame {
                        seq: f.seq,
                        ts: f.ts,
                        payload: f.payload,
                    });
                }
                RecvEvent::Reliable(f) => {
                    if entry
                        .rel_tx
                        .send(Frame { seq: f.seq, ts: f.ts, payload: f.payload })
                        .await
                        .is_err()
                    {
                        // The cache side hung up; nothing to do but stop.
                    }
                }
                RecvEvent::SendNack { missing } => {
                    if let Some(d) = entry.seal(id, Body::Nack { missing }) {
                        out.push(d);
                    }
                }
                RecvEvent::SendAck { contiguous, highest, buffered_ms } => {
                    if let Some(d) =
                        entry.seal(id, Body::Ack { contiguous, highest, buffered_ms })
                    {
                        out.push(d);
                    }
                }
                RecvEvent::SendEndAck => {
                    if let Some(d) = entry.seal(id, Body::EndAck) {
                        out.push(d);
                    }
                }
                RecvEvent::RelFinished(outcome) => {
                    if let Some(tx) = entry.outcome_tx.take() {
                        let _ = tx.send(outcome);
                    }
                }
                RecvEvent::Closed => {}
            }
        }
        out
    }
}

impl Entry {
    fn seal(&mut self, id: RequestId, body: Body) -> Option<Vec<u8>> {
        let seq = self.control_seq;
        self.control_seq = seq.next();
        let header = Header::new(body.kind(), id, seq.0);
        let plaintext = encode_body(&body).ok()?;
        crypto::seal(&self.key, header, Direction::Recv, &plaintext).ok()
    }
}

/// Holds a request's slot on the endpoint. Dropping it disarms the request.
pub struct ArmedRequest {
    endpoint: Arc<Endpoint>,
    request_id: RequestId,
}

impl ArmedRequest {
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }
}

impl Drop for ArmedRequest {
    fn drop(&mut self) {
        let endpoint = Arc::clone(&self.endpoint);
        let id = self.request_id;
        tokio::spawn(async move { endpoint.disarm(id).await });
    }
}
