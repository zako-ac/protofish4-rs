//! Receiving endpoint: one UDP socket, many concurrent transfers.
//!
//! A sink — an audio engine or the cache worker — binds one of these and then
//! [`arms`](Endpoint::arm) a request *before* it asks HQ to dispatch anything.
//! That ordering is the whole reason there is no handshake: by the time a tap
//! could possibly send a packet, the entry it demultiplexes to already exists.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
    /// Where the sink reports how much audio it is holding.
    ///
    /// The receiving state machine knows which sequence numbers arrived; it has
    /// no idea how far behind playback is running, and that is the number the
    /// sender's high/low-water brake acts on. See [`BufferFeedback`].
    pub feedback: BufferFeedback,
}

/// Where playback has reached, as told to [`Endpoint`].
///
/// The occupancy reported in [`Body::Ack`] is what paces a tap: the sender
/// pauses above `buffer_high_water_ms` and resumes below `buffer_low_water_ms`.
/// A sink cannot measure that itself — the frames it would have to count are
/// spread across queues it does not own, in this endpoint as much as in the
/// application — so it reports the one thing only it knows, the timestamp it is
/// playing, and the endpoint subtracts that from the newest frame it has
/// received. Everything unplayed is then accounted for, wherever it waits.
///
/// A report is a measurement of a moving target, so it is also dated: see
/// [`BufferFeedback::fresh_playhead_ms`].
#[derive(Clone, Debug)]
pub struct BufferFeedback {
    inner: Arc<FeedbackInner>,
}

#[derive(Debug)]
struct FeedbackInner {
    playhead_ms: AtomicU64,
    /// When `playhead_ms` was last written, in milliseconds since `epoch`.
    written_at_ms: AtomicU64,
    epoch: Instant,
}

impl Default for BufferFeedback {
    fn default() -> Self {
        Self {
            inner: Arc::new(FeedbackInner {
                playhead_ms: AtomicU64::new(0),
                written_at_ms: AtomicU64::new(0),
                epoch: Instant::now(),
            }),
        }
    }
}

impl BufferFeedback {
    /// Report the timestamp playback has reached, in milliseconds.
    pub fn set_playhead_ms(&self, ms: u64) {
        self.inner.playhead_ms.store(ms, Ordering::Relaxed);
        let elapsed = self.inner.epoch.elapsed().as_millis() as u64;
        self.inner.written_at_ms.store(elapsed, Ordering::Relaxed);
    }

    /// The last play head reported, whether or not it is still current.
    pub fn playhead_ms(&self) -> u64 {
        self.inner.playhead_ms.load(Ordering::Relaxed)
    }

    /// The play head reported, if it was reported within `ttl`.
    ///
    /// The sender's only way out of a pause is a later, lower occupancy, so a
    /// sink that stops reporting — a decoder task that died, a stream that was
    /// never really playing — would hold the tap back forever. That is worse
    /// than it sounds: a paused tap sends nothing, so the receiver's idle
    /// timeout reads the silence as a dead peer, aborts the transfer, and stops
    /// acknowledging the sender entirely. Dating the report bounds any pause to
    /// `ttl` plus an ack interval, because an unrenewed report is treated as no
    /// report at all.
    pub fn fresh_playhead_ms(&self, now: Instant, ttl: Duration) -> Option<u64> {
        let written = Duration::from_millis(self.inner.written_at_ms.load(Ordering::Relaxed));
        let reported_at = self.inner.epoch + written;
        if now.duration_since(reported_at) > ttl {
            return None;
        }
        Some(self.inner.playhead_ms.load(Ordering::Relaxed))
    }
}

/// How long a sink's report stays actionable before it is treated as absent.
///
/// The audio engine renews it on every frame it plays, twenty milliseconds
/// apart, so a sink that is genuinely backed up never goes stale; one that has
/// stopped reporting is released within a couple of seconds, far inside the
/// fifteen-second idle timeout that would otherwise abort the transfer.
pub const BUFFER_REPORT_TTL: Duration = Duration::from_secs(2);

/// How often a transport that has to discard playback frames may say so.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(5);

/// The occupancy to put in an acknowledgement.
///
/// What the sink has left to play is everything that arrived and has not been
/// played: the newest frame this endpoint has received, minus the play head the
/// sink reported. Measuring it here rather than in the sink is what makes the
/// number cover frames queued in this endpoint as well as in the application —
/// a sink counting only what it had dequeued would top out at its own pipeline
/// and never reach the sender's water marks.
///
/// The state machine's value is the fallback for a sink that has never reported
/// or has gone quiet, so the field is never simply discarded.
fn ack_buffered_ms(
    feedback: &BufferFeedback,
    state_ms: u16,
    newest_data_ms: u64,
    now: Instant,
) -> u16 {
    match feedback.fresh_playhead_ms(now, BUFFER_REPORT_TTL) {
        Some(playhead) => newest_data_ms.saturating_sub(playhead).min(u16::MAX as u64) as u16,
        None => state_ms,
    }
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
    /// The sink's play head, as handed out in [`Streams::feedback`].
    feedback: BufferFeedback,
    /// Timestamp of the newest playback frame this endpoint has received.
    ///
    /// A maximum rather than a latest: the unreliable stream reorders, and a
    /// late arrival must not make the sender look further ahead than it is.
    newest_data_ms: u64,
    /// Playback frames the transport had to discard because the sink was not
    /// draining fast enough. Uncounted, such a drop is invisible: the sender is
    /// never told and the application never sees the frame.
    dropped_unrel: u64,
    last_drop_warn: Option<Instant>,
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
        let feedback = BufferFeedback::default();

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
                feedback: feedback.clone(),
                newest_data_ms: 0,
                dropped_unrel: 0,
                last_drop_warn: None,
            },
        );
        drop(entries);

        Ok((
            ArmedRequest { endpoint: Arc::clone(self), request_id },
            Streams { unrel, rel, outcome, feedback },
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
                    entry.newest_data_ms = entry.newest_data_ms.max(f.ts.0);
                    // Playback must never be held up by a slow consumer; a full
                    // channel means the listener is behind and the frame is
                    // already stale.
                    if entry
                        .unrel_tx
                        .try_send(Frame {
                            seq: f.seq,
                            ts: f.ts,
                            payload: f.payload,
                        })
                        .is_err()
                    {
                        entry.dropped_unrel += 1;
                        let now = Instant::now();
                        if entry
                            .last_drop_warn
                            .is_none_or(|last| now.duration_since(last) >= DROP_WARN_INTERVAL)
                        {
                            entry.last_drop_warn = Some(now);
                            tracing::warn!(
                                dropped = entry.dropped_unrel,
                                "playback frame dropped: the sink is not draining the transport"
                            );
                        }
                    }
                }
                RecvEvent::Reliable(f) => {
                    entry.newest_data_ms = entry.newest_data_ms.max(f.ts.0);
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
                    // The occupancy comes from the sink, not from the state
                    // machine: without it every acknowledgement would claim an
                    // empty buffer and the sender would never slow down.
                    let buffered_ms = ack_buffered_ms(
                        &entry.feedback,
                        buffered_ms,
                        entry.newest_data_ms,
                        Instant::now(),
                    );
                    if let Some(d) = entry.seal(
                        id,
                        Body::Ack { contiguous, highest, buffered_ms },
                    ) {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use protofish4_proto::codec::decode_body;
    use protofish4_proto::crypto;
    use protofish4_proto::types::Direction;

    use super::*;

    /// The sink's occupancy report is what paces the sender, so it has to reach
    /// the wire: an acknowledgement sealed while the sink reports a full buffer
    /// must carry that number, not the state machine's placeholder zero.
    #[tokio::test]
    async fn an_ack_carries_the_buffered_ms_the_sink_reported() {
        let key = SessionKey::from_bytes(&crate::random_key()).unwrap();
        let endpoint = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let id = RequestId::random();
        let cfg = ReceiverConfig::audio_engine();
        let ack_interval = cfg.ack_interval;

        let (_armed, streams) = endpoint.arm(id, key.clone(), cfg).await.unwrap();
        // Playback has reached 1 s; the frame that arrives is timestamped 5.32 s.
        streams.feedback.set_playhead_ms(1_000);

        let now = Instant::now();
        let mut entries = endpoint.entries.lock().await;
        let entry = entries.get_mut(&id).expect("the request was armed");
        // The arrival has to be applied, not merely handled: recording the
        // newest timestamp is the endpoint's job, and the occupancy is measured
        // against it.
        let mut events = entry.state.handle(
            XferSeq(1),
            Body::Data { ts: TimestampMs(5_320), payload: vec![7; 40] },
            now,
        );

        // Past the ack interval, so the receiver has something to acknowledge.
        events.extend(entry.state.tick(now + ack_interval + Duration::from_millis(1)));
        let datagrams = Endpoint::apply(entry, id, events).await;
        drop(entries);

        let datagram = datagrams.first().expect("an ack was sealed");
        let (header, plaintext) = crypto::open(&key, datagram, Direction::Recv).expect("opens");
        match decode_body(header.kind, &plaintext).expect("decodes") {
            Body::Ack { buffered_ms, .. } => assert_eq!(buffered_ms, 4_320),
            other => panic!("expected an ack, got {other:?}"),
        }
    }

    /// The occupancy is what arrived but has not been played, measured against
    /// the sink's play head.
    #[test]
    fn a_fresh_play_head_is_what_goes_on_the_wire() {
        let feedback = BufferFeedback::default();
        feedback.set_playhead_ms(1_000);
        assert_eq!(ack_buffered_ms(&feedback, 999, 5_321, Instant::now()), 4_321);
    }

    /// The field is sixteen bits wide; a long backlog must not wrap.
    #[test]
    fn an_over_range_backlog_is_clamped_to_the_wire_limit() {
        let feedback = BufferFeedback::default();
        feedback.set_playhead_ms(0);
        assert_eq!(
            ack_buffered_ms(&feedback, 0, u64::MAX, Instant::now()),
            u16::MAX
        );
    }

    /// An unrenewed report stops counting, so a sender cannot be held back
    /// forever by a sink that has gone quiet — the difference between a pause
    /// and a wedge.
    #[test]
    fn a_stale_report_falls_back_to_the_state_machines_value() {
        let feedback = BufferFeedback::default();
        feedback.set_playhead_ms(0);
        let now = Instant::now();
        assert_eq!(ack_buffered_ms(&feedback, 1234, 60_000, now), 60_000);

        let later = now + BUFFER_REPORT_TTL + Duration::from_millis(1);
        assert_eq!(ack_buffered_ms(&feedback, 1234, 60_000, later), 1234);
    }
}
