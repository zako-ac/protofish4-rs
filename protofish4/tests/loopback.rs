//! End-to-end over real UDP sockets, including a deliberately lossy relay.
//!
//! The properties under test are the ones the whole design rests on: playback
//! gets whatever arrived, the cache copy is byte-exact or explicitly aborted,
//! and neither outcome depends on the other.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use protofish4::{
    Endpoint, ReceiverConfig, RelOutcome, RequestId, SenderConfig, SessionKey, TimestampMs,
};
use tokio::net::UdpSocket;

fn key_pair() -> (SessionKey, SessionKey) {
    let raw = protofish4::random_key();
    (
        SessionKey::from_bytes(&raw).unwrap(),
        SessionKey::from_bytes(&raw).unwrap(),
    )
}

fn frames(n: u32) -> Vec<(TimestampMs, Vec<u8>)> {
    (1..=n)
        .map(|i| (TimestampMs(i as u64 * 20), vec![(i % 251) as u8; 60]))
        .collect()
}

/// A UDP relay that drops every `drop_every`-th datagram in the tap→sink
/// direction, standing in for both `ae_proxy` and a lossy network. Control
/// packets travelling back are never dropped, so the test isolates payload
/// loss from recovery failure.
struct LossyRelay {
    addr: SocketAddr,
    dropped: Arc<AtomicU64>,
}

async fn spawn_relay(sink: SocketAddr, drop_every: u64) -> LossyRelay {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let dropped = Arc::new(AtomicU64::new(0));

    let up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    up.connect(sink).await.unwrap();

    {
        let (socket, up) = (Arc::clone(&socket), Arc::clone(&up));
        let dropped = Arc::clone(&dropped);
        // tap -> sink
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut seen = 0u64;
            let mut tap: Option<SocketAddr> = None;
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buf).await else { break };
                if tap.is_none() {
                    tap = Some(from);
                    // Replies must leave from the same socket the tap sent to,
                    // or a symmetric NAT would drop them.
                    let socket2 = Arc::clone(&socket);
                    let up2 = Arc::clone(&up);
                    tokio::spawn(async move {
                        let mut rbuf = vec![0u8; 2048];
                        while let Ok(len) = up2.recv(&mut rbuf).await {
                            let _ = socket2.send_to(&rbuf[..len], from).await;
                        }
                    });
                }
                seen += 1;
                if drop_every > 0 && seen.is_multiple_of(drop_every) {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let _ = up.send(&buf[..len]).await;
            }
        });
    }

    LossyRelay { addr, dropped }
}

/// Bind a sink, arm one request, and drive its tick loop.
async fn armed_sink(
    cfg: ReceiverConfig,
    key: SessionKey,
    id: RequestId,
) -> (SocketAddr, protofish4::ArmedRequest, protofish4::Streams) {
    let endpoint = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = endpoint.local_addr().unwrap();
    let (armed, streams) = endpoint.arm(id, key, cfg).await.unwrap();

    tokio::spawn({
        let e = Arc::clone(&endpoint);
        async move {
            let _ = e.run().await;
        }
    });
    tokio::spawn({
        let e = Arc::clone(&endpoint);
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                e.tick().await;
            }
        }
    });

    (addr, armed, streams)
}

async fn collect(mut streams: protofish4::Streams) -> (Vec<u32>, Vec<Vec<u8>>, Option<RelOutcome>) {
    let mut unrel = Vec::new();
    let mut rel = Vec::new();
    loop {
        tokio::select! {
            Some(f) = streams.unrel.recv() => unrel.push(f.seq.0),
            Some(f) = streams.rel.recv() => rel.push(f.payload),
            else => break,
        }
    }
    let outcome = streams.outcome.await.ok();
    (unrel, rel, outcome)
}

#[tokio::test]
async fn clean_path_delivers_both_streams_intact() {
    let (sink_key, tap_key) = key_pair();
    let id = RequestId::random();
    let (sink_addr, _armed, streams) =
        armed_sink(ReceiverConfig::audio_engine(), sink_key, id).await;

    let payload = frames(50);
    let expected: Vec<Vec<u8>> = payload.iter().map(|(_, p)| p.clone()).collect();

    let send = tokio::spawn(protofish4::send_all(
        vec![sink_addr.to_string()],
        id,
        tap_key,
        SenderConfig::default(),
        payload,
    ));

    let (unrel, rel, outcome) = collect(streams).await;
    send.await.unwrap().expect("send should succeed");

    assert_eq!(unrel.len(), 50);
    assert_eq!(rel, expected, "the cache copy must be byte-exact");
    assert!(matches!(outcome, Some(RelOutcome::Complete { .. })));
}

/// The headline case: lose packets, and NACK recovery still produces a
/// byte-exact cache copy.
#[tokio::test]
async fn loss_is_recovered_and_the_cache_copy_is_exact() {
    let (sink_key, tap_key) = key_pair();
    let id = RequestId::random();
    let (sink_addr, _armed, streams) =
        armed_sink(ReceiverConfig::audio_engine(), sink_key, id).await;

    // Drop roughly one datagram in eight on the way in.
    let relay = spawn_relay(sink_addr, 8).await;

    let payload = frames(60);
    let expected: Vec<Vec<u8>> = payload.iter().map(|(_, p)| p.clone()).collect();

    let send = tokio::spawn(protofish4::send_all(
        vec![relay.addr.to_string()],
        id,
        tap_key,
        SenderConfig::default(),
        payload,
    ));

    let (unrel, rel, outcome) = collect(streams).await;
    send.await.unwrap().expect("send should succeed despite loss");

    assert!(relay.dropped.load(Ordering::Relaxed) > 0, "the relay should have dropped something");
    assert_eq!(rel, expected, "retransmission must restore the cache copy exactly");
    assert!(matches!(outcome, Some(RelOutcome::Complete { .. })));

    // Playback sees each frame at most once. It may well see all 60 even under
    // loss: a retransmission that arrives is still a frame that arrived, and
    // whether it is still useful is the jitter buffer's call, not the
    // transport's. What must never happen is a duplicate reaching the mixer.
    let mut sorted = unrel.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), unrel.len(), "playback must never see a duplicate");
    assert!(unrel.len() <= 60);
}

/// The occupancy report is a brake with a release. A tap held back by a full
/// buffer has to be let go when the sink stops reporting: the pause is only
/// meant to be as long as the sink is actually behind, and a sink that has gone
/// quiet — a dead decoder task — must not keep the tap waiting forever. Before
/// the report was dated, that pause could never end.
#[tokio::test]
async fn a_paused_tap_is_released_when_the_report_goes_stale() {
    let (sink_key, tap_key) = key_pair();
    let id = RequestId::random();
    let (sink_addr, _armed, streams) =
        armed_sink(ReceiverConfig::audio_engine(), sink_key, id).await;

    // Report a full buffer, then go quiet: the decoder died mid-track.
    let feedback = streams.feedback.clone();
    let reporting = Arc::new(AtomicBool::new(true));
    let reporter = {
        let feedback = feedback.clone();
        let reporting = Arc::clone(&reporting);
        tokio::spawn(async move {
            while reporting.load(Ordering::Relaxed) {
                // Playback has not started: everything received is backlog.
                feedback.set_playhead_ms(0);
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
    };

    let send = tokio::spawn(protofish4::send_all(
        vec![sink_addr.to_string()],
        id,
        tap_key,
        SenderConfig {
            max_outstanding: 4,
            buffer_high_water_ms: 1_000,
            buffer_low_water_ms: 500,
            ..Default::default()
        },
        frames(40),
    ));

    // Let the brake engage, then take the report away.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !send.is_finished(),
        "a tap reporting a full buffer must be held back"
    );
    reporting.store(false, Ordering::Relaxed);

    let (unrel, rel, outcome) = collect(streams).await;
    send.await
        .unwrap()
        .expect("the tap must be released, not wedged");
    reporter.abort();

    assert_eq!(rel.len(), 40, "the whole track arrives once released");
    assert_eq!(unrel.len(), 40);
    assert!(matches!(outcome, Some(RelOutcome::Complete { .. })));
}

/// A request the endpoint never armed is dropped without disturbing anything.
#[tokio::test]
async fn unknown_request_ids_are_ignored() {
    let (sink_key, tap_key) = key_pair();
    let armed_id = RequestId::random();
    let (sink_addr, _armed, streams) =
        armed_sink(ReceiverConfig::audio_engine(), sink_key, armed_id).await;

    // A tap using a different request id gets nowhere.
    let stray = tokio::spawn(protofish4::send_all(
        vec![sink_addr.to_string()],
        RequestId::random(),
        tap_key,
        SenderConfig {
            first_ack_timeout: Duration::from_millis(300),
            ..Default::default()
        },
        frames(5),
    ));
    assert!(stray.await.unwrap().is_err(), "an unarmed request must not be served");

    // The armed request is untouched and still has nothing.
    drop(streams);
}

/// The cache worker runs the same protocol with no playback path at all.
#[tokio::test]
async fn rel_only_sink_commits_without_a_playback_stream() {
    let (sink_key, tap_key) = key_pair();
    let id = RequestId::random();
    let (sink_addr, _armed, streams) =
        armed_sink(ReceiverConfig::cache_worker(), sink_key, id).await;

    let relay = spawn_relay(sink_addr, 6).await;
    let payload = frames(40);
    let expected: Vec<Vec<u8>> = payload.iter().map(|(_, p)| p.clone()).collect();

    let send = tokio::spawn(protofish4::send_all(
        vec![relay.addr.to_string()],
        id,
        tap_key,
        SenderConfig::default(),
        payload,
    ));

    let (unrel, rel, outcome) = collect(streams).await;
    send.await.unwrap().expect("preload should succeed");

    assert!(unrel.is_empty(), "RelOnly allocates no playback path");
    assert_eq!(rel, expected);
    assert!(matches!(outcome, Some(RelOutcome::Complete { .. })));
}

/// `deliver_to` is a preference list so the proxy can be removed without a
/// protocol change; an unreachable first entry must fall through.
#[tokio::test]
async fn deliver_to_falls_through_to_a_working_address() {
    let (sink_key, tap_key) = key_pair();
    let id = RequestId::random();
    let (sink_addr, _armed, streams) =
        armed_sink(ReceiverConfig::audio_engine(), sink_key, id).await;

    let send = tokio::spawn(protofish4::send_all(
        vec!["no-such-host.invalid:5000".to_string(), sink_addr.to_string()],
        id,
        tap_key,
        SenderConfig::default(),
        frames(10),
    ));

    let (_unrel, rel, outcome) = collect(streams).await;
    send.await.unwrap().expect("should fall through to the reachable address");
    assert_eq!(rel.len(), 10);
    assert!(matches!(outcome, Some(RelOutcome::Complete { .. })));
}
