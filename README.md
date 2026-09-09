# Protofish 4

A minimal UDP transport that moves one audio transfer from a **tap** to a **sink**, and gives the sink two views of it at once:

- an **unreliable** stream, yielding frames the moment they arrive, for playback;
- a **reliable** stream, recovered by retransmission, for the cache.

That dual tee is the only reason this protocol exists. Everything protofish3 did beyond it — QUIC, TLS, connection and channel multiplexing, keepalive, reconnection — is gone, because in Zako4 a WebSocket to HQ carries the control plane and protofish4 carries only audio.

A "sink" is an audio engine (playback, with a cache tee) or the cache worker (preload, reliable only). The protocol does not know which.

## Model

One transfer per `request_id`. No connections, no channels, no multiplexed transfers over a shared handshake. A sink binds one socket and demultiplexes by `request_id`; a tap opens one connected socket per transfer.

There is **no handshake**. The sink mints `request_id` and the encryption key and arms itself *before* asking HQ to dispatch, so a tap's first packet always finds a receiver waiting. A handshake could not have fixed that race anyway: a receiver that does not hold the key cannot authenticate an opening packet either.

## Datagram layout

```
 0       1       2                                      18            22
 +-------+-------+--------------------------------------+-------------+
 |version| kind  |         request_id (16 bytes)        | seq (u32 BE)|
 +-------+-------+--------------------------------------+-------------+
 |                    ciphertext (variable)                           |
 +--------------------------------------------------------------------+
 |                  Poly1305 tag (16 bytes)                           |
 +--------------------------------------------------------------------+
```

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | `version` | `0x04` |
| 1 | 1 | `kind` | see below |
| 2 | 16 | `request_id` | UUID v4, raw bytes |
| 18 | 4 | `seq` | `XferSeq` for `Data`, else that direction's control counter |
| 22 | var | ciphertext + tag | ChaCha20-Poly1305 |

The 22-byte header is cleartext **and** is passed to the AEAD as associated data, so it is readable by a relay but not alterable by anyone.

`request_id` is in the clear so `ae_proxy` can route without holding key material. `seq` is in the clear because the receiver needs it to derive the nonce before it can decrypt — the same chicken-and-egg DTLS and SRTP resolve the same way.

> **Rule for implementers:** take no state action on any cleartext field until the tag verifies. Before that point they are an attacker-supplied routing hint and nothing more.

## Packet kinds

| `kind` | Name | Direction | Body |
| --- | --- | --- | --- |
| `0x00` | `Data` | tap → sink | `ts_ms u64 BE`, then the Opus packet (rest of datagram) |
| `0x01` | `End` | tap → sink | `final_seq u32 BE` |
| `0x02` | `EndAck` | sink → tap | *(empty)* |
| `0x03` | `Ack` | sink → tap | `contiguous u32 BE`, `highest u32 BE`, `buffered_ms u16 BE` |
| `0x04` | `Nack` | sink → tap | `count u16 BE`, then `count` × `u32 BE` |
| `0x05` | `Keepalive` | tap → sink | `lost_below u32 BE` |

Bodies are fixed-layout big-endian with no length prefix on the trailing payload: a datagram is self-delimiting, so the Opus frame is simply "the rest".

`XferSeq` starts at **1**.

### Why only six

- **No `Retrans`.** A batched retransmission would have to be re-encrypted, and encrypting different plaintext under an already-used nonce leaks the Poly1305 key. Retransmission here is a **verbatim resend of the sealed `Data` datagram**. The retransmission ring stores ciphertext and offers no way to insert a plaintext frame, so this is structural rather than a rule to remember.
- **No `Open`/`OpenAck`.** See *Model*.
- **No `CreditUpdate`.** `Ack` reports the receiver's real buffer occupancy, which the sender can actually reason about; an opaque credit count was only ever approximating it.
- **No `Close`.** It was the only forgeable-and-replayable primitive with teeth. Termination lives on the WebSocket, which is authenticated and reliable. UDP ends via `End`/`EndAck` or a timeout.

## Encryption

One 32-byte key per transfer, minted by the sink from a CSPRNG and delivered to the tap by HQ over an authenticated channel. The key's job is **anti-injection and integrity**, not secrecy — it is audio the user asked for out loud. That ordering is why the replay window matters more than hiding the header.

Nonce, 12 bytes, derived and never transmitted:

```
 0       1       2               4                              12
 +-------+-------+---------------+------------------------------+
 |  dir  | class |  epoch (u16)  |       counter (u64 BE)       |
 +-------+-------+---------------+------------------------------+
```

- `dir` — `0x00` tap→sink, `0x01` sink→tap. Mandatory: both directions share one key.
- `class` — `0x00` payload, `0x01` control. Keeps a `Data` and an `Ack` with the same counter apart.
- `epoch` — reserved for rekeying, currently `0`.
- `counter` — the zero-extended `seq`. A u32 payload counter is ~2.7 years of 20 ms frames, so it cannot wrap in practice.

A retransmission deliberately reproduces the same nonce, because it reproduces the same plaintext byte for byte. That is a replay of one message, not two messages under one nonce, and is safe. It is only safe because sealing happens exactly once per `seq` — see the note on `Retrans` above.

### Replay

Control packets are checked against a 1024-entry sliding window per direction; a repeated or too-old counter is dropped. `Data` is deduplicated by `XferSeq` instead, since a legitimate retransmission is a byte-identical resend that a strict window would reject.

## Flow control

Two brakes, because a tap decoding faster than realtime will otherwise push a whole track onto a residential uplink at once — roughly 4 MB in a couple of seconds for a five-minute track:

1. **Wall-clock pacing** in the tap SDK: send frame *i* at `t0 + i×20ms`, with a few seconds of lead so playback still starts promptly.
2. **A receiver-enforced window**, because a third-party tap can ignore (1). At most `max_outstanding` frames beyond `Ack.highest`. Using `highest` rather than `contiguous` means one lost frame does not stall the sender behind its own gap.

`Ack.buffered_ms` reports how much audio the receiver is holding; the tap pauses above a high-water mark and resumes below a low one.

## Recovery, and giving up

The reliable stream is **allowed to fail**, and failing must be cheap. With residential taps it will happen routinely, and the cost must always be "no cached copy" — never "no audio", never unbounded memory.

- A gap is NACKed up to `max_nack_attempts` times with a configured backoff.
- The reliable stream is abandoned on: an exhausted NACK budget, a contiguous prefix that has not advanced within `rel_stall_timeout` *while packets keep arriving*, a reorder span beyond `reorder_window`, a buffer past `max_reorder_bytes`, or a `Keepalive` whose `lost_below` shows the frames are gone from the sender's ring.
- On abandonment the whole reorder buffer is released and NACKing stops. The unreliable stream is untouched.
- The reliable stream always terminates with an explicit `RelOutcome::Complete { final_seq }` or `RelOutcome::Aborted(reason)` — never by merely stopping, so a truncated stream can never be mistaken for a complete one.

`Keepalive.lost_below` lets a sender volunteer that frames have fallen out of its ring, so the receiver gives up in one round trip instead of spending its entire budget discovering it.

### Two very different sinks

Every bound is configuration, because the sinks want opposite things:

| | Audio engine | Cache worker |
| --- | --- | --- |
| Mode | `Dual` | `RelOnly` |
| Deadline | playback is live; fail fast | none; nobody is waiting |
| NACK budget | 3, tens of ms | 12, up to seconds |
| Reorder window | 1024 frames | 65536 frames |
| A rel abort means | degradation — audio continues | the request failed |

## NAT and relaying

Control packets travel back over the same 5-tuple. The tap sent first, so its NAT mapping is open. Two consequences for a relay such as `ae_proxy`:

- **Reply from the exact socket and source port the tap sent to.** A symmetric NAT keys the mapping on `(tap_src, relay_dst)`; replying from a different socket means every NACK is silently dropped.
- **Learn the tap's source address once and pin it**, so a guessed `request_id` cannot redirect a stream's control traffic.

While streaming, a tap sends ~50 packets/sec and never idles. After `End` it goes quiet while the sink may still be recovering the tail, so it sends `Keepalive` every few seconds until `EndAck`.

## Crates

- `protofish4-proto` — sans-IO: framing, AEAD, replay window, gap tracking, retransmission ring, and the sender/receiver state machines. No tokio, no sockets.
- `protofish4` — tokio binding: `Endpoint` (sink, many transfers on one socket) and `Sender` (tap, one connected socket per transfer).

## Status

Implemented and tested: framing and codec, sealing with derived nonces, the replay window, gap tracking, the retransmission ring, both state machines, and the tokio binding. 38 tests, including end-to-end transfers over real sockets through a deliberately lossy relay.
