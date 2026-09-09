use std::collections::VecDeque;

use crate::types::XferSeq;

/// Sealed datagrams held for retransmission.
///
/// The ring stores **already-encrypted bytes**, and there is deliberately no
/// way to put a plaintext frame in. Re-sealing a frame for a retransmission
/// would mean encrypting different bytes under a nonce that has already been
/// used, which leaks the Poly1305 key — so the type simply does not offer that
/// operation. A retransmission is a byte-identical resend and nothing else.
#[derive(Debug)]
pub struct RetransRing {
    entries: VecDeque<(XferSeq, Vec<u8>)>,
    bytes: usize,
    max_frames: usize,
    max_bytes: usize,
    /// Highest sequence number that has fallen out of the ring. Reported to the
    /// receiver so it can abandon the reliable stream in one round trip instead
    /// of spending its whole NACK budget on frames that no longer exist.
    lost_below: u32,
}

impl RetransRing {
    pub fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_frames: max_frames.max(1),
            max_bytes: max_bytes.max(1),
            lost_below: 0,
        }
    }

    /// Store a sealed datagram, evicting the oldest entries to stay in budget.
    pub fn push(&mut self, seq: XferSeq, sealed: Vec<u8>) {
        self.bytes += sealed.len();
        self.entries.push_back((seq, sealed));
        while self.entries.len() > self.max_frames || self.bytes > self.max_bytes {
            if self.evict_oldest().is_none() {
                break;
            }
        }
    }

    /// The exact bytes previously sent for `seq`, if still held.
    pub fn get(&self, seq: XferSeq) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(s, _)| *s == seq)
            .map(|(_, d)| d.as_slice())
    }

    /// Drop everything the receiver has confirmed.
    pub fn ack_through(&mut self, contiguous: XferSeq) {
        while let Some((seq, _)) = self.entries.front() {
            if seq.0 > contiguous.0 {
                break;
            }
            self.evict_oldest();
        }
        // Acked frames are gone by agreement, not by overflow, so they must not
        // be reported as lost.
        if self.lost_below < contiguous.0 {
            self.lost_below = contiguous.0;
        }
    }

    /// Frames below this are gone and will never be retransmitted.
    pub fn lost_below(&self) -> XferSeq {
        XferSeq(self.lost_below)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn evict_oldest(&mut self) -> Option<XferSeq> {
        let (seq, data) = self.entries.pop_front()?;
        self.bytes -= data.len();
        if self.lost_below < seq.0 {
            self.lost_below = seq.0;
        }
        Some(seq)
    }
}
