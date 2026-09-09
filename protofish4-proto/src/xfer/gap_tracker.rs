use std::collections::BTreeSet;

use crate::types::XferSeq;

/// Tracks which transfer sequence numbers have arrived.
///
/// Keeps a contiguous prefix plus a set of everything above it. The prefix is
/// what the reliable stream may release and what `Ack.contiguous` reports; the
/// set is the reorder buffer's index.
#[derive(Debug)]
pub struct GapTracker {
    /// Everything up to and including this has arrived. Zero means nothing yet,
    /// since sequence numbers start at 1.
    contiguous: u32,
    /// Arrived, but above the prefix.
    ahead: BTreeSet<u32>,
    /// Highest sequence number seen at all.
    highest: u32,
}

impl Default for GapTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl GapTracker {
    pub fn new() -> Self {
        Self { contiguous: 0, ahead: BTreeSet::new(), highest: 0 }
    }

    /// Record an arrival. Returns `false` if it was a duplicate or already
    /// below the prefix — the caller uses that to drop retransmissions it no
    /// longer needs without treating them as an error.
    pub fn record(&mut self, seq: XferSeq) -> bool {
        let s = seq.0;
        if s == 0 || s <= self.contiguous {
            return false;
        }
        if !self.ahead.insert(s) {
            return false;
        }
        if s > self.highest {
            self.highest = s;
        }
        while self.ahead.remove(&(self.contiguous + 1)) {
            self.contiguous += 1;
        }
        true
    }

    pub fn contiguous(&self) -> XferSeq {
        XferSeq(self.contiguous)
    }

    pub fn highest(&self) -> XferSeq {
        XferSeq(self.highest)
    }

    /// True once every sequence number up to `final_seq` has arrived.
    pub fn is_complete(&self, final_seq: XferSeq) -> bool {
        self.contiguous >= final_seq.0
    }

    /// Sequence numbers between the prefix and the highest arrival, capped at
    /// `limit` so one `Nack` stays inside the MTU.
    pub fn missing(&self, limit: usize) -> Vec<XferSeq> {
        let mut out = Vec::new();
        let mut expect = self.contiguous + 1;
        for &have in &self.ahead {
            while expect < have && out.len() < limit {
                out.push(XferSeq(expect));
                expect += 1;
            }
            if out.len() >= limit {
                break;
            }
            expect = have + 1;
        }
        out
    }

    /// How far ahead of the prefix the furthest arrival sits. The receiver's
    /// reorder window is a bound on this.
    pub fn window_span(&self) -> u32 {
        self.highest.saturating_sub(self.contiguous)
    }

    /// Drop everything and jump the prefix forward, for when the reliable
    /// stream has been abandoned and its buffer is being released.
    pub fn abandon(&mut self) {
        self.ahead.clear();
    }
}
