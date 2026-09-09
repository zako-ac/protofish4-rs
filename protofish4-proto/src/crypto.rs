//! Packet sealing and opening.
//!
//! The job here is anti-injection and integrity, not secrecy: the payload is
//! audio the user asked for out loud. What matters is that nobody who is not
//! holding the key can inject a frame, forge a `Nack`, or replay one. That
//! ordering is why the replay window below is not optional decoration.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{Error, Result};
use crate::header::Header;
use crate::types::{Direction, RequestId, SeqClass};

/// Length of the authentication tag appended to every sealed body.
pub const TAG_LEN: usize = 16;

/// Length of the shared secret HQ mints per request.
pub const KEY_LEN: usize = 32;

/// A per-request secret, shared by exactly one tap and one audio engine.
///
/// Per-request scoping is doing real work: it bounds the blast radius of a
/// replay to a single track, and it means the nonce never has to carry the
/// request id.
#[derive(Clone)]
pub struct SessionKey {
    cipher: ChaCha20Poly1305,
}

impl SessionKey {
    pub fn from_bytes(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_LEN {
            return Err(Error::BadKeyLength(key.len()));
        }
        let key: &Key = key.try_into().map_err(|_| Error::BadKeyLength(key.len()))?;
        Ok(Self { cipher: ChaCha20Poly1305::new(key) })
    }

    fn seal(&self, header: Header, dir: Direction, plaintext: &[u8]) -> Result<Vec<u8>> {
        let aad = header.to_bytes();
        let nonce = nonce_for(dir, header.kind.seq_class(), header.seq);
        let sealed = self
            .cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| Error::DecryptFailed(header.request_id))?;

        let mut out = Vec::with_capacity(aad.len() + sealed.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn open(&self, header: Header, dir: Direction, sealed: &[u8]) -> Result<Vec<u8>> {
        let aad = header.to_bytes();
        let nonce = nonce_for(dir, header.kind.seq_class(), header.seq);
        self.cipher
            .decrypt(&nonce, Payload { msg: sealed, aad: &aad })
            .map_err(|_| Error::DecryptFailed(header.request_id))
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

/// Build the 12-byte nonce for a packet.
///
/// ```text
/// 0       1       2               4                              12
/// +-------+-------+---------------+------------------------------+
/// |  dir  | class |  epoch (u16)  |       counter (u64 BE)       |
/// +-------+-------+---------------+------------------------------+
/// ```
///
/// Never transmitted — both ends reconstruct it from the header plus the role
/// they are playing. Three things keep it unique for a given key:
///
/// * `dir` separates the two endpoints, which share one key.
/// * `class` separates payload from control, so a `Data` frame and an `Ack`
///   cannot collide even when their counters coincide.
/// * `counter` is the transfer sequence number for payload (u32, zero-extended
///   — roughly 2.7 years of 20 ms frames before it could wrap) and a monotonic
///   per-direction counter for control.
///
/// `epoch` is reserved for rekeying and is currently always zero.
///
/// A retransmission deliberately reproduces the same nonce, because it also
/// reproduces the same plaintext: it is a byte-identical resend of an
/// already-sealed datagram, which is a replay of one message rather than two
/// messages under one nonce. That distinction is the whole reason retransmission
/// resends sealed bytes instead of re-encrypting — see [`crate::frame::tag`].
fn nonce_for(dir: Direction, class: SeqClass, counter: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[0] = dir.to_u8();
    n[1] = class.to_u8();
    // n[2..4] is the epoch, left at zero.
    n[4..12].copy_from_slice(&(counter as u64).to_be_bytes());
    n.into()
}

/// Guards against a captured control packet being replayed later.
///
/// AEAD proves a packet was authentic when it was written; it says nothing about
/// whether it was already delivered. Without this a recorded `Nack` can be
/// re-injected to drive pointless retransmission.
///
/// Applies to control packets only. `Data` is deduplicated by transfer sequence
/// number instead, because a legitimate retransmission is a byte-identical
/// resend and would otherwise be rejected here.
#[derive(Debug)]
pub struct ReplayWindow {
    highest: u64,
    /// Bitmap of the [`Self::WIDTH`] counters below `highest`; bit `i` stands
    /// for `highest - 1 - i`. `highest` itself is implicitly seen and has no bit.
    seen: Box<[u64; 16]>,
    started: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const WIDTH: u64 = 16 * 64;

    pub fn new() -> Self {
        Self { highest: 0, seen: Box::new([0u64; 16]), started: false }
    }

    /// Record `counter`, returning `Err` if it was already seen or has fallen
    /// out of the window.
    pub fn accept(&mut self, counter: u32) -> Result<()> {
        let c = counter as u64;

        if !self.started {
            self.started = true;
            self.highest = c;
            return Ok(());
        }

        if c > self.highest {
            // `shift_by` records the outgoing highest, which is now `shift`
            // positions back. The incoming one needs no bit: `highest` itself is
            // always treated as seen.
            self.shift_by(c - self.highest);
            self.highest = c;
            return Ok(());
        }

        let back = self.highest - c;
        if back == 0 || back > Self::WIDTH {
            return Err(Error::Replay(counter));
        }
        if self.get(back - 1) {
            return Err(Error::Replay(counter));
        }
        self.set(back - 1);
        Ok(())
    }

    fn shift_by(&mut self, shift: u64) {
        if shift >= Self::WIDTH {
            self.seen.iter_mut().for_each(|w| *w = 0);
            return;
        }
        let words = (shift / 64) as usize;
        let bits = (shift % 64) as u32;
        if words > 0 {
            for i in (0..self.seen.len()).rev() {
                self.seen[i] = if i >= words { self.seen[i - words] } else { 0 };
            }
        }
        if bits > 0 {
            let mut carry = 0u64;
            for w in self.seen.iter_mut() {
                let next = *w >> (64 - bits);
                *w = (*w << bits) | carry;
                carry = next;
            }
        }
        // The previous `highest` is now `shift` positions back.
        if shift - 1 < Self::WIDTH {
            self.set(shift - 1);
        }
    }

    fn set(&mut self, bit: u64) {
        if bit >= Self::WIDTH {
            return;
        }
        self.seen[(bit / 64) as usize] |= 1u64 << (bit % 64);
    }

    fn get(&self, bit: u64) -> bool {
        if bit >= Self::WIDTH {
            return false;
        }
        self.seen[(bit / 64) as usize] & (1u64 << (bit % 64)) != 0
    }
}

/// Seal a body into a complete datagram, header included.
pub fn seal(key: &SessionKey, header: Header, dir: Direction, plaintext: &[u8]) -> Result<Vec<u8>> {
    key.seal(header, dir, plaintext)
}

/// Open a datagram sent by our peer.
///
/// `dir` is the direction the *sender* was writing in, so a receiver passes
/// [`Direction::Send`].
pub fn open(key: &SessionKey, datagram: &[u8], dir: Direction) -> Result<(Header, Vec<u8>)> {
    let (header, sealed) = Header::parse(datagram)?;
    if header.kind.direction() != dir {
        return Err(Error::WrongDirection(header.kind.name()));
    }
    let plaintext = key.open(header, dir, sealed)?;
    Ok((header, plaintext))
}

pub fn request_id_of(datagram: &[u8]) -> Result<RequestId> {
    Header::peek_request_id(datagram)
}
