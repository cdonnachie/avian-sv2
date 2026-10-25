//! Avian Stratum v2: the protocol core, and the Mining Protocol client.
//!
//! Built before the miners rather than after them, because the pool is Rust
//! and the miners are C and CUDA: extracting later would have meant writing
//! the Stratum v2 client twice in C first, Noise included. Avian Core's own
//! Noise was self-consistent, passed every test written for it, and could not
//! complete a handshake with any conforming implementation. A second and third
//! hand-written Noise inside mining software, where the feedback loop is a
//! miner that silently earns nothing, is not a bet worth taking.
//!
//! ```text
//! transport   Noise NX and framing, both roles, over a blocking socket
//! avian       extension 0x4001 and the negotiation extension 0x0001
//! block       header serialization, SHA256d, target arithmetic
//! wire        the field codecs SRI does not provide
//! authority   the key a certificate is checked against
//! reconnect   backoff, and what does not survive a reconnect
//! client      the Mining Protocol client: what a miner needs
//! capi        the same client over `extern "C"`
//! ```
//!
//! # What is deliberately not here
//!
//! **X16RT, MinotaurX, CUDA and CPU hashing.** A miner already has its own,
//! heavily optimised, and that is the entire reason it is a miner. The
//! library's job is to hand it a job and take back a share, so
//! [`client::MiningJob::header`] assembles the 80 bytes and stops. The pool
//! links Avian's own hashers separately, through `avian-pow`, because a pool
//! has to check a share and has no optimised hasher of its own.
//!
//! Coinbase construction is not here either: the pool builds the coinbase, a
//! miner never does. Nor is the Template Distribution Protocol, which is a
//! pool's business with a node and no miner ever speaks.

pub mod authority;
pub mod avian;
pub mod block;
pub mod capi;
pub mod client;
pub mod error;
pub mod reconnect;
pub mod transport;
pub mod wire;

pub use avian::{PowType, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION};
pub use client::{ClientConfig, Event, MiningClient, MiningJob};
pub use error::{Error, Result};
pub use reconnect::Backoff;
pub use transport::{Connection, ConnectionReader, ConnectionWriter, Frame};

/// The crate version, which the C API reports so a miner can log what it
/// linked.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `SetupConnection` flags an Avian mining connection uses.
///
/// Two sets of bits share one field, which is why they are easy to confuse:
/// the miner's and the pool's mean different things at the same positions. The
/// table is in doc/sv2.md, "Flags on an Avian mining connection".
pub mod flags {
    /// Set by the miner: the worker needs `NewMiningJob`. Avian v1 requires
    /// it, because without it a standard channel may be served grouped or
    /// extended jobs.
    pub const REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
    /// Set by the miner: Job Declaration, which Avian v1 does not serve.
    pub const REQUIRES_WORK_SELECTION: u32 = 1 << 1;
    /// Set by the miner: version rolling. Avian v1 refuses a connection that
    /// sets it, rather than answering and then holding the miner to a fixed
    /// version, because the specification makes this and
    /// `REQUIRES_FIXED_VERSION` mutually exclusive.
    pub const REQUIRES_VERSION_ROLLING: u32 = 1 << 2;

    /// Set by the pool: the version field is not negotiable. Always set.
    pub const REQUIRES_FIXED_VERSION: u32 = 1 << 0;
    /// Set by the pool: standard channels are the only kind. Never set.
    pub const REQUIRES_EXTENDED_CHANNELS: u32 = 1 << 1;
}

#[cfg(test)]
mod tests {
    use super::flags;

    #[test]
    fn the_two_flag_sets_overlap_and_are_read_by_role() {
        // The same bit position means different things in each direction,
        // which is the whole reason doc/sv2.md tabulates them separately.
        assert_eq!(flags::REQUIRES_STANDARD_JOBS, flags::REQUIRES_FIXED_VERSION);
        assert_eq!(
            flags::REQUIRES_WORK_SELECTION,
            flags::REQUIRES_EXTENDED_CHANNELS
        );
    }
}
