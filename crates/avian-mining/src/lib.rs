//! The Stratum v2 Mining Protocol server half of the Avian pool.
//!
//! Sits downstream of [`avian_tdp::TdpSession`]: a session per algorithm turns
//! templates into work, an [`server::AlgoContext`] per algorithm holds the
//! channels mining it, and a [`channel::Channel`] per worker turns a round of
//! work into a job and a submission into a share.
//!
//! What this is responsible for, and a worker is not, is the coinbase. On a
//! standard channel the pool builds it, so doc/sv2.md's "What a client must
//! reproduce" is this crate's contract with the node rather than a worker's
//! with the pool. [`avian_tdp::block`] is where that lives.

pub mod channel;
pub mod job;
pub mod pool;
pub mod server;
pub mod share;

/// The Mining Protocol lives under `extension_type = 0`, like the core
/// messages: a protocol is chosen by `SetupConnection.protocol`, not by an
/// extension.
pub const EXT_CORE_MINING: u16 = 0x0000;

pub const PROTOCOL_VERSION: u16 = 2;

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
