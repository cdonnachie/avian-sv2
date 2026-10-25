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
pub mod ratelimit;
pub mod server;
pub mod share;

/// The Mining Protocol lives under `extension_type = 0`, like the core
/// messages: a protocol is chosen by `SetupConnection.protocol`, not by an
/// extension.
pub const EXT_CORE_MINING: u16 = 0x0000;

pub const PROTOCOL_VERSION: u16 = 2;

/// The flag contract lives in the library, because both roles need it.
pub use avian_sv2::flags;
