//! A Stratum v2 front for an Avian pool that already speaks Stratum v1.
//!
//! Downstream it is the same Mining Protocol server a miner sees on the solo
//! pool: Noise, `SetupConnection`, the Avian extension, standard and extended
//! channels. Upstream it is one Stratum v1 connection per channel, opened in
//! the miner's name and closed when the miner goes. In between it translates,
//! and that is all: a `mining.notify` becomes a job, a `SubmitShares` becomes
//! a `mining.submit`, and the pool's answer becomes the miner's. The bridge
//! holds no coins, keeps no ledger and credits nobody; the operator's pool
//! goes on doing all of that in its own database, which is why running one
//! changes nothing about the pool's accounting and why this belongs in a
//! project whose one invariant is never holding anyone's money.
//!
//! What it cannot deliver is job declaration, because an existing pool
//! chooses the block and `coinb1`/`coinb2` arrive fixed. A miner on an
//! extended channel still sees the coinbase it is committing to, which is
//! more than Stratum v1 ever showed it.
//!
//! doc/design.md, "In front of a pool that already exists", is the design;
//! [`channel`] is where the mapping lives and [`server`] is the listener.
//! The solo pool's channel is solo policy from end to end, so this crate has
//! its own and shares what sits beneath it: `avian_mining::job::Job`,
//! `avian_mining::share::validate`, the submission limiter, and the Stratum
//! v2 handshake, which is the protocol rather than either pool's policy.

pub mod channel;
pub mod server;
