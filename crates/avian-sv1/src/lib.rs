//! A Stratum v1 client: the upstream half of `avian-sv2-bridge`.
//!
//! The bridge terminates Stratum v2 and Noise facing miners and speaks
//! Stratum v1 facing a pool the operator already runs, so that an operator
//! with working accounting, payouts and vardiff can offer Stratum v2 without
//! reimplementing any of it, and without this project ever holding a coin.
//! See `doc/design.md`, "In front of a pool that already exists".
//!
//! This crate is only the client. It knows nothing about Stratum v2, channels
//! or jobs: it connects, subscribes, authorizes, hands up submissions and
//! hands back notifications. Translating those into Stratum v2 jobs is the
//! bridge's work, not this crate's, which is what keeps the one piece that
//! has to be right about someone else's accounting, the difficulty
//! conversion, out of the protocol code and in one testable place.
//!
//! **Not a pool.** Nothing here credits a share or holds a balance. A
//! submission goes upstream and the operator's own pool decides what it is
//! worth.

pub mod client;
pub mod difficulty;
pub mod json;
pub mod message;
pub mod mock;
