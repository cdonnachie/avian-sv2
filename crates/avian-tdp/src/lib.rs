//! The Template Distribution half of the pool: its business with the node.
//!
//! No miner speaks this protocol, which is why it is not in the library. What
//! is in the library is everything underneath it — Noise, framing, the Avian
//! extension codecs — so this crate is the Template Distribution messages, a
//! session that carries one algorithm, and the coinbase the pool owes the
//! node.
//!
//! ```text
//! tdp         the stock Template Distribution messages, owned
//! coinbase    the coinbase and merkle root a pool must build
//! session     one connection, one algorithm, with reconnection
//! ```

pub mod coinbase;
pub mod session;
pub mod tdp;

pub use avian_sv2::avian::PowType;
pub use avian_sv2::error::{Error, Result};
pub use avian_sv2::{authority, block, wire};
pub use session::{
    ReconnectingSession, SessionConfig, SolutionSubmitter, SubmitterSlot, TdpSession, Work,
    PROTOCOL_VERSION,
};

/// The port `aviand` listens on with `-sv2` and no `-sv2bind`.
pub fn default_port(chain: &str) -> u16 {
    match chain {
        "main" | "mainnet" => 8442,
        "test" | "testnet" => 18442,
        "testnet4" => 28442,
        "signet" => 38442,
        _ => 18447,
    }
}

/// The chain's subdirectory under a datadir, where the key files live.
pub fn chain_subdir(chain: &str) -> &str {
    match chain {
        "main" | "mainnet" => "",
        "test" | "testnet" => "testnet3",
        "testnet4" => "testnet4",
        "signet" => "signet",
        _ => "regtest",
    }
}
