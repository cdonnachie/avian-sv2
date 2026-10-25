//! A Stratum v2 Template Distribution client for Avian.
//!
//! Layered so a Mining Protocol server can be added above it without changing
//! anything here:
//!
//! - [`transport`] is the Noise NX handshake and frame encryption, all of it
//!   SRI's, with a blocking socket loop on top. Both roles: the initiator a
//!   pool is to a node, and the responder it is to a worker.
//! - [`block`] is coinbase construction, merkle folding and target
//!   comparison, which are the pool's obligations to the node.
//! - [`avian`] is extension `0x4001` and the Extensions Negotiation extension
//!   `0x0001`, which SRI does not define. It includes
//!   `AvianJobTimeConstraints`, the Mining Protocol half, which this client
//!   never sends.
//! - [`tdp`] is the stock Template Distribution messages, decoded through
//!   SRI's codecs into owned structs.
//! - [`session`] is one connection carrying one algorithm.

pub mod authority;
pub mod avian;
pub mod block;
pub mod error;
pub mod session;
pub mod tdp;
pub mod transport;
pub mod wire;

pub use avian::{PowType, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION};
pub use error::{Error, Result};
pub use session::{SessionConfig, SolutionSubmitter, TdpSession, Work, PROTOCOL_VERSION};
pub use transport::{Connection, ConnectionReader, ConnectionWriter, Frame};

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
