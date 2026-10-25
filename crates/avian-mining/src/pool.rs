//! Wiring: Template Distribution sessions upstream, a Mining Protocol
//! listener downstream, and a thread per algorithm moving work between them.
//!
//! This lives in the library rather than the binary so the integration tests
//! drive the same wiring the pool does. A test that built its own would be
//! testing itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use avian_tdp::avian::PowType;
use avian_tdp::error::{Error, Result};
use avian_tdp::{SessionConfig, TdpSession, Work};
use secp256k1::XOnlyPublicKey;

use crate::server::{AlgoContext, Server, ServerConfig, ServerHandle};
use crate::share::PowHasher;

/// Called with every round of work, for logging. Runs on the algorithm's own
/// thread, so it must not block.
pub type WorkObserver = Arc<dyn Fn(PowType, &Work) + Send + Sync>;

pub struct PoolConfig {
    pub node: SocketAddr,
    /// `None` is trust on first use for the node's certificate.
    pub node_authority: Option<XOnlyPublicKey>,
    pub algorithms: Vec<PowType>,
    pub server: ServerConfig,
    pub coinbase_size: u32,
    pub coinbase_sigops: u16,
    /// How long the work threads run. `None` runs until the handle is dropped.
    pub duration: Option<Duration>,
}

pub struct PoolHandle {
    mining_addr: SocketAddr,
    algos: Vec<Arc<AlgoContext>>,
    _server: ServerHandle,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl PoolHandle {
    pub fn mining_addr(&self) -> SocketAddr {
        self.mining_addr
    }

    pub fn algo(&self, pow: PowType) -> Option<&Arc<AlgoContext>> {
        self.algos.iter().find(|algo| algo.pow == pow)
    }

    pub fn join(self) {
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Opens the upstream sessions, pulls one round of work on each, then starts
/// serving.
///
/// The order matters: a worker that connects before any template has arrived
/// has no target to be given and no job to mine, so the listener does not open
/// until there is work.
pub fn spawn(
    config: PoolConfig,
    hasher: Arc<dyn PowHasher>,
    observer: Option<WorkObserver>,
) -> Result<PoolHandle> {
    let mut algos = Vec::new();
    let mut sessions = Vec::new();
    for pow in &config.algorithms {
        let mut session_config = SessionConfig::new(config.node, *pow);
        session_config.authority = config.node_authority;
        session_config.coinbase_output_max_additional_size = config.coinbase_size;
        session_config.coinbase_output_max_additional_sigops = config.coinbase_sigops;

        let session = TdpSession::open(&session_config)?;
        let algo = Arc::new(AlgoContext::new(*pow, session.submitter()));
        algos.push(algo.clone());
        sessions.push((session, algo));
    }

    let server = Arc::new(Server::new(config.server, algos.clone(), hasher));

    for (session, algo) in &mut sessions {
        let work = session.next_work()?;
        if let Some(observer) = &observer {
            observer(algo.pow, &work);
        }
        if let Some((id, e)) = algo.publish(work).into_iter().next() {
            return Err(Error::Protocol(format!("channel {id}: {e}")));
        }
    }

    let handle = server.clone().listen()?;
    let mining_addr = handle.addr();

    let deadline = config.duration.map(|d| Instant::now() + d);
    let threads = sessions
        .into_iter()
        .map(|(mut session, algo)| {
            let observer = observer.clone();
            std::thread::spawn(move || loop {
                if let Some(deadline) = deadline {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() || session.set_read_timeout(Some(left)).is_err() {
                        return;
                    }
                }
                let work = match session.next_work() {
                    Ok(work) => work,
                    Err(e) => {
                        // Past the deadline any failure is the deadline, since
                        // the read timeout is what fired.
                        if !deadline.is_some_and(|d| Instant::now() >= d) {
                            eprintln!("[pool] {}: {e}", algo.pow);
                        }
                        return;
                    }
                };
                if let Some(observer) = &observer {
                    observer(algo.pow, &work);
                }
                for (id, e) in algo.publish(work) {
                    eprintln!("[pool] {} channel {id}: {e}", algo.pow);
                }
            })
        })
        .collect();

    Ok(PoolHandle {
        mining_addr,
        algos,
        _server: handle,
        threads,
    })
}
