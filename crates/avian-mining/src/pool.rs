//! Wiring: Template Distribution sessions upstream, a Mining Protocol
//! listener downstream, and a thread per algorithm moving work between them.
//!
//! This lives in the library rather than the binary so the integration tests
//! drive the same wiring the pool does. A test that built its own would be
//! testing itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use avian_sv2::avian::PowType;
use avian_sv2::error::{Error, Result};
use avian_sv2::Backoff;
use avian_tdp::session::Round;
use avian_tdp::{ReconnectingSession, SessionConfig, Work};
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
    /// Backoff for re-establishing a dropped session to the node.
    pub upstream_backoff: Backoff,
}

pub struct PoolHandle {
    mining_addr: SocketAddr,
    started_at: Instant,
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

    /// Every algorithm the pool serves, for the stats endpoint.
    pub fn algos(&self) -> &[Arc<AlgoContext>] {
        &self.algos
    }

    /// When the pool started serving. There is no persistence, so this is also
    /// how far back every counter on the stats endpoint reaches.
    pub fn started_at(&self) -> Instant {
        self.started_at
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

        let session = ReconnectingSession::open(session_config, config.upstream_backoff)?;
        // The submitter outlives any one connection: it resolves through the
        // session's slot, which is re-pointed on reconnect.
        let algo = Arc::new(AlgoContext::new(*pow, session.submitter()));
        algos.push(algo.clone());
        sessions.push((session, algo));
    }

    let server = Arc::new(Server::new(config.server, algos.clone(), hasher)?);

    for (session, algo) in &mut sessions {
        let work = match session.next_work()? {
            Round::Work { work, .. } => work,
            Round::Reconnected { .. } => {
                return Err(Error::Protocol(
                    "the node's session dropped before it issued a template".into(),
                ))
            }
        };
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
        .map(|(session, algo)| {
            let observer = observer.clone();
            std::thread::spawn(move || pump(session, algo, observer, deadline))
        })
        .collect();

    Ok(PoolHandle {
        mining_addr,
        started_at: Instant::now(),
        algos,
        _server: handle,
        threads,
    })
}

fn pump(
    mut session: ReconnectingSession,
    algo: Arc<AlgoContext>,
    observer: Option<WorkObserver>,
    deadline: Option<Instant>,
) {
    loop {
        if let Some(deadline) = deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || session.set_read_timeout(Some(left)).is_err() {
                return;
            }
        }
        match session.next_work() {
            Ok(Round::Work { work, .. }) => {
                if let Some(observer) = &observer {
                    observer(algo.pow, &work);
                }
                for (id, e) in algo.publish(work) {
                    eprintln!("[pool] {} channel {id}: {e}", algo.pow);
                }
            }
            Ok(Round::Reconnected {
                generation,
                attempts,
            }) => {
                // A new session means new template ids, so every template the
                // pool held is unsubmittable and every job built from one has
                // to be withdrawn. The next round pushes fresh jobs, and each
                // channel's first one will be a future job again.
                let withdrawn = algo.withdraw();
                eprintln!(
                    "[pool] {}: reconnected to the node after {attempts} attempt(s), session \
                     {generation}; withdrew the jobs on {withdrawn} channel(s) because template \
                     ids do not survive a reconnect",
                    algo.pow
                );
            }
            Err(e) => {
                // Past the deadline any failure is the deadline, since the
                // read timeout is what fired.
                if !deadline.is_some_and(|d| Instant::now() >= d) {
                    eprintln!("[pool] {}: {e}", algo.pow);
                }
                return;
            }
        }
    }
}
