//! The miner-facing listener, and the session each miner gets.
//!
//! A session is three threads' worth of work on two connections. The thread
//! that accepted the miner runs the Stratum v2 handshake, opens the upstream
//! Stratum v1 connection in the miner's name, and then reads the miner's
//! submissions for as long as it stays. The upstream client's own reader
//! thread turns the pool's lines into events, and a pump thread drains those
//! onto the channel: jobs, difficulty, verdicts. When either side goes, the
//! other is closed: a miner that leaves takes its upstream session with it,
//! because that session was opened in its name and nobody else may submit on
//! it, and a pool that hangs up ends the miner's session, because the miner
//! already knows how to reconnect and the bridge has nothing to offer it in
//! the meantime.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use avian_mining::channel::ChannelKind;
use avian_mining::ratelimit::RateLimitConfig;
use avian_mining::server::{request_extensions, select_algorithm, send, setup_connection};
use avian_mining::share::{PowHasher, Refusal, Submission};
use avian_mining::EXT_CORE_MINING;
use avian_sv1::client::{self, Client, Event};
use avian_sv1::message::Notify;
use avian_sv2::avian::PowType;
use avian_sv2::error::{Error, Result};
use avian_sv2::logln;
use avian_sv2::transport::{Connection, ConnectionReader, ConnectionWriter};
use mining_sv2::{
    OpenMiningChannelError, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
};
use secp256k1::Keypair;

use crate::channel::BridgeChannel;

#[derive(Clone)]
pub struct BridgeConfig {
    pub bind: SocketAddr,
    /// The authority keypair the certificate is signed with, which a miner
    /// pins exactly as it would the solo pool's.
    pub authority: Keypair,
    pub cert_validity: u32,
    /// Loopback only unless set, for the solo pool's reason: Noise NX
    /// authenticates the bridge to the miner and not the miner to the
    /// bridge, so it is transport security rather than access control.
    pub allow_public_bind: bool,
    /// The Stratum v1 pool to stand in front of, per algorithm, one entry
    /// each. A miner can only select an algorithm that has one, because the
    /// pool's job carries the algorithm in its version and a bridge cannot
    /// change it.
    pub upstreams: Vec<(PowType, SocketAddr)>,
    /// The chain's proof-of-work limit, which is what the pool's difficulty
    /// is relative to. Avian has one for both algorithms.
    pub pow_limit: [u8; 32],
    /// Sent in `mining.authorize`. Pools nearly all ignore it, and the ones
    /// that do not expect one value for every worker.
    pub password: String,
    /// How long the connection to the pool may be silent before it is
    /// treated as dead.
    pub upstream_idle_timeout: Option<Duration>,
    /// How long after `mining.authorize` to wait for the pool's first job
    /// before refusing the channel. Pools send it inside a second.
    pub first_work_timeout: Duration,
    /// How far past a job's `ntime` a miner may roll, in seconds. Zero pins
    /// it, and zero is the default: a Stratum v1 pool checks `ntime` against
    /// its own rules, which it does not publish, and a share refused for
    /// rolling is a share wasted.
    pub ntime_roll: u32,
    /// The slowest and fastest hash rate the bridge will believe, which
    /// bound what a miner's declaration can do to its submission limiter.
    pub min_hash_rate: f64,
    pub max_hash_rate: f64,
    pub rate_limit: RateLimitConfig,
}

impl BridgeConfig {
    /// Checks the parts that would otherwise fail later and less clearly.
    pub fn validate(&self) -> Result<()> {
        if self.upstreams.is_empty() {
            return Err(Error::Protocol(
                "no upstream pool was configured for any algorithm".into(),
            ));
        }
        for (i, (pow, _)) in self.upstreams.iter().enumerate() {
            if self.upstreams[..i].iter().any(|(other, _)| other == pow) {
                return Err(Error::Protocol(format!(
                    "two upstream pools were configured for {pow}"
                )));
            }
        }
        if !self.min_hash_rate.is_finite() || self.min_hash_rate <= 0.0 {
            return Err(Error::Protocol(format!(
                "the slowest believed hash rate must be above zero, not {}",
                self.min_hash_rate
            )));
        }
        // is_nan, not a bare `max < min`: a NaN compares false against
        // everything, so `<` would accept it and the bound would then
        // silently do nothing. The slowest rate is known finite by here.
        if self.max_hash_rate.is_nan() || self.max_hash_rate < self.min_hash_rate {
            return Err(Error::Protocol(format!(
                "the fastest believed hash rate ({}) is below the slowest ({})",
                self.max_hash_rate, self.min_hash_rate
            )));
        }
        if self.first_work_timeout.is_zero() {
            return Err(Error::Protocol(
                "the first-work timeout must be above zero".into(),
            ));
        }
        Ok(())
    }

    /// The hash rate to believe, from what the miner declared.
    fn believed_hash_rate(&self, declared: f32) -> f64 {
        let declared = f64::from(declared);
        // Not `clamp`, which panics on a NaN bound and would pass a NaN
        // declaration straight through.
        if declared.is_finite() {
            declared.max(self.min_hash_rate).min(self.max_hash_rate)
        } else {
            self.min_hash_rate
        }
    }
}

pub struct Bridge {
    config: BridgeConfig,
    hasher: Arc<dyn PowHasher>,
    /// Starts at 1, because 0 is the "no group channel" value in the open
    /// replies.
    next_channel_id: AtomicU32,
}

impl Bridge {
    pub fn new(config: BridgeConfig, hasher: Arc<dyn PowHasher>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            hasher,
            next_channel_id: AtomicU32::new(1),
        })
    }

    /// The algorithms with an upstream, which are the ones on offer.
    pub fn offered(&self) -> Vec<PowType> {
        self.config.upstreams.iter().map(|(pow, _)| *pow).collect()
    }

    /// Binds and serves until the listener is dropped, one thread per miner.
    pub fn listen(self: Arc<Self>) -> Result<BridgeHandle> {
        if !self.config.bind.ip().is_loopback() && !self.config.allow_public_bind {
            return Err(Error::Protocol(format!(
                "refusing to bind {}: loopback only unless allow_public_bind is set",
                self.config.bind
            )));
        }
        let listener = TcpListener::bind(self.config.bind)?;
        let addr = listener.local_addr()?;
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let bridge = self.clone();
                std::thread::spawn(move || {
                    if let Err(e) = bridge.serve(stream) {
                        logln!("[bridge] miner session ended: {e}");
                    }
                });
            }
        });
        Ok(BridgeHandle {
            addr,
            _thread: thread,
        })
    }

    fn serve(&self, stream: TcpStream) -> Result<()> {
        let peer = stream.peer_addr()?;
        let conn = Connection::accept(stream, &self.config.authority, self.config.cert_validity)?;
        let (mut reader, writer) = conn.split();
        logln!("[bridge] {peer} completed the Noise handshake");

        // The handshake is the solo pool's, verbatim: a miner built for one
        // connects to the other without knowing the difference.
        setup_connection(&mut reader, &writer)?;
        let extensions = request_extensions(&mut reader, &writer)?;
        let pow = select_algorithm(&mut reader, &writer, &self.offered())?;
        let upstream_addr = self
            .config
            .upstreams
            .iter()
            .find(|(offered, _)| *offered == pow)
            .map(|(_, addr)| *addr)
            .ok_or_else(|| Error::Protocol(format!("no upstream for {pow}")))?;

        // The bridge can say a share was a block, because it hashes every
        // share to validate it. It cannot say whether the block was accepted:
        // the Stratum v1 pool upstream has no way to tell it, so the second
        // notification never comes and a miner here only ever sees the
        // submitted one.
        let blocks = extensions.contains(&avian_sv2::avian::EXT_AVIAN_BLOCKS);
        let (channel, upstream) =
            self.open_channel(&mut reader, &writer, pow, upstream_addr, blocks)?;
        logln!(
            "[bridge] {peer} opened channel {} on {pow} as {:?}, difficulty {} upstream at {}",
            channel.id,
            channel.identity,
            channel.difficulty(),
            upstream.addr()
        );

        let pump = {
            let channel = channel.clone();
            let upstream = upstream.clone();
            let writer = writer.clone();
            std::thread::spawn(move || {
                let why = pump_upstream(&channel, &upstream);
                logln!(
                    "[bridge] channel {}: upstream session over: {why}",
                    channel.id
                );
                // Ends the miner's session: its reader fails and it
                // reconnects, with its own backoff, to a fresh upstream
                // session.
                if let Ok(writer) = writer.lock() {
                    writer.shutdown();
                }
            })
        };

        let result = self.pump_submissions(&mut reader, &channel, &extensions);
        // The upstream session was opened in this miner's name; nobody else
        // may submit on it. Closing the socket is what lets the pump thread
        // finish, since it holds its own reference to the client.
        upstream.shutdown();
        let _ = pump.join();
        let (invalid, refused) = channel.refusals();
        logln!(
            "[bridge] channel {} closed: {} accepted, {invalid} invalid, {refused} refused for \
             rate, {} unanswered",
            channel.id,
            channel.accepted(),
            channel.pending()
        );
        result
    }

    fn open_channel(
        &self,
        reader: &mut ConnectionReader,
        writer: &Arc<Mutex<ConnectionWriter>>,
        pow: PowType,
        upstream_addr: SocketAddr,
        blocks_negotiated: bool,
    ) -> Result<(Arc<BridgeChannel>, Arc<Client>)> {
        let mut frame = reader.recv()?;
        if frame.extension_type != EXT_CORE_MINING {
            return Err(Error::Protocol(format!(
                "expected a channel open, got {}",
                frame.describe()
            )));
        }
        let (request_id, identity, nominal_hash_rate, worker_max_target, wanted) =
            match frame.msg_type {
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => {
                    let open: mining_sv2::OpenStandardMiningChannel =
                        binary_sv2::from_bytes(&mut frame.payload)?;
                    let mut max_target = [0u8; 32];
                    max_target.copy_from_slice(open.max_target.as_ref());
                    (
                        open.request_id,
                        String::from_utf8_lossy(open.user_identity.as_ref()).into_owned(),
                        open.nominal_hash_rate,
                        max_target,
                        None,
                    )
                }
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
                    let open: mining_sv2::OpenExtendedMiningChannel =
                        binary_sv2::from_bytes(&mut frame.payload)?;
                    let mut max_target = [0u8; 32];
                    max_target.copy_from_slice(open.max_target.as_ref());
                    (
                        open.request_id,
                        String::from_utf8_lossy(open.user_identity.as_ref()).into_owned(),
                        open.nominal_hash_rate,
                        max_target,
                        Some(open.min_extranonce_size as usize),
                    )
                }
                other => {
                    refuse(writer, 0, "unsupported-channel-type")?;
                    return Err(Error::Protocol(format!(
                        "expected a channel open, got message 0x{other:02x}"
                    )));
                }
            };

        // The identity is the pool's business. A solo pool has to parse it,
        // because the address in it is where the money goes; here the money
        // is the pool's to send and the name is whatever the pool's
        // accounting expects, so it is handed over untouched. An empty one
        // is still refused, because no pool authorizes a nameless worker and
        // the pool's own refusal would be less clear about why.
        if identity.trim().is_empty() {
            refuse(writer, request_id, "unauthorized-worker")?;
            return Err(Error::Refused(
                "a channel was opened with an empty user_identity".into(),
            ));
        }

        let mut config = client::Config::new(upstream_addr, identity.clone());
        config.password = self.config.password.clone();
        config.idle_timeout = self.config.upstream_idle_timeout;
        let upstream = match Client::connect(&config) {
            Ok(client) => Arc::new(client),
            Err(e @ Error::Refused(_)) => {
                // The pool said no to this worker: a name it does not know,
                // on a pool that checks.
                refuse(writer, request_id, "unauthorized-worker")?;
                return Err(Error::Refused(format!(
                    "the pool at {upstream_addr} refused {identity:?}: {e}"
                )));
            }
            Err(e) => {
                refuse(writer, request_id, "upstream-unavailable")?;
                return Err(Error::Protocol(format!(
                    "could not open a session for {identity:?} at {upstream_addr}: {e}"
                )));
            }
        };

        let mut subscription = upstream.subscription().clone();
        let kind = match wanted {
            None => ChannelKind::Standard,
            Some(wanted) => {
                // The miner's half of the extranonce is the pool's
                // extranonce2, no more and no less: the pool's coinbase
                // reserved exactly that many bytes, and a miner that wants
                // more cannot be given them.
                if wanted > subscription.extranonce2_size {
                    refuse(writer, request_id, "min-extranonce-size-too-large")?;
                    return Err(Error::Refused(format!(
                        "a {wanted}-byte extranonce was asked for and the pool's extranonce2 \
                         is {} bytes",
                        subscription.extranonce2_size
                    )));
                }
                ChannelKind::Extended {
                    extranonce_size: subscription.extranonce2_size,
                }
            }
        };

        // The pool's first words: a difficulty, usually, and then a job.
        // The channel cannot be answered without a target, and the miner
        // must not be left holding an open channel with nothing to mine, so
        // both are waited for here. A pool that sends no difficulty is at
        // Stratum's default of 1, and says so in the log.
        let (difficulty, first_job) =
            match await_first_work(&upstream, &mut subscription, self.config.first_work_timeout) {
                Ok(found) => found,
                Err(e) => {
                    refuse(writer, request_id, "upstream-sent-no-work")?;
                    return Err(e);
                }
            };
        let difficulty = difficulty.unwrap_or_else(|| {
            logln!(
                "[bridge] {upstream_addr} sent a job before any difficulty; assuming Stratum's \
                 default of 1"
            );
            1.0
        });

        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        let channel = match BridgeChannel::new(
            id,
            kind,
            pow,
            identity.clone(),
            upstream.clone(),
            subscription,
            difficulty,
            self.config.pow_limit,
            worker_max_target,
            self.config.believed_hash_rate(nominal_hash_rate),
            self.config.ntime_roll,
            self.config.rate_limit,
            blocks_negotiated,
            writer.clone(),
        ) {
            Ok(channel) => Arc::new(channel),
            Err(e) => {
                refuse(writer, request_id, "upstream-sent-bad-work")?;
                return Err(e);
            }
        };
        logln!(
            "[bridge] {} channel {id} for {identity:?} on {pow}, up to {:.2} submissions/s",
            if kind.is_extended() {
                "extended"
            } else {
                "standard"
            },
            channel.submission_rate(),
        );
        channel.send_open_success(request_id)?;
        channel.push_job(&first_job)?;
        Ok((channel, upstream))
    }

    fn pump_submissions(
        &self,
        reader: &mut ConnectionReader,
        channel: &Arc<BridgeChannel>,
        negotiated: &[u16],
    ) -> Result<()> {
        loop {
            let mut frame = reader.recv()?;
            match (frame.extension_type, frame.msg_type) {
                (EXT_CORE_MINING, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD)
                | (EXT_CORE_MINING, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED) => {
                    let extended = frame.msg_type == MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED;
                    let (channel_id, sequence_number, submission) = if extended {
                        let submit: mining_sv2::SubmitSharesExtended =
                            binary_sv2::from_bytes(&mut frame.payload)?;
                        (
                            submit.channel_id,
                            submit.sequence_number,
                            Submission {
                                job_id: submit.job_id,
                                nonce: submit.nonce,
                                ntime: submit.ntime,
                                version: submit.version,
                                extranonce: submit.extranonce.as_ref().to_vec(),
                            },
                        )
                    } else {
                        let submit: mining_sv2::SubmitSharesStandard =
                            binary_sv2::from_bytes(&mut frame.payload)?;
                        (
                            submit.channel_id,
                            submit.sequence_number,
                            Submission {
                                job_id: submit.job_id,
                                nonce: submit.nonce,
                                ntime: submit.ntime,
                                version: submit.version,
                                extranonce: Vec::new(),
                            },
                        )
                    };
                    if channel_id != channel.id {
                        channel.send_error(sequence_number, Refusal::InvalidChannelId)?;
                        continue;
                    }
                    // A miner must submit the form its channel was opened as.
                    if extended != channel.kind.is_extended() {
                        channel.send_error(sequence_number, Refusal::InvalidExtranonce)?;
                        continue;
                    }
                    channel.handle_submit(submission, sequence_number, self.hasher.as_ref())?;
                }
                _ => {
                    // As in the pool: an unknown message number inside an
                    // extension this bridge granted means the miner was built
                    // at another time, and is read past so that a message can
                    // be added without breaking it.
                    if frame.is_skippable(negotiated) {
                        logln!(
                            "[bridge] channel {} sent {}, which this build does not serve; \
                             ignoring it",
                            channel.id,
                            frame.describe()
                        );
                        continue;
                    }
                    return Err(Error::Protocol(format!(
                        "unexpected {} on a mining connection",
                        frame.describe()
                    )));
                }
            }
        }
    }
}

/// Drains the pool's events onto the channel until the session is over, and
/// says why it ended.
fn pump_upstream(channel: &BridgeChannel, upstream: &Client) -> String {
    let events = upstream.events();
    loop {
        let event = match events.recv() {
            Ok(event) => event,
            Err(_) => return "the client was shut down".into(),
        };
        let result = match event {
            Event::Job(notify) => channel.push_job(&notify),
            Event::Difficulty(difficulty) => channel.set_difficulty(difficulty),
            Event::Extranonce(subscription) => channel.set_extranonce(subscription),
            Event::Share {
                id,
                accepted,
                error,
            } => channel.answer(id, accepted, error.as_deref()),
            Event::Reconnect { host, port } => {
                // Not honoured. A pool telling a client to go elsewhere is
                // also the one thing a compromised pool would say, and the
                // operator configured this address on purpose. Logged, so
                // the operator can reconfigure if it was meant.
                logln!(
                    "[bridge] channel {}: the pool asked for a reconnect to {host}:{port}, \
                     which is ignored; change --upstream if that was intended",
                    channel.id
                );
                Ok(())
            }
            Event::Closed(reason) => return reason,
        };
        if let Err(e) = result {
            return e.to_string();
        }
    }
}

/// Collects the pool's opening difficulty and first job, keeping any
/// `mining.set_extranonce` that arrives first, within the timeout.
fn await_first_work(
    upstream: &Client,
    subscription: &mut avian_sv1::message::Subscription,
    timeout: Duration,
) -> Result<(Option<f64>, Notify)> {
    let deadline = Instant::now() + timeout;
    let mut difficulty = None;
    let events = upstream.events();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(remaining) {
            Ok(Event::Difficulty(d)) => difficulty = Some(d),
            Ok(Event::Job(notify)) => return Ok((difficulty, notify)),
            Ok(Event::Extranonce(fresh)) => *subscription = fresh,
            Ok(Event::Closed(reason)) => {
                return Err(Error::Protocol(format!(
                    "the pool closed the session before sending work: {reason}"
                )))
            }
            Ok(Event::Share { .. }) | Ok(Event::Reconnect { .. }) => {}
            Err(RecvTimeoutError::Timeout) => {
                return Err(Error::Protocol(format!(
                    "the pool sent no job within {}s of authorizing",
                    timeout.as_secs()
                )))
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(Error::Protocol(
                    "the upstream client stopped before sending work".into(),
                ))
            }
        }
    }
}

fn refuse(writer: &Arc<Mutex<ConnectionWriter>>, request_id: u32, code: &str) -> Result<()> {
    send(
        writer,
        EXT_CORE_MINING,
        MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
        false,
        OpenMiningChannelError {
            request_id,
            error_code: code.as_bytes().try_into()?,
        },
    )
}

pub struct BridgeHandle {
    addr: SocketAddr,
    _thread: std::thread::JoinHandle<()>,
}

impl BridgeHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration that passes, so each test can break one thing.
    fn config() -> BridgeConfig {
        BridgeConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            authority: Keypair::from_seckey_slice(&secp256k1::Secp256k1::new(), &[1u8; 32])
                .unwrap(),
            cert_validity: 3600,
            allow_public_bind: false,
            upstreams: vec![(PowType::X16rt, "127.0.0.1:3333".parse().unwrap())],
            pow_limit: [0xff; 32],
            password: String::new(),
            upstream_idle_timeout: None,
            first_work_timeout: Duration::from_secs(5),
            ntime_roll: 0,
            min_hash_rate: 1000.0,
            max_hash_rate: 1e12,
            rate_limit: RateLimitConfig::default(),
        }
    }

    #[test]
    fn a_bridge_with_nowhere_to_send_a_share_is_refused() {
        assert!(config().validate().is_ok());

        let mut nowhere = config();
        nowhere.upstreams.clear();
        assert!(nowhere.validate().is_err());

        // Two pools for one algorithm is ambiguous rather than redundant:
        // which one a miner's shares went to would be decided by the order of
        // a vector, which is not something an operator chose.
        let mut twice = config();
        twice
            .upstreams
            .push((PowType::X16rt, "127.0.0.1:4444".parse().unwrap()));
        assert!(twice.validate().is_err());

        // One pool per algorithm is the setup this exists for.
        let mut both = config();
        both.upstreams
            .push((PowType::MinotaurX, "127.0.0.1:4444".parse().unwrap()));
        assert!(both.validate().is_ok());
    }

    #[test]
    fn an_unusable_hash_rate_bound_is_refused_at_startup() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut floor = config();
            floor.min_hash_rate = bad;
            assert!(
                floor.validate().is_err(),
                "a slowest believed rate of {bad} should be refused"
            );
        }

        let mut inverted = config();
        inverted.max_hash_rate = 1.0;
        assert!(inverted.validate().is_err());

        // The case the is_nan in validate is there for. A NaN compares false
        // against everything, so a bare `max < min` would accept it and the
        // ceiling would then silently do nothing, which is also why
        // believed_hash_rate does its own bounding rather than using clamp.
        let mut not_a_number = config();
        not_a_number.max_hash_rate = f64::NAN;
        assert!(not_a_number.validate().is_err());

        // An infinite ceiling is accepted, and the asymmetry with the floor
        // above is deliberate: it defeats the point of the bound but it is
        // not ambiguous, and believed_hash_rate's min() against it is a
        // no-op rather than a wrong answer.
        let mut unbounded = config();
        unbounded.max_hash_rate = f64::INFINITY;
        assert!(unbounded.validate().is_ok());
    }

    #[test]
    fn a_first_work_timeout_of_zero_is_refused() {
        // It would refuse every channel the instant it opened, the pool's
        // first job being unable to arrive in no time at all.
        let mut instant = config();
        instant.first_work_timeout = Duration::ZERO;
        assert!(instant.validate().is_err());
    }
}
