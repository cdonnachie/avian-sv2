//! The Mining Protocol client: what a miner needs and nothing else.
//!
//! Promoted out of the pool's test worker, which was already doing this job.
//! It opens a standard channel, decodes jobs, tracks the ntime window and the
//! share target, submits shares, and reconnects when the pool goes away.
//!
//! It does not hash. [`MiningJob::header`] assembles the 80 bytes and stops
//! there; the caller's own X16RT or MinotaurX turns that into a hash. That
//! boundary is the point of the library, and it is what lets a miner keep its
//! optimised hashing and gain the protocol without rewriting either.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use binary_sv2::{from_bytes, Sv2Option, U256};
use common_messages_sv2::{
    Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use mining_sv2::{
    OpenStandardMiningChannel, SubmitSharesStandard, CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
    CHANNEL_BIT_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_SET_TARGET, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
    MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};
use secp256k1::XOnlyPublicKey;

use crate::avian::{
    self, PowType, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION, MSG_JOB_TIME_CONSTRAINTS,
    MSG_REQUEST_EXTENSIONS, MSG_REQUEST_EXTENSIONS_ERROR, MSG_REQUEST_EXTENSIONS_SUCCESS,
    MSG_SELECT_ALGORITHM, MSG_SELECT_ALGORITHM_ERROR, MSG_SELECT_ALGORITHM_SUCCESS,
};
use crate::block;
use crate::error::{Error, Result};
use crate::flags;
use crate::reconnect::{self, Backoff};
use crate::transport::{Connection, ConnectionReader, ConnectionWriter};
use crate::wire::{Reader, Writer};

pub const PROTOCOL_VERSION: u16 = 2;

/// How many protocol events the client remembers, for diagnostics.
///
/// A miner debugging a pool needs to know the order messages arrived in, not
/// just their contents: most of what doc/sv2.md requires of a pool is
/// ordering. This is also what the pool's own ordering tests assert against.
const TRACE_CAPACITY: usize = 64;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub pool: SocketAddr,
    /// The pool's authority x-only public key. `None` is trust on first use:
    /// the session is still encrypted, but nothing says the peer is the pool
    /// you meant.
    pub pool_authority: Option<XOnlyPublicKey>,
    pub pow: PowType,
    pub user_identity: String,
    pub nominal_hash_rate: f32,
    /// The easiest target this miner is willing to be given. The pool may
    /// choose a harder one.
    pub max_target: [u8; 32],
    pub timeout: Duration,
    pub reconnect: Backoff,
}

impl ClientConfig {
    pub fn new(pool: SocketAddr, pow: PowType) -> Self {
        Self {
            pool,
            pool_authority: None,
            pow,
            user_identity: String::new(),
            nominal_hash_rate: 1.0,
            max_target: [0xff; 32],
            timeout: Duration::from_secs(30),
            reconnect: Backoff::default(),
        }
    }
}

/// A job, in the neutral form section 10 of the plan asks for.
///
/// Everything needed to build and judge a header, and nothing about Stratum
/// v2. This is the shape the C API hands across.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningJob {
    pub job_id: u32,
    /// Which connection this job came from. A reconnect bumps it, and work in
    /// flight from an earlier generation must be discarded: job ids restart.
    pub generation: u64,
    pub pow_type: PowType,
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    /// Where to start, which is `ntime_min`.
    pub ntime: u32,
    pub ntime_min: u32,
    pub ntime_max: u32,
    pub nbits: u32,
    pub share_target: [u8; 32],
}

impl MiningJob {
    /// The 80 bytes to hash. Does not hash them.
    pub fn header(&self, ntime: u32, nonce: u32) -> [u8; 80] {
        block::header(
            self.version,
            &self.prev_hash,
            &self.merkle_root,
            ntime,
            self.nbits,
            nonce,
        )
    }

    pub fn meets_share_target(&self, hash: &[u8; 32]) -> bool {
        block::meets_target(hash, &self.share_target)
    }

    /// Whether an `ntime` is inside the job's inclusive window.
    ///
    /// Rolling outside it is the failure `AvianJobTimeConstraints` exists to
    /// prevent: past the end of an X16RT epoch the hash chain changes and the
    /// miner computes a different function, silently.
    pub fn allows_ntime(&self, ntime: u32) -> bool {
        (self.ntime_min..=self.ntime_max).contains(&ntime)
    }
}

/// What a `poll` produced.
#[derive(Debug, Clone)]
pub enum Event {
    /// A job is active and minable. Anything held from an earlier generation
    /// is dead.
    Job(MiningJob),
    /// The tip moved. Every job from before this is unsubmittable; the pool
    /// has dropped them.
    JobsInvalidated {
        generation: u64,
    },
    ShareAccepted {
        sequence_number: u32,
        accepted_count: u32,
        shares_sum: u64,
    },
    ShareRejected {
        sequence_number: u32,
        code: String,
    },
    /// The connection went away. The next `poll` reconnects.
    Disconnected {
        reason: String,
    },
    /// A fresh session. `generation` has bumped and all previous jobs are
    /// gone; see [`crate::reconnect`] for what that means.
    Reconnected {
        generation: u64,
        attempts: u32,
    },
    /// Nothing arrived inside the poll timeout. Keep hashing.
    Idle,
}

/// One protocol message, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trace {
    SetupSuccess {
        flags: u32,
    },
    SetupError {
        flags: u32,
        code: String,
    },
    ExtensionsSuccess(Vec<u16>),
    ExtensionsError {
        unsupported: Vec<u16>,
        required: Vec<u16>,
    },
    AlgorithmSuccess {
        pow_type: PowType,
        mask: u32,
    },
    AlgorithmError(String),
    OpenSuccess {
        channel_id: u32,
    },
    OpenError(String),
    SetTarget,
    NewMiningJob {
        job_id: u32,
        future: bool,
    },
    JobConstraints {
        job_id: u32,
        ntime_min: u32,
        ntime_max: u32,
    },
    SetNewPrevHash {
        job_id: u32,
        min_ntime: u32,
    },
    ShareAccepted {
        sequence_number: u32,
    },
    ShareRejected {
        sequence_number: u32,
        code: String,
    },
    Connected {
        generation: u64,
    },
    Disconnected,
}

struct Session {
    reader: ConnectionReader,
    writer: Arc<Mutex<ConnectionWriter>>,
    channel_id: u32,
}

pub struct MiningClient {
    config: ClientConfig,
    session: Option<Session>,
    generation: u64,
    reconnects: u32,
    sequence: u32,
    share_target: [u8; 32],
    prev_hash: Option<[u8; 32]>,
    nbits: u32,
    jobs: HashMap<u32, MiningJob>,
    active: Option<u32>,
    trace: VecDeque<Trace>,
    /// One message can produce two events, when a tip change invalidates the
    /// old jobs and activates a new one. The second waits here.
    pending: Option<Event>,
}

impl MiningClient {
    /// Connects and opens a channel, retrying per the configured backoff.
    pub fn connect(config: ClientConfig) -> Result<Self> {
        let mut client = Self {
            config,
            session: None,
            generation: 0,
            reconnects: 0,
            sequence: 0,
            share_target: [0xff; 32],
            prev_hash: None,
            nbits: 0,
            jobs: HashMap::new(),
            active: None,
            trace: VecDeque::new(),
            pending: None,
        };
        client.establish()?;
        Ok(client)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn channel_id(&self) -> Option<u32> {
        self.session.as_ref().map(|s| s.channel_id)
    }

    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    pub fn share_target(&self) -> [u8; 32] {
        self.share_target
    }

    pub fn active_job(&self) -> Option<&MiningJob> {
        self.jobs.get(&self.active?)
    }

    pub fn job(&self, job_id: u32) -> Option<&MiningJob> {
        self.jobs.get(&job_id)
    }

    /// The last [`TRACE_CAPACITY`] protocol messages, oldest first.
    pub fn trace(&self) -> impl Iterator<Item = &Trace> {
        self.trace.iter()
    }

    /// Closes the socket, so the next `poll` reconnects.
    ///
    /// For a miner failing over, and for a test that wants to watch a real
    /// reconnection rather than a retry counter: the pool sees a genuine peer
    /// disconnect and the next session is a fresh Noise handshake.
    pub fn disconnect(&mut self) {
        if let Some(session) = self.session.take() {
            if let Ok(writer) = session.writer.lock() {
                writer.shutdown();
            }
        }
        self.invalidate();
        self.record(Trace::Disconnected);
    }

    /// Reads one message, waiting at most `timeout`.
    ///
    /// Reconnects transparently: a dropped connection surfaces as
    /// [`Event::Disconnected`] and the next call re-establishes and reports
    /// [`Event::Reconnected`]. A caller that wants to know nothing about that
    /// can treat both as "keep going" and watch `generation` on the jobs.
    pub fn poll(&mut self, timeout: Duration) -> Result<Event> {
        if let Some(event) = self.pending.take() {
            return Ok(event);
        }
        if self.session.is_none() {
            let attempts = self.establish()?;
            return Ok(Event::Reconnected {
                generation: self.generation,
                attempts,
            });
        }

        let ready = {
            let session = self.session.as_mut().expect("a session");
            session.reader.wait_readable(timeout)
        };
        match ready {
            Ok(false) => return Ok(Event::Idle),
            Ok(true) => {}
            Err(e) => return Ok(self.fail(e)),
        }

        let frame = {
            let session = self.session.as_mut().expect("a session");
            session.reader.recv()
        };
        match frame {
            Ok(frame) => self.handle(frame),
            Err(e) => Ok(self.fail(e)),
        }
    }

    /// Submits a share for the job the caller was handed.
    ///
    /// Takes the whole job rather than its id, because **a job id is only
    /// unique within a generation**: a reconnect restarts them, so submitting
    /// by id alone would let a nonce found for job 1 of one connection be
    /// applied to job 1 of the next. That is not a theoretical hazard. A test
    /// hit it, and the pool accepted the share against the wrong job.
    ///
    /// The version is not the caller's to choose either:
    /// `REQUIRES_FIXED_VERSION` is set on every Avian mining connection, and
    /// bits 16-23 are the algorithm, so changing them moves the share to the
    /// other algorithm's proof-of-work limit.
    pub fn submit(&mut self, job: &MiningJob, nonce: u32, ntime: u32) -> Result<u32> {
        if job.generation != self.generation {
            return Err(Error::Protocol(format!(
                "job {} is from connection {} and this is connection {}; work does not survive \
                 a reconnect",
                job.job_id, job.generation, self.generation
            )));
        }
        let current = self.jobs.get(&job.job_id).ok_or_else(|| {
            Error::Protocol(format!(
                "job {} has been withdrawn, so a share against it cannot be submitted",
                job.job_id
            ))
        })?;
        if current != job {
            return Err(Error::Protocol(format!(
                "job {} has been replaced since this copy was taken",
                job.job_id
            )));
        }
        if !job.allows_ntime(ntime) {
            return Err(Error::Protocol(format!(
                "ntime {ntime} is outside the job's window {}..{}",
                job.ntime_min, job.ntime_max
            )));
        }
        let version = job.version;
        self.submit_exact(job.job_id, nonce, ntime, version)
    }

    /// Submits exactly these fields, checking none of them.
    ///
    /// For a caller that wants to submit precisely what it hashed, and for
    /// testing a pool's refusals. [`Self::submit`] is the normal path.
    pub fn submit_exact(
        &mut self,
        job_id: u32,
        nonce: u32,
        ntime: u32,
        version: u32,
    ) -> Result<u32> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| Error::Protocol("not connected".into()))?;
        self.sequence += 1;
        let sequence_number = self.sequence;
        let message = SubmitSharesStandard {
            channel_id: session.channel_id,
            sequence_number,
            job_id,
            nonce,
            ntime,
            version,
        };
        session
            .writer
            .lock()
            .map_err(|_| Error::Protocol("the client's writer is poisoned".into()))?
            .send(
                EXT_CORE,
                MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
                CHANNEL_BIT_SUBMIT_SHARES_STANDARD,
                message,
            )?;
        Ok(sequence_number)
    }

    // Everything below is the session machinery.

    fn fail(&mut self, error: Error) -> Event {
        self.session = None;
        self.invalidate();
        self.record(Trace::Disconnected);
        Event::Disconnected {
            reason: error.to_string(),
        }
    }

    fn invalidate(&mut self) {
        self.jobs.clear();
        self.active = None;
        self.prev_hash = None;
        self.pending = None;
    }

    fn record(&mut self, entry: Trace) {
        if self.trace.len() == TRACE_CAPACITY {
            self.trace.pop_front();
        }
        self.trace.push_back(entry);
    }

    /// Opens a session, retrying transient failures. Returns the attempt count.
    fn establish(&mut self) -> Result<u32> {
        let config = self.config.clone();
        let mut attempts_used = 0;
        let mut setup_trace = Vec::new();
        let session = reconnect::with_retry(
            &config.reconnect,
            |attempt| {
                attempts_used = attempt;
                setup_trace.clear();
                // with_retry decides whether to try again: a refusal or a bad
                // certificate will fail the same way forever, and retrying
                // would hide a misconfiguration behind a hang.
                Self::open_session(&config, &mut setup_trace)
            },
            |_, _, _| {},
        );
        // Kept even on a failure, so a caller can see how far the handshake
        // and negotiation got before it was refused.
        for entry in setup_trace {
            self.record(entry);
        }
        let session = session?;

        self.generation += 1;
        if self.generation > 1 {
            self.reconnects += 1;
        }
        self.sequence = 0;
        self.invalidate();
        self.session = Some(session);
        let generation = self.generation;
        self.record(Trace::Connected { generation });
        Ok(attempts_used)
    }

    fn open_session(config: &ClientConfig, trace: &mut Vec<Trace>) -> Result<Session> {
        let conn = Connection::connect(config.pool, config.pool_authority, config.timeout)?;
        let (reader, writer) = conn.split();
        let mut session = Session {
            reader,
            writer,
            channel_id: 0,
        };
        Self::setup_connection(&mut session, trace)?;
        Self::request_extensions(&mut session, trace)?;
        Self::select_algorithm(&mut session, config.pow, trace)?;
        Self::open_channel(&mut session, config, trace)?;
        Ok(session)
    }

    fn setup_connection(session: &mut Session, trace: &mut Vec<Trace>) -> Result<()> {
        let host = b"0.0.0.0";
        let vendor = b"libavian-sv2";
        let empty: &[u8] = b"";
        Self::send(
            session,
            EXT_CORE,
            MESSAGE_TYPE_SETUP_CONNECTION,
            false,
            SetupConnection {
                protocol: Protocol::MiningProtocol,
                min_version: PROTOCOL_VERSION,
                max_version: PROTOCOL_VERSION,
                // REQUIRES_STANDARD_JOBS because this client only handles
                // NewMiningJob, and neither of the other two: no Job
                // Declaration, and version rolling must not be demanded,
                // because a pool that honoured it could not hold the
                // algorithm fixed.
                flags: flags::REQUIRES_STANDARD_JOBS,
                endpoint_host: host.as_slice().try_into()?,
                endpoint_port: 0,
                vendor: vendor.as_slice().try_into()?,
                hardware_version: empty.try_into()?,
                firmware: empty.try_into()?,
                device_id: empty.try_into()?,
            },
        )?;

        let frame = session.reader.recv()?;
        match (frame.extension_type, frame.msg_type) {
            (EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) => {
                let mut r = Reader::new(&frame.payload);
                let used_version = r.u16()?;
                let answered = r.u32()?;
                r.done()?;
                if used_version != PROTOCOL_VERSION {
                    return Err(Error::Protocol(format!(
                        "the pool chose protocol version {used_version}"
                    )));
                }
                // A pool that did not set REQUIRES_FIXED_VERSION has not
                // promised to hold the version still, and on Avian that means
                // it cannot promise which algorithm a share is judged under.
                if answered & flags::REQUIRES_FIXED_VERSION == 0 {
                    return Err(Error::Protocol(
                        "the pool did not set REQUIRES_FIXED_VERSION, so it has not undertaken \
                         to keep nVersion fixed, and on Avian that is the algorithm"
                            .into(),
                    ));
                }
                if answered & flags::REQUIRES_EXTENDED_CHANNELS != 0 {
                    return Err(Error::Protocol(
                        "the pool requires extended channels, which this client does not open"
                            .into(),
                    ));
                }
                trace.push(Trace::SetupSuccess { flags: answered });
                Ok(())
            }
            (EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_ERROR) => {
                let mut r = Reader::new(&frame.payload);
                let named = r.u32()?;
                let code = r.text()?;
                trace.push(Trace::SetupError {
                    flags: named,
                    code: code.clone(),
                });
                Err(Error::Refused(format!(
                    "SetupConnection: {code} (flags 0x{named:08x})"
                )))
            }
            _ => Err(Error::Protocol(format!(
                "unexpected reply to SetupConnection: {}",
                frame.describe()
            ))),
        }
    }

    fn request_extensions(session: &mut Session, trace: &mut Vec<Trace>) -> Result<()> {
        let payload = avian::encode_request_extensions(1, &[EXT_AVIAN]);
        Self::send_raw(
            session,
            EXT_NEGOTIATION,
            MSG_REQUEST_EXTENSIONS,
            false,
            &payload,
        )?;
        let frame = session.reader.recv()?;
        match (frame.extension_type, frame.msg_type) {
            (EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_SUCCESS) => {
                let success = avian::decode_request_extensions_success(&frame.payload)?;
                if !success.extensions.contains(&EXT_AVIAN) {
                    return Err(Error::Protocol(format!(
                        "the pool did not accept 0x{EXT_AVIAN:04x}: {:04x?}",
                        success.extensions
                    )));
                }
                trace.push(Trace::ExtensionsSuccess(success.extensions));
                Ok(())
            }
            (EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_ERROR) => {
                let error = avian::decode_request_extensions_error(&frame.payload)?;
                trace.push(Trace::ExtensionsError {
                    unsupported: error.unsupported.clone(),
                    required: error.required.clone(),
                });
                Err(Error::Refused(format!(
                    "RequestExtensions: unsupported {:04x?}, required {:04x?}",
                    error.unsupported, error.required
                )))
            }
            _ => Err(Error::Protocol(format!(
                "unexpected reply to RequestExtensions: {}",
                frame.describe()
            ))),
        }
    }

    fn select_algorithm(session: &mut Session, pow: PowType, trace: &mut Vec<Trace>) -> Result<()> {
        Self::send_raw(
            session,
            EXT_AVIAN,
            MSG_SELECT_ALGORITHM,
            false,
            &avian::encode_select_algorithm(pow),
        )?;
        let frame = session.reader.recv()?;
        match (frame.extension_type, frame.msg_type) {
            (EXT_AVIAN, MSG_SELECT_ALGORITHM_SUCCESS) => {
                let success = avian::decode_select_algorithm_success(&frame.payload)?;
                if success.pow_type != pow {
                    return Err(Error::Protocol(format!(
                        "asked for {pow} and was given {}",
                        success.pow_type
                    )));
                }
                if success.version_rolling_mask != 0 {
                    return Err(Error::Protocol(format!(
                        "version_rolling_mask is 0x{:08x} and this version of the extension \
                         specifies 0; rolling bits 16-23 would change the algorithm",
                        success.version_rolling_mask
                    )));
                }
                trace.push(Trace::AlgorithmSuccess {
                    pow_type: success.pow_type,
                    mask: success.version_rolling_mask,
                });
                Ok(())
            }
            (EXT_AVIAN, MSG_SELECT_ALGORITHM_ERROR) => {
                let code = avian::decode_select_algorithm_error(&frame.payload)?;
                trace.push(Trace::AlgorithmError(code.clone()));
                Err(Error::Refused(format!("AvianSelectAlgorithm: {code}")))
            }
            _ => Err(Error::Protocol(format!(
                "unexpected reply to AvianSelectAlgorithm: {}",
                frame.describe()
            ))),
        }
    }

    fn open_channel(
        session: &mut Session,
        config: &ClientConfig,
        trace: &mut Vec<Trace>,
    ) -> Result<()> {
        let identity = config.user_identity.clone();
        let max_target = config.max_target;
        Self::send(
            session,
            EXT_CORE,
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
            OpenStandardMiningChannel {
                request_id: 1,
                user_identity: identity.as_bytes().try_into()?,
                nominal_hash_rate: config.nominal_hash_rate,
                max_target: U256::try_from(max_target.as_slice())?,
            },
        )?;
        let mut frame = session.reader.recv()?;
        match (frame.extension_type, frame.msg_type) {
            (EXT_CORE, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS) => {
                let success: mining_sv2::OpenStandardMiningChannelSuccess =
                    from_bytes(&mut frame.payload)?;
                session.channel_id = success.channel_id;
                trace.push(Trace::OpenSuccess {
                    channel_id: success.channel_id,
                });
                Ok(())
            }
            (EXT_CORE, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR) => {
                let error: mining_sv2::OpenMiningChannelError = from_bytes(&mut frame.payload)?;
                let code = String::from_utf8_lossy(error.error_code.as_ref()).into_owned();
                trace.push(Trace::OpenError(code.clone()));
                Err(Error::Refused(format!("OpenStandardMiningChannel: {code}")))
            }
            _ => Err(Error::Protocol(format!(
                "unexpected reply to OpenStandardMiningChannel: {}",
                frame.describe()
            ))),
        }
    }

    fn handle(&mut self, mut frame: crate::transport::Frame) -> Result<Event> {
        match (frame.extension_type, frame.msg_type) {
            (EXT_CORE, MESSAGE_TYPE_SET_TARGET) => {
                let set: mining_sv2::SetTarget = from_bytes(&mut frame.payload)?;
                self.share_target
                    .copy_from_slice(set.maximum_target.as_ref());
                for job in self.jobs.values_mut() {
                    job.share_target = self.share_target;
                }
                self.record(Trace::SetTarget);
                Ok(Event::Idle)
            }
            (EXT_CORE, MESSAGE_TYPE_NEW_MINING_JOB) => {
                let job: mining_sv2::NewMiningJob = from_bytes(&mut frame.payload)?;
                let min_ntime: Sv2Option<u32> = job.min_ntime;
                let start = min_ntime.into_inner();
                let mut merkle_root = [0u8; 32];
                merkle_root.copy_from_slice(job.merkle_root.as_ref());
                let future = start.is_none();
                let pow_type = avian::pow_type_from_version(job.version)?;
                if pow_type != self.config.pow {
                    return Err(Error::Protocol(format!(
                        "a {pow_type} job arrived on a {} channel",
                        self.config.pow
                    )));
                }
                self.jobs.insert(
                    job.job_id,
                    MiningJob {
                        job_id: job.job_id,
                        generation: self.generation,
                        pow_type,
                        version: job.version,
                        // A future job has no prev hash yet; the
                        // SetNewPrevHash that activates it supplies one.
                        prev_hash: self.prev_hash.unwrap_or([0u8; 32]),
                        merkle_root,
                        ntime: start.unwrap_or(0),
                        ntime_min: start.unwrap_or(0),
                        // Filled in by the constraints that follow. Until they
                        // do, the window is empty, so nothing can be submitted
                        // against this job: that is deliberate, because a job
                        // whose ntime_max is unknown cannot be mined safely.
                        ntime_max: 0,
                        nbits: self.nbits,
                        share_target: self.share_target,
                    },
                );
                self.record(Trace::NewMiningJob {
                    job_id: job.job_id,
                    future,
                });
                Ok(Event::Idle)
            }
            (EXT_AVIAN, MSG_JOB_TIME_CONSTRAINTS) => {
                if !frame.channel_msg {
                    return Err(Error::Protocol(
                        "AvianJobTimeConstraints must set the channel_msg bit, so that it \
                         travels under 0xc001"
                            .into(),
                    ));
                }
                let bounds = avian::decode_job_time_constraints(&frame.payload)?;
                if let Some(job) = self.jobs.get_mut(&bounds.job_id) {
                    job.ntime_min = bounds.ntime_min;
                    job.ntime_max = bounds.ntime_max;
                    job.ntime = bounds.ntime_min;
                }
                self.record(Trace::JobConstraints {
                    job_id: bounds.job_id,
                    ntime_min: bounds.ntime_min,
                    ntime_max: bounds.ntime_max,
                });
                // An already-active job whose window moved is a new job to
                // hash, so report it.
                if self.active == Some(bounds.job_id) {
                    if let Some(job) = self.jobs.get(&bounds.job_id) {
                        return Ok(Event::Job(job.clone()));
                    }
                }
                Ok(Event::Idle)
            }
            (EXT_CORE, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH) => {
                let set: mining_sv2::SetNewPrevHash = from_bytes(&mut frame.payload)?;
                let mut prev = [0u8; 32];
                prev.copy_from_slice(set.prev_hash.as_ref());
                let moved = self.prev_hash.is_some_and(|old| old != prev);
                self.prev_hash = Some(prev);
                self.nbits = set.nbits;
                self.active = Some(set.job_id);
                self.record(Trace::SetNewPrevHash {
                    job_id: set.job_id,
                    min_ntime: set.min_ntime,
                });

                if moved {
                    // Everything built on the old tip is dead, which is what
                    // the pool has just done with its own copies.
                    let activating = self.jobs.remove(&set.job_id);
                    self.jobs.clear();
                    if let Some(job) = activating {
                        self.jobs.insert(set.job_id, job);
                    }
                }
                let Some(job) = self.jobs.get_mut(&set.job_id) else {
                    return Err(Error::Protocol(format!(
                        "SetNewPrevHash activated job {} which was never announced",
                        set.job_id
                    )));
                };
                job.prev_hash = prev;
                job.nbits = set.nbits;
                if job.ntime_min != set.min_ntime {
                    // doc/sv2.md: the ntime_start SetNewPrevHash supplies must
                    // equal the ntime_min in force for that job.
                    return Err(Error::Protocol(format!(
                        "SetNewPrevHash says ntime starts at {} but the job's constraints say \
                         {}",
                        set.min_ntime, job.ntime_min
                    )));
                }
                if job.ntime_max < job.ntime_min {
                    return Err(Error::Protocol(format!(
                        "job {} was activated before its AvianJobTimeConstraints arrived, so \
                         its ntime_max is unknown and it cannot be mined",
                        set.job_id
                    )));
                }
                let job = job.clone();
                if moved {
                    let generation = self.generation;
                    self.pending = Some(Event::Job(job));
                    return Ok(Event::JobsInvalidated { generation });
                }
                Ok(Event::Job(job))
            }
            (EXT_CORE, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS) => {
                let success: mining_sv2::SubmitSharesSuccess = from_bytes(&mut frame.payload)?;
                self.record(Trace::ShareAccepted {
                    sequence_number: success.last_sequence_number,
                });
                Ok(Event::ShareAccepted {
                    sequence_number: success.last_sequence_number,
                    accepted_count: success.new_submits_accepted_count,
                    shares_sum: success.new_shares_sum,
                })
            }
            (EXT_CORE, MESSAGE_TYPE_SUBMIT_SHARES_ERROR) => {
                let error: mining_sv2::SubmitSharesError = from_bytes(&mut frame.payload)?;
                let code = String::from_utf8_lossy(error.error_code.as_ref()).into_owned();
                self.record(Trace::ShareRejected {
                    sequence_number: error.sequence_number,
                    code: code.clone(),
                });
                Ok(Event::ShareRejected {
                    sequence_number: error.sequence_number,
                    code,
                })
            }
            _ => Err(Error::Protocol(format!(
                "the pool sent an unexpected {}",
                frame.describe()
            ))),
        }
    }

    fn send<T: binary_sv2::Serialize + binary_sv2::GetSize>(
        session: &mut Session,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        message: T,
    ) -> Result<()> {
        session
            .writer
            .lock()
            .map_err(|_| Error::Protocol("the client's writer is poisoned".into()))?
            .send(extension_type, msg_type, channel_msg, message)
    }

    fn send_raw(
        session: &mut Session,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        payload: &[u8],
    ) -> Result<()> {
        session
            .writer
            .lock()
            .map_err(|_| Error::Protocol("the client's writer is poisoned".into()))?
            .send_raw(extension_type, msg_type, channel_msg, payload)
    }
}

/// Serializes a `RequestExtensions` for a caller that wants to ask for
/// something other than `0x4001`, which only a test does.
pub fn encode_request_extensions(request_id: u16, wanted: &[u16]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(request_id).seq_u16(wanted).finish()
}
