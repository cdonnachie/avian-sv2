//! The worker-facing listener and the session each worker gets.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use avian_sv2::avian::{
    PowType, EXT_AVIAN, EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS, MSG_REQUEST_EXTENSIONS_ERROR,
    MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM, MSG_SELECT_ALGORITHM_ERROR,
    MSG_SELECT_ALGORITHM_SUCCESS,
};
use avian_sv2::block;
use avian_sv2::error::{Error, Result};
use avian_sv2::transport::{Connection, ConnectionReader, ConnectionWriter};
use avian_sv2::wire::{Reader, Writer};
use avian_tdp::tdp::PrevHash;
use avian_tdp::{SolutionSubmitter, Work};
use common_messages_sv2::{
    SetupConnectionError, SetupConnectionSuccess, MESSAGE_TYPE_SETUP_CONNECTION,
    MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
    SV2_MINING_PROTOCOL_DISCRIMINANT,
};
use mining_sv2::{
    OpenMiningChannelError, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
};
use secp256k1::Keypair;

use crate::channel::Channel;
use crate::share::{PowHasher, Submission};
use avian_sv2::flags;

use crate::{EXT_CORE_MINING, PROTOCOL_VERSION};

#[derive(Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    /// The authority keypair the certificate is signed with. A worker pins the
    /// matching x-only public key.
    pub authority: Keypair,
    pub cert_validity: u32,
    /// The script the pool pays itself. This is the only place pool revenue
    /// appears: there is no share accounting and no payout, so a worker's
    /// shares earn it nothing here.
    pub payout_script: Vec<u8>,
    /// How many halvings below the network target a share must be. Zero makes
    /// the share target the network target, which on regtest is the
    /// algorithm's own floor, so nearly every share is also a block.
    pub share_target_shift: u32,
}

/// One algorithm's worth of pool: its Template Distribution session's output
/// and the channels mining it.
pub struct AlgoContext {
    pub pow: PowType,
    submitter: SolutionSubmitter,
    state: Mutex<AlgoState>,
}

#[derive(Default)]
struct AlgoState {
    work: Option<Arc<Work>>,
    /// The prev hash in force, remembered separately from the work so a round
    /// that omits `SetNewPrevHash` still has one. aviand always sends it, but
    /// doc/sv2.md says an in-place refresh does not, and a pool that assumed
    /// the node's behaviour would break against a conforming one.
    prev: Option<PrevHash>,
    channels: Vec<Arc<Channel>>,
}

impl AlgoContext {
    pub fn new(pow: PowType, submitter: SolutionSubmitter) -> Self {
        Self {
            pow,
            submitter,
            state: Mutex::new(AlgoState::default()),
        }
    }

    pub fn submitter(&self) -> &SolutionSubmitter {
        &self.submitter
    }

    /// Records a round of work and pushes a job to every channel.
    ///
    /// Returns the errors of any channels that could not be written to, which
    /// is how a worker that went away is noticed; the rest still got their
    /// job.
    pub fn publish(&self, work: Work) -> Vec<(u32, Error)> {
        let (work, prev, channels) = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return vec![],
            };
            if let Some(prev) = &work.prev_hash {
                state.prev = Some(prev.clone());
            }
            let Some(prev) = state.prev.clone() else {
                // Nothing has ever told us a prev hash, so there is no header
                // to build. Only reachable against a Template Provider that
                // never sends SetNewPrevHash at all.
                return vec![(
                    0,
                    Error::Protocol("a template arrived before any SetNewPrevHash".into()),
                )];
            };
            let work = Arc::new(work);
            state.work = Some(work.clone());
            (work, prev, state.channels.clone())
        };

        channels
            .iter()
            .filter_map(|channel| {
                channel
                    .push_work(&work, &prev)
                    .err()
                    .map(|e| (channel.id, e))
            })
            .collect()
    }

    pub fn current(&self) -> Option<(Arc<Work>, PrevHash)> {
        let state = self.state.lock().ok()?;
        Some((state.work.clone()?, state.prev.clone()?))
    }

    pub fn channel_count(&self) -> usize {
        self.state.lock().map(|s| s.channels.len()).unwrap_or(0)
    }

    /// Withdraws every job on every channel, and forgets the current work.
    ///
    /// For an upstream reconnect: the new session issues new `template_id`s,
    /// so a solution against anything held from the old one has nowhere to go.
    /// Returns the number of channels affected. Each one's next job will be a
    /// future job again, activated by its own `SetNewPrevHash`, because that
    /// is what a fresh tip announcement is.
    pub fn withdraw(&self) -> usize {
        let channels = match self.state.lock() {
            Ok(mut state) => {
                state.work = None;
                state.prev = None;
                state.channels.clone()
            }
            Err(_) => return 0,
        };
        for channel in &channels {
            channel.withdraw();
        }
        channels.len()
    }

    fn register(&self, channel: Arc<Channel>) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| Error::Protocol("the algorithm state is poisoned".into()))?
            .channels
            .push(channel);
        Ok(())
    }

    fn unregister(&self, id: u32) {
        if let Ok(mut state) = self.state.lock() {
            state.channels.retain(|channel| channel.id != id);
        }
    }
}

pub struct Server {
    config: ServerConfig,
    algos: Vec<Arc<AlgoContext>>,
    hasher: Arc<dyn PowHasher>,
    // Pool-wide rather than per algorithm, because a channel id goes into the
    // coinbase extranonce: two channels sharing one would hash identical
    // headers whenever their templates happened to match. Starts at 1,
    // because 0 is the "no group channel" value in
    // OpenStandardMiningChannel.Success.
    next_channel_id: AtomicU32,
}

impl Server {
    pub fn new(
        config: ServerConfig,
        algos: Vec<Arc<AlgoContext>>,
        hasher: Arc<dyn PowHasher>,
    ) -> Self {
        Self {
            config,
            algos,
            hasher,
            next_channel_id: AtomicU32::new(1),
        }
    }

    pub fn algo(&self, pow: PowType) -> Option<&Arc<AlgoContext>> {
        self.algos.iter().find(|algo| algo.pow == pow)
    }

    /// Binds and serves until the listener is dropped, one thread per worker.
    ///
    /// Loopback only. A pool's Mining Protocol port is as exposed as its
    /// Template Distribution one, and Noise NX authenticates the server to the
    /// worker and not the worker to the server, so it is transport security
    /// rather than access control.
    pub fn listen(self: Arc<Self>) -> Result<ServerHandle> {
        if !self.config.bind.ip().is_loopback() {
            return Err(Error::Protocol(format!(
                "refusing to bind {}: loopback only",
                self.config.bind
            )));
        }
        let listener = TcpListener::bind(self.config.bind)?;
        let addr = listener.local_addr()?;
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let server = self.clone();
                std::thread::spawn(move || {
                    if let Err(e) = server.serve(stream) {
                        eprintln!("[pool] worker session ended: {e}");
                    }
                });
            }
        });
        Ok(ServerHandle {
            addr,
            _thread: thread,
        })
    }

    fn serve(&self, stream: TcpStream) -> Result<()> {
        let peer = stream.peer_addr()?;
        let conn = Connection::accept(stream, &self.config.authority, self.config.cert_validity)?;
        let (mut reader, writer) = conn.split();
        eprintln!("[pool] {peer} completed the Noise handshake");

        setup_connection(&mut reader, &writer)?;
        request_extensions(&mut reader, &writer)?;
        let pow = select_algorithm(&mut reader, &writer, &self.algos)?;
        let algo = self
            .algo(pow)
            .ok_or_else(|| Error::Protocol(format!("no session for {pow}")))?;

        let channel = self.open_channel(&mut reader, &writer, algo)?;
        eprintln!("[pool] {peer} opened channel {} on {pow}", channel.id);

        let result = self.pump_submissions(&mut reader, algo, &channel);
        algo.unregister(channel.id);
        result
    }

    fn open_channel(
        &self,
        reader: &mut ConnectionReader,
        writer: &Arc<Mutex<ConnectionWriter>>,
        algo: &Arc<AlgoContext>,
    ) -> Result<Arc<Channel>> {
        let mut frame = reader.recv()?;
        if frame.extension_type != EXT_CORE_MINING {
            return Err(Error::Protocol(format!(
                "expected OpenStandardMiningChannel, got {}",
                frame.describe()
            )));
        }
        if frame.msg_type != MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL {
            // Extended channels are out of scope, and doc/sv2.md says
            // REQUIRES_EXTENDED_CHANNELS is never set, so this is the only
            // kind served.
            send(
                writer,
                EXT_CORE_MINING,
                MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
                false,
                OpenMiningChannelError {
                    request_id: 0,
                    error_code: b"unsupported-channel-type".as_slice().try_into()?,
                },
            )?;
            return Err(Error::Protocol(format!(
                "only standard channels are served, got {}",
                frame.describe()
            )));
        }

        let open: mining_sv2::OpenStandardMiningChannel =
            binary_sv2::from_bytes(&mut frame.payload)?;
        let request_id = open.request_id;
        let worker_max_target = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(open.max_target.as_ref());
            bytes
        };

        let (_, prev) = algo.current().ok_or_else(|| {
            Error::Protocol("no template has arrived yet, so there is no target to set".into())
        })?;

        // The share target is the network target made harder by a fixed
        // number of halvings, then clamped to whatever the worker said it
        // could accept. There is no vardiff.
        let mut share_target = block::harder_by(&prev.target, self.config.share_target_shift);
        if !block::meets_target(&share_target, &worker_max_target) {
            share_target = worker_max_target;
        }

        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        let channel = Arc::new(Channel::new(
            id,
            algo.pow,
            share_target,
            self.config.payout_script.clone(),
            writer.clone(),
        ));
        channel.send_open_success(request_id)?;
        algo.register(channel.clone())?;

        // A worker must not wait for the next refresh to get its first job.
        if let Some((work, prev)) = algo.current() {
            channel.push_work(&work, &prev)?;
        }
        Ok(channel)
    }

    fn pump_submissions(
        &self,
        reader: &mut ConnectionReader,
        algo: &Arc<AlgoContext>,
        channel: &Arc<Channel>,
    ) -> Result<()> {
        loop {
            let mut frame = reader.recv()?;
            match (frame.extension_type, frame.msg_type) {
                (EXT_CORE_MINING, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD) => {
                    let submit: mining_sv2::SubmitSharesStandard =
                        binary_sv2::from_bytes(&mut frame.payload)?;
                    if submit.channel_id != channel.id {
                        channel.send_error(
                            submit.sequence_number,
                            crate::share::Refusal::InvalidChannelId,
                        )?;
                        continue;
                    }
                    let submission = Submission {
                        job_id: submit.job_id,
                        nonce: submit.nonce,
                        ntime: submit.ntime,
                        version: submit.version,
                    };
                    if let Some(candidate) = channel.handle_submit(
                        submission,
                        submit.sequence_number,
                        self.hasher.as_ref(),
                    )? {
                        // A share at or under the network target is a block,
                        // so it goes up to the node. There is no reply to a
                        // SubmitSolution: the only way to see it refused is
                        // the node's -debug=sv2 log.
                        eprintln!(
                            "[pool] channel {} found a block for template {}, submitting",
                            channel.id, candidate.template_id
                        );
                        algo.submitter().submit(
                            candidate.template_id,
                            candidate.version,
                            candidate.ntime,
                            candidate.nonce,
                            &candidate.coinbase,
                        )?;
                    }
                }
                _ => {
                    return Err(Error::Protocol(format!(
                        "unexpected {} on a mining connection",
                        frame.describe()
                    )))
                }
            }
        }
    }
}

pub struct ServerHandle {
    addr: SocketAddr,
    _thread: std::thread::JoinHandle<()>,
}

impl ServerHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

fn send<T: binary_sv2::Serialize + binary_sv2::GetSize>(
    writer: &Arc<Mutex<ConnectionWriter>>,
    extension_type: u16,
    msg_type: u8,
    channel_msg: bool,
    message: T,
) -> Result<()> {
    writer
        .lock()
        .map_err(|_| Error::Protocol("a worker's writer is poisoned".into()))?
        .send(extension_type, msg_type, channel_msg, message)
}

fn send_raw(
    writer: &Arc<Mutex<ConnectionWriter>>,
    extension_type: u16,
    msg_type: u8,
    channel_msg: bool,
    payload: &[u8],
) -> Result<()> {
    writer
        .lock()
        .map_err(|_| Error::Protocol("a worker's writer is poisoned".into()))?
        .send_raw(extension_type, msg_type, channel_msg, payload)
}

/// `SetupConnection` with the v1 contract from doc/sv2.md.
fn setup_connection(
    reader: &mut ConnectionReader,
    writer: &Arc<Mutex<ConnectionWriter>>,
) -> Result<()> {
    let frame = reader.recv_expect(EXT_CORE_MINING, MESSAGE_TYPE_SETUP_CONNECTION)?;
    // Hand-decoded rather than through SRI's SetupConnection, because that
    // struct's `protocol` is an enum and an unknown discriminant has to be
    // answerable with unsupported-protocol rather than a decode failure.
    let mut r = Reader::new(&frame.payload);
    let protocol = r.u8()?;
    let min_version = r.u16()?;
    let max_version = r.u16()?;
    let requested = r.u32()?;

    let refuse = |flags: u32, code: &str| -> Result<()> {
        send(
            writer,
            EXT_CORE_MINING,
            MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
            false,
            SetupConnectionError {
                flags,
                error_code: code.as_bytes().try_into()?,
            },
        )?;
        Err(Error::Refused(format!("SetupConnection: {code}")))
    };

    if protocol != SV2_MINING_PROTOCOL_DISCRIMINANT {
        return refuse(0, "unsupported-protocol");
    }
    if !(min_version..=max_version).contains(&PROTOCOL_VERSION) {
        return refuse(0, "protocol-version-mismatch");
    }

    // The specification says that if the miner set REQUIRES_VERSION_ROLLING
    // the pool must not set REQUIRES_FIXED_VERSION, so the two are mutually
    // exclusive rather than one overriding the other. An Avian pool cannot
    // honour rolling at all, so a miner that demands it is refused rather than
    // answered and then quietly held to a fixed version.
    if requested & flags::REQUIRES_VERSION_ROLLING != 0 {
        return refuse(flags::REQUIRES_VERSION_ROLLING, "unsupported-feature-flags");
    }
    // Without this a standard channel may be served grouped or extended jobs.
    // A worker that can only process NewMiningJob has to say so.
    if requested & flags::REQUIRES_STANDARD_JOBS == 0 {
        return refuse(flags::REQUIRES_STANDARD_JOBS, "unsupported-feature-flags");
    }
    if requested & flags::REQUIRES_WORK_SELECTION != 0 {
        return refuse(flags::REQUIRES_WORK_SELECTION, "unsupported-feature-flags");
    }

    send(
        writer,
        EXT_CORE_MINING,
        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        false,
        SetupConnectionSuccess {
            used_version: PROTOCOL_VERSION,
            // REQUIRES_FIXED_VERSION always, REQUIRES_EXTENDED_CHANNELS never.
            flags: flags::REQUIRES_FIXED_VERSION,
        },
    )
}

/// The upstream half of the Extensions Negotiation extension.
///
/// The pool requires `0x4001` of its workers for the same reason the node
/// requires it of the pool: every failure mode the extension prevents is
/// silent, so a worker that has not negotiated it is refused rather than
/// served work it cannot mine correctly.
fn request_extensions(
    reader: &mut ConnectionReader,
    writer: &Arc<Mutex<ConnectionWriter>>,
) -> Result<()> {
    let frame = reader.recv_expect(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS)?;
    let mut r = Reader::new(&frame.payload);
    let request_id = r.u16()?;
    let wanted = r.seq_u16()?;
    r.done()?;

    if !wanted.contains(&EXT_AVIAN) {
        let unsupported: Vec<u16> = wanted
            .iter()
            .copied()
            .filter(|ext| *ext != EXT_AVIAN)
            .collect();
        let mut w = Writer::new();
        // The error names what it could not provide and what it requires, so
        // a worker that asked for the wrong thing can correct itself.
        let payload = w
            .u16(request_id)
            .seq_u16(&unsupported)
            .seq_u16(&[EXT_AVIAN])
            .finish();
        send_raw(
            writer,
            EXT_NEGOTIATION,
            MSG_REQUEST_EXTENSIONS_ERROR,
            false,
            &payload,
        )?;
        return Err(Error::Refused(format!(
            "RequestExtensions did not ask for 0x{EXT_AVIAN:04x}: {wanted:04x?}"
        )));
    }

    let mut w = Writer::new();
    let payload = w.u16(request_id).seq_u16(&[EXT_AVIAN]).finish();
    send_raw(
        writer,
        EXT_NEGOTIATION,
        MSG_REQUEST_EXTENSIONS_SUCCESS,
        false,
        &payload,
    )
}

fn select_algorithm(
    reader: &mut ConnectionReader,
    writer: &Arc<Mutex<ConnectionWriter>>,
    algos: &[Arc<AlgoContext>],
) -> Result<PowType> {
    let frame = reader.recv_expect(EXT_AVIAN, MSG_SELECT_ALGORITHM)?;
    let mut r = Reader::new(&frame.payload);
    let requested = r.u8()?;
    r.done()?;

    let refuse = |code: &str| -> Result<PowType> {
        let mut w = Writer::new();
        let payload = w.bytes_u8(code.as_bytes()).finish();
        send_raw(
            writer,
            EXT_AVIAN,
            MSG_SELECT_ALGORITHM_ERROR,
            false,
            &payload,
        )?;
        Err(Error::Refused(format!("AvianSelectAlgorithm: {code}")))
    };

    let Ok(pow) = PowType::from_u8(requested) else {
        return refuse("unsupported-pow-type");
    };
    if !algos.iter().any(|algo| algo.pow == pow) {
        return refuse("unsupported-pow-type");
    }

    let mut w = Writer::new();
    // version_rolling_mask is always 0, and there is no option to change it.
    let payload = w.u8(pow as u8).u32(0).finish();
    send_raw(
        writer,
        EXT_AVIAN,
        MSG_SELECT_ALGORITHM_SUCCESS,
        false,
        &payload,
    )?;
    Ok(pow)
}
