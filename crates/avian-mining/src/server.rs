//! The worker-facing listener and the session each worker gets.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use avian_sv2::address::{self, Network};
use avian_sv2::avian::{
    PowType, EXT_AVIAN, EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS, MSG_REQUEST_EXTENSIONS_ERROR,
    MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM, MSG_SELECT_ALGORITHM_ERROR,
    MSG_SELECT_ALGORITHM_SUCCESS,
};
use avian_sv2::block;
use avian_sv2::error::{Error, Result};
use avian_sv2::transport::{Connection, ConnectionReader, ConnectionWriter};
use avian_sv2::wire::{Reader, Writer};
use avian_tdp::coinbase::{
    PayoutPlan, EXTENDED_EXTRANONCE_PREFIX, EXTENDED_EXTRANONCE_SIZE, MAX_COINBASE_TAG,
    MAX_HEIGHT_PUSH, MAX_SCRIPT_SIG,
};
use avian_tdp::tdp::PrevHash;
use avian_tdp::{SolutionSubmitter, Work};
use common_messages_sv2::{
    SetupConnectionError, SetupConnectionSuccess, MESSAGE_TYPE_SETUP_CONNECTION,
    MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
    SV2_MINING_PROTOCOL_DISCRIMINANT,
};
use mining_sv2::{
    OpenMiningChannelError, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
};

/// The bits of a submission that are the same in both forms.
struct SubmitMeta {
    sequence_number: u32,
}
use secp256k1::Keypair;

use crate::channel::{Channel, ChannelKind};
use crate::ratelimit::RateLimitConfig;
use crate::share::{PowHasher, Submission};
use avian_sv2::flags;

use crate::{EXT_CORE_MINING, PROTOCOL_VERSION};

#[derive(Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    /// The authority keypair the certificate is signed with. A worker pins the
    /// matching x-only public key, which
    /// [`avian_sv2::address::encode_authority_key`] prints in the form a
    /// miner's configuration takes.
    pub authority: Keypair,
    pub cert_validity: u32,
    /// Which chain's addresses to accept. Getting this wrong means accepting
    /// an address for another network and mining to it.
    pub network: Network,
    /// The operator's cut. Zero basis points, or an empty script, means the
    /// worker takes the whole coinbase, which is what solo mining is.
    pub fee_script: Vec<u8>,
    pub fee_basis_points: u32,
    /// Goes in the coinbase scriptSig after `coinbase_prefix`. At most
    /// [`avian_tdp::coinbase::MAX_COINBASE_TAG`] bytes; longer is refused when
    /// the server is built, not when the node rejects the block.
    pub coinbase_tag: Vec<u8>,
    /// Whether the Mining Protocol listener may be on an address that is not
    /// loopback.
    ///
    /// False by default, and the default is the point: a pool's Mining
    /// Protocol port is as exposed as its Template Distribution one, and Noise
    /// NX authenticates the server to the worker and not the worker to the
    /// server, so it is transport security rather than access control. Inside
    /// a container the listener has to be on the container's network for a
    /// published port to reach it, which is a deliberate act by whoever wrote
    /// the deployment rather than something to allow quietly.
    pub allow_public_bind: bool,
    /// How many halvings below the network target a share must be. Zero makes
    /// the share target the network target, which on regtest is the
    /// algorithm's own floor, so nearly every share is also a block.
    pub share_target_shift: u32,
    pub rate_limit: RateLimitConfig,
}

impl ServerConfig {
    /// Checks the parts that would otherwise fail later and less clearly.
    ///
    /// An over-long coinbase tag is the sharp one: it would build a coinbase
    /// the node refuses with nothing on the wire to say why, because the
    /// Template Distribution Protocol has no `SubmitSolution.Error`. So it is
    /// refused here, where an operator is reading the message.
    pub fn validate(&self) -> Result<()> {
        if self.coinbase_tag.len() > MAX_COINBASE_TAG {
            return Err(Error::Protocol(format!(
                "the coinbase tag is {} bytes and the most that always fits is \
                 {MAX_COINBASE_TAG}; the scriptSig must be 2 to 100 bytes and also carries the \
                 BIP34 height push and 8 bytes of extranonce",
                self.coinbase_tag.len()
            )));
        }
        if self.fee_basis_points > 10_000 {
            return Err(Error::Protocol(format!(
                "an operator fee of {} basis points is more than the whole coinbase",
                self.fee_basis_points
            )));
        }
        if self.fee_basis_points > 0 && self.fee_script.is_empty() {
            return Err(Error::Protocol(
                "an operator fee was configured with no address to pay it to".into(),
            ));
        }
        if !self.fee_script.is_empty() && self.fee_basis_points == 0 {
            return Err(Error::Protocol(
                "an operator fee address was configured with a fee of zero".into(),
            ));
        }
        Ok(())
    }
}

/// One algorithm's worth of pool: its Template Distribution session's output
/// and the channels mining it.
pub struct AlgoContext {
    pub pow: PowType,
    submitter: SolutionSubmitter,
    state: Mutex<AlgoState>,
    /// Blocks this algorithm has forwarded to the node.
    blocks: AtomicU32,
    /// Blocks whose hash later became the tip, which is the only honest way to
    /// count accepted ones: SubmitSolution has no reply, so the node cannot
    /// say, but the next SetNewPrevHash carries the new tip and a match is
    /// proof the block connected.
    confirmed: AtomicU32,
    /// Hashes forwarded and not yet seen as a tip, with the channel and
    /// sequence number they came from so the miner can be told which share it
    /// was. Bounded: an unconfirmed block either becomes the tip within a few
    /// rounds or lost a race, and the pool cannot tell which.
    pending: Mutex<VecDeque<(u32, u32, [u8; 32])>>,
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
            blocks: AtomicU32::new(0),
            confirmed: AtomicU32::new(0),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    pub fn submitter(&self) -> &SolutionSubmitter {
        &self.submitter
    }

    /// Every channel on this algorithm, for the stats endpoint. A clone of the
    /// list, so nothing holds the lock while a snapshot is rendered.
    pub fn channels(&self) -> Vec<Arc<Channel>> {
        self.state
            .lock()
            .map(|s| s.channels.clone())
            .unwrap_or_default()
    }

    /// Blocks forwarded upstream for this algorithm.
    pub fn blocks(&self) -> u32 {
        self.blocks.load(Ordering::Relaxed)
    }

    /// Blocks whose hash was later seen as the tip.
    pub fn confirmed(&self) -> u32 {
        self.confirmed.load(Ordering::Relaxed)
    }

    /// Records a forwarded block so a later tip can confirm it.
    fn remember_block(&self, channel_id: u32, sequence_number: u32, hash: [u8; 32]) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.push_back((channel_id, sequence_number, hash));
            // A dozen rounds is generous. Past that it lost a race, and the
            // pool has no way to know that rather than guess it.
            while pending.len() > 16 {
                pending.pop_front();
            }
        }
    }

    /// Tells any channel whose block is now the tip that it connected.
    ///
    /// Called with the new tip, from the SetNewPrevHash that moved it. This is
    /// the whole confirmation mechanism: not the absence of a complaint from
    /// the node, which cannot complain, but the hash actually appearing as the
    /// tip.
    fn confirm_tip(&self, tip: &[u8; 32], channels: &[Arc<Channel>]) {
        let matched: Vec<(u32, u32)> = match self.pending.lock() {
            Ok(mut pending) => {
                let mut hits = Vec::new();
                pending.retain(|(channel_id, sequence, hash)| {
                    if hash == tip {
                        hits.push((*channel_id, *sequence));
                        false
                    } else {
                        true
                    }
                });
                hits
            }
            Err(_) => return,
        };
        for (channel_id, sequence) in matched {
            self.confirmed.fetch_add(1, Ordering::Relaxed);
            if let Some(channel) = channels.iter().find(|c| c.id == channel_id) {
                if let Err(e) = channel.send_block_found(sequence, tip, true) {
                    eprintln!("[pool] channel {channel_id}: could not confirm its block: {e}");
                } else {
                    eprintln!("[pool] channel {channel_id}'s block is the tip now, told it so");
                }
            }
        }
    }

    /// The prev hash in force, so the page can show which tip is being mined.
    pub fn prev_hash(&self) -> Option<[u8; 32]> {
        self.state.lock().ok()?.prev.as_ref().map(|p| p.prev_hash)
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

        // A moved tip is the only evidence the pool can have that a block it
        // forwarded was accepted, so it is checked here, before the new work
        // goes out. SubmitSolution has no reply; the node cannot say yes.
        if work.tip_changed {
            self.confirm_tip(&prev.prev_hash, &channels);
        }

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
    /// Builds a server, checking the configuration first.
    pub fn new(
        config: ServerConfig,
        algos: Vec<Arc<AlgoContext>>,
        hasher: Arc<dyn PowHasher>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self::new_unchecked(config, algos, hasher))
    }

    fn new_unchecked(
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
                "expected a channel open, got {}",
                frame.describe()
            )));
        }

        // Both kinds are served, and REQUIRES_EXTENDED_CHANNELS is never set,
        // because serving both is the point: a miner that can only do
        // standard channels still works, and one that can do extended
        // channels gets to assemble its own coinbase and see what it is
        // committing to. For solo mining that verification is the product.
        let (request_id, identity, nominal_hash_rate, worker_max_target, kind) = match frame
            .msg_type
        {
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
                    ChannelKind::Standard,
                )
            }
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
                let open: mining_sv2::OpenExtendedMiningChannel =
                    binary_sv2::from_bytes(&mut frame.payload)?;
                let mut max_target = [0u8; 32];
                max_target.copy_from_slice(open.max_target.as_ref());
                let wanted = open.min_extranonce_size as usize;
                // The scriptSig is the constraint: the BIP34 height push, the
                // operator tag and the extranonce all share 100 bytes. A miner
                // asking for more than is left is refused rather than given a
                // channel whose every coinbase the node would reject.
                let available = MAX_SCRIPT_SIG
                    .saturating_sub(MAX_HEIGHT_PUSH)
                    .saturating_sub(self.config.coinbase_tag.len())
                    .saturating_sub(EXTENDED_EXTRANONCE_PREFIX);
                let size = EXTENDED_EXTRANONCE_SIZE.max(wanted);
                if size > available {
                    send(
                        writer,
                        EXT_CORE_MINING,
                        MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
                        false,
                        OpenMiningChannelError {
                            request_id: open.request_id,
                            error_code: b"min-extranonce-size-too-large".as_slice().try_into()?,
                        },
                    )?;
                    return Err(Error::Refused(format!(
                        "a {wanted}-byte extranonce was asked for and only {available} bytes of \
                         scriptSig are left after a {}-byte height push, a {}-byte operator tag \
                         and {EXTENDED_EXTRANONCE_PREFIX} bytes of pool prefix",
                        MAX_HEIGHT_PUSH,
                        self.config.coinbase_tag.len()
                    )));
                }
                (
                    open.request_id,
                    String::from_utf8_lossy(open.user_identity.as_ref()).into_owned(),
                    open.nominal_hash_rate,
                    max_target,
                    ChannelKind::Extended {
                        extranonce_size: size,
                    },
                )
            }
            other => {
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
                    "expected a channel open, got message 0x{other:02x}"
                )));
            }
        };

        // The money. On a solo pool the worker's own address goes in the
        // coinbase and consensus pays them directly, so this is the one place
        // where getting it wrong hands someone else's block reward away.
        //
        // There is deliberately no fallback. Not a default address, not a
        // burn address, not the operator's: a worker that mistypes its address
        // and is quietly mined to somebody else's is the worst thing this can
        // do, and it is silent in exactly the way everything else found in
        // this project has been silent.
        let parsed = match address::parse_identity(&identity, self.config.network) {
            Ok(parsed) => parsed,
            Err(e) => {
                let code = e.code();
                send(
                    writer,
                    EXT_CORE_MINING,
                    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
                    false,
                    OpenMiningChannelError {
                        request_id,
                        error_code: code.as_bytes().try_into()?,
                    },
                )?;
                return Err(Error::Refused(format!(
                    "OpenStandardMiningChannel with user_identity {identity:?}: {e} ({code})"
                )));
            }
        };

        let (_, prev) = algo.current().ok_or_else(|| {
            Error::Protocol("no template has arrived yet, so there is no target to set".into())
        })?;

        // The share target is the network target made easier by a fixed
        // number of halvings, then clamped to whatever the worker said it
        // could accept. There is no vardiff.
        //
        // Easier, not harder. This called harder_by, which divides the target
        // and so made a share rarer than a block: with the shift at its old
        // default of zero the two were identical and every accepted share was
        // a block, and raising it to see more shares produced fewer.
        let mut share_target = block::easier_by(&prev.target, self.config.share_target_shift);
        if !block::meets_target(&share_target, &worker_max_target) {
            share_target = worker_max_target;
        }

        let payout = PayoutPlan {
            worker_script: parsed.address.script_pubkey(),
            fee_script: self.config.fee_script.clone(),
            fee_basis_points: self.config.fee_basis_points,
        };

        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        let channel = Arc::new(Channel::new(
            id,
            kind,
            algo.pow,
            share_target,
            payout,
            parsed.worker.clone(),
            parsed.address_text.clone(),
            self.config.coinbase_tag.clone(),
            nominal_hash_rate,
            self.config.rate_limit,
            writer.clone(),
        ));
        eprintln!(
            "[pool] {} channel {id} pays {} ({:?}){}, worker {:?}, up to {:.2} submissions/s",
            if kind.is_extended() {
                "extended"
            } else {
                "standard"
            },
            parsed.address_text,
            parsed.address.kind,
            if self.config.fee_basis_points > 0 {
                format!(
                    " less an operator fee of {}.{:02}%",
                    self.config.fee_basis_points / 100,
                    self.config.fee_basis_points % 100
                )
            } else {
                String::new()
            },
            parsed.worker,
            channel.submission_rate(),
        );
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
                        channel
                            .send_error(sequence_number, crate::share::Refusal::InvalidChannelId)?;
                        continue;
                    }
                    // A miner must submit the form its channel was opened as.
                    if extended != channel.kind.is_extended() {
                        channel.send_error(
                            sequence_number,
                            crate::share::Refusal::InvalidExtranonce,
                        )?;
                        continue;
                    }
                    let submit = SubmitMeta { sequence_number };
                    let outcome = channel.handle_submit(
                        submission,
                        submit.sequence_number,
                        self.hasher.as_ref(),
                    )?;
                    // A channel that submitted against a job it does not have
                    // is desynchronised from the pool, and the repair is work,
                    // not a disconnect. Pushing here means the first refused
                    // share fixes the channel instead of starting a countdown.
                    if channel.wants_work() {
                        if let Some((work, prev)) = algo.current() {
                            match channel.push_work(&work, &prev) {
                                Ok(()) => eprintln!(
                                    "[pool] channel {} reissued work after a desync",
                                    channel.id
                                ),
                                Err(e) => eprintln!(
                                    "[pool] channel {} could not be reissued work: {e}",
                                    channel.id
                                ),
                            }
                        }
                    }
                    if let Some(candidate) = outcome {
                        // A share at or under the network target is a block,
                        // so it goes up to the node. There is no reply to a
                        // SubmitSolution: the only way to see it refused is
                        // the node's -debug=sv2 log.
                        eprintln!(
                            "[pool] channel {} found a block for template {}, submitting",
                            channel.id, candidate.template_id
                        );
                        channel.record_block();
                        algo.blocks.fetch_add(1, Ordering::Relaxed);
                        algo.remember_block(channel.id, submit.sequence_number, candidate.hash);
                        // Told before the node is, because the node has no
                        // reply to give and the miner is the one that cares.
                        if let Err(e) =
                            channel.send_block_found(submit.sequence_number, &candidate.hash, false)
                        {
                            eprintln!(
                                "[pool] channel {}: could not tell it about its block: {e}",
                                channel.id
                            );
                        }
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
