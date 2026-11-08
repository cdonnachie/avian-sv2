//! The worker-facing listener and the session each worker gets.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use avian_sv2::address::{self, Network};
use avian_sv2::avian::{
    PowType, EXT_AVIAN, EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS, MSG_REQUEST_EXTENSIONS_ERROR,
    MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM, MSG_SELECT_ALGORITHM_ERROR,
    MSG_SELECT_ALGORITHM_SUCCESS, TLV_FIELD_POW_TYPE,
};
use avian_sv2::block;
use avian_sv2::error::{Error, Result};
use avian_sv2::logln;
use avian_sv2::tlv;
use avian_sv2::transport::{Connection, ConnectionReader, ConnectionWriter, Frame};
use avian_sv2::wire::{Reader, Writer};
use avian_tdp::coinbase::{
    PayoutPlan, EXTENDED_EXTRANONCE_PREFIX, EXTENDED_EXTRANONCE_SIZE, MAX_COINBASE_TAG,
    MAX_HEIGHT_PUSH, MAX_SCRIPT_SIG,
};
use avian_tdp::tdp::PrevHash;
use avian_tdp::{SolutionSubmitter, Work};
use binary_sv2::GetSize;
use common_messages_sv2::{
    SetupConnectionError, SetupConnectionSuccess, MESSAGE_TYPE_SETUP_CONNECTION,
    MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
    SV2_MINING_PROTOCOL_DISCRIMINANT,
};
use mining_sv2::{
    OpenMiningChannelError, SubmitSharesError, UpdateChannelError, CHANNEL_BIT_SUBMIT_SHARES_ERROR,
    CHANNEL_BIT_UPDATE_CHANNEL_ERROR, MESSAGE_TYPE_CLOSE_CHANNEL,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
    MESSAGE_TYPE_UPDATE_CHANNEL, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
};

/// The bits of a submission that are the same in both forms.
struct SubmitMeta {
    sequence_number: u32,
}

/// One channel and the algorithm it is being served on.
///
/// The two travel together because the algorithm is no longer a property of
/// the connection: a channel may carry one the rest of the connection does
/// not, so the work, the target and the solution submitter all have to be
/// looked up per channel rather than taken from the session.
struct Served {
    channel: Arc<Channel>,
    algo: Arc<AlgoContext>,
}
use secp256k1::Keypair;

use crate::channel::{Channel, ChannelKind};
use crate::ratelimit::RateLimitConfig;
use crate::share::{PowHasher, Refusal, Submission};
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
    /// How many shares a minute each channel should average.
    ///
    /// Each channel's target is derived from this and the hash rate the worker
    /// declared when it opened, so a 1 kH/s CPU and a 25 MH/s card aim at the
    /// same cadence instead of differing by the ratio of their hardware. There
    /// is still no vardiff, in that the pool never moves a target on its own
    /// judgement, so a worker whose declaration was wrong keeps a cadence
    /// wrong by the same factor until it says otherwise with `UpdateChannel`.
    ///
    /// Nothing is paid by share weight here, so that costs a dashboard some
    /// liveliness and costs nobody any money. On a pool that shared a reward
    /// it would not be an acceptable trade.
    pub shares_per_minute: f64,
    /// The slowest worker the pool will believe in, in hashes a second.
    ///
    /// A declaration below this is raised to it. `nominal_hash_rate` is
    /// worker-supplied and unverifiable, and a worker that never sets it sends
    /// 1.0, which would otherwise derive a target of a few dozen hashes a
    /// share. Erring upwards costs an honestly slow worker part of its cadence
    /// and costs the pool nothing, which is not true of the other direction.
    pub min_hash_rate: f64,
    /// The fastest, for the same reason the other way about: a worker claiming
    /// a petahash would be handed a target nothing it owns can meet, and would
    /// sit there submitting nothing at all.
    pub max_hash_rate: f64,
    /// A share target set outright, instead of derived from the declaration.
    ///
    /// For regtest, where the derivation cannot do anything useful: one
    /// share's worth of work at any believable hash rate is already more than
    /// a regtest block, so the derived target always clamps to the network
    /// target and every share is also a block. That is correct, but it leaves
    /// no way to exercise a share that is not a block, which is most of what
    /// share handling does.
    ///
    /// Still bounded by the network target at the hard end and by the worker's
    /// own `max_target`, so it cannot lose a block or hand out a target the
    /// worker said it could not take. There is deliberately no command-line
    /// flag for it: on a real chain the cadence is the thing to set.
    pub share_target_override: Option<[u8; 32]>,
    pub rate_limit: RateLimitConfig,
}

impl ServerConfig {
    /// Checks the parts that would otherwise fail later and less clearly.
    ///
    /// An over-long coinbase tag is the sharp one: it would build a coinbase
    /// the node refuses, and the node says so only when a block is found,
    /// which for a solo pool can be weeks. So it is refused here, where an
    /// operator is reading the message.
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
        // A fee script with zero basis points is not checked: it is the
        // donations-only setup, where nothing is taken and a donate/ prefix
        // has somewhere to go. PayoutPlan emits no fee output for it on a
        // plain channel.
        if !self.shares_per_minute.is_finite() || self.shares_per_minute <= 0.0 {
            return Err(Error::Protocol(format!(
                "shares per minute must be above zero, not {}",
                self.shares_per_minute
            )));
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
        Ok(())
    }

    /// The target one channel's shares are judged against.
    ///
    /// Derived from the hash rate the worker declared, so that it averages
    /// [`Self::shares_per_minute`], then bounded at the hard end by the
    /// network target itself: a share must never be rarer than a block. On
    /// regtest the network target is the algorithm's own floor, so that bound
    /// is the one that applies and nearly every share is also a block.
    ///
    /// The easy end needs no separate bound. [`Self::min_hash_rate`] is what
    /// limits how easy the derivation can get, and the per-channel submission
    /// limiter is sized from `shares_per_minute` rather than from anything the
    /// worker said, so a worker that understates itself gets more shares than
    /// it should and is refused by the limiter rather than served by the pool.
    pub fn share_target(&self, declared: f32, network_target: &[u8; 32]) -> [u8; 32] {
        let target = match self.share_target_override {
            Some(target) => target,
            None => {
                let declared = f64::from(declared);
                // Not `clamp`, which panics on a NaN bound and would pass a
                // NaN declaration straight through.
                let believed = if declared.is_finite() {
                    declared.max(self.min_hash_rate).min(self.max_hash_rate)
                } else {
                    self.min_hash_rate
                };
                let work = block::hashes_per_share_for(believed, self.shares_per_minute);
                // Saturating, which is what `as` does to a float too large to
                // fit an integer.
                block::target_for_hashes_per_share(work as u128)
            }
        };
        if block::meets_target(network_target, &target) {
            target
        } else {
            *network_target
        }
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
    /// count accepted ones: the node's reply to a SubmitSolution says
    /// validation took the block and not that it won, so the next
    /// SetNewPrevHash is what settles it and a match is proof it connected.
    confirmed: AtomicU32,
    /// Hashes forwarded and not yet seen as a tip, with the channel and
    /// sequence number they came from so the miner can be told which share it
    /// was. Bounded: an unconfirmed block either becomes the tip within a few
    /// rounds or lost a race, and the pool cannot tell which.
    pending: Mutex<VecDeque<(u32, u32, [u8; 32])>>,
    /// Blocks this algorithm made, and who each was made for, newest last.
    ///
    /// Separate from `pending` above because it answers a different question
    /// and has to outlive the answer to that one. `pending` is a worklist
    /// that `confirm_tip` drains, so a block that connects leaves it within
    /// a round, usually inside a second: anything reading the endpoint
    /// slower than the chain moves would collect a list made up of the
    /// blocks that failed. This is kept whatever became of a block, because
    /// the one thing only the pool can say about a block is which worker
    /// found it, and the chain, which is the record of everything else,
    /// carries no worker label at all.
    found: Mutex<VecDeque<FoundBlock>>,
}

/// A block this pool made, and who it was made for.
#[derive(Clone)]
pub struct FoundBlock {
    /// Internal byte order, like every other hash the pool holds.
    pub hash: [u8; 32],
    /// The channel's worker label. Untrusted text, straight from the miner.
    pub worker: String,
    /// The whole address its coinbase pays, not a prefix. How much of it an
    /// endpoint will show is the endpoint's policy and is applied there, so
    /// that one rule covers this and the channel list rather than two rules
    /// that are free to disagree.
    pub payout_address: String,
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
            found: Mutex::new(VecDeque::new()),
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

    /// Blocks forwarded upstream whose hash has not been seen as the tip,
    /// oldest first, in internal byte order.
    ///
    /// The pool does not say what became of these, and three unrelated fates
    /// look the same from here: a block that lost a race, one whose tip
    /// announcement has not arrived yet, and one the node refused outright,
    /// since the refusal it sends is logged by the upstream reader rather
    /// than recorded here. Something beside the node can tell all three apart
    /// with `getblock`, so the hashes are handed out rather than kept as a
    /// number. Nothing is added to the pool to do this; the list is the one
    /// `confirm_tip` already drains.
    pub fn unconfirmed(&self) -> Vec<[u8; 32]> {
        self.pending
            .lock()
            .map(|pending| pending.iter().map(|(_, _, hash)| *hash).collect())
            .unwrap_or_default()
    }

    /// Every block this algorithm has made lately, oldest first.
    pub fn found(&self) -> Vec<FoundBlock> {
        self.found
            .lock()
            .map(|found| found.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Records who a forwarded block was made for.
    ///
    /// Thirty two, where `pending` keeps sixteen, and for the opposite
    /// reason: nothing drains this, so the bound is the whole of its length.
    /// At a rate that makes a solo pool worth running it is hours of
    /// history, which is far longer than anything needs to poll on, and the
    /// cost of being wrong about that is losing the attribution on the
    /// oldest block rather than losing the block.
    fn remember_found(&self, worker: &str, payout_address: &str, hash: [u8; 32]) {
        if let Ok(mut found) = self.found.lock() {
            found.push_back(FoundBlock {
                hash,
                worker: worker.to_string(),
                payout_address: payout_address.to_string(),
            });
            while found.len() > 32 {
                found.pop_front();
            }
        }
    }

    /// Records a forwarded block so a later tip can confirm it.
    fn remember_block(&self, channel_id: u32, sequence_number: u32, hash: [u8; 32]) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.push_back((channel_id, sequence_number, hash));
            // Sixteen unconfirmed blocks, not sixteen rounds: one that
            // becomes the tip is removed by confirm_tip, so only blocks that
            // look like they lost a race accumulate here, and the pool cannot
            // tell those from one whose tip announcement has not arrived yet.
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
                    logln!("[pool] channel {channel_id}: could not confirm its block: {e}");
                } else {
                    logln!("[pool] channel {channel_id}'s block is the tip now, told it so");
                }
            }
        }
    }

    /// The prev hash in force, so the page can show which tip is being mined.
    pub fn prev_hash(&self) -> Option<[u8; 32]> {
        self.state.lock().ok()?.prev.as_ref().map(|p| p.prev_hash)
    }

    /// The network target in force, from the same place a job takes it.
    ///
    /// Published so a channel's best share can be read against a block.
    /// Without it, the hash the pool reports is a number with no scale: a
    /// renderer would have to carry its own idea of the network's difficulty
    /// and would be free to disagree with the target shares are judged by.
    pub fn network_target(&self) -> Option<[u8; 32]> {
        self.state.lock().ok()?.prev.as_ref().map(|p| p.target)
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

        // A moved tip is the only evidence that a block the pool forwarded
        // won, so it is checked here, before the new work goes out. The
        // node's reply to a SubmitSolution says validation took the block,
        // which is a weaker claim than this one.
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
                        logln!("[pool] worker session ended: {e}");
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
        logln!("[pool] {peer} completed the Noise handshake");

        let identity = setup_connection(&mut reader, &writer)?;
        let extensions = request_extensions(&mut reader, &writer)?;
        let offered: Vec<PowType> = self.algos.iter().map(|algo| algo.pow).collect();
        let pow = select_algorithm(&mut reader, &writer, &offered)?;
        let algo = self
            .algo(pow)
            .ok_or_else(|| Error::Protocol(format!("no session for {pow}")))?;

        // A connection carries however many channels the worker opens, each
        // on whichever algorithm it asked for. `SelectAlgorithm` settles the
        // connection's default, which is what a channel gets when it says
        // nothing, and that is what every peer built before the TLV field
        // does.
        let mut channels: HashMap<u32, Served> = HashMap::new();
        let from = Peer {
            addr: peer,
            identity,
        };
        let result = self.pump(
            &mut reader,
            &writer,
            algo,
            &extensions,
            &mut channels,
            &from,
        );

        // Every channel, on its own algorithm. One left registered is one the
        // publisher goes on pushing work to, down a socket nobody reads.
        for served in channels.values() {
            served.algo.unregister(served.channel.id);
        }
        result
    }

    /// Refuses a share on a channel this connection does not have.
    ///
    /// A free function rather than a `Channel` method, because the whole point
    /// is that there is no such channel to call one on. The id is echoed back
    /// as the worker sent it, so it can see which one was not recognised.
    fn refuse_unknown_share(
        writer: &Arc<Mutex<ConnectionWriter>>,
        channel_id: u32,
        sequence_number: u32,
    ) -> Result<()> {
        send(
            writer,
            EXT_CORE_MINING,
            MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
            CHANNEL_BIT_SUBMIT_SHARES_ERROR,
            SubmitSharesError {
                channel_id,
                sequence_number,
                error_code: Refusal::InvalidChannelId.code().as_bytes().try_into()?,
            },
        )
    }

    /// The same for `UpdateChannel`, which has an error message of its own.
    fn refuse_unknown_update(writer: &Arc<Mutex<ConnectionWriter>>, channel_id: u32) -> Result<()> {
        send(
            writer,
            EXT_CORE_MINING,
            MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
            CHANNEL_BIT_UPDATE_CHANNEL_ERROR,
            UpdateChannelError {
                channel_id,
                error_code: b"invalid-channel-id".as_slice().try_into()?,
            },
        )
    }

    /// Opens one channel from an already-read `OpenStandardMiningChannel` or
    /// `OpenExtendedMiningChannel`.
    ///
    /// The frame is read by the caller's loop rather than here, because a
    /// channel open is no longer the one thing that can arrive first. It is
    /// one of several messages the connection dispatches, and it can arrive
    /// again later.
    ///
    /// A refusal returns [`Error::Refused`] after the worker has been told
    /// why. The caller keeps the connection for that, and only that: with
    /// several channels on one connection, tearing it down over one bad open
    /// would punish every other channel for a mistake that was not theirs.
    ///
    /// `default_algo` is the connection's, from `AvianSelectAlgorithm`. A
    /// channel may override it with a `pow_type` TLV field, in which case it
    /// is served on that algorithm and the connection's others are not
    /// affected.
    fn open_channel(
        &self,
        frame: &mut Frame,
        writer: &Arc<Mutex<ConnectionWriter>>,
        default_algo: &Arc<AlgoContext>,
        blocks_negotiated: bool,
        peer: &PeerIdentity,
    ) -> Result<Served> {
        // Both kinds are served, and REQUIRES_EXTENDED_CHANNELS is never set,
        // because serving both is the point: a miner that can only do
        // standard channels still works, and one that can do extended
        // channels gets to assemble its own coinbase and see what it is
        // committing to. For solo mining that verification is the product.
        let (request_id, identity, nominal_hash_rate, worker_max_target, kind, tlv_start) =
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
                        ChannelKind::Standard,
                        open.get_size(),
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
                                error_code: b"min-extranonce-size-too-large"
                                    .as_slice()
                                    .try_into()?,
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
                    let tlv_start = open.get_size();
                    (
                        open.request_id,
                        String::from_utf8_lossy(open.user_identity.as_ref()).into_owned(),
                        open.nominal_hash_rate,
                        max_target,
                        ChannelKind::Extended {
                            extranonce_size: size,
                        },
                        tlv_start,
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

        // Which algorithm this channel carries. A `pow_type` TLV field names
        // one; no field means the connection's, which is what everything
        // built before this sends and is why adding the field broke nothing.
        //
        // A malformed TLV region tears the connection down rather than
        // refusing the channel. A peer that cannot encode one correctly will
        // not encode the next one correctly either, and unlike a mistyped
        // address it is not something an operator can fix by retrying.
        let fields = tlv::parse(&frame.payload[tlv_start..]).map_err(|e| {
            Error::Protocol(format!(
                "the channel open carried a malformed TLV region: {e}"
            ))
        })?;
        let algo = match tlv::find(&fields, EXT_AVIAN, TLV_FIELD_POW_TYPE) {
            None => default_algo.clone(),
            Some(field) => {
                let declared = field.as_u8()?;
                let known = PowType::from_u8(declared).ok();
                match known.and_then(|pow| self.algo(pow).cloned()) {
                    Some(algo) => algo,
                    None => {
                        // Two different failures, and a worker can act on
                        // the difference: a value the chain does not define
                        // is the worker's bug, one the chain defines but
                        // this pool does not serve is the operator's
                        // configuration.
                        let code = if known.is_some() {
                            "pow-type-not-enabled"
                        } else {
                            "unsupported-pow-type"
                        };
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
                            "a channel asked for pow_type {declared} and this pool serves \
                             {:?} ({code})",
                            self.algos.iter().map(|a| a.pow).collect::<Vec<_>>()
                        )));
                    }
                }
            }
        };
        let algo = &algo;

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

        // Derived from the rate this worker declared, so it aims at the
        // configured cadence rather than at a fixed distance below the network
        // target, then clamped to whatever the worker said it could accept.
        let mut share_target = self.config.share_target(nominal_hash_rate, &prev.target);
        if !block::meets_target(&share_target, &worker_max_target) {
            share_target = worker_max_target;
        }

        // A donation adds to whatever the operator charges and goes to the
        // same script, so PayoutPlan needs to know nothing about it.
        //
        // With no fee script configured there is nowhere to send it, and the
        // miner simply keeps everything. Refusing the channel instead would
        // punish a miner for the operator's configuration, and paying them
        // more than they asked wrongs nobody, which is not true of the
        // reverse. It is logged so it is visible rather than silent.
        let mut fee_basis_points = self.config.fee_basis_points;
        if parsed.donation_basis_points > 0 {
            if self.config.fee_script.is_empty() {
                logln!(
                    "[pool] {} offered {}.{:02}% but no donation address is set, \
                     so it keeps the lot",
                    parsed.address_text,
                    parsed.donation_basis_points / 100,
                    parsed.donation_basis_points % 100
                );
            } else {
                // Capped, because the two are set by different people and
                // nothing else stops them summing past everything. At the cap
                // the worker output rounds to zero and PayoutPlan emits no
                // dust output for it.
                fee_basis_points = fee_basis_points
                    .saturating_add(parsed.donation_basis_points)
                    .min(10_000);
            }
        }

        let payout = PayoutPlan {
            worker_script: parsed.address.script_pubkey(),
            fee_script: self.config.fee_script.clone(),
            fee_basis_points,
        };

        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        let channel = Arc::new(Channel::new(
            id,
            kind,
            algo.pow,
            share_target,
            payout,
            parsed.donation_basis_points,
            parsed.worker.clone(),
            parsed.address_text.clone(),
            self.config.coinbase_tag.clone(),
            self.config.shares_per_minute,
            self.config.rate_limit,
            blocks_negotiated,
            peer.clone(),
            writer.clone(),
        ));
        logln!(
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
        Ok(Served {
            channel,
            algo: algo.clone(),
        })
    }

    /// Answers `UpdateChannel`: a worker revising the hash rate it declared
    /// when the channel opened.
    ///
    /// Honoured rather than refused, and the distinction is not vardiff.
    /// Vardiff is the pool moving a target on its own judgement, which it
    /// still never does. This is the worker asking, and the pool has a reason
    /// to listen: `ratelimit` sizes every channel's budget from the configured
    /// shares a minute, on the assumption that each channel's target makes it
    /// average that cadence. A declaration that has gone stale, because a card
    /// dropped out or throttled, is exactly what breaks that assumption, and
    /// this is the only message that repairs it without a reconnect.
    ///
    /// Refusing was the other option and it would have had to be dishonest:
    /// `UpdateChannel.Error` carries only `invalid-channel-id`,
    /// `invalid-nominal-hashrate` and `max-target-out-of-range`, and none of
    /// them means "I would rather not".
    fn update_channel(
        &self,
        algo: &Arc<AlgoContext>,
        channel: &Arc<Channel>,
        update: &mining_sv2::UpdateChannel,
    ) -> Result<()> {
        // The id was matched by the caller's routing, so there is nothing to
        // check here: an unknown one never reaches this.
        //
        // Worker-supplied and unverifiable, as at channel open, so it goes
        // through the same clamp. A non-finite or negative one is not
        // something share_target can floor into sense, and it is the one shape
        // the specification has an error code for.
        if !update.nominal_hash_rate.is_finite() || update.nominal_hash_rate < 0.0 {
            return channel.send_update_error(channel.id, "invalid-nominal-hashrate");
        }
        let Some((_, prev)) = algo.current() else {
            // No template, so no network target to clamp against and nothing
            // to derive. The target in force stands, which is the honest
            // answer rather than an error the worker cannot act on.
            return Ok(());
        };
        let mut target = self
            .config
            .share_target(update.nominal_hash_rate, &prev.target);
        let mut worker_max = [0u8; 32];
        worker_max.copy_from_slice(update.maximum_target.as_ref());
        // The worker's own ceiling wins, as it does at open.
        if !block::meets_target(&target, &worker_max) {
            target = worker_max;
        }
        if channel.retarget(target)? {
            logln!(
                "[pool] channel {} retargeted at its own request, now declaring {} H/s",
                channel.id,
                update.nominal_hash_rate
            );
        }
        Ok(())
    }

    /// The connection's message loop, for as many channels as it opens.
    fn pump(
        &self,
        reader: &mut ConnectionReader,
        writer: &Arc<Mutex<ConnectionWriter>>,
        algo: &Arc<AlgoContext>,
        negotiated: &[u16],
        channels: &mut HashMap<u32, Served>,
        from: &Peer,
    ) -> Result<()> {
        // Unpacked once so every log line below still names the address the
        // way it always has, and the claim stays a separate thing to pass on.
        let (peer, identity) = (from.addr, &from.identity);
        let blocks = negotiated.contains(&avian_sv2::avian::EXT_AVIAN_BLOCKS);
        loop {
            let mut frame = reader.recv()?;
            match (frame.extension_type, frame.msg_type) {
                (EXT_CORE_MINING, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL)
                | (EXT_CORE_MINING, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL) => {
                    match self.open_channel(&mut frame, writer, algo, blocks, identity) {
                        Ok(served) => {
                            logln!(
                                "[pool] {peer} opened channel {} on {}",
                                served.channel.id,
                                served.algo.pow
                            );
                            channels.insert(served.channel.id, served);
                        }
                        // Told, and told why, so the connection stands and
                        // whatever else it is carrying goes on working.
                        Err(Error::Refused(why)) => {
                            logln!("[pool] {peer} was refused a channel: {why}");
                        }
                        Err(e) => return Err(e),
                    }
                }
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
                    let Some(served) = channels.get(&channel_id) else {
                        Self::refuse_unknown_share(writer, channel_id, sequence_number)?;
                        continue;
                    };
                    // Shadowed so the body below reads as it did, but both
                    // now come from the channel rather than the connection.
                    let channel = &served.channel;
                    let algo = &served.algo;
                    // A miner must submit the form its channel was opened as.
                    if extended != channel.kind.is_extended() {
                        channel.send_error(sequence_number, Refusal::InvalidExtranonce)?;
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
                                Ok(()) => logln!(
                                    "[pool] channel {} reissued work after a desync",
                                    channel.id
                                ),
                                Err(e) => logln!(
                                    "[pool] channel {} could not be reissued work: {e}",
                                    channel.id
                                ),
                            }
                        }
                    }
                    if let Some(candidate) = outcome {
                        // A share at or under the network target is a block,
                        // so it goes up to the node. A refusal comes back as
                        // AvianSubmitSolution.Error, which the upstream
                        // reader logs; nothing here waits for it.
                        logln!(
                            "[pool] channel {} found a block for template {}, submitting",
                            channel.id,
                            candidate.template_id
                        );
                        channel.record_block();
                        algo.blocks.fetch_add(1, Ordering::Relaxed);
                        algo.remember_block(channel.id, submit.sequence_number, candidate.hash);
                        algo.remember_found(
                            &channel.worker,
                            &channel.payout_address,
                            candidate.hash,
                        );
                        // Told before the node is asked, because this
                        // notification means the share was a block and not
                        // that the node took it, and the miner is the one
                        // that cares.
                        if let Err(e) =
                            channel.send_block_found(submit.sequence_number, &candidate.hash, false)
                        {
                            logln!(
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
                (EXT_CORE_MINING, MESSAGE_TYPE_UPDATE_CHANNEL) => {
                    let update: mining_sv2::UpdateChannel =
                        binary_sv2::from_bytes(&mut frame.payload)?;
                    let Some(served) = channels.get(&update.channel_id) else {
                        Self::refuse_unknown_update(writer, update.channel_id)?;
                        continue;
                    };
                    self.update_channel(&served.algo, &served.channel, &update)?;
                }
                (EXT_CORE_MINING, MESSAGE_TYPE_CLOSE_CHANNEL) => {
                    let close: mining_sv2::CloseChannel =
                        binary_sv2::from_bytes(&mut frame.payload)?;
                    let reason = String::from_utf8_lossy(close.reason_code.as_ref()).into_owned();
                    match channels.remove(&close.channel_id) {
                        Some(served) => {
                            // Unregistered here and not only at the end,
                            // because the publisher would otherwise go on
                            // pushing work to a channel the worker has said
                            // it is finished with. On its own algorithm,
                            // which need not be the connection's.
                            served.algo.unregister(served.channel.id);
                            logln!(
                                "[pool] channel {} closed by the worker: {reason}",
                                served.channel.id
                            );
                        }
                        None => {
                            // There is no CloseChannel.Error to answer with.
                            // Logged and dropped rather than guessed at.
                            logln!(
                                "[pool] {peer} asked to close channel {}, which it does not have",
                                close.channel_id
                            );
                        }
                    }
                    // The connection stands. Closing a channel is not closing
                    // a connection, and a worker may open another.
                }
                _ => {
                    // A message number this build does not know, inside an
                    // extension it granted, means the worker was built at
                    // another time. Reading past it is what lets a message be
                    // added at all; disconnecting would break every worker
                    // built before the next one. An extension that was never
                    // negotiated, or an unknown core message, still ends the
                    // connection.
                    if frame.is_skippable(negotiated) {
                        logln!(
                            "[pool] {peer} sent {}, which this build does not serve; ignoring it",
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

pub struct ServerHandle {
    addr: SocketAddr,
    _thread: std::thread::JoinHandle<()>,
}

impl ServerHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

pub fn send<T: binary_sv2::Serialize + binary_sv2::GetSize>(
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

pub fn send_raw(
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

/// What a worker said it is, from the tail of `SetupConnection`.
///
/// The protocol reserves four free-text fields for this and the pool read
/// past every one of them until now, which left no way to tell a rig on last
/// month's build from one on today's. That is worth more here than on a pool
/// with vardiff: the share target is derived from the hash rate a worker
/// declares when it opens a channel and then never moves, so which build did
/// the declaring decides whether the whole session is aimed correctly.
///
/// Every field is the worker's claim about itself. Nothing in here is
/// checked, nothing in here can be checked, and anything that displays it
/// should say so rather than present it as something the pool established.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Who makes the software, as it describes itself.
    pub vendor: String,
    /// Which build. The specification names the field for firmware, which
    /// for a software miner is its version.
    pub firmware: String,
}

/// The other end of a connection: where it dialled from, and what it says
/// it is running.
///
/// One argument rather than two because they travel together everywhere and
/// answer the same question. The address is the pool's own observation; the
/// identity is the worker's claim, and keeping them in one place is a
/// reminder that a line printing both is printing one of each.
pub struct Peer {
    pub addr: SocketAddr,
    pub identity: PeerIdentity,
}

impl PeerIdentity {
    /// Reads the fields that follow the flags.
    ///
    /// `endpoint_host` and `endpoint_port` are read only to get past them:
    /// they are what the worker believes it dialled, and the pool knows its
    /// own address better than a worker does. `device_id` comes after
    /// `firmware` and is left unread, because it names one unit of hardware
    /// to the vendor that built it and this pool has no use for it.
    fn read(r: &mut Reader) -> Result<Self> {
        let _endpoint_host = r.text()?;
        let _endpoint_port = r.u16()?;
        let vendor = r.text()?;
        let _hardware_version = r.text()?;
        let firmware = r.text()?;
        Ok(Self { vendor, firmware })
    }
}

/// `SetupConnection` with the v1 contract from doc/sv2.md.
/// Public because the bridge serves the same handshake in front of a
/// different pool: `SetupConnection` is the protocol, not solo policy.
pub fn setup_connection(
    reader: &mut ConnectionReader,
    writer: &Arc<Mutex<ConnectionWriter>>,
) -> Result<PeerIdentity> {
    let frame = reader.recv_expect(EXT_CORE_MINING, MESSAGE_TYPE_SETUP_CONNECTION)?;
    // Hand-decoded rather than through SRI's SetupConnection, because that
    // struct's `protocol` is an enum and an unknown discriminant has to be
    // answerable with unsupported-protocol rather than a decode failure.
    let mut r = Reader::new(&frame.payload);
    let protocol = r.u8()?;
    let min_version = r.u16()?;
    let max_version = r.u16()?;
    let requested = r.u32()?;

    let refuse = |flags: u32, code: &str| -> Result<PeerIdentity> {
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

    // Read after every check that can refuse this connection, and never
    // allowed to cause one. A worker whose identity fields are malformed is
    // still a worker with hash rate, and trading a mining session for a label
    // nobody needs would be the wrong way round. A peer that sends nothing
    // readable is simply a peer that said nothing about itself.
    let identity = PeerIdentity::read(&mut r).unwrap_or_default();

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
    )?;
    Ok(identity)
}

/// The upstream half of the Extensions Negotiation extension.
///
/// The pool requires `0x4001` of its workers for the same reason the node
/// requires it of the pool: every failure mode the extension prevents is
/// silent, so a worker that has not negotiated it is refused rather than
/// served work it cannot mine correctly.
/// Public for the bridge, like [`setup_connection`].
/// Answers `RequestExtensions`, returning what was agreed.
///
/// `EXT_AVIAN` is required and its absence refuses the connection.
/// `EXT_AVIAN_BLOCKS` is optional: a client that does not ask for it is served
/// exactly as before and is never sent a block notification, which is the
/// whole reason that message no longer lives inside `EXT_AVIAN`.
pub fn request_extensions(
    reader: &mut ConnectionReader,
    writer: &Arc<Mutex<ConnectionWriter>>,
) -> Result<Vec<u16>> {
    let frame = reader.recv_expect(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS)?;
    let mut r = Reader::new(&frame.payload);
    let request_id = r.u16()?;
    let wanted = r.seq_u16()?;
    r.done()?;

    if !wanted.contains(&EXT_AVIAN) {
        let unsupported: Vec<u16> = wanted
            .iter()
            .copied()
            .filter(|ext| *ext != EXT_AVIAN && *ext != avian_sv2::avian::EXT_AVIAN_BLOCKS)
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

    let mut accepted = vec![EXT_AVIAN];
    if wanted.contains(&avian_sv2::avian::EXT_AVIAN_BLOCKS) {
        accepted.push(avian_sv2::avian::EXT_AVIAN_BLOCKS);
    }
    let mut w = Writer::new();
    let payload = w.u16(request_id).seq_u16(&accepted).finish();
    send_raw(
        writer,
        EXT_NEGOTIATION,
        MSG_REQUEST_EXTENSIONS_SUCCESS,
        false,
        &payload,
    )?;
    Ok(accepted)
}

/// Answers `AvianSelectAlgorithm` with one of `offered`, or refuses.
///
/// Takes the algorithms rather than the solo pool's per-algorithm contexts,
/// so the bridge, which has an upstream pool per algorithm instead, can
/// serve the same step.
pub fn select_algorithm(
    reader: &mut ConnectionReader,
    writer: &Arc<Mutex<ConnectionWriter>>,
    offered: &[PowType],
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
    if !offered.contains(&pow) {
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

#[cfg(test)]
mod unconfirmed_tests {
    use super::*;
    use avian_tdp::SubmitterSlot;

    fn context() -> AlgoContext {
        // A submitter with nothing behind it: these tests never submit.
        AlgoContext::new(PowType::X16rt, SubmitterSlot::new().submitter())
    }

    fn hash(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn attribution_outlives_the_confirmation_that_drains_the_worklist() {
        // The whole reason this list is separate from the one above. A block
        // that becomes the tip leaves the worklist at once, and who found it
        // is asked long afterwards by something reading the chain, so the
        // answer has to still be here when it is.
        let algo = context();
        algo.remember_block(1, 1, hash(1));
        algo.remember_found("rig-a", "RXp2d4address", hash(1));
        algo.confirm_tip(&hash(1), &[]);

        assert!(algo.unconfirmed().is_empty());
        let found = algo.found();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].hash, hash(1));
        assert_eq!(found[0].worker, "rig-a");
        assert_eq!(found[0].payout_address, "RXp2d4address");
    }

    #[test]
    fn the_oldest_attribution_goes_rather_than_the_list_growing() {
        let algo = context();
        for i in 0..40u8 {
            algo.remember_found("rig", "RXp2d4address", hash(i));
        }
        let found = algo.found();
        assert_eq!(found.len(), 32);
        // Oldest first, so what survives is the last thirty two: whatever
        // somebody might still be asking about, rather than this morning.
        assert_eq!(found[0].hash, hash(8));
        assert_eq!(found[31].hash, hash(39));
    }

    #[test]
    fn a_block_stays_listed_until_its_hash_is_the_tip() {
        let algo = context();
        algo.remember_block(1, 1, hash(1));
        algo.remember_block(1, 2, hash(2));
        algo.remember_block(2, 1, hash(3));
        assert_eq!(algo.unconfirmed(), vec![hash(1), hash(2), hash(3)]);

        // No channels to tell: confirmation is the hash leaving the list.
        algo.confirm_tip(&hash(2), &[]);
        assert_eq!(algo.confirmed(), 1);
        assert_eq!(
            algo.unconfirmed(),
            vec![hash(1), hash(3)],
            "the ones that did not become the tip stay, in the order submitted"
        );

        algo.confirm_tip(&hash(9), &[]);
        assert_eq!(
            algo.confirmed(),
            1,
            "a tip the pool did not mine confirms nothing"
        );
        assert_eq!(algo.unconfirmed(), vec![hash(1), hash(3)]);
    }

    #[test]
    fn the_list_drops_its_oldest_past_sixteen() {
        let algo = context();
        for n in 0..20u8 {
            algo.remember_block(1, u32::from(n), hash(n));
        }
        let listed = algo.unconfirmed();
        assert_eq!(listed.len(), 16);
        assert_eq!(listed[0], hash(4), "the four oldest went first");
        assert_eq!(listed[15], hash(19));
    }
}

#[cfg(test)]
mod share_target_tests {
    use super::*;
    use crate::stats::hashes_per_share;

    /// Regtest's own target: the algorithm's floor, met by about half of all
    /// nonces.
    fn regtest_target() -> [u8; 32] {
        let mut target = [0u8; 32];
        target[31] = 0x7f;
        target[30] = 0xff;
        target[29] = 0xff;
        target
    }

    /// A network target of one: harder than any target the derivation can
    /// produce, so the never-rarer-than-a-block bound cannot fire and the
    /// derivation itself is what is under test. Absurd as a real chain, which
    /// is why it is only here.
    fn no_block_bound() -> [u8; 32] {
        let mut target = [0u8; 32];
        target[0] = 0x01;
        target
    }

    fn config(shares_per_minute: f64) -> ServerConfig {
        ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            authority: Keypair::from_seckey_slice(&secp256k1::Secp256k1::new(), &[1u8; 32])
                .unwrap(),
            cert_validity: 3600,
            network: Network::Regtest,
            fee_script: Vec::new(),
            fee_basis_points: 0,
            coinbase_tag: b"/test/".to_vec(),
            allow_public_bind: false,
            shares_per_minute,
            min_hash_rate: 1000.0,
            max_hash_rate: 1e12,
            share_target_override: None,
            rate_limit: RateLimitConfig::default(),
        }
    }

    #[test]
    fn a_declared_rate_becomes_the_cadence_the_pool_asked_for() {
        // The first row is this machine's measured MinotaurX rate; the third
        // is the RX 6900 XT on X16RT. They differ by a factor of 1400 and must
        // come out at the same cadence, which is the whole point.
        for (declared, shares_per_minute) in [
            (17_440.0f32, 4.5f64),
            (1_200.0, 4.5),
            (25_000_000.0, 6.0),
            (1_000_000.0, 1.0),
        ] {
            let target = config(shares_per_minute).share_target(declared, &no_block_bound());
            let work = hashes_per_share(&target);
            let want = f64::from(declared) * 60.0 / shares_per_minute;
            assert!(
                // Not exact: the work is truncated to an integer before the
                // target is built, and `hashes_per_share` reads it back as
                // `2^256 / (t + 1)` rather than `(2^256 - t) / (t + 1)`.
                // Both are worth about one hash in a quarter million.
                (work - want).abs() / want < 1e-4,
                "{declared} H/s at {shares_per_minute} a minute wanted {want} \
                 hashes a share and got {work}"
            );
        }
    }

    #[test]
    fn a_declaration_below_the_floor_is_not_believed() {
        let config = config(4.5);
        // 1.0 is what a worker that never sets the field sends, and is the
        // default in this library's own client. Taken at face value it would
        // derive a target of thirteen hashes a share.
        let unset = config.share_target(1.0, &no_block_bound());
        let floored = config.share_target(config.min_hash_rate as f32, &no_block_bound());
        assert_eq!(unset, floored);
        assert!(
            hashes_per_share(&unset) > 10_000.0,
            "the protocol default was taken at face value"
        );
    }

    #[test]
    fn a_declaration_above_the_ceiling_is_capped() {
        let config = config(4.5);
        let work = hashes_per_share(&config.share_target(1e15, &no_block_bound()));
        let want = config.max_hash_rate * 60.0 / config.shares_per_minute;
        assert!(
            (work - want).abs() / want < 1e-4,
            "a petahash claim bought {work} hashes a share and the cap is {want}"
        );
        // Everything past the cap lands in the same place. Compared this
        // way round rather than against `max_hash_rate as f32`, which is
        // not 1e12: an f32 has 24 bits of mantissa and that needs 40.
        assert_eq!(
            config.share_target(1e15, &no_block_bound()),
            config.share_target(1e20, &no_block_bound())
        );
    }

    #[test]
    fn an_unusable_declaration_falls_back_to_the_floor() {
        let config = config(4.5);
        let floored = config.share_target(config.min_hash_rate as f32, &no_block_bound());
        for declared in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -5.0, 0.0] {
            assert_eq!(
                config.share_target(declared, &no_block_bound()),
                floored,
                "a declaration of {declared} should fall back to the floor"
            );
        }
    }

    #[test]
    fn a_share_is_never_rarer_than_a_block() {
        // On regtest one share's worth of work at any believable rate is more
        // than a whole block, so the derivation is clamped and every share is
        // also a block. Without this bound the pool would reject a hash that
        // met the network target, which is to say it would throw away a block.
        let network = regtest_target();
        assert_eq!(config(4.5).share_target(17_440.0, &network), network);
        assert_eq!(config(600.0).share_target(1_000.0, &network), network);
    }

    #[test]
    fn an_override_replaces_the_derivation_but_not_the_block_bound() {
        let mut config = config(4.5);
        config.share_target_override = Some([0xff; 32]);
        assert_eq!(config.share_target(17_440.0, &no_block_bound()), [0xff; 32]);
        // An override harder than the network target would lose blocks the
        // same way the derivation would, so it is bounded too.
        let network = regtest_target();
        config.share_target_override = Some(block::harder_by(&network, 40));
        assert_eq!(config.share_target(17_440.0, &network), network);
    }

    #[test]
    fn an_impossible_cadence_is_refused_at_startup() {
        assert!(config(4.5).validate().is_ok());
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(
                config(bad).validate().is_err(),
                "a cadence of {bad} should be refused"
            );
        }
        let mut zero_floor = config(4.5);
        zero_floor.min_hash_rate = 0.0;
        assert!(zero_floor.validate().is_err());
        let mut inverted = config(4.5);
        inverted.max_hash_rate = 1.0;
        assert!(inverted.validate().is_err());
        // A NaN ceiling is refused too, and is the reason the check is
        // written as a NaN test rather than as `max < min`: a NaN compares
        // false against everything, so `max < min` would let it through and
        // the bound would then quietly do nothing.
        let mut not_a_number = config(4.5);
        not_a_number.max_hash_rate = f64::NAN;
        assert!(not_a_number.validate().is_err());
    }

    #[test]
    fn a_fee_address_with_a_zero_fee_is_the_donations_only_setup() {
        let mut donations_only = config(4.5);
        donations_only.fee_script = vec![0x51];
        donations_only.fee_basis_points = 0;
        assert!(
            donations_only.validate().is_ok(),
            "charging nothing and still accepting donations is a valid setup"
        );
        // The two refusals that remain are still refusals.
        let mut no_address = config(4.5);
        no_address.fee_basis_points = 25;
        assert!(no_address.validate().is_err());
        let mut whole_coinbase = config(4.5);
        whole_coinbase.fee_script = vec![0x51];
        whole_coinbase.fee_basis_points = 10_001;
        assert!(whole_coinbase.validate().is_err());
    }
}

#[cfg(test)]
mod peer_identity_tests {
    use super::*;

    /// The tail of a `SetupConnection`, from `endpoint_host` on.
    fn tail(host: &str, port: u16, vendor: &str, hardware: &str, firmware: &str) -> Vec<u8> {
        fn text(out: &mut Vec<u8>, value: &str) {
            out.push(value.len() as u8);
            out.extend_from_slice(value.as_bytes());
        }
        let mut out = Vec::new();
        text(&mut out, host);
        out.extend_from_slice(&port.to_le_bytes());
        text(&mut out, vendor);
        text(&mut out, hardware);
        text(&mut out, firmware);
        out
    }

    #[test]
    fn the_vendor_and_the_build_are_read_out_of_the_right_fields() {
        // The order is the specification's, and getting it wrong does not
        // fail: it reports the hardware string as the version, or the host
        // as the vendor, and looks plausible on a page either way.
        let bytes = tail("pool.example", 3333, "avian-miner", "ryzen", "1.2.0");
        let identity = PeerIdentity::read(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(identity.vendor, "avian-miner");
        assert_eq!(identity.firmware, "1.2.0");
    }

    #[test]
    fn a_worker_that_fills_nothing_in_says_nothing() {
        let bytes = tail("0.0.0.0", 0, "", "", "");
        let identity = PeerIdentity::read(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(identity.vendor, "");
        assert_eq!(identity.firmware, "");
    }

    #[test]
    fn a_truncated_tail_is_an_error_the_handshake_swallows() {
        // Every miner built before the pool read these fields still has to
        // mine. The read fails and `setup_connection` takes the default,
        // which is why this asserts the error rather than a panic: the
        // failure has to be the ordinary kind that `unwrap_or_default`
        // turns into an empty identity.
        let mut bytes = tail("0.0.0.0", 0, "avian-miner", "", "1.2.0");
        bytes.truncate(bytes.len() - 3);
        assert!(PeerIdentity::read(&mut Reader::new(&bytes)).is_err());
        assert_eq!(
            PeerIdentity::read(&mut Reader::new(&bytes)).unwrap_or_default(),
            PeerIdentity::default()
        );
    }

    #[test]
    fn nothing_at_all_is_an_empty_identity_and_not_a_panic() {
        assert!(PeerIdentity::read(&mut Reader::new(&[])).is_err());
    }
}
