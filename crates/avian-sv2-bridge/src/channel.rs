//! One downstream channel, and the upstream Stratum v1 session behind it.
//!
//! The solo pool's channel is solo policy through and through: a coinbase
//! from a payout plan, a verdict the moment a share is hashed, a target fixed
//! at open. This channel differs in exactly those three places. A job comes
//! from a `mining.notify` and the coinbase arrives already built; a share's
//! verdict is the upstream pool's and arrives later, matched back to the
//! miner's sequence number; and the target is the pool's difficulty, which
//! moves whenever `mining.set_difficulty` says so. Everything under those is
//! shared with the solo pool rather than copied: the job, the metadata checks
//! in `share::validate`, the submission limiter, and the Stratum v2 messages.
//!
//! Two threads touch a channel. The one reading the miner answers its
//! submissions; the one draining the upstream client pushes jobs, moves the
//! target and delivers verdicts. Both go through the same writer mutex, which
//! keeps a round of work contiguous on the wire exactly as it does on the
//! solo pool.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use avian_mining::channel::ChannelKind;
use avian_mining::job::{self, Job, JobWork, Window};
use avian_mining::ratelimit::{self, Decision, Limiter, RateLimitConfig};
use avian_mining::share::{self, Outcome, PowHasher, Refusal, Submission};
use avian_mining::EXT_CORE_MINING;
use avian_sv1::client::Client;
use avian_sv1::difficulty;
use avian_sv1::message::{Notify, Subscription};
use avian_sv2::avian::{self, PowType, EXT_AVIAN, MSG_JOB_TIME_CONSTRAINTS, TIME_MASK};
use avian_sv2::block;
use avian_sv2::error::{Error, Result};
use avian_sv2::logln;
use avian_sv2::transport::ConnectionWriter;
use avian_tdp::coinbase::CoinbaseSplit;
use binary_sv2::{Seq0255, Sv2Option, U256};
use mining_sv2::{
    NewExtendedMiningJob, NewMiningJob, OpenExtendedMiningChannelSuccess,
    OpenStandardMiningChannelSuccess, SetNewPrevHash, SetTarget, SubmitSharesError,
    SubmitSharesSuccess, CHANNEL_BIT_MINING_SET_NEW_PREV_HASH, CHANNEL_BIT_NEW_EXTENDED_MINING_JOB,
    CHANNEL_BIT_NEW_MINING_JOB, CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, CHANNEL_BIT_SET_TARGET,
    CHANNEL_BIT_SUBMIT_SHARES_ERROR, CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_TARGET,
    MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};

/// How many upstream jobs stay submittable on one channel.
///
/// More than the solo pool keeps, because the verdict is not this bridge's
/// to give: a Stratum v1 pool decides for itself how long a job stays valid,
/// and a share the bridge still remembers is one the pool gets to judge. A
/// share against anything older is answered here, and that answer is
/// `invalid-job-id` rather than `stale-share` because the bridge cannot know
/// which the pool would have said.
const JOBS_RETAINED: usize = 8;

/// A job as the miner has it, plus what the pool needs to hear back.
struct BridgeJob {
    job: Job,
    /// `mining.notify`'s `job_id`, echoed in `mining.submit` and never
    /// interpreted.
    upstream_id: String,
    /// On a standard channel, the `extranonce2` this bridge chose when it
    /// built the merkle root; the miner never sees it and the pool needs it
    /// back. Empty on an extended channel, where the miner's own extranonce
    /// is the `extranonce2`.
    extranonce2: Vec<u8>,
}

pub struct BridgeChannel {
    pub id: u32,
    pub kind: ChannelKind,
    pub pow: PowType,
    /// What the miner put in `user_identity`, passed to the pool verbatim
    /// in `mining.authorize` and again on every `mining.submit`. The pool
    /// keys its accounting on it, so the bridge never rewrites it.
    pub identity: String,
    upstream: Arc<Client>,
    pow_limit: [u8; 32],
    /// The easiest target the miner said it would take.
    worker_max_target: [u8; 32],
    /// What the miner declared, which sizes the limiter: the expected share
    /// rate here is that times the chance a hash meets the pool's target,
    /// because the target is the pool's and not derived to hit a cadence.
    nominal_hash_rate: f64,
    /// How far past a job's `ntime` a miner may roll. Zero pins it.
    ntime_roll: u32,
    rate_limit: RateLimitConfig,
    /// Whether this peer negotiated `EXT_AVIAN_BLOCKS`. False means it is
    /// never sent a block notification, which is what makes the message safe
    /// to serve to clients built before it existed.
    blocks_negotiated: bool,
    writer: Arc<Mutex<ConnectionWriter>>,
    state: Mutex<State>,
}

struct State {
    subscription: Subscription,
    difficulty: f64,
    share_target: [u8; 32],
    next_job_id: u32,
    jobs: VecDeque<BridgeJob>,
    /// The tip in force, from the last job. `None` until the first, which is
    /// what makes the first job a future one.
    prev_hash: Option<[u8; 32]>,
    /// Standard channels only: the next `extranonce2`, so two jobs on one
    /// tip never hand the miner the same header.
    extranonce2_counter: u64,
    /// Shares forwarded and not yet judged, by the upstream request id, so a
    /// verdict can be matched to the miner's sequence number.
    pending: HashMap<u64, u32>,
    accepted: u32,
    shares: u64,
    /// The extranonce is part of the fingerprint, unlike on the solo pool:
    /// on an extended channel two shares can legitimately share a nonce and
    /// an ntime and differ only in the extranonce the miner rolled.
    seen: HashSet<(u32, u32, u32, Vec<u8>)>,
    limiter: Limiter,
}

impl BridgeChannel {
    /// Builds the channel from the upstream session's first word on the
    /// extranonce and on difficulty. Fails only if the two halves of the
    /// extranonce disagree or the difficulty is unusable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u32,
        kind: ChannelKind,
        pow: PowType,
        identity: String,
        upstream: Arc<Client>,
        subscription: Subscription,
        difficulty: f64,
        pow_limit: [u8; 32],
        worker_max_target: [u8; 32],
        nominal_hash_rate: f64,
        ntime_roll: u32,
        rate_limit: RateLimitConfig,
        blocks_negotiated: bool,
        writer: Arc<Mutex<ConnectionWriter>>,
    ) -> Result<Self> {
        if let ChannelKind::Extended { extranonce_size } = kind {
            if extranonce_size != subscription.extranonce2_size {
                return Err(Error::Protocol(format!(
                    "an extended channel was opened with {extranonce_size} bytes of extranonce \
                     and the pool's extranonce2 is {} bytes",
                    subscription.extranonce2_size
                )));
            }
        }
        let share_target = share_target_for(&pow_limit, difficulty, &worker_max_target)?;
        let limiter = limiter_for(nominal_hash_rate, &share_target, rate_limit);
        Ok(Self {
            id,
            kind,
            pow,
            identity,
            upstream,
            pow_limit,
            worker_max_target,
            nominal_hash_rate,
            ntime_roll,
            rate_limit,
            blocks_negotiated,
            writer,
            state: Mutex::new(State {
                subscription,
                difficulty,
                share_target,
                next_job_id: 1,
                jobs: VecDeque::new(),
                prev_hash: None,
                extranonce2_counter: 0,
                pending: HashMap::new(),
                accepted: 0,
                shares: 0,
                seen: HashSet::new(),
                limiter,
            }),
        })
    }

    pub fn share_target(&self) -> [u8; 32] {
        self.lock_state().map(|s| s.share_target).unwrap_or([0; 32])
    }

    pub fn difficulty(&self) -> f64 {
        self.lock_state().map(|s| s.difficulty).unwrap_or(0.0)
    }

    /// Submissions per second this channel may sustain, for logging.
    pub fn submission_rate(&self) -> f64 {
        self.lock_state().map(|s| s.limiter.rate()).unwrap_or(0.0)
    }

    pub fn accepted(&self) -> u32 {
        self.lock_state().map(|s| s.accepted).unwrap_or(0)
    }

    /// Invalid submissions so far, and submissions refused for rate.
    pub fn refusals(&self) -> (u32, u64) {
        self.lock_state()
            .map(|s| (s.limiter.invalid(), s.limiter.refused_for_rate()))
            .unwrap_or((0, 0))
    }

    /// Shares forwarded and still waiting on the pool.
    pub fn pending(&self) -> usize {
        self.lock_state().map(|s| s.pending.len()).unwrap_or(0)
    }

    /// Answers the channel open and states the target, in the same two
    /// messages the solo pool sends. The `extranonce_prefix` is the pool's
    /// `extranonce1` on both kinds of channel: on an extended one it is the
    /// half the miner prepends, on a standard one it is informational.
    pub fn send_open_success(&self, request_id: u32) -> Result<()> {
        let (target, prefix, size) = {
            let state = self.lock_state()?;
            (
                state.share_target,
                state.subscription.extranonce1.clone(),
                state.subscription.extranonce2_size,
            )
        };
        let mut writer = self.lock_writer()?;
        match self.kind {
            ChannelKind::Standard => writer.send(
                EXT_CORE_MINING,
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                OpenStandardMiningChannelSuccess {
                    request_id,
                    channel_id: self.id,
                    target: U256::try_from(target.as_slice())?,
                    extranonce_prefix: prefix.as_slice().try_into()?,
                    group_channel_id: 0,
                },
            )?,
            ChannelKind::Extended { .. } => writer.send(
                EXT_CORE_MINING,
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                OpenExtendedMiningChannelSuccess {
                    request_id,
                    channel_id: self.id,
                    target: U256::try_from(target.as_slice())?,
                    extranonce_size: size as u16,
                    extranonce_prefix: prefix.as_slice().try_into()?,
                    group_channel_id: 0,
                },
            )?,
        }
        writer.send(
            EXT_CORE_MINING,
            MESSAGE_TYPE_SET_TARGET,
            CHANNEL_BIT_SET_TARGET,
            SetTarget {
                channel_id: self.id,
                maximum_target: U256::try_from(target.as_slice())?,
            },
        )
    }

    /// Turns one `mining.notify` into one round of work and pushes it.
    ///
    /// The round goes out in the order doc/sv2.md requires and the solo pool
    /// uses: the job, its time constraints, and then, when the tip moved, the
    /// `SetNewPrevHash` that activates it. A notify on the same tip is an
    /// active job from the start, which is what a `NewMiningJob` with
    /// `min_ntime` set means. `clean_jobs` on the same tip has no Stratum v2
    /// equivalent, so the bridge forgets its own copies of the earlier jobs
    /// and answers a share against one with `invalid-job-id`; the pool would
    /// have refused it anyway.
    pub fn push_job(&self, notify: &Notify) -> Result<()> {
        let mut state = self.lock_state()?;
        let tip_changed = state.prev_hash != Some(notify.prev_hash);

        let job_id = state.next_job_id;
        state.next_job_id = state.next_job_id.wrapping_add(1).max(1);
        let window = window_for(notify.ntime, self.ntime_roll, self.pow);

        let work = match self.kind {
            ChannelKind::Standard => {
                // The whole extranonce is the bridge's to choose, and the
                // miner never sees it as search space: it rolls the nonce
                // and, within the window, the ntime. A counter keeps two
                // jobs on one tip from being the same header.
                let extranonce2 = extranonce2_for(
                    state.extranonce2_counter,
                    state.subscription.extranonce2_size,
                );
                state.extranonce2_counter = state.extranonce2_counter.wrapping_add(1);
                let mut full = state.subscription.extranonce1.clone();
                full.extend_from_slice(&extranonce2);
                let split = split_for(notify, full.len());
                let root = block::merkle_root(&split.txid(&full)?, &notify.merkle_branch);
                (
                    JobWork::Standard {
                        merkle_root: root,
                        // The solo pool keeps the witnessed coinbase here for
                        // SubmitSolution. The bridge never submits a block,
                        // the pool does, so there is nothing to keep.
                        coinbase: Vec::new(),
                    },
                    extranonce2,
                )
            }
            ChannelKind::Extended { extranonce_size } => (
                JobWork::Extended {
                    split: split_for(
                        notify,
                        state.subscription.extranonce1.len() + extranonce_size,
                    ),
                    merkle_path: notify.merkle_branch.clone(),
                    extranonce_prefix: state.subscription.extranonce1.clone(),
                    extranonce_size,
                },
                Vec::new(),
            ),
        };
        let (work, extranonce2) = work;

        let mut job = Job {
            job_id,
            // A template id is the node's; the pool's job id is a string and
            // lives beside the job.
            template_id: 0,
            version: notify.version,
            prev_hash: notify.prev_hash,
            nbits: notify.nbits,
            window,
            network_target: block::target_from_nbits(notify.nbits),
            work,
            future: tip_changed,
        };

        // The pool's job declares its algorithm in nVersion, and a job for
        // the other one means the operator pointed this upstream at the wrong
        // port. Nothing downstream can mine it, so the session ends here with
        // the reason in the log rather than every share being refused.
        let declared = job::pow_type_of(&job)?;
        if declared != self.pow {
            return Err(Error::Protocol(format!(
                "the upstream pool sent a {declared} job on a {} channel: is the {} upstream \
                 pointed at the right port?",
                self.pow, self.pow
            )));
        }

        let mut writer = self.lock_writer()?;
        let min_ntime = Sv2Option::new(if tip_changed {
            None
        } else {
            Some(job.window.ntime_min)
        });
        match &job.work {
            JobWork::Standard { merkle_root, .. } => {
                let merkle_root = *merkle_root;
                writer.send(
                    EXT_CORE_MINING,
                    MESSAGE_TYPE_NEW_MINING_JOB,
                    CHANNEL_BIT_NEW_MINING_JOB,
                    NewMiningJob {
                        channel_id: self.id,
                        job_id,
                        min_ntime,
                        version: job.version,
                        merkle_root: U256::try_from(merkle_root.as_slice())?,
                    },
                )?;
            }
            JobWork::Extended {
                split, merkle_path, ..
            } => {
                let path: Vec<U256> = merkle_path
                    .iter()
                    .map(|hash| U256::try_from(hash.as_slice()))
                    .collect::<std::result::Result<_, _>>()?;
                writer.send(
                    EXT_CORE_MINING,
                    MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                    CHANNEL_BIT_NEW_EXTENDED_MINING_JOB,
                    NewExtendedMiningJob {
                        channel_id: self.id,
                        job_id,
                        min_ntime,
                        version: job.version,
                        // REQUIRES_FIXED_VERSION, as on the solo pool: bits
                        // 16-23 are the algorithm.
                        version_rolling_allowed: false,
                        merkle_path: Seq0255::new(path)?,
                        coinbase_tx_prefix: split.prefix.as_slice().try_into()?,
                        coinbase_tx_suffix: split.suffix.as_slice().try_into()?,
                    },
                )?;
            }
        }

        writer.send_raw(
            EXT_AVIAN,
            MSG_JOB_TIME_CONSTRAINTS,
            true,
            &avian::encode_job_time_constraints(&avian::JobTimeConstraints {
                channel_id: self.id,
                job_id,
                ntime_min: job.window.ntime_min,
                ntime_max: job.window.ntime_max,
            }),
        )?;

        if tip_changed {
            writer.send(
                EXT_CORE_MINING,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
                CHANNEL_BIT_MINING_SET_NEW_PREV_HASH,
                SetNewPrevHash {
                    channel_id: self.id,
                    job_id,
                    prev_hash: U256::try_from(job.prev_hash.as_slice())?,
                    min_ntime: job.window.ntime_min,
                    nbits: job.nbits,
                },
            )?;
            job.future = false;
        }
        drop(writer);

        if tip_changed || notify.clean_jobs {
            state.jobs.clear();
            state.seen.clear();
        }
        state.prev_hash = Some(notify.prev_hash);
        state.jobs.push_back(BridgeJob {
            job,
            upstream_id: notify.job_id.clone(),
            extranonce2,
        });
        while state.jobs.len() > JOBS_RETAINED {
            state.jobs.pop_front();
        }
        Ok(())
    }

    /// Applies a `mining.set_difficulty`: the miner's target moves with it,
    /// and so does the limiter, which was sized for the old one. Nothing is
    /// sent if the target did not change, which happens when the miner's own
    /// `max_target` is the harder of the two.
    pub fn set_difficulty(&self, difficulty: f64) -> Result<()> {
        let target = share_target_for(&self.pow_limit, difficulty, &self.worker_max_target)?;
        let mut state = self.lock_state()?;
        state.difficulty = difficulty;
        if target == state.share_target {
            return Ok(());
        }
        state.share_target = target;
        state.limiter = limiter_for(self.nominal_hash_rate, &target, self.rate_limit);
        drop(state);
        self.lock_writer()?.send(
            EXT_CORE_MINING,
            MESSAGE_TYPE_SET_TARGET,
            CHANNEL_BIT_SET_TARGET,
            SetTarget {
                channel_id: self.id,
                maximum_target: U256::try_from(target.as_slice())?,
            },
        )
    }

    /// Applies a `mining.set_extranonce`.
    ///
    /// A standard channel takes it quietly: the next job is built with the
    /// new `extranonce1` and the miner, which never saw the old one as
    /// anything but a label, notices nothing. An extended channel cannot,
    /// because its miner holds the prefix and the jobs it has built on it;
    /// `SetExtranoncePrefix` exists for this, but a miner built for the solo
    /// pool has never needed it and does not speak it. So the session ends,
    /// and the miner reopens with the new prefix on the next connection,
    /// which is what its own backoff is for.
    pub fn set_extranonce(&self, subscription: Subscription) -> Result<()> {
        if self.kind.is_extended() {
            return Err(Error::Refused(format!(
                "the pool changed channel {}'s extranonce and an extended channel cannot \
                 follow; the miner reopens to get the new one",
                self.id
            )));
        }
        self.lock_state()?.subscription = subscription;
        Ok(())
    }

    /// Checks a submission and forwards it, or refuses it here.
    ///
    /// What is refused here is what the bridge can know on its own: the
    /// rate, a job it no longer holds, a duplicate, and the metadata that
    /// `share::validate` checks before any hashing. With the `pow` feature
    /// the hash is checked too, and a share under the target never costs the
    /// pool a round trip. Without it the hasher answers `PowUnavailable`,
    /// which here means "the pool decides" rather than a refusal: that is
    /// the design, and it is the reason the bridge builds without the
    /// Avian sources.
    pub fn handle_submit(
        &self,
        submission: Submission,
        sequence_number: u32,
        hasher: &dyn PowHasher,
    ) -> Result<()> {
        let mut state = self.lock_state()?;

        match state.limiter.admit() {
            Decision::Allow => {}
            Decision::TooFast => {
                drop(state);
                return self.send_error(sequence_number, Refusal::TooManyShares);
            }
            Decision::TooManyInvalid => {
                drop(state);
                self.send_error(sequence_number, Refusal::TooManyInvalidShares)?;
                return Err(Error::Refused(format!(
                    "channel {} sent too many invalid submissions",
                    self.id
                )));
            }
        }

        let Some(index) = state
            .jobs
            .iter()
            .position(|held| held.job.job_id == submission.job_id)
        else {
            // Not counted as invalid, for the solo pool's reason: a miner
            // submitting against the job it holds has done nothing wrong.
            drop(state);
            return self.send_error(sequence_number, Refusal::InvalidJobId);
        };

        if !self.kind.is_extended() && !submission.extranonce.is_empty() {
            state.limiter.record_invalid();
            drop(state);
            return self.send_error(sequence_number, Refusal::InvalidExtranonce);
        }

        let fingerprint = (
            submission.job_id,
            submission.nonce,
            submission.ntime,
            submission.extranonce.clone(),
        );
        if !state.seen.insert(fingerprint) {
            state.limiter.record_invalid();
            drop(state);
            return self.send_error(sequence_number, Refusal::DuplicateShare);
        }

        let share_target = state.share_target;
        let outcome = share::validate(
            &state.jobs[index].job,
            self.pow,
            &submission,
            &share_target,
            hasher,
        );
        let block_hash = match outcome {
            Outcome::Refused(Refusal::PowUnavailable) => None,
            Outcome::Refused(refusal) => {
                state.limiter.record_invalid();
                drop(state);
                return self.send_error(sequence_number, refusal);
            }
            Outcome::Accepted { hash, is_block, .. } => is_block.then_some(hash),
        };

        let held = &state.jobs[index];
        let extranonce2 = if self.kind.is_extended() {
            submission.extranonce.as_slice()
        } else {
            held.extranonce2.as_slice()
        };
        // Under the state lock, so the verdict cannot arrive before the id
        // is in `pending`. The write is a line on a socket with no delay;
        // the pool's answer takes a round trip.
        let upstream_id = self.upstream.submit(
            &self.identity,
            &held.upstream_id,
            extranonce2,
            submission.ntime,
            submission.nonce,
        )?;
        state.pending.insert(upstream_id, sequence_number);
        drop(state);

        if let Some(hash) = block_hash {
            // Only with the hashers. The pool submits the block, not the
            // bridge, so this is forwarded and never confirmed: a Stratum v1
            // pool does not say which share became the tip.
            logln!(
                "[bridge] channel {} forwarded a share at or under the network target",
                self.id
            );
            self.send_block_found(sequence_number, &hash)?;
        }
        Ok(())
    }

    /// Delivers the pool's verdict on a forwarded share to the miner.
    ///
    /// A refusal counts against the channel's invalid allowance exactly as a
    /// local one would: the pool judged the work and found it wanting, and
    /// a miner that keeps producing such work is the one the limiter exists
    /// for. The pool's wording is folded to a Stratum v2 code; see
    /// [`upstream_error_code`].
    pub fn answer(&self, upstream_id: u64, accepted: bool, error: Option<&str>) -> Result<()> {
        let mut state = self.lock_state()?;
        let Some(sequence_number) = state.pending.remove(&upstream_id) else {
            // The client already drops replies to requests it never made,
            // so this is a reply to a share forwarded before a reset. Nothing
            // to tell the miner.
            return Ok(());
        };
        if accepted {
            state.accepted = state.accepted.saturating_add(1);
            state.shares = state.shares.saturating_add(1);
            let accepted = state.accepted;
            let shares = state.shares;
            drop(state);
            return self.lock_writer()?.send(
                EXT_CORE_MINING,
                MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
                CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
                SubmitSharesSuccess {
                    channel_id: self.id,
                    last_sequence_number: sequence_number,
                    new_submits_accepted_count: accepted,
                    new_shares_sum: shares,
                },
            );
        }
        state.limiter.record_invalid();
        drop(state);
        self.send_error_code(sequence_number, upstream_error_code(error))
    }

    pub fn send_error(&self, sequence_number: u32, refusal: Refusal) -> Result<()> {
        self.send_error_code(sequence_number, refusal.code())
    }

    fn send_error_code(&self, sequence_number: u32, code: &str) -> Result<()> {
        self.lock_writer()?.send(
            EXT_CORE_MINING,
            MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
            CHANNEL_BIT_SUBMIT_SHARES_ERROR,
            SubmitSharesError {
                channel_id: self.id,
                sequence_number,
                error_code: code.as_bytes().try_into()?,
            },
        )
    }

    fn send_block_found(&self, sequence_number: u32, block_hash: &[u8; 32]) -> Result<()> {
        // A client that did not ask for block notifications is not sent one.
        // Silently, and that is the point: this used to be a message inside
        // the extension every client must negotiate, so a client built before
        // it existed received one and ended the session.
        if !self.blocks_negotiated {
            return Ok(());
        }
        let payload = avian::encode_block_found(&avian::BlockFound {
            channel_id: self.id,
            sequence_number,
            block_hash: *block_hash,
            confirmed: false,
        });
        self.lock_writer()?.send_raw(
            avian::EXT_AVIAN_BLOCKS,
            avian::MSG_BLOCK_FOUND,
            true,
            &payload,
        )
    }

    fn lock_writer(&self) -> Result<MutexGuard<'_, ConnectionWriter>> {
        self.writer
            .lock()
            .map_err(|_| Error::Protocol("a channel's writer is poisoned".into()))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| Error::Protocol("a channel's state is poisoned".into()))
    }
}

/// The pool's difficulty as a target, then the harder of that and the
/// miner's own ceiling. Harder is always safe: a share under the miner's
/// target is under the pool's too, so nothing the miner sends is wasted, and
/// the pool only ever sees fewer shares than it asked for, never easier ones.
fn share_target_for(
    pow_limit: &[u8; 32],
    difficulty: f64,
    worker_max_target: &[u8; 32],
) -> Result<[u8; 32]> {
    let target = difficulty::target_from_difficulty(pow_limit, difficulty)?;
    Ok(if block::meets_target(&target, worker_max_target) {
        target
    } else {
        *worker_max_target
    })
}

/// A limiter for the rate a miner of the declared speed should find shares
/// at this target. The solo pool sizes its limiter from the cadence every
/// channel was derived to hit; here the target is the pool's, so the cadence
/// is worked out from it instead.
fn limiter_for(hash_rate: f64, target: &[u8; 32], config: RateLimitConfig) -> Limiter {
    let per_minute = hash_rate * ratelimit::target_probability(target) * 60.0;
    Limiter::new(per_minute, config)
}

/// The window a miner may roll `ntime` in: from the pool's `ntime`, forward
/// by the configured allowance, and on X16RT never past the end of the
/// 128-second epoch the pool's `ntime` is in, because the hash chain is
/// derived from `ntime & TIME_MASK` and a miner rolling past the boundary
/// computes a different hash function and burns its hashrate silently.
fn window_for(ntime: u32, roll: u32, pow: PowType) -> Window {
    let mut ntime_max = ntime.saturating_add(roll);
    if pow == PowType::X16rt {
        ntime_max = ntime_max.min(ntime | !TIME_MASK);
    }
    Window {
        ntime_min: ntime,
        ntime_max,
    }
}

/// `coinb1` and `coinb2` are a `CoinbaseSplit`'s prefix and suffix, with the
/// full extranonce, `extranonce1` and `extranonce2` together, in between.
fn split_for(notify: &Notify, extranonce_len: usize) -> CoinbaseSplit {
    CoinbaseSplit {
        prefix: notify.coinb1.clone(),
        suffix: notify.coinb2.clone(),
        extranonce_len,
    }
}

/// A counter as `extranonce2`, little-endian, as wide as the pool asked.
/// Wider than eight bytes is zero-padded; narrower is truncated, which wraps
/// sooner than the counter does and still never repeats within the jobs a
/// channel retains.
fn extranonce2_for(counter: u64, size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    let bytes = counter.to_le_bytes();
    let n = size.min(bytes.len());
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// The Stratum v2 code for a Stratum v1 refusal.
///
/// Stratum v1 pools refuse with a numeric code and a sentence, and the codes
/// are the same handful nearly everywhere: 21 for a job the pool no longer
/// has, 22 for a duplicate, 23 for a share over the target, 24 and 25 for a
/// worker it does not know. The sentence is read as well, for pools that
/// use 20 for everything. Anything else is `upstream-rejected`, which tells
/// the miner the truth: the pool said no and did not say why in terms the
/// bridge recognises.
pub fn upstream_error_code(error: Option<&str>) -> &'static str {
    let text = error.unwrap_or("");
    let code: Option<u32> = text
        .split_once(':')
        .and_then(|(code, _)| code.trim().parse().ok());
    match code {
        Some(21) => return Refusal::StaleShare.code(),
        Some(22) => return Refusal::DuplicateShare.code(),
        Some(23) => return Refusal::DifficultyTooLow.code(),
        Some(24) | Some(25) => return "unauthorized-worker",
        _ => {}
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("stale") || lower.contains("not found") || lower.contains("unknown job") {
        Refusal::StaleShare.code()
    } else if lower.contains("duplicate") {
        Refusal::DuplicateShare.code()
    } else if lower.contains("low diff")
        || lower.contains("difficulty")
        || lower.contains("above target")
    {
        Refusal::DifficultyTooLow.code()
    } else if lower.contains("unauthor") || lower.contains("not subscribed") {
        "unauthorized-worker"
    } else {
        "upstream-rejected"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_starts_at_the_pools_ntime_and_x16rt_stops_at_the_epoch() {
        let base = 1_792_943_722u32 & TIME_MASK;
        // Pinned by default.
        let pinned = window_for(base + 10, 0, PowType::X16rt);
        assert_eq!(pinned.ntime_min, base + 10);
        assert_eq!(pinned.ntime_max, base + 10);
        // An allowance that would cross the epoch is cut at its last second.
        let cut = window_for(base + 100, 600, PowType::X16rt);
        assert_eq!(cut.ntime_max, base + 127);
        assert!(cut.within_one_epoch());
        // MinotaurX has no epochs.
        let free = window_for(base + 100, 600, PowType::MinotaurX);
        assert_eq!(free.ntime_max, base + 700);
    }

    #[test]
    fn extranonce2_fills_the_pools_width_from_a_counter() {
        assert_eq!(extranonce2_for(1, 4), vec![1, 0, 0, 0]);
        assert_eq!(extranonce2_for(0x0102, 2), vec![2, 1]);
        assert_eq!(extranonce2_for(7, 12), {
            let mut v = vec![7u8];
            v.extend_from_slice(&[0; 11]);
            v
        });
        assert_ne!(extranonce2_for(1, 4), extranonce2_for(2, 4));
    }

    #[test]
    fn the_harder_of_the_pools_target_and_the_miners_ceiling_wins() {
        let limit = difficulty::POW_LIMIT;
        // A miner that takes anything gets the pool's target.
        let pools = share_target_for(&limit, 1024.0, &[0xff; 32]).unwrap();
        assert_eq!(
            pools,
            difficulty::target_from_difficulty(&limit, 1024.0).unwrap()
        );
        // A miner whose ceiling is harder than the pool's target keeps it.
        let harder = difficulty::target_from_difficulty(&limit, 1_000_000.0).unwrap();
        assert_eq!(share_target_for(&limit, 1024.0, &harder).unwrap(), harder);
        // Nonsense from the pool is an error, not a target.
        assert!(share_target_for(&limit, 0.0, &[0xff; 32]).is_err());
    }

    #[test]
    fn pool_refusals_fold_to_the_specifications_codes() {
        assert_eq!(
            upstream_error_code(Some("21: job not found")),
            "stale-share"
        );
        assert_eq!(
            upstream_error_code(Some("22: duplicate share")),
            "duplicate-share"
        );
        assert_eq!(
            upstream_error_code(Some("23: low difficulty share")),
            "difficulty-too-low"
        );
        assert_eq!(
            upstream_error_code(Some("24: unauthorized worker")),
            "unauthorized-worker"
        );
        // Code 20 is "other", so the sentence decides.
        assert_eq!(upstream_error_code(Some("20: Stale share")), "stale-share");
        assert_eq!(
            upstream_error_code(Some("20: share above target")),
            "difficulty-too-low"
        );
        assert_eq!(
            upstream_error_code(Some("20: something new")),
            "upstream-rejected"
        );
        assert_eq!(upstream_error_code(None), "upstream-rejected");
    }
}
