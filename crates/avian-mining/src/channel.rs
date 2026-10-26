//! One standard mining channel.
//!
//! A channel is where the two halves meet: the thread that received a template
//! pushes jobs onto it, and the thread reading from the worker answers its
//! submissions. Both go through the same writer mutex, which is also what
//! keeps a round of work contiguous on the wire: a `SubmitShares.Success`
//! cannot land between a `NewMiningJob` and the `SetNewPrevHash` that
//! activates it.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use avian_sv2::avian::{self, PowType, EXT_AVIAN, MSG_JOB_TIME_CONSTRAINTS};
use avian_sv2::error::{Error, Result};
use avian_sv2::transport::ConnectionWriter;
use avian_tdp::coinbase::PayoutPlan;
use avian_tdp::tdp::PrevHash;
use avian_tdp::Work;
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

use crate::job::{self, Job, JobWork};
use crate::ratelimit::{Decision, Limiter, RateLimitConfig};
use crate::share::{self, Outcome, PowHasher, Refusal, Submission};
use crate::EXT_CORE_MINING;

/// How many jobs stay submittable on one channel.
///
/// The node keeps `-sv2maxtemplates` templates per client, three by default,
/// and a pool should not hold work open longer than the node will honour it.
/// Jobs are dropped outright when the tip moves, whatever this is.
const JOBS_RETAINED: usize = 3;

/// What a winning share turned into.
pub struct BlockCandidate {
    pub template_id: u64,
    pub version: u32,
    pub ntime: u32,
    pub nonce: u32,
    pub coinbase: Vec<u8>,
    pub hash: [u8; 32],
}

/// Which kind of channel this is.
///
/// Both are served, and `REQUIRES_EXTENDED_CHANNELS` is never set, because
/// serving both is the point: a miner that can only do standard channels still
/// works, and one that can do extended channels gets to see what it is
/// committing to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// The pool builds the whole coinbase and hands down a merkle root.
    Standard,
    /// The pool hands down the coinbase in two halves and the miner assembles
    /// it, with `extranonce_size` bytes of its own to roll.
    Extended { extranonce_size: usize },
}

impl ChannelKind {
    pub fn is_extended(self) -> bool {
        matches!(self, ChannelKind::Extended { .. })
    }
}

pub struct Channel {
    pub id: u32,
    pub kind: ChannelKind,
    pub pow: PowType,
    pub share_target: [u8; 32],
    pub extranonce_prefix: Vec<u8>,
    /// Who the coinbase pays. From the worker's `user_identity`, not from
    /// configuration.
    pub payout: PayoutPlan,
    /// The worker label after the address, for logging only.
    pub worker: String,
    /// The payout address as the worker wrote it. Kept so the stats endpoint
    /// can show a prefix: enough for someone to recognise their own channel,
    /// not enough to publish where everyone is paid.
    pub payout_address: String,
    /// When the channel opened, which is what turns a share count into a rate.
    pub opened_at: Instant,
    coinbase_tag: Vec<u8>,
    writer: Arc<Mutex<ConnectionWriter>>,
    state: Mutex<ChannelState>,
}

struct ChannelState {
    next_job_id: u32,
    jobs: VecDeque<Job>,
    /// False until the first `SetNewPrevHash` has activated a job, which is
    /// what makes the first job on a channel a future job.
    activated: bool,
    accepted: u32,
    shares: u64,
    /// Shares that were also blocks, so the page can say so per channel
    /// rather than only per algorithm.
    blocks: u32,
    /// Shares naming a job this channel does not have.
    ///
    /// Counted apart from invalid shares deliberately. An unknown job id is
    /// not bad work: it is the pool and the miner disagreeing about state, and
    /// that is nearly always the pool's end. Counting it as invalid punished a
    /// miner for the pool losing track of it, and the disconnect that followed
    /// repaired the symptom, which is how the real bug stayed hidden.
    desync: u32,
    /// Set when this channel has asked for a job it does not have, so the
    /// server knows to push it work. Cleared by a successful push.
    wants_work: bool,
    last_sequence: u32,
    seen: HashSet<(u32, u32, u32)>,
    limiter: Limiter,
}

impl Channel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u32,
        kind: ChannelKind,
        pow: PowType,
        share_target: [u8; 32],
        payout: PayoutPlan,
        worker: String,
        payout_address: String,
        coinbase_tag: Vec<u8>,
        nominal_hash_rate: f32,
        rate_limit: RateLimitConfig,
        writer: Arc<Mutex<ConnectionWriter>>,
    ) -> Self {
        Self {
            id,
            kind,
            pow,
            share_target,
            // On an extended channel this is the pool's half of the
            // extranonce, which the miner prepends to its own. On a standard
            // one it is informational: the pool chose the whole coinbase.
            extranonce_prefix: match kind {
                ChannelKind::Standard => job::extranonce(id, 0).to_vec(),
                ChannelKind::Extended { .. } => job::extranonce_prefix(id),
            },
            payout,
            worker,
            payout_address,
            opened_at: Instant::now(),
            coinbase_tag,
            writer,
            state: Mutex::new(ChannelState {
                next_job_id: 1,
                jobs: VecDeque::new(),
                activated: false,
                accepted: 0,
                shares: 0,
                blocks: 0,
                desync: 0,
                wants_work: false,
                last_sequence: 0,
                seen: HashSet::new(),
                limiter: Limiter::new(&share_target, nominal_hash_rate, rate_limit),
            }),
        }
    }

    fn shape(&self, job_id: u32) -> job::Shape {
        match self.kind {
            ChannelKind::Standard => job::Shape::Standard {
                extranonce: job::extranonce(self.id, job_id).to_vec(),
            },
            ChannelKind::Extended { extranonce_size } => job::Shape::Extended {
                extranonce_prefix: self.extranonce_prefix.clone(),
                extranonce_size,
            },
        }
    }

    /// Submissions per second this channel may sustain, for logging.
    pub fn submission_rate(&self) -> f64 {
        self.state.lock().map(|s| s.limiter.rate()).unwrap_or(0.0)
    }

    /// Answers `OpenStandardMiningChannel` and states the target.
    ///
    /// The target travels twice, in the success reply and then in `SetTarget`,
    /// which is the order doc/sv2.md's diagram shows. `SetTarget` is what a
    /// pool with vardiff would resend later; there is none here, so this is
    /// the only one.
    pub fn send_open_success(&self, request_id: u32) -> Result<()> {
        let mut writer = self.lock_writer()?;
        let target = self.share_target;
        match self.kind {
            ChannelKind::Standard => writer.send(
                EXT_CORE_MINING,
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                OpenStandardMiningChannelSuccess {
                    request_id,
                    channel_id: self.id,
                    target: U256::try_from(target.as_slice())?,
                    extranonce_prefix: self.extranonce_prefix.as_slice().try_into()?,
                    // Standard channels are not grouped here, and 0 is the
                    // "no group" value.
                    group_channel_id: 0,
                },
            )?,
            ChannelKind::Extended { extranonce_size } => writer.send(
                EXT_CORE_MINING,
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                OpenExtendedMiningChannelSuccess {
                    request_id,
                    channel_id: self.id,
                    target: U256::try_from(target.as_slice())?,
                    extranonce_size: extranonce_size as u16,
                    extranonce_prefix: self.extranonce_prefix.as_slice().try_into()?,
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

    /// Pushes one round of work onto the channel.
    ///
    /// The whole round goes out under one lock, in the order doc/sv2.md
    /// requires: the job, then its time constraints, then, when the job needs
    /// activating, the `SetNewPrevHash` that activates it. Constraints before
    /// activation, never after, because a worker activated by `SetNewPrevHash`
    /// must start hashing immediately and the only safe thing it could do
    /// without a window is idle.
    pub fn push_work(&self, work: &Work, prev: &PrevHash) -> Result<()> {
        let mut state = self.lock_state()?;

        // Activation is driven by the prev hash having changed, not by a
        // SetNewPrevHash having arrived from the node: aviand sends one every
        // round whether the tip moved or not.
        let activate = !state.activated || work.tip_changed;

        // Nothing is cleared yet, and the ordering is deliberate. This used to
        // drop the channel's jobs here, before building the replacement, so
        // every error below left the channel with no jobs and nothing to
        // replace them: the same stranding by another route. A channel left
        // holding stale work is strictly better than one holding none.
        let job_id = state.next_job_id;
        state.next_job_id = state.next_job_id.wrapping_add(1).max(1);

        let mut job = job::build(
            job_id,
            &work.template,
            prev,
            &work.constraints,
            &self.payout,
            &self.coinbase_tag,
            self.shape(job_id),
            activate,
        )?;

        if job::pow_type_of(&job)? != self.pow {
            return Err(Error::Protocol(format!(
                "a template for {} arrived on a {} channel",
                job::pow_type_of(&job)?,
                self.pow
            )));
        }
        if self.pow == PowType::X16rt && !job.window.within_one_epoch() {
            return Err(Error::Protocol(
                "the ntime window crosses a 128-second X16RT epoch boundary".into(),
            ));
        }

        let mut writer = self.lock_writer()?;
        // A future job leaves min_ntime unset; the specification requires the
        // first job on a channel to be one.
        let min_ntime = Sv2Option::new(if activate {
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
                        // False, to match REQUIRES_FIXED_VERSION. nVersion
                        // bits 16-23 are the algorithm, so rolling them moves
                        // the share to the other algorithm's proof-of-work
                        // limit, and there is no safe subset to open.
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
            // A channel message, so this travels under 0xc001 while the
            // extension it belongs to is still 0x4001.
            true,
            &avian::encode_job_time_constraints(&avian::JobTimeConstraints {
                channel_id: self.id,
                job_id,
                ntime_min: job.window.ntime_min,
                ntime_max: job.window.ntime_max,
            }),
        )?;

        if activate {
            let prev_hash = job.prev_hash;
            writer.send(
                EXT_CORE_MINING,
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
                CHANNEL_BIT_MINING_SET_NEW_PREV_HASH,
                SetNewPrevHash {
                    channel_id: self.id,
                    job_id,
                    prev_hash: U256::try_from(prev_hash.as_slice())?,
                    // doc/sv2.md: the ntime_start SetNewPrevHash supplies must
                    // equal the ntime_min in force for that job.
                    min_ntime: job.window.ntime_min,
                    nbits: job.nbits,
                },
            )?;
            job.future = false;
            state.activated = true;
        }
        drop(writer);

        // Now, and only now. Work on a superseded tip can never produce a
        // connecting block, so it goes exactly as the node drops its own, but
        // not one line before there is a replacement for it.
        if work.tip_changed {
            state.jobs.clear();
            state.seen.clear();
        }
        state.wants_work = false;
        state.jobs.push_back(job);
        while state.jobs.len() > JOBS_RETAINED {
            state.jobs.pop_front();
        }
        Ok(())
    }

    /// Validates a submission and answers it.
    ///
    /// Returns the block candidate when the share also meets the network
    /// target, for the caller to pass to the node.
    pub fn handle_submit(
        &self,
        submission: Submission,
        sequence_number: u32,
        hasher: &dyn PowHasher,
    ) -> Result<Option<BlockCandidate>> {
        let mut state = self.lock_state()?;
        state.last_sequence = sequence_number;

        // Before anything else, including the job lookup. Avian has no cheap
        // proof-of-work pre-filter, so a submission that reaches the hash
        // costs a whole X16RT or MinotaurX, and a flood has to be refused
        // without getting that far.
        match state.limiter.admit() {
            Decision::Allow => {}
            Decision::TooFast => {
                drop(state);
                self.send_error(sequence_number, Refusal::TooManyShares)?;
                return Ok(None);
            }
            Decision::TooManyInvalid => {
                drop(state);
                self.send_error(sequence_number, Refusal::TooManyInvalidShares)?;
                // Dropped, in the spirit of the node's -sv2maxrejects: a
                // worker that keeps failing has been told something it is not
                // acting on and will never find a block.
                return Err(Error::Refused(format!(
                    "channel {} sent too many invalid submissions",
                    self.id
                )));
            }
        }

        let Some(job) = state
            .jobs
            .iter()
            .find(|job| job.job_id == submission.job_id)
            .cloned()
        else {
            // Not record_invalid(). A miner submitting against the only job
            // it holds has done nothing wrong, and dropping it for that
            // punishes the wrong party.
            state.desync = state.desync.saturating_add(1);
            state.wants_work = true;
            let desync = state.desync;
            drop(state);
            self.send_error(sequence_number, Refusal::InvalidJobId)?;
            if desync == 1 {
                eprintln!(
                    "[pool] channel {} asked for job {}, which it does not have:                      reissuing work rather than counting this against it",
                    self.id, submission.job_id
                );
            }
            return Ok(None);
        };

        if !self.kind.is_extended() && !submission.extranonce.is_empty() {
            state.limiter.record_invalid();
            drop(state);
            self.send_error(sequence_number, Refusal::InvalidExtranonce)?;
            return Ok(None);
        }

        let fingerprint = (submission.job_id, submission.nonce, submission.ntime);
        if !state.seen.insert(fingerprint) {
            state.limiter.record_invalid();
            drop(state);
            self.send_error(sequence_number, Refusal::DuplicateShare)?;
            return Ok(None);
        }

        match share::validate(&job, self.pow, &submission, &self.share_target, hasher) {
            Outcome::Refused(refusal) => {
                state.limiter.record_invalid();
                drop(state);
                self.send_error(sequence_number, refusal)?;
                Ok(None)
            }
            Outcome::Accepted { hash, is_block, .. } => {
                state.accepted += 1;
                state.shares += 1;
                let accepted = state.accepted;
                let shares = state.shares;
                drop(state);

                self.lock_writer()?.send(
                    EXT_CORE_MINING,
                    MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
                    CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
                    SubmitSharesSuccess {
                        channel_id: self.id,
                        last_sequence_number: sequence_number,
                        new_submits_accepted_count: accepted,
                        new_shares_sum: shares,
                    },
                )?;

                if !is_block {
                    return Ok(None);
                }
                // The pool's side of an extended channel: reassemble what the
                // miner hashed and add the witness it never saw.
                Ok(Some(BlockCandidate {
                    template_id: job.template_id,
                    version: job.version,
                    ntime: submission.ntime,
                    nonce: submission.nonce,
                    coinbase: job.coinbase(&submission.extranonce)?,
                    hash,
                }))
            }
        }
    }

    /// Tells the miner one of its shares was a block, and later that the
    /// block became the tip.
    ///
    /// Nothing in the Mining Protocol carries this: a miner is given a share
    /// target and never the network target, so it cannot work out that its own
    /// share was a block. For a pool paying by share that does not matter. For
    /// a solo pool it is backwards, because consensus pays the miner directly
    /// for exactly these.
    pub fn send_block_found(
        &self,
        sequence_number: u32,
        block_hash: &[u8; 32],
        confirmed: bool,
    ) -> Result<()> {
        let payload = avian::encode_block_found(&avian::BlockFound {
            channel_id: self.id,
            sequence_number,
            block_hash: *block_hash,
            confirmed,
        });
        self.lock_writer()?
            .send_raw(EXT_AVIAN, avian::MSG_BLOCK_FOUND, true, &payload)
    }

    pub fn send_error(&self, sequence_number: u32, refusal: Refusal) -> Result<()> {
        let code = refusal.code();
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

    /// Drops every job, so nothing from a previous upstream session can be
    /// submitted against, and resets the channel to needing a future job.
    pub fn withdraw(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.jobs.clear();
            state.seen.clear();
            state.activated = false;
        }
    }

    pub fn job_count(&self) -> usize {
        self.state.lock().map(|s| s.jobs.len()).unwrap_or(0)
    }

    /// The newest job pushed to this channel, which is the one a miner should
    /// be working on.
    pub fn current_job_id(&self) -> Option<u32> {
        self.state.lock().ok()?.jobs.back().map(|job| job.job_id)
    }

    /// Shares from this channel that were at or under the network target.
    pub fn blocks(&self) -> u32 {
        self.state.lock().map(|s| s.blocks).unwrap_or(0)
    }

    /// Shares this channel sent against a job it did not have.
    pub fn desync(&self) -> u32 {
        self.state.lock().map(|s| s.desync).unwrap_or(0)
    }

    /// Whether this channel is waiting for work it can submit against.
    pub fn wants_work(&self) -> bool {
        self.state.lock().map(|s| s.wants_work).unwrap_or(false)
    }

    /// Counted here rather than only at the algorithm, because "which worker
    /// found it" is the first thing anyone asks.
    pub fn record_block(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.blocks = state.blocks.saturating_add(1);
        }
    }

    pub fn accepted(&self) -> u32 {
        self.state.lock().map(|s| s.accepted).unwrap_or(0)
    }

    /// Invalid submissions so far, and submissions refused for rate.
    pub fn refusals(&self) -> (u32, u64) {
        self.state
            .lock()
            .map(|s| (s.limiter.invalid(), s.limiter.refused_for_rate()))
            .unwrap_or((0, 0))
    }

    fn lock_writer(&self) -> Result<std::sync::MutexGuard<'_, ConnectionWriter>> {
        self.writer
            .lock()
            .map_err(|_| Error::Protocol("a channel's writer is poisoned".into()))
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ChannelState>> {
        self.state
            .lock()
            .map_err(|_| Error::Protocol("a channel's state is poisoned".into()))
    }
}
