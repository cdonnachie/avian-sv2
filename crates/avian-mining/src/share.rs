//! Validating a submitted share.
//!
//! Everything except the hash is metadata a pool can check from the job it
//! issued. The hash is the one thing it cannot: Avian's target is compared
//! against the X16RT or MinotaurX hash, not SHA256d, which is also why no
//! unmodified Stratum v2 miner can work here. [`PowHasher`] is behind a trait
//! so the metadata checks can be tested without the algorithms, and so a
//! build without them fails loudly instead of accepting everything.

use avian_sv2::avian::PowType;
use avian_sv2::block;

use crate::job::Job;

/// Computes Avian's proof-of-work hash.
pub trait PowHasher: Send + Sync {
    fn hash(&self, pow: PowType, header: &[u8; 80]) -> Option<[u8; 32]>;
    fn describe(&self) -> &'static str;
}

/// Avian's own implementation, linked through `avian-pow`.
pub struct AvianHasher;

impl PowHasher for AvianHasher {
    fn hash(&self, pow: PowType, header: &[u8; 80]) -> Option<[u8; 32]> {
        let pow = match pow {
            PowType::X16rt => avian_pow::PowType::X16rt,
            PowType::MinotaurX => avian_pow::PowType::MinotaurX,
        };
        avian_pow::hash(pow, header)
    }

    fn describe(&self) -> &'static str {
        if avian_pow::AVAILABLE {
            "Avian's own X16RT and MinotaurX, linked from src/algo"
        } else {
            "unavailable: built without the Avian sources"
        }
    }
}

/// Checks everything except the hash.
///
/// Only for testing the metadata ladder. A pool running on this would accept
/// any nonce, so it refuses every share rather than pretending, and says which
/// check it could not make.
pub struct MetadataOnlyHasher;

impl PowHasher for MetadataOnlyHasher {
    fn hash(&self, _pow: PowType, _header: &[u8; 80]) -> Option<[u8; 32]> {
        None
    }

    fn describe(&self) -> &'static str {
        "STUB: metadata only, no proof-of-work hash is computed"
    }
}

/// Why a share was refused.
///
/// The first four are the Stratum v2 specification's `SubmitShares.Error`
/// codes. The last two are not: the specification's list has no value for
/// "you changed a field you were told not to", which an Avian pool needs
/// because `REQUIRES_FIXED_VERSION` and the ntime window are the two things
/// the extension exists to enforce. `error_code` is a `STR0_255`, so these are
/// legal, but they are this pool's invention and a worker cannot know them in
/// advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    InvalidChannelId,
    InvalidJobId,
    StaleShare,
    DifficultyTooLow,
    /// The version did not match the job's, which `REQUIRES_FIXED_VERSION`
    /// forbids.
    InvalidVersion,
    /// ntime outside the job's inclusive window.
    InvalidNtime,
    /// The same job, nonce and ntime twice.
    DuplicateShare,
    /// The hasher could not run, so the share was neither accepted nor
    /// genuinely refused.
    PowUnavailable,
    /// Over the channel's submission rate. Refused without hashing.
    TooManyShares,
    /// Too many invalid submissions; the channel is being dropped.
    TooManyInvalidShares,
    /// An extranonce of the wrong length for the channel, or one sent on a
    /// standard channel where the pool chose the whole coinbase.
    InvalidExtranonce,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::InvalidChannelId => "invalid-channel-id",
            Refusal::InvalidJobId => "invalid-job-id",
            Refusal::StaleShare => "stale-share",
            Refusal::DifficultyTooLow => "difficulty-too-low",
            Refusal::InvalidVersion => "invalid-version",
            Refusal::InvalidNtime => "invalid-ntime",
            Refusal::DuplicateShare => "duplicate-share",
            Refusal::PowUnavailable => "pow-unavailable",
            Refusal::TooManyShares => "too-many-shares",
            Refusal::TooManyInvalidShares => "too-many-invalid-shares",
            Refusal::InvalidExtranonce => "invalid-extranonce",
        }
    }
}

/// What a submitted share turned out to be.
#[derive(Debug, Clone)]
pub enum Outcome {
    Accepted {
        /// The header the worker hashed, rebuilt from the job.
        header: [u8; 80],
        hash: [u8; 32],
        /// True when the hash also meets the network target, so this is a
        /// block and not only a share.
        is_block: bool,
    },
    Refused(Refusal),
}

/// A submission, in the fields `SubmitSharesStandard` and
/// `SubmitSharesExtended` carry.
#[derive(Debug, Clone)]
pub struct Submission {
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
    /// The miner's half of the extranonce, on an extended channel. Empty on a
    /// standard one, where the pool chose the whole coinbase.
    pub extranonce: Vec<u8>,
}

/// Validates a share against the job it names.
///
/// The order is deliberate: every cheap field check runs before the hash,
/// because for Avian the hash is the expensive part and there is no partial
/// check that can stand in for it. doc/sv2.md calls that out as the reason the
/// node needs a rate limit, and it applies to a pool just as much.
pub fn validate(
    job: &Job,
    pow: PowType,
    submission: &Submission,
    share_target: &[u8; 32],
    hasher: &dyn PowHasher,
) -> Outcome {
    if job.future {
        // A future job has no prev hash yet, so there is no header to rebuild.
        return Outcome::Refused(Refusal::StaleShare);
    }
    if submission.version != job.version {
        return Outcome::Refused(Refusal::InvalidVersion);
    }
    if !job.window.contains(submission.ntime) {
        return Outcome::Refused(Refusal::InvalidNtime);
    }

    // On an extended channel this is where the miner's extranonce enters: the
    // pool reassembles the coinbase the miner hashed and folds the same path,
    // so a submission that named a different extranonce produces a different
    // root and will simply fail the target.
    let merkle_root = match job.merkle_root(&submission.extranonce) {
        Ok(root) => root,
        Err(_) => return Outcome::Refused(Refusal::InvalidExtranonce),
    };
    let header = block::header(
        job.version,
        &job.prev_hash,
        &merkle_root,
        submission.ntime,
        job.nbits,
        submission.nonce,
    );
    let Some(hash) = hasher.hash(pow, &header) else {
        return Outcome::Refused(Refusal::PowUnavailable);
    };
    if !block::meets_target(&hash, share_target) {
        return Outcome::Refused(Refusal::DifficultyTooLow);
    }
    Outcome::Accepted {
        header,
        hash,
        is_block: block::meets_target(&hash, &job.network_target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::Window;

    fn job() -> Job {
        Job {
            job_id: 1,
            template_id: 1,
            version: 0x3200_0000,
            prev_hash: [0x11; 32],
            nbits: 0x207f_ffff,
            window: Window {
                ntime_min: 1000,
                ntime_max: 1000,
            },
            network_target: [0xff; 32],
            work: crate::job::JobWork::Standard {
                merkle_root: [0x22; 32],
                coinbase: vec![],
            },
            future: false,
        }
    }

    fn submission() -> Submission {
        Submission {
            job_id: 1,
            nonce: 7,
            ntime: 1000,
            version: 0x3200_0000,
            extranonce: Vec::new(),
        }
    }

    #[test]
    fn a_rolled_version_is_refused_before_any_hashing() {
        let mut s = submission();
        s.version ^= 0x0001_0000; // flip to the other algorithm
        let outcome = validate(&job(), PowType::X16rt, &s, &[0xff; 32], &MetadataOnlyHasher);
        // MetadataOnlyHasher would have answered PowUnavailable if the version
        // check had not run first.
        assert!(matches!(outcome, Outcome::Refused(Refusal::InvalidVersion)));
    }

    #[test]
    fn an_ntime_outside_the_window_is_refused_before_any_hashing() {
        let mut s = submission();
        s.ntime = 1001;
        let outcome = validate(&job(), PowType::X16rt, &s, &[0xff; 32], &MetadataOnlyHasher);
        assert!(matches!(outcome, Outcome::Refused(Refusal::InvalidNtime)));
    }

    #[test]
    fn a_future_job_cannot_be_submitted_against() {
        let mut j = job();
        j.future = true;
        let outcome = validate(
            &j,
            PowType::X16rt,
            &submission(),
            &[0xff; 32],
            &MetadataOnlyHasher,
        );
        assert!(matches!(outcome, Outcome::Refused(Refusal::StaleShare)));
    }

    #[test]
    fn the_stub_refuses_rather_than_accepting() {
        let outcome = validate(
            &job(),
            PowType::X16rt,
            &submission(),
            &[0xff; 32],
            &MetadataOnlyHasher,
        );
        assert!(matches!(outcome, Outcome::Refused(Refusal::PowUnavailable)));
    }

    #[test]
    fn the_real_hasher_accepts_a_share_under_an_easy_target_and_refuses_a_hard_one() {
        if !avian_pow::AVAILABLE {
            eprintln!("skipping: built without the Avian sources");
            return;
        }
        // An all-ones target is met by any hash.
        let easy = validate(
            &job(),
            PowType::X16rt,
            &submission(),
            &[0xff; 32],
            &AvianHasher,
        );
        assert!(matches!(easy, Outcome::Accepted { .. }));

        // An all-zeros target is met by none.
        let hard = validate(
            &job(),
            PowType::X16rt,
            &submission(),
            &[0x00; 32],
            &AvianHasher,
        );
        assert!(matches!(hard, Outcome::Refused(Refusal::DifficultyTooLow)));
    }
}
