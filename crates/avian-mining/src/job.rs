//! A job, and the ntime window that comes with it.

use avian_sv2::avian::{PowType, TimeConstraints, TIME_MASK};
use avian_sv2::error::{Error, Result};
use avian_tdp::coinbase::{self, Coinbase, CoinbaseSplit, PayoutPlan};
use avian_tdp::tdp::{PrevHash, Template};

/// What the miner was given to build a header from.
///
/// The difference between the two kinds of channel, and the reason extended
/// channels exist: on a standard channel the pool hands down a finished merkle
/// root and the miner can only take its word for what is in the block. On an
/// extended channel it hands down the coinbase in two halves, and the miner
/// assembles it, hashes it, folds the path itself, and can read every output
/// it is committing to.
#[derive(Debug, Clone)]
pub enum JobWork {
    Standard {
        /// Already folded, because the pool chose the whole coinbase.
        merkle_root: [u8; 32],
        /// Serialized with its witness, ready for `SubmitSolution`.
        coinbase: Vec<u8>,
    },
    Extended {
        split: CoinbaseSplit,
        merkle_path: Vec<[u8; 32]>,
        /// The pool's half of the extranonce, which the miner prepends to its
        /// own.
        extranonce_prefix: Vec<u8>,
        /// How many bytes the miner may use.
        extranonce_size: usize,
    },
}

/// Everything needed to rebuild the header a worker hashed, and to turn a
/// winning share into a `SubmitSolution`.
#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: u32,
    pub template_id: u64,
    /// Fixed. `REQUIRES_FIXED_VERSION` is set on every Avian mining
    /// connection, and `version_rolling_allowed` is false on every extended
    /// job, so a submission whose version differs is refused: bits 16-23 are
    /// the algorithm, and rolling them moves the share to the other
    /// algorithm's proof-of-work limit.
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub nbits: u32,
    pub window: Window,
    pub network_target: [u8; 32],
    pub work: JobWork,
    /// True while this job has not been activated by a `SetNewPrevHash`.
    pub future: bool,
}

impl Job {
    /// The merkle root for a submission, which on an extended channel depends
    /// on the extranonce the miner chose.
    pub fn merkle_root(&self, extranonce: &[u8]) -> Result<[u8; 32]> {
        match &self.work {
            JobWork::Standard { merkle_root, .. } => Ok(*merkle_root),
            JobWork::Extended {
                split,
                merkle_path,
                extranonce_prefix,
                extranonce_size,
            } => {
                if extranonce.len() != *extranonce_size {
                    return Err(Error::Protocol(format!(
                        "this channel's extranonce is {extranonce_size} bytes and the share \
                         carried {}",
                        extranonce.len()
                    )));
                }
                let mut full = extranonce_prefix.clone();
                full.extend_from_slice(extranonce);
                Ok(coinbase::merkle_root(&split.txid(&full)?, merkle_path))
            }
        }
    }

    /// The coinbase to put in `SubmitSolution`, witness included.
    pub fn coinbase(&self, extranonce: &[u8]) -> Result<Vec<u8>> {
        match &self.work {
            JobWork::Standard { coinbase, .. } => Ok(coinbase.clone()),
            JobWork::Extended {
                split,
                extranonce_prefix,
                ..
            } => {
                let mut full = extranonce_prefix.clone();
                full.extend_from_slice(extranonce);
                split.assemble_with_witness(&full)
            }
        }
    }

    pub fn is_extended(&self) -> bool {
        matches!(self.work, JobWork::Extended { .. })
    }
}

/// The inclusive ntime bounds a worker may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub ntime_min: u32,
    pub ntime_max: u32,
}

impl Window {
    /// Derives a job's window from the template's.
    ///
    /// doc/sv2.md: a pool must **narrow, never widen**, because the node will
    /// refuse a solution outside its own window and a worker told it had more
    /// room will mine work that cannot be submitted. This pool narrows by
    /// nothing, which is the widest it is allowed to be and still correct;
    /// [`Window::narrow`] is what a pool that wanted a tighter one would use,
    /// and it cannot widen by construction.
    pub fn from_template(constraints: &TimeConstraints) -> Self {
        Self {
            ntime_min: constraints.ntime_min,
            ntime_max: constraints.ntime_max,
        }
    }

    pub fn narrow(self, ntime_min: u32, ntime_max: u32) -> Self {
        Self {
            ntime_min: self.ntime_min.max(ntime_min),
            ntime_max: self.ntime_max.min(ntime_max),
        }
    }

    pub fn contains(&self, ntime: u32) -> bool {
        (self.ntime_min..=self.ntime_max).contains(&ntime)
    }

    /// Whether the window stays inside one X16RT 128-second epoch. It must for
    /// an X16RT job: the hash chain comes from `SHA256d(nTime & 0xffffff80)`,
    /// so a worker rolling past the boundary computes a different hash
    /// function and burns its hashrate silently.
    pub fn within_one_epoch(&self) -> bool {
        self.ntime_min & TIME_MASK == self.ntime_max & TIME_MASK
    }

    pub fn is_empty(&self) -> bool {
        self.ntime_min > self.ntime_max
    }
}

/// Builds the job for one channel out of one round of template work.
///
/// The coinbase is the pool's to build and the pool's to get right: the node
/// re-serializes it and compares bytes before computing any proof of work.
/// That check only ever applies to what the pool submits, which is why an
/// extended channel can hand a miner a witness-free split without the two
/// requirements colliding.
#[allow(clippy::too_many_arguments)]
pub fn build(
    job_id: u32,
    template: &Template,
    prev: &PrevHash,
    constraints: &TimeConstraints,
    payout: &PayoutPlan,
    tag: &[u8],
    shape: Shape,
    future: bool,
) -> Result<Job> {
    // The worker's own address takes the spendable value. On a solo pool this
    // is the money, and it comes from the channel rather than from
    // configuration.
    let outputs = payout.outputs(template.coinbase_tx_value_remaining);
    let window = Window::from_template(constraints);
    if window.is_empty() {
        return Err(Error::Protocol(format!(
            "the node's ntime window is empty: {}..{}",
            window.ntime_min, window.ntime_max
        )));
    }

    let work = match shape {
        Shape::Standard { extranonce } => {
            let coinbase = Coinbase::build(template, &outputs, tag, &extranonce)?;
            JobWork::Standard {
                merkle_root: coinbase::merkle_root(&coinbase.txid, &template.merkle_path),
                coinbase: coinbase.with_witness,
            }
        }
        Shape::Extended {
            extranonce_prefix,
            extranonce_size,
        } => {
            let split = Coinbase::split(
                template,
                &outputs,
                tag,
                extranonce_prefix.len() + extranonce_size,
            )?;
            JobWork::Extended {
                split,
                merkle_path: template.merkle_path.clone(),
                extranonce_prefix,
                extranonce_size,
            }
        }
    };

    Ok(Job {
        job_id,
        template_id: template.template_id,
        version: template.version,
        prev_hash: prev.prev_hash,
        nbits: prev.nbits,
        window,
        network_target: prev.target,
        work,
        future,
    })
}

/// Which kind of job to build.
#[derive(Debug, Clone)]
pub enum Shape {
    Standard {
        extranonce: Vec<u8>,
    },
    Extended {
        extranonce_prefix: Vec<u8>,
        extranonce_size: usize,
    },
}

/// The extranonce for a job: the channel it belongs to and the job's own id.
///
/// On a standard channel the pool builds the coinbase, so the worker never
/// sees this as search space. It exists so two channels never hash the same
/// header, and it goes in the scriptSig after `coinbase_prefix`.
pub fn extranonce(channel_id: u32, job_id: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&channel_id.to_le_bytes());
    out[4..].copy_from_slice(&job_id.to_le_bytes());
    out
}

/// The algorithm a job's version declares, which must be the one the
/// connection selected.
pub fn pow_type_of(job: &Job) -> Result<PowType> {
    avian_sv2::avian::pow_type_from_version(job.version)
}

/// The pool's half of an extended channel's extranonce: the channel id.
///
/// Four bytes, so two channels cannot collide however the miner rolls its own
/// half.
pub fn extranonce_prefix(channel_id: u32) -> Vec<u8> {
    channel_id.to_le_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrowing_cannot_widen() {
        let window = Window {
            ntime_min: 100,
            ntime_max: 200,
        };
        // Asking for more room on either side gives none.
        let wider = window.narrow(50, 500);
        assert_eq!(wider, window);
        let tighter = window.narrow(120, 150);
        assert_eq!(tighter.ntime_min, 120);
        assert_eq!(tighter.ntime_max, 150);
    }

    #[test]
    fn a_window_is_inclusive_at_both_ends() {
        let window = Window {
            ntime_min: 100,
            ntime_max: 102,
        };
        assert!(!window.contains(99));
        assert!(window.contains(100));
        assert!(window.contains(102));
        assert!(!window.contains(103));
    }

    #[test]
    fn an_epoch_crossing_window_is_detected() {
        let base = 1_792_943_722u32 & TIME_MASK;
        assert!(Window {
            ntime_min: base,
            ntime_max: base + 127
        }
        .within_one_epoch());
        assert!(!Window {
            ntime_min: base,
            ntime_max: base + 128
        }
        .within_one_epoch());
    }

    #[test]
    fn an_extranonce_distinguishes_channels_and_jobs() {
        assert_ne!(extranonce(1, 1), extranonce(2, 1));
        assert_ne!(extranonce(1, 1), extranonce(1, 2));
        assert_eq!(extranonce(1, 1).len(), 8);
    }
}
