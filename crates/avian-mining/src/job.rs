//! A job, and the ntime window that comes with it.

use avian_sv2::avian::{PowType, TimeConstraints, TIME_MASK};
use avian_sv2::error::{Error, Result};
use avian_tdp::coinbase::{self, Coinbase};
use avian_tdp::tdp::{PrevHash, Template};

/// Everything needed to rebuild the header a worker hashed, and to turn a
/// winning share into a `SubmitSolution`.
#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: u32,
    pub template_id: u64,
    /// Fixed. `REQUIRES_FIXED_VERSION` is set on every Avian mining
    /// connection, so a submission whose version differs is refused: bits
    /// 16-23 are the algorithm, and rolling them moves the share to the other
    /// algorithm's proof-of-work limit.
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub nbits: u32,
    pub merkle_root: [u8; 32],
    pub window: Window,
    pub network_target: [u8; 32],
    /// Serialized with its witness, which is what `SubmitSolution` carries.
    pub coinbase: Vec<u8>,
    /// True while this job has not been activated by a `SetNewPrevHash`.
    pub future: bool,
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
pub fn build(
    job_id: u32,
    template: &Template,
    prev: &PrevHash,
    constraints: &TimeConstraints,
    payout_script: &[u8],
    extranonce: &[u8],
    future: bool,
) -> Result<Job> {
    let coinbase = Coinbase::build(template, payout_script, extranonce)?;
    let window = Window::from_template(constraints);
    if window.is_empty() {
        return Err(Error::Protocol(format!(
            "the node's ntime window is empty: {}..{}",
            window.ntime_min, window.ntime_max
        )));
    }
    Ok(Job {
        job_id,
        template_id: template.template_id,
        version: template.version,
        prev_hash: prev.prev_hash,
        nbits: prev.nbits,
        merkle_root: coinbase::merkle_root(&coinbase.txid, &template.merkle_path),
        window,
        network_target: prev.target,
        coinbase: coinbase.with_witness,
        future,
    })
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
