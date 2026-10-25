//! Per-channel submission limits.
//!
//! Not optional, and not a nicety. doc/sv2.md explains why for the node and
//! the same applies here: **there is no cheap pre-filter for Avian's proof of
//! work.** SHA256d lets a server check a few leading bytes before committing
//! to real work; X16RT and MinotaurX have no such form, so the only way to
//! know whether a submission is valid is to compute the whole hash. A worker
//! that writes nonces as fast as its socket allows costs the pool a full
//! X16RT or MinotaurX hash per nonce, and no amount of cheap field checking
//! changes that.
//!
//! So the limiter runs **before** anything else on a submission, including the
//! job lookup. A refused-by-rate submission costs a mutex and a subtraction.
//!
//! Two counters, kept apart, as the node keeps `-sv2maxrejects` apart from its
//! rate limit:
//!
//! - a token bucket on **every** submission, because the cost is the hash and
//!   a valid submission costs exactly as much as an invalid one
//! - a running total of **invalid** submissions, which drops the channel,
//!   because a worker that keeps failing has been told something it is not
//!   acting on and will never find a block
//!
//! What is deliberately absent is vardiff. The honest answer to a worker
//! flooding cheap shares is usually to raise its target, and that is vardiff,
//! which is entangled with this and deferred. The share target here is fixed.

use std::time::Instant;

use avian_sv2::block;

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// How many times the expected share rate a channel may sustain.
    ///
    /// Shares arrive as a Poisson process, so a worker mining honestly at the
    /// expected rate will exceed it often over short windows. This is the
    /// headroom for that, not a licence to flood.
    pub tolerance: f64,
    /// Allowed regardless of the expected rate, so a slow worker is not
    /// throttled to nothing by arithmetic.
    pub floor_per_second: f64,
    /// A hard ceiling, because the expected rate is derived in part from a
    /// number the worker supplied.
    pub ceiling_per_second: f64,
    /// How many submissions may arrive at once.
    pub burst: f64,
    /// `nominal_hash_rate` above this is ignored. The field is worker-supplied
    /// and unverifiable: a worker claiming a petahash would otherwise be
    /// granting itself an unlimited budget.
    pub max_nominal_hash_rate: f64,
    /// Invalid submissions before the channel is dropped, in the spirit of
    /// the node's `-sv2maxrejects`.
    pub max_invalid: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            tolerance: 8.0,
            floor_per_second: 2.0,
            ceiling_per_second: 50.0,
            burst: 16.0,
            // 1 TH/s. Far above any Avian CPU or GPU miner, and far below a
            // number that would make the ceiling irrelevant.
            max_nominal_hash_rate: 1e12,
            max_invalid: 50,
        }
    }
}

/// The chance a random hash is at or under a target.
///
/// The target is little-endian, so byte `j` has weight `256^j`, and the whole
/// space is `256^32`. Summing `byte[j] * 256^(j-32)` in `f64` stays well
/// inside its exponent range even for the lowest byte.
pub fn target_probability(target: &[u8; 32]) -> f64 {
    let mut probability = 0.0f64;
    for (j, byte) in target.iter().enumerate() {
        if *byte != 0 {
            probability += *byte as f64 * 256f64.powi(j as i32 - 32);
        }
    }
    probability
}

/// Shares per second a worker claiming `nominal_hash_rate` should find at
/// `target`.
pub fn expected_share_rate(
    target: &[u8; 32],
    nominal_hash_rate: f32,
    config: &RateLimitConfig,
) -> f64 {
    let claimed = (nominal_hash_rate as f64)
        .max(0.0)
        .min(config.max_nominal_hash_rate);
    if !claimed.is_finite() {
        return 0.0;
    }
    claimed * target_probability(target)
}

/// What the limiter decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Over the rate. Refuse cheaply and do not hash.
    TooFast,
    /// Too many invalid submissions. Refuse and drop the channel.
    TooManyInvalid,
}

/// A token bucket plus an invalid-submission tally, for one channel.
pub struct Limiter {
    config: RateLimitConfig,
    /// Tokens refilled per second.
    rate: f64,
    tokens: f64,
    last: Instant,
    invalid: u32,
    refused_for_rate: u64,
}

impl Limiter {
    /// Sizes the bucket from the channel's target and the hash rate the worker
    /// claimed.
    pub fn new(target: &[u8; 32], nominal_hash_rate: f32, config: RateLimitConfig) -> Self {
        let expected = expected_share_rate(target, nominal_hash_rate, &config);
        let rate = (expected * config.tolerance)
            .max(config.floor_per_second)
            .min(config.ceiling_per_second);
        Self {
            config,
            rate,
            tokens: config.burst,
            last: Instant::now(),
            invalid: 0,
            refused_for_rate: 0,
        }
    }

    /// Submissions per second this channel may sustain.
    pub fn rate(&self) -> f64 {
        self.rate
    }

    pub fn invalid(&self) -> u32 {
        self.invalid
    }

    pub fn refused_for_rate(&self) -> u64 {
        self.refused_for_rate
    }

    /// Call once per submission, before any work is done on it.
    pub fn admit(&mut self) -> Decision {
        self.admit_at(Instant::now())
    }

    pub fn admit_at(&mut self, now: Instant) -> Decision {
        if self.invalid >= self.config.max_invalid {
            return Decision::TooManyInvalid;
        }
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.config.burst);
        if self.tokens < 1.0 {
            self.refused_for_rate += 1;
            return Decision::TooFast;
        }
        self.tokens -= 1.0;
        Decision::Allow
    }

    /// Record that an admitted submission turned out to be invalid.
    pub fn record_invalid(&mut self) {
        self.invalid = self.invalid.saturating_add(1);
    }

    /// Whether the channel has used up its allowance of invalid submissions.
    pub fn exhausted(&self) -> bool {
        self.invalid >= self.config.max_invalid
    }
}

/// Whether a target is the easiest one there is, which is what regtest uses.
///
/// Only for logging: a pool on regtest should not be surprised that every
/// share is a block.
pub fn is_trivial_target(target: &[u8; 32]) -> bool {
    target_probability(target) > 0.01
}

/// Re-exported so a caller sizing a limiter does not need two imports.
pub use block::meets_target;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Regtest's target, little-endian: the algorithm's own floor.
    fn regtest_target() -> [u8; 32] {
        let mut target = [0u8; 32];
        target[31] = 0x7f;
        target[30] = 0xff;
        target[29] = 0xff;
        target
    }

    #[test]
    fn the_regtest_target_is_met_by_about_half_of_all_nonces() {
        let probability = target_probability(&regtest_target());
        assert!(
            (0.49..0.51).contains(&probability),
            "expected about a half, got {probability}"
        );
    }

    #[test]
    fn a_harder_target_is_proportionally_less_likely() {
        let easy = regtest_target();
        let harder = block::harder_by(&easy, 10);
        let ratio = target_probability(&easy) / target_probability(&harder);
        assert!(
            (1000.0..1030.0).contains(&ratio),
            "ten halvings should be about 1024 times less likely, got {ratio}"
        );
        assert_eq!(target_probability(&[0u8; 32]), 0.0);
    }

    #[test]
    fn the_expected_rate_ignores_an_absurd_hash_rate_claim() {
        let config = RateLimitConfig::default();
        let honest = expected_share_rate(&regtest_target(), 1.0, &config);
        assert!((0.49..0.51).contains(&honest), "{honest}");

        // A worker claiming a petahash is clamped to the configured maximum,
        // so its budget stops growing with its claim. The comparison is
        // approximate because nominal_hash_rate is an f32 and neither 1e12 nor
        // 1e15 is exact in one.
        let absurd = expected_share_rate(&regtest_target(), 1e15, &config);
        let ceiling = config.max_nominal_hash_rate * target_probability(&regtest_target());
        assert!(
            absurd <= ceiling * 1.001,
            "a petahash claim bought {absurd}, and the cap is {ceiling}"
        );
        // And what actually matters: the budget is the same either way,
        // because both land on the ceiling.
        assert_eq!(
            Limiter::new(&regtest_target(), 1e15, config).rate(),
            Limiter::new(&regtest_target(), 1e12, config).rate()
        );
    }

    #[test]
    fn a_limiter_lets_a_burst_through_and_then_throttles() {
        let config = RateLimitConfig::default();
        let mut limiter = Limiter::new(&regtest_target(), 1.0, config);
        // Half a share a second at eight times tolerance is four a second,
        // which is above the floor and below the ceiling, so neither clamp
        // applies.
        let rate = limiter.rate();
        assert!(
            (3.9..4.1).contains(&rate),
            "expected about four a second, got {rate}"
        );

        let now = Instant::now();
        for i in 0..config.burst as u32 {
            assert_eq!(limiter.admit_at(now), Decision::Allow, "submission {i}");
        }
        assert_eq!(
            limiter.admit_at(now),
            Decision::TooFast,
            "the burst is spent and no time has passed"
        );
        assert_eq!(limiter.refused_for_rate(), 1);
    }

    #[test]
    fn tokens_come_back_with_time() {
        let config = RateLimitConfig::default();
        let mut limiter = Limiter::new(&regtest_target(), 1.0, config);
        let start = Instant::now();
        for _ in 0..config.burst as u32 {
            limiter.admit_at(start);
        }
        assert_eq!(limiter.admit_at(start), Decision::TooFast);
        // At about four a second, one second buys about four and no more.
        let later = start + Duration::from_secs(1);
        let mut allowed = 0;
        while limiter.admit_at(later) == Decision::Allow {
            allowed += 1;
            assert!(allowed < 100, "the bucket refilled without time passing");
        }
        assert!(
            (3..=4).contains(&allowed),
            "one second at {} a second bought {allowed}",
            limiter.rate()
        );
    }

    #[test]
    fn an_honest_worker_at_the_expected_rate_is_never_throttled() {
        // A worker finding shares at exactly the rate its target implies must
        // not be refused, or the pool is broken for the people using it
        // correctly. Ten minutes of simulated mining, submitting on the
        // expected interval.
        let config = RateLimitConfig::default();
        let target = regtest_target();
        let hash_rate = 20.0f32;
        let expected = expected_share_rate(&target, hash_rate, &config);
        let mut limiter = Limiter::new(&target, hash_rate, config);

        let interval = Duration::from_secs_f64(1.0 / expected);
        let mut now = Instant::now();
        for i in 0..600 {
            assert_eq!(
                limiter.admit_at(now),
                Decision::Allow,
                "submission {i} at the expected rate was throttled; rate is {}",
                limiter.rate()
            );
            now += interval;
        }
        assert_eq!(limiter.refused_for_rate(), 0);
    }

    #[test]
    fn invalid_submissions_eventually_drop_the_channel() {
        let config = RateLimitConfig {
            max_invalid: 3,
            ..RateLimitConfig::default()
        };
        let mut limiter = Limiter::new(&regtest_target(), 1.0, config);
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.admit_at(now), Decision::Allow);
            limiter.record_invalid();
        }
        assert!(limiter.exhausted());
        assert_eq!(limiter.admit_at(now), Decision::TooManyInvalid);
    }

    #[test]
    fn a_rate_refusal_does_not_count_as_invalid() {
        // Otherwise a flood would be punished twice, and a worker whose only
        // sin is being fast would be dropped as if it were sending rubbish.
        let config = RateLimitConfig::default();
        let mut limiter = Limiter::new(&regtest_target(), 1.0, config);
        let now = Instant::now();
        for _ in 0..100 {
            limiter.admit_at(now);
        }
        assert!(limiter.refused_for_rate() > 0);
        assert_eq!(limiter.invalid(), 0);
        assert!(!limiter.exhausted());
    }

    #[test]
    fn a_very_fast_worker_is_capped_by_the_ceiling() {
        let config = RateLimitConfig::default();
        // A claim that would otherwise buy an enormous rate.
        let limiter = Limiter::new(&regtest_target(), 1e9, config);
        assert_eq!(limiter.rate(), config.ceiling_per_second);
    }
}
