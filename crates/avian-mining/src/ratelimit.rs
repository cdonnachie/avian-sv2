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
//! The budget is sized from the pool's configured shares a minute, not from
//! anything the worker said. Each channel's target is derived so that it
//! averages that cadence, so the expected rate is the same for every channel
//! by construction and `nominal_hash_rate` never reaches this file. That is
//! the point: it was the one unverifiable, worker-supplied number on the path
//! that decides whether the pool spends a hash.
//!
//! It also decides what happens to a worker that understates itself. It is
//! handed a target that is too easy, finds shares far faster than the pool
//! asked for, and is refused here rather than served. Raising its target
//! instead would be vardiff, which stays out: the target is set once, when
//! the channel opens, and never moves.

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
    /// Allowed regardless of the expected rate, so that a pool configured for
    /// a very slow cadence does not throttle its workers to nothing.
    pub floor_per_second: f64,
    /// A hard ceiling, for a pool configured for an absurd one. Every admitted
    /// submission costs a full X16RT or MinotaurX hash, so this is the bound
    /// on what a single channel can make the pool spend.
    pub ceiling_per_second: f64,
    /// How many submissions may arrive at once.
    pub burst: f64,
    /// Invalid submissions before the channel is dropped, in the spirit of
    /// the node's `-sv2maxrejects`.
    pub max_invalid: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            tolerance: 8.0,
            // The expected rate no longer depends on the worker, so this is
            // a guard for a very low configured cadence rather than the
            // allowance every slow worker used to land on.
            floor_per_second: 1.0,
            ceiling_per_second: 50.0,
            burst: 16.0,
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

/// Shares per second a channel aiming at `shares_per_minute` should find.
///
/// Every channel's target is derived to hit that cadence, so this is the
/// expected rate for all of them and the worker's own figures do not appear.
pub fn expected_share_rate(shares_per_minute: f64) -> f64 {
    if !shares_per_minute.is_finite() || shares_per_minute <= 0.0 {
        return 0.0;
    }
    shares_per_minute / 60.0
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
    /// Sizes the bucket from the cadence the pool asked every channel to aim
    /// at, which is the same for all of them.
    pub fn new(shares_per_minute: f64, config: RateLimitConfig) -> Self {
        let expected = expected_share_rate(shares_per_minute);
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

    /// Thirty shares a minute is half a share a second, which at eight times
    /// tolerance is four a second: above the floor and below the ceiling, so
    /// neither clamp hides what the tests below are checking.
    const UNCLAMPED: f64 = 30.0;

    #[test]
    fn the_expected_rate_is_the_configured_cadence() {
        assert_eq!(expected_share_rate(60.0), 1.0);
        assert_eq!(expected_share_rate(UNCLAMPED), 0.5);
        assert_eq!(expected_share_rate(4.5), 4.5 / 60.0);
        // Unusable configuration buys nothing rather than an endless budget.
        assert_eq!(expected_share_rate(0.0), 0.0);
        assert_eq!(expected_share_rate(-1.0), 0.0);
        assert_eq!(expected_share_rate(f64::NAN), 0.0);
        assert_eq!(expected_share_rate(f64::INFINITY), 0.0);
    }

    #[test]
    fn the_default_cadence_lands_on_the_floor() {
        // 4.5 a minute at eight times tolerance is 0.6 a second, under the
        // floor, so every channel on the default configuration gets the floor.
        // Worth pinning: it is the allowance almost every real channel has.
        let config = RateLimitConfig::default();
        let limiter = Limiter::new(4.5, config);
        assert_eq!(limiter.rate(), config.floor_per_second);
    }

    #[test]
    fn a_limiter_lets_a_burst_through_and_then_throttles() {
        let config = RateLimitConfig::default();
        let mut limiter = Limiter::new(UNCLAMPED, config);
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
        let mut limiter = Limiter::new(UNCLAMPED, config);
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
        let expected = expected_share_rate(UNCLAMPED);
        let mut limiter = Limiter::new(UNCLAMPED, config);

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
        let mut limiter = Limiter::new(UNCLAMPED, config);
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
        let mut limiter = Limiter::new(UNCLAMPED, config);
        let now = Instant::now();
        for _ in 0..100 {
            limiter.admit_at(now);
        }
        assert!(limiter.refused_for_rate() > 0);
        assert_eq!(limiter.invalid(), 0);
        assert!(!limiter.exhausted());
    }

    #[test]
    fn an_absurd_configured_cadence_is_capped_by_the_ceiling() {
        let config = RateLimitConfig::default();
        // An operator asking for a thousand shares a minute would otherwise
        // let one channel spend 133 hashes a second of the pool's time.
        let limiter = Limiter::new(1000.0, config);
        assert_eq!(limiter.rate(), config.ceiling_per_second);
    }
}
