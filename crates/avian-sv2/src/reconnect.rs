//! Reconnection, and what does not survive it.
//!
//! This is in the library rather than in the pool because a miner needs it
//! more: a miner that stops on a dropped connection is useless, and nobody is
//! watching its logs.
//!
//! # What a reconnect preserves
//!
//! Configuration, and nothing else. **Every piece of protocol state is new.**
//! That is not a limitation of this implementation, it is what Stratum v2 is:
//!
//! - a new Noise handshake, so new session keys and nonce counters
//! - a new `SetupConnection`, extension negotiation and algorithm selection
//! - a new `channel_id`, and so a new coinbase extranonce from the pool
//! - new `job_id`s, which start again from the pool's counter
//! - the pool's accepted-share counters for the channel start at zero
//! - upstream, new `template_id`s, so every template held from the old session
//!   is unsubmittable
//!
//! So both ends must **discard every job and template** across a reconnect
//! rather than carrying them over. A share submitted against a job id from a
//! previous connection would at best be refused as `invalid-job-id` and at
//! worst be accepted against a different job that now has that id. The
//! `generation` counter on [`crate::client::MiningClient`] exists so a caller
//! can tell which connection a job came from and throw away work in flight.
//!
//! Hashrate in flight is lost too: a nonce found for a job from the previous
//! connection cannot be submitted anywhere.

use std::time::Duration;

use crate::error::{Error, Result};

/// Exponential backoff between reconnection attempts.
///
/// Deliberately without jitter, so a test can reason about the delays. A pool
/// with many miners reconnecting at once wants jitter to avoid a thundering
/// herd; on loopback, and for a single miner, it would only make the behaviour
/// harder to reason about. Add it at the point where a deployment has enough
/// miners for it to matter.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    pub factor: u32,
    /// `None` retries forever, which is what a miner wants: a pool that is
    /// down for an hour should be mined again when it comes back.
    pub max_attempts: Option<u32>,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(250),
            max: Duration::from_secs(30),
            factor: 2,
            max_attempts: None,
        }
    }
}

impl Backoff {
    /// No waiting and one attempt, for a caller that wants to handle failure
    /// itself.
    pub fn none() -> Self {
        Self {
            initial: Duration::ZERO,
            max: Duration::ZERO,
            factor: 1,
            max_attempts: Some(1),
        }
    }

    /// The delay before attempt `attempt`, counting from 1. Attempt 1 is
    /// immediate, because the first thing to try after a drop is reconnecting
    /// at once.
    pub fn delay(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        let mut delay = self.initial;
        for _ in 0..attempt.saturating_sub(2) {
            delay = delay.saturating_mul(self.factor);
            if delay >= self.max {
                return self.max;
            }
        }
        delay.min(self.max)
    }

    pub fn exhausted(&self, attempts: u32) -> bool {
        self.max_attempts.is_some_and(|max| attempts >= max)
    }
}

/// Runs `attempt` until it succeeds, the failure is one that will recur, or
/// the backoff is exhausted.
///
/// Whether to retry is decided here by [`is_transient`] rather than left to
/// the caller, because getting it wrong is invisible: an earlier version let
/// the caller signal "do not retry" by returning a different error, which this
/// loop then dutifully retried. A miner pointed at a pool that does not serve
/// its algorithm sat in a reconnect loop instead of saying so, which is the
/// silent-failure shape this project keeps meeting.
///
/// `on_retry` is told the attempt number, why it failed and how long the next
/// wait will be, so a caller can log it. Nothing here logs on its own: a
/// library that printed to stderr inside a miner would be a nuisance.
pub fn with_retry<T>(
    backoff: &Backoff,
    mut attempt: impl FnMut(u32) -> Result<T>,
    mut on_retry: impl FnMut(u32, &Error, Duration),
) -> Result<T> {
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let delay = backoff.delay(attempts);
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        match attempt(attempts) {
            Ok(value) => return Ok(value),
            Err(e) => {
                if !is_transient(&e) || backoff.exhausted(attempts) {
                    return Err(e);
                }
                on_retry(attempts, &e, backoff.delay(attempts + 1));
            }
        }
    }
}

/// A read that found nothing inside the caller's own deadline.
///
/// Not a dead connection, and so not something to reconnect over: the caller
/// asked to be given up on after a while and it was. Telling these apart
/// matters because a session that reconnected every time a caller's timeout
/// expired would log a reconnection storm on an idle chain, and an operator
/// reading that would reasonably think something was wrong.
pub fn is_read_timeout(error: &Error) -> bool {
    match error {
        Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        _ => false,
    }
}

/// A failure that should be retried, as opposed to one that will fail the same
/// way every time.
///
/// A refused `SetupConnection` or a certificate that does not verify will not
/// improve on a retry, and retrying forever would turn a configuration mistake
/// into a silent hang, which is the failure mode this whole project keeps
/// running into. A dropped socket will improve.
pub fn is_transient(error: &Error) -> bool {
    match error {
        Error::Io(_) => true,
        Error::Protocol(message) => message.contains("closed the Stratum v2 connection"),
        // A refusal names a reason the peer will give again, and a malformed
        // payload or a framing error means the two sides disagree about the
        // format.
        Error::Refused(_) | Error::Payload(_) | Error::Framing(_) | Error::Binary(_) => false,
        // A Noise failure is either a bad certificate or a transcript
        // mismatch, and neither is fixed by trying again.
        Error::Codec(_) | Error::Secp(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_attempt_does_not_wait() {
        let backoff = Backoff::default();
        assert_eq!(backoff.delay(1), Duration::ZERO);
        assert_eq!(backoff.delay(2), Duration::from_millis(250));
        assert_eq!(backoff.delay(3), Duration::from_millis(500));
        assert_eq!(backoff.delay(4), Duration::from_millis(1000));
    }

    #[test]
    fn the_delay_is_capped() {
        let backoff = Backoff::default();
        assert_eq!(backoff.delay(100), Duration::from_secs(30));
        assert_eq!(backoff.delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn unlimited_attempts_never_exhaust() {
        let backoff = Backoff::default();
        assert!(!backoff.exhausted(1_000_000));
        assert!(Backoff::none().exhausted(1));
    }

    #[test]
    fn a_read_timeout_is_told_apart_from_a_dropped_socket() {
        assert!(is_read_timeout(&Error::Io(std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        ))));
        assert!(is_read_timeout(&Error::Io(std::io::Error::from(
            std::io::ErrorKind::TimedOut
        ))));
        assert!(!is_read_timeout(&Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
        assert!(!is_read_timeout(&Error::Protocol(
            "the peer closed the Stratum v2 connection".into()
        )));
    }

    #[test]
    fn a_refusal_is_not_retried_but_a_dropped_socket_is() {
        assert!(!is_transient(&Error::Refused(
            "unsupported-protocol".into()
        )));
        assert!(!is_transient(&Error::Protocol(
            "version_rolling_mask is 0x0000ffff".into()
        )));
        assert!(is_transient(&Error::Protocol(
            "the peer closed the Stratum v2 connection".into()
        )));
        assert!(is_transient(&Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
    }

    #[test]
    fn with_retry_stops_when_attempts_run_out() {
        let backoff = Backoff {
            initial: Duration::ZERO,
            max: Duration::ZERO,
            factor: 1,
            max_attempts: Some(3),
        };
        let mut seen = 0;
        let result: Result<()> = with_retry(
            &backoff,
            |attempt| {
                seen = attempt;
                Err(Error::Io(std::io::Error::from(
                    std::io::ErrorKind::ConnectionRefused,
                )))
            },
            |_, _, _| {},
        );
        assert!(result.is_err());
        assert_eq!(seen, 3);
    }

    #[test]
    fn with_retry_gives_up_at_once_on_a_failure_that_will_recur() {
        // Unlimited attempts, so a wrong decision here would loop forever
        // rather than fail a test. A refused algorithm is the real case: a
        // miner pointed at a pool that does not serve it must be told, not
        // left reconnecting.
        let backoff = Backoff {
            initial: Duration::ZERO,
            max: Duration::ZERO,
            factor: 1,
            max_attempts: None,
        };
        let mut seen = 0;
        let result: Result<()> = with_retry(
            &backoff,
            |attempt| {
                seen = attempt;
                Err(Error::Refused("unsupported-pow-type".into()))
            },
            |_, _, _| {},
        );
        assert!(result.is_err());
        assert_eq!(seen, 1, "a refusal must not be retried even once");
    }

    #[test]
    fn with_retry_returns_the_first_success() {
        let backoff = Backoff::none();
        let got: u32 = with_retry(&backoff, Ok, |_, _, _| {}).unwrap();
        assert_eq!(got, 1);
    }
}
