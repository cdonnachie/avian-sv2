//! Stratum v1 difficulty to Stratum v2 target, and back.
//!
//! This is the one piece of a bridge that has to be right about somebody
//! else's accounting, so it lives on its own and is tested on its own.
//! `mining.set_difficulty` is in difficulty units and so is the operator's
//! entire ledger, while a Stratum v2 `SetTarget` carries a 256-bit target and
//! nothing else, so the conversion has to exist in both directions and agree
//! with itself.
//!
//! **A conversion wrong by a constant factor is the worst failure available
//! to a bridge.** Every miner would see a working pool, every share would be
//! accepted, and every number in the operator's database would be wrong, with
//! nothing anywhere saying so. Unlike a byte order, which breaks loudly and
//! immediately, this one has to be checked on purpose: see the round-trip
//! tests below, and check a live pool's accepted-share count before trusting
//! it with anyone's payouts.
//!
//! Difficulty is defined against a reference target, and Avian's is its
//! `powLimit`. The one piece of luck here is that there is a single
//! `powLimit` for both algorithms rather than one each — `src/pow.cpp` in
//! Avian Core annotates it "Minimum diff, 00000ffff... for both algos" — so
//! X16RT and MinotaurX share this arithmetic and a bridge needs no per
//! algorithm table.

use avian_sv2::block::{hashes_per_share, target_for_hashes_per_share};
use avian_sv2::error::{Error, Result};

/// `powLimit` for mainnet and the public testnets, little-endian, which is the
/// byte order every target in this tree is in. Written big-endian, the way
/// `chainparams.cpp` and an explorer show it, this is
/// `00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
pub const POW_LIMIT: [u8; 32] = {
    let mut limit = [0xffu8; 32];
    // `00000f` is two zero bytes and then `0f`, not three and then `0f`: it is
    // five hex zeros, which is an odd number of nibbles. Counting them wrong
    // puts the limit at 2^228 instead of 2^236 and every converted difficulty
    // out by 256, which is exactly the kind of mistake this module exists to
    // keep in one place.
    limit[31] = 0x00;
    limit[30] = 0x00;
    limit[29] = 0x0f;
    limit
};

/// `powLimit` on regtest, where it is
/// `7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`: one
/// difficulty unit is two hashes, so a test can mine without waiting.
pub const POW_LIMIT_REGTEST: [u8; 32] = {
    let mut limit = [0xffu8; 32];
    limit[31] = 0x7f;
    limit
};

/// The `powLimit` for a chain by the name `--chain` takes.
pub fn pow_limit(chain: &str) -> [u8; 32] {
    match chain {
        "regtest" => POW_LIMIT_REGTEST,
        _ => POW_LIMIT,
    }
}

/// The target a `mining.set_difficulty` of `difficulty` asks for.
///
/// Difficulty 1 is `pow_limit` itself and difficulty 2 is twice the work, so
/// this is `pow_limit`'s worth of hashes scaled by the difficulty and then run
/// through the target derivation the Stratum v2 side already uses. Going
/// through hashes rather than dividing a 256-bit number by a float is what
/// keeps this exact: [`target_for_hashes_per_share`] does the 256-bit
/// arithmetic in integers, and the only float is the difficulty the pool sent.
pub fn target_from_difficulty(pow_limit: &[u8; 32], difficulty: f64) -> Result<[u8; 32]> {
    if !difficulty.is_finite() || difficulty <= 0.0 {
        return Err(Error::Protocol(format!(
            "mining.set_difficulty sent {difficulty}, which is not a difficulty"
        )));
    }
    let hashes = hashes_per_share(pow_limit) * difficulty;
    if !hashes.is_finite() {
        return Err(Error::Protocol(format!(
            "a difficulty of {difficulty} overflows the work it stands for"
        )));
    }
    // Above this the work per share exceeds what a u128 holds, which is some
    // 10^25 times the hash rate of everything that has ever mined Avian. It is
    // refused rather than clamped, because clamping would hand a miner a
    // target easier than the pool asked for and let it flood shares the pool
    // will refuse.
    if hashes >= u128::MAX as f64 {
        return Err(Error::Protocol(format!(
            "a difficulty of {difficulty} is past what a 256-bit target can express"
        )));
    }
    Ok(target_for_hashes_per_share(hashes.round() as u128))
}

/// What difficulty a target corresponds to, for a `mining.submit` the upstream
/// pool will credit, and for reporting a channel's difficulty the way the
/// operator's own pages already do.
pub fn difficulty_from_target(pow_limit: &[u8; 32], target: &[u8; 32]) -> f64 {
    let reference = hashes_per_share(pow_limit);
    if reference <= 0.0 {
        return 0.0;
    }
    hashes_per_share(target) / reference
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a target the way `chainparams.cpp` does, for readable failures.
    fn big_endian(target: &[u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for byte in target.iter().rev() {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn the_constants_are_the_values_avian_core_has() {
        assert_eq!(
            big_endian(&POW_LIMIT),
            "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(
            big_endian(&POW_LIMIT_REGTEST),
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(pow_limit("regtest"), POW_LIMIT_REGTEST);
        assert_eq!(pow_limit("main"), POW_LIMIT);
        // An unknown chain gets the hard limit rather than the easy one: a
        // bridge pointed at a chain it does not know should hand out targets
        // nobody can meet by accident, not targets everybody can.
        assert_eq!(pow_limit("nonesuch"), POW_LIMIT);
    }

    #[test]
    fn difficulty_one_is_the_pow_limit_itself() {
        // The definition of difficulty, and the assertion that would have
        // caught a reference target off by a factor of anything.
        let difficulty = difficulty_from_target(&POW_LIMIT, &POW_LIMIT);
        assert!(
            (difficulty - 1.0).abs() < 1e-9,
            "the pow limit should be difficulty 1, got {difficulty}"
        );
    }

    #[test]
    fn doubling_the_difficulty_halves_the_target() {
        let easy = target_from_difficulty(&POW_LIMIT, 1024.0).expect("a plain difficulty");
        let hard = target_from_difficulty(&POW_LIMIT, 2048.0).expect("a plain difficulty");
        let ratio = hashes_per_share(&hard) / hashes_per_share(&easy);
        assert!(
            (ratio - 2.0).abs() < 1e-6,
            "twice the difficulty should be twice the work, got {ratio}"
        );
    }

    #[test]
    fn a_difficulty_survives_the_round_trip() {
        // The test that matters: a pool says a difficulty, the bridge turns it
        // into a target for the miner, and reading that target back has to
        // give the pool's number again. Anything else and the operator's
        // database and the miner's screen disagree.
        //
        // The guarantee is one hash of work and not a flat relative error,
        // because [`target_for_hashes_per_share`] takes whole hashes: at
        // difficulty 0.001 a mainnet share is about 1048 of them, so rounding
        // to the nearest costs 0.04% and no arithmetic here can do better. A
        // test demanding 1e-6 at that difficulty would be testing a promise
        // the type signature cannot keep.
        for difficulty in [
            0.001, 0.015625, 0.5, 1.0, 2.0, 16.0, 1000.0, 65536.0, 1.5e6, 1e9, 4.2e11,
        ] {
            let target = target_from_difficulty(&POW_LIMIT, difficulty)
                .unwrap_or_else(|e| panic!("difficulty {difficulty} should convert: {e}"));
            let asked = hashes_per_share(&POW_LIMIT) * difficulty;
            let got = hashes_per_share(&target);
            assert!(
                (got - asked).abs() <= 1.0,
                "difficulty {difficulty} asked for {asked} hashes and the target is worth {got}"
            );

            // And the difficulty itself comes back, to the precision those
            // whole hashes allow.
            let back = difficulty_from_target(&POW_LIMIT, &target);
            let tolerance = (2.0 / asked).max(1e-12);
            let error = (back - difficulty).abs() / difficulty;
            assert!(
                error < tolerance,
                "difficulty {difficulty} came back as {back}, off by {error} \
                 (target {})",
                big_endian(&target)
            );
        }
    }

    #[test]
    fn difficulty_one_on_regtest_is_the_regtest_limit() {
        // `7fff...` is met by half of all hashes, so a share there takes two
        // draws on average, while `hashes_per_share` reports one: it counts
        // the draws that fail, which is the convention
        // `target_for_hashes_per_share` inverts and therefore the convention
        // this module has to use to round-trip. The difference is one hash. It
        // is invisible at any target a pool hands out and glaring here, which
        // is why the assertion below is the inverse property and not a hash
        // count.
        let target = target_from_difficulty(&POW_LIMIT_REGTEST, 1.0).expect("difficulty 1");
        assert_eq!(
            big_endian(&target),
            big_endian(&POW_LIMIT_REGTEST),
            "difficulty 1 on regtest should be the regtest pow limit"
        );
    }

    #[test]
    fn mainnet_difficulty_one_costs_about_a_million_hashes() {
        // 00000fffff... is 2^-20 of the space, so a difficulty-1 share is
        // roughly a million hashes. A sanity check on the constant itself:
        // Bitcoin's difficulty 1 is 2^32 hashes, and reading Avian's as that
        // would miscredit every share by a factor of four thousand.
        let work = hashes_per_share(&POW_LIMIT);
        assert!(
            (work / 1_048_576.0 - 1.0).abs() < 0.001,
            "expected about 2^20 hashes for difficulty 1, got {work}"
        );
    }

    #[test]
    fn a_difficulty_that_is_not_one_is_refused_rather_than_guessed_at() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, 1e300] {
            assert!(
                target_from_difficulty(&POW_LIMIT, bad).is_err(),
                "a difficulty of {bad} should be refused"
            );
        }
    }
}
