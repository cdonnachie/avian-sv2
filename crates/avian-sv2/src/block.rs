//! Header serialization, hashing and target arithmetic.
//!
//! Everything here is needed by both ends: a pool to check a share, a miner to
//! build the header it hashes and to decide whether the result is worth
//! submitting. None of it computes a proof of work. X16RT and MinotaurX are
//! deliberately absent from this library, and so is CPU and GPU hashing: a
//! miner has its own, heavily optimised, and that is the entire reason it is a
//! miner. The library's job is to hand it a job and take back a share.
//!
//! Coinbase construction is not here either. The pool builds the coinbase, so
//! it lives with the pool, in `avian_tdp::coinbase`.

use secp256k1::hashes::{sha256, Hash, HashEngine};

use crate::wire::Writer;

/// Bitcoin's double SHA256, in its natural byte order. A block hash or txid is
/// displayed with these bytes reversed.
pub fn sha256d(parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    for part in parts {
        engine.input(part);
    }
    let first = sha256::Hash::from_engine(engine).to_byte_array();
    sha256::Hash::hash(&first).to_byte_array()
}

/// Folds a merkle path onto a leaf.
///
/// The coinbase is always the leftmost leaf, so every sibling in the path is a
/// right-hand one and the order never varies. `solution_check.cpp` does the
/// same thing with the same orientation.
///
/// In the library because both ends need it: a pool folding the path onto a
/// coinbase it built, and a miner on an extended channel folding it onto one
/// it assembled itself.
pub fn merkle_root(leaf: &[u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *leaf;
    for sibling in path {
        current = sha256d(&[&current, sibling]);
    }
    current
}

/// The 80 bytes a proof-of-work hash is computed over.
pub fn header(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut writer = Writer::new();
    let bytes = writer
        .u32(version)
        .raw(prev_hash)
        .raw(merkle_root)
        .u32(ntime)
        .u32(nbits)
        .u32(nonce)
        .finish();
    let mut out = [0u8; 80];
    out.copy_from_slice(&bytes);
    out
}

/// Whether a proof-of-work hash is at or under a target.
///
/// Both are 32 bytes in `uint256`'s internal order, which is little-endian, so
/// the comparison runs from the most significant byte down. `aviand` compares
/// `UintToArith256(hash) > bnTarget`, so equality passes.
pub fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        match hash[i].cmp(&target[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Divides a target by a power of two, making it that many times harder.
///
/// Used to set a share target below the network target. Shifting rather than
/// dividing keeps this exact and keeps the result a valid `uint256`.
pub fn harder_by(target: &[u8; 32], shift: u32) -> [u8; 32] {
    // Work most-significant first, which is index 31 downwards.
    let mut big = [0u8; 32];
    for i in 0..32 {
        big[i] = target[31 - i];
    }
    for _ in 0..shift {
        let mut carry = 0u8;
        for byte in big.iter_mut() {
            let next = (*byte & 1) << 7;
            *byte = (*byte >> 1) | carry;
            carry = next;
        }
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = big[31 - i];
    }
    out
}

/// The target a compact `nBits` encodes, as a little-endian integer.
///
/// The sign bit is dropped rather than honoured, matching what consensus does
/// with a negative compact target: nothing can meet it, and treating it as
/// positive keeps this a pure decoder with no error case.
pub fn target_from_nbits(nbits: u32) -> [u8; 32] {
    let exponent = (nbits >> 24) as usize;
    let mantissa = nbits & 0x007f_ffff;
    let mut out = [0u8; 32];
    if exponent <= 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        for i in 0..3 {
            out[i] = ((shifted >> (8 * i)) & 0xff) as u8;
        }
    } else {
        let offset = exponent - 3;
        for i in 0..3 {
            if offset + i < 32 {
                out[offset + i] = ((mantissa >> (8 * i)) & 0xff) as u8;
            }
        }
    }
    out
}

/// The target made easier by `shift` halvings of difficulty.
///
/// The counterpart to [`harder_by`], and the one a share target wants:
/// halving the difficulty doubles the target, so this shifts the integer up
/// rather than down. Saturates at the largest representable target instead of
/// wrapping, because a wrapped share target would come out harder than the
/// one asked for, which is the opposite of what the caller wanted and would
/// be invisible.
pub fn easier_by(target: &[u8; 32], shift: u32) -> [u8; 32] {
    // Work most-significant first, which is index 31 downwards.
    let mut big = [0u8; 32];
    for i in 0..32 {
        big[i] = target[31 - i];
    }
    for _ in 0..shift {
        let mut carry = 0u8;
        for byte in big.iter_mut().rev() {
            let next = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next;
        }
        if carry != 0 {
            return [0xff; 32];
        }
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = big[31 - i];
    }
    out
}

/// How much work one share should cost, for a worker at `hash_rate` hashes a
/// second to average `shares_per_minute` of them.
///
/// The whole of the pool's share cadence is this one line. It is a function so
/// that [`target_for_hashes_per_share`], which is meaningless without it, has
/// something to point at.
///
/// Returns zero for an unusable rate, which yields the easiest target there
/// is, so callers clamp the hash rate before asking rather than after.
pub fn hashes_per_share_for(hash_rate: f64, shares_per_minute: f64) -> f64 {
    if !hash_rate.is_finite() || !(shares_per_minute > 0.0) {
        return 0.0;
    }
    hash_rate * 60.0 / shares_per_minute
}

/// The target at which finding a share costs `hashes_per_share` hashes.
///
/// A hash is a uniform draw from `2^256` values of which `t + 1` succeed, so
/// the expected number of draws before one lands at or under `t` is
/// `(2^256 - t) / (t + 1)`. Setting that equal to the work we want a share to
/// cost and solving for `t` gives
///
/// ```text
/// t = (2^256 - s) / (s + 1)
/// ```
///
/// which is the same derivation the Stratum v2 reference implementation uses,
/// so a worker built against another pool's arithmetic meets this one.
///
/// Little-endian, like every other target here.
pub fn target_for_hashes_per_share(hashes_per_share: u128) -> [u8; 32] {
    // No work per share would be the easiest target there is, and the formula
    // divides by `s + 1`, so one is the floor rather than a special case.
    let s = hashes_per_share.max(1);
    // The division below holds its remainder in a u128 and shifts it a byte at
    // a time, so the divisor needs eight bits of headroom. Callers clamp the
    // hash rate far below this; saturating keeps one that stops doing so from
    // wrapping into an easier target than it asked for.
    let s = s.min((1u128 << 120) - 1);

    // The numerator is 2^256 - s, which does not fit in 32 bytes written that
    // way round, so build it as (2^256 - 1) - (s - 1). Big-endian, for the
    // division.
    let mut subtrahend = [0u8; 32];
    let below = s - 1;
    for i in 0..16 {
        subtrahend[31 - i] = ((below >> (8 * i)) & 0xff) as u8;
    }
    let mut numerator = [0xffu8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let lhs = u16::from(numerator[i]);
        let rhs = u16::from(subtrahend[i]) + borrow;
        if lhs >= rhs {
            numerator[i] = (lhs - rhs) as u8;
            borrow = 0;
        } else {
            numerator[i] = (lhs + 256 - rhs) as u8;
            borrow = 1;
        }
    }

    // Long division, most significant byte first. Every remainder is below the
    // divisor, so `remainder * 256 + byte` stays below `divisor * 256` and each
    // quotient digit fits in a byte.
    let divisor = s + 1;
    let mut quotient = [0u8; 32];
    let mut remainder = 0u128;
    for i in 0..32 {
        remainder = (remainder << 8) | u128::from(numerator[i]);
        quotient[i] = (remainder / divisor) as u8;
        remainder %= divisor;
    }

    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = quotient[31 - i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_matches_a_known_digest() {
        // SHA256d of the empty string.
        assert_eq!(
            crate::wire::hex(&sha256d(&[b""])),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn an_empty_path_leaves_the_leaf_as_the_root() {
        let leaf = [7u8; 32];
        assert_eq!(merkle_root(&leaf, &[]), leaf);
    }

    #[test]
    fn the_leaf_is_always_on_the_left() {
        let leaf = [1u8; 32];
        let sibling = [2u8; 32];
        assert_eq!(
            merkle_root(&leaf, &[sibling]),
            sha256d(&[&leaf, &sibling]),
            "the sibling must be concatenated on the right"
        );
    }

    #[test]
    fn a_header_is_eighty_bytes_in_field_order() {
        let bytes = header(0x3200_0000, &[0xaa; 32], &[0xbb; 32], 1, 2, 3);
        assert_eq!(bytes.len(), 80);
        assert_eq!(&bytes[0..4], &0x3200_0000u32.to_le_bytes());
        assert_eq!(&bytes[4..36], &[0xaa; 32]);
        assert_eq!(&bytes[36..68], &[0xbb; 32]);
        assert_eq!(&bytes[68..72], &1u32.to_le_bytes());
    }

    #[test]
    fn a_target_is_compared_as_a_little_endian_integer() {
        let mut target = [0u8; 32];
        target[31] = 0x7f;
        let mut under = [0u8; 32];
        under[31] = 0x7e;
        let mut over = [0u8; 32];
        over[31] = 0x80;

        assert!(meets_target(&under, &target));
        assert!(meets_target(&target, &target), "equality passes");
        assert!(!meets_target(&over, &target));

        // A difference in a low-order byte must not outrank a high-order one.
        let mut low_byte_big = [0u8; 32];
        low_byte_big[0] = 0xff;
        low_byte_big[31] = 0x7e;
        assert!(meets_target(&low_byte_big, &target));
    }

    #[test]
    fn harder_by_shifts_the_whole_integer() {
        let mut target = [0u8; 32];
        target[31] = 0x7f;
        target[30] = 0xff;
        let once = harder_by(&target, 1);
        assert_eq!(once[31], 0x3f);
        assert_eq!(once[30], 0xff);
        assert!(meets_target(&once, &target), "harder is still under");
        assert!(!meets_target(&target, &once));
        assert_eq!(harder_by(&target, 0), target);
    }

    #[test]
    fn nbits_decodes_to_a_little_endian_target() {
        // Bitcoin's difficulty-1 target, which is quoted big-endian as
        // 00000000ffff0000... So the mantissa sits at big-endian bytes four
        // and five, which are indices 27 and 26 here.
        let target = target_from_nbits(0x1d00_ffff);
        assert_eq!(target[31], 0x00);
        assert_eq!(target[28], 0x00);
        assert_eq!(target[27], 0xff);
        assert_eq!(target[26], 0xff);
        assert_eq!(target[25], 0x00);

        // Regtest's limit, which is as easy as a target gets.
        let regtest = target_from_nbits(0x207f_ffff);
        assert_eq!(regtest[31], 0x7f);
        assert_eq!(regtest[30], 0xff);
        assert_eq!(regtest[29], 0xff);
        assert!(meets_target(&target, &regtest), "difficulty 1 is under regtest's limit");

        // An exponent of three puts the mantissa in the lowest bytes with no
        // shift at all.
        let tiny = target_from_nbits(0x0300_00ff);
        assert_eq!(tiny[0], 0xff);
        assert!(tiny[1..].iter().all(|b| *b == 0));

        // Below three the mantissa is shifted down, and far enough down it
        // vanishes. Consensus does the same, and such a target is unmeetable
        // rather than invalid.
        assert_eq!(target_from_nbits(0x0100_00ff), [0u8; 32]);
    }

    #[test]
    fn easier_by_is_the_other_direction() {
        let mut target = [0u8; 32];
        target[31] = 0x3f;
        target[30] = 0xff;
        let once = easier_by(&target, 1);
        assert_eq!(once[31], 0x7f);
        assert_eq!(once[30], 0xfe);
        // Easier means a hash that misses the original can still meet this.
        assert!(meets_target(&target, &once));
        assert!(!meets_target(&once, &target));
        assert_eq!(easier_by(&target, 0), target);
        // And it undoes harder_by, which is what makes the shift a dial
        // rather than two unrelated knobs.
        assert_eq!(easier_by(&harder_by(&target, 5), 5), target);
    }

    #[test]
    fn easier_by_saturates_rather_than_wrapping() {
        let mut target = [0u8; 32];
        target[31] = 0x80;
        // One shift takes the top bit out of the integer. Wrapping would make
        // the result harder than the input, so it clamps instead.
        assert_eq!(easier_by(&target, 1), [0xff; 32]);
        assert_eq!(easier_by(&[0xff; 32], 1), [0xff; 32]);
        assert_eq!(easier_by(&target, 300), [0xff; 32]);
    }

    /// The expected number of hashes before one lands at or under `target`,
    /// read back out of the target itself. The inverse of
    /// [`target_for_hashes_per_share`], in f64, for checking round trips.
    fn expected_draws(target: &[u8; 32]) -> f64 {
        let mut t = 0.0f64;
        for byte in target.iter().rev() {
            t = t * 256.0 + f64::from(*byte);
        }
        (2.0f64.powi(256) - t) / (t + 1.0)
    }

    #[test]
    fn one_hash_per_share_is_half_the_space() {
        // t = (2^256 - 1) / 2 = 2^255 - 1, which is exact and so pins the
        // arithmetic without going through f64.
        let mut want = [0xffu8; 32];
        want[31] = 0x7f;
        assert_eq!(target_for_hashes_per_share(1), want);
        // Zero work per share cannot mean a target easier than everything, so
        // it floors to the same place rather than dividing by zero.
        assert_eq!(target_for_hashes_per_share(0), want);
    }

    #[test]
    fn a_target_costs_the_work_it_was_asked_for() {
        // The middle value is this machine's measured MinotaurX rate of
        // 17,440 H/s at 4.5 shares a minute, which is the case the pool
        // actually runs.
        for work in [1u128, 2, 1_000, 13_333, 232_533, 333_333_333, 5_000_000_000_000] {
            let target = target_for_hashes_per_share(work);
            let back = expected_draws(&target);
            let error = (back - work as f64).abs() / work as f64;
            assert!(
                error < 1e-9,
                "asked for {work} hashes a share and got {back}, off by {error}"
            );
        }
    }

    #[test]
    fn more_work_per_share_means_a_harder_target() {
        let mut previous = target_for_hashes_per_share(1);
        for work in [2u128, 100, 10_000, 1_000_000, 1_000_000_000] {
            let target = target_for_hashes_per_share(work);
            // Harder means smaller, so the previous target must not be met by
            // a hash that only just meets this one.
            assert!(
                meets_target(&target, &previous) && target != previous,
                "{work} hashes a share did not come out harder"
            );
            previous = target;
        }
    }

    #[test]
    fn an_absurd_hash_rate_saturates_instead_of_wrapping() {
        // Past the u120 headroom the division needs. The target must stay
        // sane, not wrap into an easy one.
        let huge = target_for_hashes_per_share(u128::MAX);
        let capped = target_for_hashes_per_share((1u128 << 120) - 1);
        assert_eq!(huge, capped);
        assert!(meets_target(&huge, &target_for_hashes_per_share(1)));
    }

    #[test]
    fn the_share_cadence_is_rate_times_sixty_over_shares() {
        assert_eq!(hashes_per_share_for(17_440.0, 4.5), 17_440.0 * 60.0 / 4.5);
        assert_eq!(hashes_per_share_for(1_000.0, 6.0), 10_000.0);
        // Unusable inputs give zero, which the target floor then turns into
        // the easiest target, so the caller has to clamp first.
        assert_eq!(hashes_per_share_for(f64::NAN, 4.5), 0.0);
        assert_eq!(hashes_per_share_for(f64::INFINITY, 4.5), 0.0);
        assert_eq!(hashes_per_share_for(1_000.0, 0.0), 0.0);
        assert_eq!(hashes_per_share_for(1_000.0, -1.0), 0.0);
    }
}
