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
}
